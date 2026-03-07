"""
VBAi Studio — Backend License Server
File: backend_server.py
Stack: FastAPI + Supabase + Dodo Payments webhook
Deploy: Railway / Render (free tier)

Routes:
  GET  /health              — health check
  GET  /license/{email}     — check license status (called by Excel add-in)
  POST /webhook/dodo        — Dodo Payments webhook (activate/cancel)
  POST /webhook/test        — test webhook manually
  GET  /admin/users         — admin: list all users (requires admin key)
  POST /admin/grant         — admin: manually grant access
"""

from fastapi import FastAPI, HTTPException, Request, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from supabase import create_client, Client
from datetime import datetime, timedelta
import hashlib
import hmac
import json
import os
import logging
from typing import Optional

# ── CONFIG ─────────────────────────────────────────────────────────────────────
DODO_API_KEY        = os.environ.get("DODO_API_KEY", "")
ANTHROPIC_API_KEY   = os.environ.get("ANTHROPIC_API_KEY", "")
SUPABASE_URL        = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY        = os.environ.get("SUPABASE_KEY", "")
JWT_SECRET          = os.environ.get("JWT_SECRET", "vbai-secret-2025")
DODO_WEBHOOK_SECRET = os.environ.get("DODO_WEBHOOK_SECRET", "")

# ── INIT ────────────────────────────────────────────────────────────────────────
app = FastAPI(title="VBAi License Server", version="1.0.0")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("vbai")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # restrict to Excel add-in domains in production
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ── MODELS ──────────────────────────────────────────────────────────────────────
class LicenseResponse(BaseModel):
    email: str
    status: str          # "active" | "expired" | "free"
    plan: str            # "pro" | "teams" | "free"
    expires_at: Optional[str]
    daily_prompt_limit: int
    message: str

class AdminGrantRequest(BaseModel):
    email: str
    plan: str = "pro"
    months: int = 1
    admin_key: str

# ── HELPERS ─────────────────────────────────────────────────────────────────────
def get_prompt_limit(plan: str) -> int:
    return {"pro": 20, "teams": 50, "free": 3}.get(plan, 3)

def normalize_email(email: str) -> str:
    return email.strip().lower()

async def verify_dodo_signature(request: Request, x_dodo_signature: str = Header(None)) -> bool:
    """Verify Dodo Payments webhook signature"""
    if not x_dodo_signature:
        return False
    body = await request.body()
    expected = hmac.new(
        DODO_WEBHOOK_SECRET.encode(),
        body,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", x_dodo_signature)

# ── ROUTES ──────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "service": "VBAi License Server", "time": datetime.utcnow().isoformat()}

@app.get("/license/{email}", response_model=LicenseResponse)
async def check_license(email: str):
    """
    Called by the Excel add-in to check subscription status.
    Excel VBA sends: GET /license/user@email.com
    """
    email = normalize_email(email)
    log.info(f"License check: {email}")

    try:
        result = supabase.table("licenses") \
            .select("email,status,plan,expires_at") \
            .eq("email", email) \
            .limit(1) \
            .execute()

        if not result.data:
            return LicenseResponse(
                email=email, status="free", plan="free",
                expires_at=None, daily_prompt_limit=3,
                message="No subscription found. Visit vbai.in to subscribe."
            )

        row = result.data[0]
        expires_at = row.get("expires_at")
        plan = row.get("plan", "pro")

        # Check expiry
        if expires_at:
            expiry_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            if expiry_dt < datetime.now(expiry_dt.tzinfo):
                # Update status to expired
                supabase.table("licenses").update({"status": "expired"}) \
                    .eq("email", email).execute()
                return LicenseResponse(
                    email=email, status="expired", plan=plan,
                    expires_at=expires_at, daily_prompt_limit=3,
                    message="Subscription expired. Renew at vbai.in"
                )

        status = row.get("status", "free")
        return LicenseResponse(
            email=email, status=status, plan=plan,
            expires_at=expires_at,
            daily_prompt_limit=get_prompt_limit(plan if status == "active" else "free"),
            message="Active" if status == "active" else "Subscription not active"
        )

    except Exception as e:
        log.error(f"License check error: {e}")
        # Fail open — don't block the user if server has issues
        return LicenseResponse(
            email=email, status="free", plan="free",
            expires_at=None, daily_prompt_limit=3,
            message="Server error — defaulting to free tier"
        )

@app.post("/webhook/dodo")
async def dodo_webhook(request: Request):
    """
    Dodo Payments sends events here when:
    - subscription.activated
    - subscription.cancelled
    - subscription.payment_failed
    - subscription.renewed
    """
    # Verify signature
    sig_valid = await verify_dodo_signature(request)
    if not sig_valid:
        log.warning("Invalid Dodo webhook signature!")
        raise HTTPException(status_code=401, detail="Invalid signature")

    body = await request.body()
    try:
        event = json.loads(body)
    except:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    event_type = event.get("type", "")
    payload = event.get("data", {})
    email = normalize_email(payload.get("customer", {}).get("email", ""))
    plan = payload.get("product", {}).get("metadata", {}).get("plan", "pro")

    log.info(f"Dodo webhook: {event_type} for {email}")

    if not email:
        return {"received": True, "action": "skipped — no email"}

    if event_type == "subscription.activated":
        # New subscriber — grant access
        expires_at = (datetime.utcnow() + timedelta(days=32)).isoformat()
        subscription_id = payload.get("id", "")

        supabase.table("licenses").upsert({
            "email": email,
            "status": "active",
            "plan": plan,
            "expires_at": expires_at,
            "dodo_subscription_id": subscription_id,
            "activated_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
        }).execute()

        log.info(f"✅ Activated: {email} ({plan})")
        return {"received": True, "action": "activated", "email": email}

    elif event_type == "subscription.renewed":
        # Extend by 32 days from now
        new_expiry = (datetime.utcnow() + timedelta(days=32)).isoformat()
        supabase.table("licenses").update({
            "status": "active",
            "expires_at": new_expiry,
            "updated_at": datetime.utcnow().isoformat(),
        }).eq("email", email).execute()

        log.info(f"🔄 Renewed: {email}")
        return {"received": True, "action": "renewed", "email": email}

    elif event_type == "subscription.cancelled":
        supabase.table("licenses").update({
            "status": "cancelled",
            "updated_at": datetime.utcnow().isoformat(),
        }).eq("email", email).execute()

        log.info(f"❌ Cancelled: {email}")
        return {"received": True, "action": "cancelled", "email": email}

    elif event_type == "subscription.payment_failed":
        # Don't immediately revoke — give 3 day grace period
        grace_expiry = (datetime.utcnow() + timedelta(days=3)).isoformat()
        supabase.table("licenses").update({
            "status": "payment_failed",
            "expires_at": grace_expiry,
            "updated_at": datetime.utcnow().isoformat(),
        }).eq("email", email).execute()

        log.info(f"⚠️ Payment failed: {email}")
        return {"received": True, "action": "payment_failed", "email": email}

    return {"received": True, "action": "unhandled_event", "type": event_type}

@app.post("/webhook/test")
async def test_activate(email: str, plan: str = "pro", admin_key: str = ""):
    """Test endpoint to manually activate a license (admin only)"""
    if admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Unauthorized")

    email = normalize_email(email)
    expires_at = (datetime.utcnow() + timedelta(days=32)).isoformat()

    supabase.table("licenses").upsert({
        "email": email,
        "status": "active",
        "plan": plan,
        "expires_at": expires_at,
        "activated_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat(),
    }).execute()

    return {"activated": True, "email": email, "plan": plan, "expires_at": expires_at}

@app.get("/admin/users")
async def list_users(admin_key: str = "", limit: int = 50, status: str = ""):
    """Admin: list all licensed users"""
    if admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Unauthorized")

    query = supabase.table("licenses").select("*").order("activated_at", desc=True).limit(limit)
    if status:
        query = query.eq("status", status)

    result = query.execute()
    total_active = supabase.table("licenses").select("email", count="exact").eq("status", "active").execute()

    return {
        "users": result.data,
        "count": len(result.data),
        "total_active": total_active.count,
        "monthly_revenue": (total_active.count or 0) * 149
    }

@app.post("/admin/grant")
async def grant_access(req: AdminGrantRequest):
    """Admin: manually grant access to a user"""
    if req.admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Unauthorized")

    email = normalize_email(req.email)
    expires_at = (datetime.utcnow() + timedelta(days=req.months * 32)).isoformat()

    supabase.table("licenses").upsert({
        "email": email,
        "status": "active",
        "plan": req.plan,
        "expires_at": expires_at,
        "activated_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat(),
    }).execute()

    return {"granted": True, "email": email, "plan": req.plan, "expires_at": expires_at}

# ── STARTUP ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
