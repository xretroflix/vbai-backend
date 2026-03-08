"""
VBAi Studio — Backend Server v4
Stack: FastAPI + Supabase Auth + Dodo Payments webhook
Routes: /register /verify-email /resend-otp /login /me /license /webhook/dodo /admin/*
"""
from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from supabase import create_client, Client
from datetime import datetime, timedelta
import hashlib, hmac, json, os, logging, jwt
from typing import Optional

SUPABASE_URL        = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY        = os.environ.get("SUPABASE_KEY", "")
DODO_WEBHOOK_SECRET = os.environ.get("DODO_WEBHOOK_SECRET", "placeholder")
ADMIN_KEY           = os.environ.get("ADMIN_KEY", "vbai-admin-2025")
JWT_SECRET          = os.environ.get("JWT_SECRET", "vbai-secret-mani-2025")
DODO_CHECKOUT_MONTHLY = os.environ.get("DODO_CHECKOUT_MONTHLY","https://test.checkout.dodopayments.com/buy/pdt_0Na1c5RxiEbi1xSlfxpQG?quantity=1")
DODO_CHECKOUT_ANNUAL  = os.environ.get("DODO_CHECKOUT_ANNUAL", "https://test.checkout.dodopayments.com/buy/pdt_0Na1cJLZo6Tu2GLesZPIr?quantity=1")

app = FastAPI(title="VBAi Studio API", version="4.0.0")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY) if SUPABASE_URL else None
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("vbai")

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

class RegisterRequest(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    password: str
    country: str
    plan: Optional[str] = "monthly"
    marketing_consent: Optional[bool] = False

class VerifyOTPRequest(BaseModel):
    email: EmailStr
    otp: str
    plan: Optional[str] = "monthly"

class ResendOTPRequest(BaseModel):
    email: EmailStr

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class AdminGrantRequest(BaseModel):
    email: str; plan: str = "pro"; months: int = 1; admin_key: str

def ne(email): return email.strip().lower()
def gpl(plan): return {"pro":20,"teams":50,"free":3}.get(plan,3)
def make_jwt(email, uid=""):
    return jwt.encode({"sub":email,"uid":uid,"exp":datetime.utcnow()+timedelta(days=30)}, JWT_SECRET, algorithm="HS256")
def ensure_db():
    if not supabase: raise HTTPException(503, "Database not configured")

@app.get("/health")
async def health():
    db_status = "not configured"
    if supabase:
        try:
            supabase.table("licenses").select("count").limit(1).execute()
            db_status = "connected"
        except: db_status = "error"
    return {
        "status": "ok",
        "service": "VBAi Studio API",
        "version": "4.1.0",
        "time": datetime.utcnow().isoformat(),
        "db": db_status,
        "anthropic_key": "set" if os.environ.get("ANTHROPIC_API_KEY") else "NOT SET",
        "supabase_url": "set" if SUPABASE_URL else "NOT SET",
    }

@app.get("/debug/email-test")
async def debug_email_test(email: str = "test@example.com", admin: str = ""):
    """
    Diagnostic route — tests the full Supabase email flow.
    Call: /debug/email-test?email=YOUR_EMAIL&admin=vbai-admin-2025
    Returns exactly what Supabase returns so you can see the error.
    """
    if admin != ADMIN_KEY:
        raise HTTPException(403, "Admin key required")
    if not supabase:
        return {"error": "Supabase not connected — check SUPABASE_URL and SUPABASE_KEY in Railway vars"}
    results = {}
    # Test 1: Can we reach Supabase at all?
    try:
        supabase.table("licenses").select("count").limit(1).execute()
        results["supabase_db"] = "✅ Connected"
    except Exception as e:
        results["supabase_db"] = f"❌ DB Error: {str(e)}"
    # Test 2: Try sign_up and capture exact response
    try:
        test_email = email.strip().lower()
        res = supabase.auth.sign_up({
            "email": test_email,
            "password": "TestPass123!",
            "options": {"data": {"first_name": "Debug", "last_name": "Test"}}
        })
        if res.user:
            results["sign_up"] = "✅ User created"
            results["user_id"] = str(res.user.id)
            results["email_confirmed"] = str(res.user.email_confirmed_at)
            results["confirmation_sent_at"] = str(res.user.confirmation_sent_at)
            if res.user.email_confirmed_at:
                results["email_status"] = "⚠️ Email already confirmed (existing user) — no new email sent"
            elif res.user.confirmation_sent_at:
                results["email_status"] = "✅ Confirmation email was SENT by Supabase"
            else:
                results["email_status"] = "❌ Email NOT sent — check Supabase SMTP settings"
        else:
            results["sign_up"] = "❌ No user returned"
            results["raw_response"] = str(res)
    except Exception as e:
        err = str(e)
        results["sign_up"] = f"❌ Error: {err}"
        if "already registered" in err.lower():
            results["hint"] = "Email already exists — try a different test email"
        elif "smtp" in err.lower() or "email" in err.lower():
            results["hint"] = "SMTP error — Resend credentials wrong in Supabase"
        elif "rate" in err.lower():
            results["hint"] = "Rate limited — wait 60 seconds and try again"
    results["instructions"] = {
        "if_email_not_sent": [
            "1. Go to Supabase Dashboard → Authentication → SMTP Settings",
            "2. Make sure 'Enable Custom SMTP' is TOGGLED ON (green)",
            "3. Host: smtp.resend.com | Port: 465 | User: resend",
            "4. Password: your Resend API key (starts with re_)",
            "5. Sender email: onboarding@resend.dev (use this until domain verified)",
            "6. Click Save and test again"
        ],
        "if_smtp_error": [
            "Go to resend.com → API Keys → make sure key is active",
            "Copy the key again and re-paste into Supabase SMTP password field"
        ]
    }
    return results

@app.post("/register")
async def register(req: RegisterRequest):
    ensure_db()
    email = ne(req.email)
    if len(req.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters.")
    try:
        res = supabase.auth.sign_up({"email": email, "password": req.password, "options": {"data": {"first_name": req.first_name, "last_name": req.last_name, "country": req.country, "plan": req.plan}}})
        if res.user:
            try:
                supabase.table("licenses").upsert({"email":email,"status":"pending","plan":"trial","first_name":req.first_name,"last_name":req.last_name,"country":req.country,"created_at":datetime.utcnow().isoformat(),"updated_at":datetime.utcnow().isoformat()}).execute()
            except Exception as e: log.warning(f"DB upsert warn: {e}")
            log.info(f"Registered: {email}")
            return {"success":True,"message":"Verification code sent to your email. Check your inbox (and spam folder).","email":email,"next":"verify_email"}
        raise HTTPException(400, "Registration failed.")
    except HTTPException: raise
    except Exception as e:
        es = str(e).lower()
        if "already registered" in es or "already exists" in es:
            raise HTTPException(409, "An account with this email already exists. Please log in.")
        log.error(f"Register error: {e}")
        raise HTTPException(500, "Registration failed. Please try again.")

@app.post("/verify-email")
async def verify_email(req: VerifyOTPRequest):
    ensure_db()
    email = ne(req.email)
    try:
        res = supabase.auth.verify_otp({"email": email, "token": req.otp.strip(), "type": "signup"})
        if res.user and res.session:
            token = make_jwt(email, str(res.user.id))
            try:
                supabase.table("licenses").update({"status":"email_verified","updated_at":datetime.utcnow().isoformat()}).eq("email",email).execute()
            except: pass
            plan = req.plan or "monthly"
            base = DODO_CHECKOUT_MONTHLY if plan == "monthly" else DODO_CHECKOUT_ANNUAL
            checkout_url = f"{base}&email={email}"
            log.info(f"Email verified: {email}")
            return {"success":True,"token":token,"email":email,"checkout_url":checkout_url,"message":"Email verified!"}
        raise HTTPException(400, "Invalid or expired code.")
    except HTTPException: raise
    except Exception as e:
        log.error(f"OTP error: {e}")
        raise HTTPException(400, "Invalid or expired code. Click Resend to get a new one.")

@app.post("/resend-otp")
async def resend_otp(req: ResendOTPRequest):
    ensure_db()
    email = ne(req.email)
    try:
        supabase.auth.resend({"type":"signup","email":email})
        return {"success":True,"message":"New verification code sent. Check your inbox."}
    except Exception as e:
        log.error(f"Resend error: {e}")
        raise HTTPException(500, "Could not resend. Please try again.")

@app.post("/login")
async def login(req: LoginRequest):
    ensure_db()
    email = ne(req.email)
    try:
        res = supabase.auth.sign_in_with_password({"email": email, "password": req.password})
        if res.user and res.session:
            token = make_jwt(email, str(res.user.id))
            log.info(f"Login: {email}")
            return {"success":True,"token":token,"email":email}
        raise HTTPException(401,"Invalid email or password.")
    except HTTPException: raise
    except Exception as e:
        if "invalid" in str(e).lower(): raise HTTPException(401,"Invalid email or password.")
        log.error(f"Login error: {e}")
        raise HTTPException(500,"Login failed.")

@app.get("/me")
async def get_me(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Not authenticated.")
    try:
        payload = jwt.decode(authorization.split(" ",1)[1], JWT_SECRET, algorithms=["HS256"])
        email = payload["sub"]
        if supabase:
            r = supabase.table("licenses").select("*").eq("email",email).limit(1).execute()
            if r.data: return {"email":email,"license":r.data[0]}
        return {"email":email,"license":None}
    except: raise HTTPException(401,"Invalid or expired token.")

@app.get("/license/{email}")
async def check_license(email: str):
    email = ne(email)
    if not supabase:
        return {"email":email,"status":"free","plan":"free","expires_at":None,"daily_prompt_limit":3,"message":"DB not configured"}
    try:
        r = supabase.table("licenses").select("*").eq("email",email).limit(1).execute()
        if not r.data:
            return {"email":email,"status":"free","plan":"free","expires_at":None,"daily_prompt_limit":3,"message":"No subscription"}
        row = r.data[0]; ea = row.get("expires_at"); plan = row.get("plan","pro")
        if ea:
            exp = datetime.fromisoformat(ea.replace("Z","+00:00"))
            if exp < datetime.now(exp.tzinfo):
                supabase.table("licenses").update({"status":"expired"}).eq("email",email).execute()
                return {"email":email,"status":"expired","plan":plan,"expires_at":ea,"daily_prompt_limit":3,"message":"Expired"}
        st = row.get("status","free")
        return {"email":email,"status":st,"plan":plan,"expires_at":ea,"daily_prompt_limit":gpl(plan if st=="active" else "free"),"message":"Active" if st=="active" else "Not active"}
    except Exception as e:
        log.error(f"License error: {e}")
        return {"email":email,"status":"free","plan":"free","expires_at":None,"daily_prompt_limit":3,"message":"Server error"}

class ConfirmLinkRequest(BaseModel):
    token_hash: str
    type: Optional[str] = "signup"

class ExchangeTokenRequest(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None

@app.post("/confirm-link")
async def confirm_link(req: ConfirmLinkRequest):
    """
    Called by auth/callback.html after Supabase sends a magic link.
    Supabase embeds token_hash in the confirmation URL.
    We verify it via Supabase Auth, create our own JWT, return checkout URL.
    """
    ensure_db()
    try:
        # Exchange the token_hash for a session using Supabase Auth
        res = supabase.auth.verify_otp({
            "token_hash": req.token_hash,
            "type": req.type or "signup"
        })
        if res.user and res.session:
            email = ne(res.user.email or "")
            token = make_jwt(email, str(res.user.id))
            # Update license status to confirmed
            try:
                supabase.table("licenses").update({
                    "status": "email_verified",
                    "updated_at": datetime.utcnow().isoformat(),
                }).eq("email", email).execute()
            except: pass
            log.info(f"✅ Magic link confirmed: {email}")
            return {"success": True, "token": token, "email": email}
        raise HTTPException(400, "Invalid or expired confirmation link. Please register again.")
    except HTTPException: raise
    except Exception as e:
        log.error(f"Confirm link error: {e}")
        raise HTTPException(400, "Confirmation failed. The link may have expired. Please register again.")

@app.post("/exchange-token")
async def exchange_token(req: ExchangeTokenRequest):
    """Fallback: exchange Supabase access_token (from URL hash) for our JWT."""
    ensure_db()
    try:
        # Get user info from Supabase using their access token
        res = supabase.auth.get_user(req.access_token)
        if res.user:
            email = ne(res.user.email or "")
            token = make_jwt(email, str(res.user.id))
            try:
                supabase.table("licenses").update({
                    "status": "email_verified",
                    "updated_at": datetime.utcnow().isoformat(),
                }).eq("email", email).execute()
            except: pass
            log.info(f"✅ Token exchanged: {email}")
            return {"success": True, "token": token, "email": email}
        raise HTTPException(401, "Invalid access token.")
    except HTTPException: raise
    except Exception as e:
        log.error(f"Exchange token error: {e}")
        raise HTTPException(401, "Could not process session. Please log in manually.")

@app.post("/webhook/dodo")
async def dodo_webhook(request: Request, x_dodo_signature: str = Header(None)):
    body = await request.body()
    if x_dodo_signature and DODO_WEBHOOK_SECRET != "placeholder":
        expected = "sha256=" + hmac.new(DODO_WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, x_dodo_signature):
            raise HTTPException(401,"Invalid signature")
    try: event = json.loads(body)
    except: raise HTTPException(400,"Invalid JSON")
    et = event.get("type",""); pd = event.get("data",{})
    email = ne(pd.get("customer",{}).get("email",""))
    plan = pd.get("product",{}).get("metadata",{}).get("plan","pro")
    log.info(f"Dodo: {et} → {email}")
    if not email: return {"received":True,"action":"skipped"}
    now = datetime.utcnow().isoformat()
    if et == "subscription.activated":
        supabase.table("licenses").upsert({"email":email,"status":"active","plan":plan,"expires_at":(datetime.utcnow()+timedelta(days=32)).isoformat(),"dodo_subscription_id":pd.get("id",""),"activated_at":now,"updated_at":now}).execute()
    elif et == "subscription.renewed":
        supabase.table("licenses").update({"status":"active","expires_at":(datetime.utcnow()+timedelta(days=32)).isoformat(),"updated_at":now}).eq("email",email).execute()
    elif et == "subscription.cancelled":
        supabase.table("licenses").update({"status":"cancelled","updated_at":now}).eq("email",email).execute()
    elif et == "subscription.payment_failed":
        supabase.table("licenses").update({"status":"payment_failed","expires_at":(datetime.utcnow()+timedelta(days=3)).isoformat(),"updated_at":now}).eq("email",email).execute()
    return {"received":True,"action":et}

@app.post("/webhook/test")
async def test_activate(email: str, plan: str = "pro", admin_key: str = ""):
    if admin_key != ADMIN_KEY: raise HTTPException(403,"Unauthorized")
    email = ne(email); ea = (datetime.utcnow()+timedelta(days=32)).isoformat()
    supabase.table("licenses").upsert({"email":email,"status":"active","plan":plan,"expires_at":ea,"activated_at":datetime.utcnow().isoformat(),"updated_at":datetime.utcnow().isoformat()}).execute()
    return {"activated":True,"email":email,"plan":plan,"expires_at":ea}

@app.get("/admin/users")
async def list_users(admin_key: str = "", limit: int = 50, status: str = ""):
    if admin_key != ADMIN_KEY: raise HTTPException(403,"Unauthorized")
    ensure_db()
    q = supabase.table("licenses").select("*").order("created_at",desc=True).limit(limit)
    if status: q = q.eq("status",status)
    r = q.execute()
    active = supabase.table("licenses").select("email",count="exact").eq("status","active").execute()
    return {"users":r.data,"count":len(r.data),"total_active":active.count,"monthly_revenue_usd":(active.count or 0)*14}

@app.post("/admin/grant")
async def grant_access(req: AdminGrantRequest):
    if req.admin_key != ADMIN_KEY: raise HTTPException(403,"Unauthorized")
    ensure_db()
    email = ne(req.email); ea = (datetime.utcnow()+timedelta(days=req.months*32)).isoformat()
    supabase.table("licenses").upsert({"email":email,"status":"active","plan":req.plan,"expires_at":ea,"activated_at":datetime.utcnow().isoformat(),"updated_at":datetime.utcnow().isoformat()}).execute()
    return {"granted":True,"email":email,"plan":req.plan,"expires_at":ea}

# ── AI PROXY ROUTES ──────────────────────────────────────────────────────────────
# These proxy calls to Anthropic using VBAi's API key (never exposed to browser)
# Requires valid JWT + active subscription

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY","")
ANTHROPIC_ENDPOINT = "https://api.anthropic.com/v1/messages"

SYSTEM_GENERATE = """You are VBAi Studio's VBA code generator. Generate Excel VBA macro code only.
Rules: Always wrap in Sub/End Sub. Use meaningful variable names. Add brief comments.
Output ONLY the VBA code — no explanation, no markdown fences, no preamble."""

SYSTEM_EXPLAIN = """You are a VBA teacher. Explain the given VBA code clearly for a non-programmer.
Use simple language. Format: 1 sentence summary, then bullet points for each main action.
Be concise — max 200 words."""

SYSTEM_FIX = """You are a VBA debugger. Fix the given VBA code. 
Output: brief explanation of the bug (1-2 sentences), then the corrected full code.
Output ONLY explanation + fixed code — no markdown fences."""

class AIRequest(BaseModel):
    prompt: str
    mode: str = "generate"          # generate | explain | fix | improve | convert
    model: Optional[str] = None     # auto-selected if None
    context: Optional[str] = ""    # extra context (Indian format, etc)
    error_msg: Optional[str] = ""  # for fix mode

def get_auth_email(authorization: str) -> str:
    """Extract email from Bearer JWT. Raises 401 if invalid."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Authentication required. Please log in.")
    try:
        payload = jwt.decode(authorization.split(" ",1)[1], JWT_SECRET, algorithms=["HS256"])
        return payload["sub"]
    except Exception:
        raise HTTPException(401, "Session expired. Please log in again.")

def check_subscription(email: str) -> dict:
    """Return license row. Raises 403 if not active/trial."""
    if not supabase:
        return {"status":"active","plan":"pro"}  # fail-open if DB down
    try:
        r = supabase.table("licenses").select("*").eq("email",email).limit(1).execute()
        if not r.data:
            raise HTTPException(403, "No subscription found. Please complete payment setup.")
        row = r.data[0]
        status = row.get("status","")
        # Allow active subscriptions and email-verified (grace period before Dodo webhook)
        if status in ("active", "email_verified"):
            return row
        elif status in ("expired","cancelled","payment_failed"):
            raise HTTPException(403, f"Subscription {status}. Please renew at vbai.online")
        elif status in ("pending",):
            raise HTTPException(403, "Please complete payment setup to access the builder.")
        return row  # any other status: allow
    except HTTPException: raise
    except Exception as e:
        log.error(f"Subscription check error: {e}")
        return {"status":"active","plan":"pro"}  # fail-open

@app.get("/subscription/status")
async def subscription_status(authorization: str = Header(None)):
    """Called by builder.html on load to check auth + subscription state."""
    email = get_auth_email(authorization)
    row = check_subscription(email)
    # Calculate trial days remaining
    days_left = None
    activated = row.get("activated_at") or row.get("created_at")
    if activated and row.get("status") == "active":
        try:
            act_dt = datetime.fromisoformat(activated.replace("Z",""))
            days_left = max(0, 3 - (datetime.utcnow() - act_dt).days)
        except: pass
    return {
        "email": email,
        "status": row.get("status","active"),
        "plan": row.get("plan","pro"),
        "first_name": row.get("first_name",""),
        "days_left": days_left,
        "ai_credits": row.get("ai_credits", 20),
    }

@app.post("/ai/generate")
async def ai_generate(req: AIRequest, authorization: str = Header(None)):
    """Generate VBA macro via Claude. Requires active subscription."""
    email = get_auth_email(authorization)
    check_subscription(email)

    if not ANTHROPIC_API_KEY:
        raise HTTPException(503, "AI service not configured. Please contact support.")

    # Build prompt based on mode
    mode_prefix = {
        "generate": "Generate this Excel VBA macro: ",
        "improve":  "Improve this Excel VBA code:\n",
        "convert":  "Convert this Excel formula to a VBA macro:\n",
        "explain":  "Explain this VBA code clearly:\n",
        "fix":      "Fix this VBA code" + (f" that gives error: {req.error_msg}" if req.error_msg else "") + ":\n",
    }
    full_prompt = mode_prefix.get(req.mode, "") + req.prompt
    if req.context:
        full_prompt += "\n\n" + req.context

    # Route to appropriate model
    mode = req.mode
    model = req.model or ("claude-haiku-4-5-20251001" if mode in ("explain",) else "claude-sonnet-4-6")
    system = SYSTEM_EXPLAIN if mode=="explain" else SYSTEM_FIX if mode=="fix" else SYSTEM_GENERATE

    try:
        import httpx
        async with httpx.AsyncClient(timeout=45.0) as client:
            r = await client.post(
                ANTHROPIC_ENDPOINT,
                headers={
                    "x-api-key": ANTHROPIC_API_KEY,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": model,
                    "max_tokens": 1500,
                    "system": system,
                    "messages": [{"role":"user","content": full_prompt}]
                }
            )
            if not r.is_success:
                log.error(f"Anthropic error {r.status_code}: {r.text[:200]}")
                raise HTTPException(502, "AI service error. Please try again.")
            data = r.json()
            result_text = data["content"][0]["text"]

        # Deduct 1 AI credit from user's allocation
        try:
            current = supabase.table("licenses").select("ai_credits").eq("email",email).limit(1).execute()
            current_credits = (current.data[0].get("ai_credits") or 20) if current.data else 20
            if current_credits > 0:
                supabase.table("licenses").update({"ai_credits": max(0, current_credits-1),"updated_at":datetime.utcnow().isoformat()}).eq("email",email).execute()
        except: pass

        return {"success": True, "code": result_text, "model": model, "email": email}

    except HTTPException: raise
    except Exception as e:
        log.error(f"AI generate error: {e}")
        raise HTTPException(502, "AI generation failed. Please try again.")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT",8000)))
