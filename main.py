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
    return {"status":"ok","service":"VBAi Studio API","version":"4.0.0","time":datetime.utcnow().isoformat(),"db":"connected" if supabase else "not configured"}

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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT",8000)))
