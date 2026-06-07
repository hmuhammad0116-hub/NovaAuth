import os
import uuid
import random
from datetime import datetime, timedelta

import requests
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, Request
from sqlalchemy.orm import Session

from database import Base, engine, get_db
from models import (
    Account,
    EmailCode,
    StaffRequest,
    App,
    User,
    License,
    Session as UserSession,
    Log,
)
from schemas import (
    AccountRegisterRequest,
    AccountVerifyRequest,
    AccountLoginRequest,
    StaffRequestCreate,
    StaffRequestAction,
    MakeAdminRequest,
    CreateAppRequest,
    RegisterRequest,
    LoginRequest,
    ValidateRequest,
    LogoutRequest,
    BanUserRequest,
    ResetHWIDRequest,
    ExtendUserRequest,
    DeleteUserRequest,
    DeleteLicenseRequest,
    DeleteAppRequest,
    AppStatusRequest,
)
from auth import hash_password, verify_password, create_token, decode_token
from email_utils import send_verification_code, send_staff_request_email

load_dotenv()

app = FastAPI(title="NovaAuth API", version="2.0.0")

Base.metadata.create_all(bind=engine)

from sqlalchemy import text

def safe_migrate():
    with engine.connect() as conn:
        try:
            conn.execute(text("ALTER TABLE apps ADD COLUMN owner_id INT NULL"))
            conn.commit()
        except Exception:
            conn.rollback()

        try:
            conn.execute(text("ALTER TABLE users ADD COLUMN email VARCHAR(255) NULL"))
            conn.commit()
        except Exception:
            conn.rollback()

safe_migrate()

ADMIN_SECRET = os.getenv("ADMIN_SECRET", "NovaAuth_Admin_Secret_2026_ChangeMe")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")


def get_ip(request: Request):
    return request.client.host if request.client else "unknown"


def check_admin(request: Request):
    return request.headers.get("X-Admin-Secret") == ADMIN_SECRET


def admin_required(request: Request):
    if not check_admin(request):
        return {"success": False, "message": "Unauthorized admin request"}
    return None


def log_action(db: Session, app_id: str, user_id, action: str, ip: str):
    db.add(Log(app_id=app_id, user_id=user_id, action=action, ip=ip))
    db.commit()


def make_code():
    return str(random.randint(100000, 999999))


def check_app(db: Session, app_id: str, secret: str):
    app_data = db.query(App).filter(App.app_id == app_id).first()

    if not app_data:
        return None, "App not found"

    if app_data.secret != secret:
        return None, "Invalid app secret"

    if app_data.status != "active":
        return None, "App disabled"

    return app_data, None


def account_from_token(db: Session, token: str):
    payload = decode_token(token)
    if not payload:
        return None

    account_id = payload.get("account_id")
    if not account_id:
        return None

    return db.query(Account).filter(Account.id == account_id).first()


def account_can_admin(account: Account):
    return account and account.role in ["owner", "admin", "support"] and not account.banned


@app.get("/")
def home():
    return {
        "success": True,
        "message": "NovaAuth API is running",
        "version": "2.0.0"
    }


@app.get("/health")
def health():
    return {"status": "online"}


# =========================
# ACCOUNT AUTH SYSTEM
# =========================

@app.post("/api/v1/account/register")
def account_register(data: AccountRegisterRequest, db: Session = Depends(get_db)):
    existing_email = db.query(Account).filter(Account.email == data.email).first()
    if existing_email:
        return {"success": False, "message": "Email already registered"}

    existing_user = db.query(Account).filter(Account.username == data.username).first()
    if existing_user:
        return {"success": False, "message": "Username already taken"}

    account = Account(
        email=data.email,
        username=data.username,
        password_hash=hash_password(data.password),
        role="customer",
        email_verified=False,
        banned=False
    )

    db.add(account)
    db.commit()
    db.refresh(account)

    code = make_code()

    db.add(EmailCode(email=data.email, code=code, used=False))
    db.commit()

    send_verification_code(data.email, code)

    return {
        "success": True,
        "message": "Account created. Verification code sent to email.",
        "account_id": account.id
    }


@app.post("/api/v1/account/verify-email")
def verify_email(data: AccountVerifyRequest, db: Session = Depends(get_db)):
    code_row = db.query(EmailCode).filter(
        EmailCode.email == data.email,
        EmailCode.code == data.code,
        EmailCode.used == False
    ).order_by(EmailCode.id.desc()).first()

    if not code_row:
        return {"success": False, "message": "Invalid verification code"}

    account = db.query(Account).filter(Account.email == data.email).first()
    if not account:
        return {"success": False, "message": "Account not found"}

    account.email_verified = True
    code_row.used = True

    db.commit()

    return {"success": True, "message": "Email verified successfully"}


@app.post("/api/v1/account/login")
def account_login(data: AccountLoginRequest, request: Request, db: Session = Depends(get_db)):
    account = db.query(Account).filter(Account.email == data.email).first()

    if not account:
        return {"success": False, "message": "Invalid email or password"}

    if account.banned:
        return {"success": False, "message": "Account banned"}

    if not account.password_hash or not verify_password(data.password, account.password_hash):
        return {"success": False, "message": "Invalid email or password"}

    if not account.email_verified:
        return {"success": False, "message": "Email not verified"}

    token = create_token({
        "account_id": account.id,
        "email": account.email,
        "username": account.username,
        "role": account.role
    })

    return {
        "success": True,
        "message": "Login successful",
        "token": token,
        "account": {
            "id": account.id,
            "email": account.email,
            "username": account.username,
            "role": account.role,
            "email_verified": account.email_verified
        }
    }


@app.post("/api/v1/account/google")
def google_login(id_token: str, db: Session = Depends(get_db)):
    if not GOOGLE_CLIENT_ID:
        return {"success": False, "message": "Google login not configured"}

    r = requests.get(
        "https://oauth2.googleapis.com/tokeninfo",
        params={"id_token": id_token},
        timeout=15
    )

    if r.status_code != 200:
        return {"success": False, "message": "Invalid Google token"}

    info = r.json()

    if info.get("aud") != GOOGLE_CLIENT_ID:
        return {"success": False, "message": "Invalid Google client"}

    email = info.get("email")
    google_id = info.get("sub")
    verified = info.get("email_verified") == "true"

    if not email or not google_id or not verified:
        return {"success": False, "message": "Google email not verified"}

    account = db.query(Account).filter(Account.email == email).first()

    if not account:
        username = email.split("@")[0]
        base_username = username
        counter = 1

        while db.query(Account).filter(Account.username == username).first():
            username = f"{base_username}{counter}"
            counter += 1

        account = Account(
            email=email,
            username=username,
            password_hash=None,
            google_id=google_id,
            role="customer",
            email_verified=True,
            banned=False
        )
        db.add(account)
        db.commit()
        db.refresh(account)

    if account.banned:
        return {"success": False, "message": "Account banned"}

    account.google_id = google_id
    account.email_verified = True
    db.commit()

    token = create_token({
        "account_id": account.id,
        "email": account.email,
        "username": account.username,
        "role": account.role
    })

    return {
        "success": True,
        "message": "Google login successful",
        "token": token,
        "account": {
            "id": account.id,
            "email": account.email,
            "username": account.username,
            "role": account.role
        }
    }


@app.post("/api/v1/account/request-staff")
def request_staff(data: StaffRequestCreate, db: Session = Depends(get_db)):
    account = account_from_token(db, data.token)

    if not account:
        return {"success": False, "message": "Invalid account token"}

    if data.requested_role not in ["support", "admin"]:
        return {"success": False, "message": "Invalid requested role"}

    existing = db.query(StaffRequest).filter(
        StaffRequest.account_id == account.id,
        StaffRequest.status == "pending"
    ).first()

    if existing:
        return {"success": False, "message": "Request already pending"}

    req = StaffRequest(
        account_id=account.id,
        requested_role=data.requested_role,
        status="pending"
    )

    db.add(req)
    db.commit()

    send_staff_request_email(account.username, account.email, data.requested_role)

    return {"success": True, "message": "Staff request sent to owner"}


# =========================
# OWNER / ADMIN ACCOUNT MANAGEMENT
# =========================

@app.get("/api/v1/admin/accounts")
def list_accounts(request: Request, db: Session = Depends(get_db)):
    denied = admin_required(request)
    if denied:
        return denied

    accounts = db.query(Account).order_by(Account.id.desc()).all()

    return {
        "success": True,
        "accounts": [
            {
                "id": a.id,
                "email": a.email,
                "username": a.username,
                "role": a.role,
                "email_verified": a.email_verified,
                "banned": a.banned,
                "created_at": str(a.created_at)
            }
            for a in accounts
        ]
    }


@app.get("/api/v1/admin/staff-requests")
def list_staff_requests(request: Request, db: Session = Depends(get_db)):
    denied = admin_required(request)
    if denied:
        return denied

    reqs = db.query(StaffRequest).order_by(StaffRequest.id.desc()).all()

    data = []

    for req in reqs:
        acc = db.query(Account).filter(Account.id == req.account_id).first()
        data.append({
            "id": req.id,
            "account_id": req.account_id,
            "username": acc.username if acc else "",
            "email": acc.email if acc else "",
            "requested_role": req.requested_role,
            "status": req.status,
            "created_at": str(req.created_at)
        })

    return {"success": True, "requests": data}


@app.post("/api/v1/admin/staff-request/action")
def staff_request_action(data: StaffRequestAction, request: Request, db: Session = Depends(get_db)):
    denied = admin_required(request)
    if denied:
        return denied

    req = db.query(StaffRequest).filter(StaffRequest.id == data.request_id).first()

    if not req:
        return {"success": False, "message": "Staff request not found"}

    account = db.query(Account).filter(Account.id == req.account_id).first()

    if not account:
        return {"success": False, "message": "Account not found"}

    if data.approve:
        account.role = req.requested_role
        req.status = "approved"
        msg = "Staff request approved"
    else:
        req.status = "rejected"
        msg = "Staff request rejected"

    db.commit()

    return {
        "success": True,
        "message": msg,
        "account_id": account.id,
        "role": account.role,
        "request_status": req.status
    }


@app.post("/api/v1/admin/make-admin")
def make_admin(data: MakeAdminRequest, request: Request, db: Session = Depends(get_db)):
    denied = admin_required(request)
    if denied:
        return denied

    if data.role not in ["owner", "admin", "support", "customer"]:
        return {"success": False, "message": "Invalid role"}

    account = db.query(Account).filter(Account.id == data.account_id).first()

    if not account:
        return {"success": False, "message": "Account not found"}

    account.role = data.role
    db.commit()

    return {
        "success": True,
        "message": "Role updated",
        "account_id": account.id,
        "role": account.role
    }


@app.post("/api/v1/admin/ban-account")
def ban_account(account_id: int, banned: bool, request: Request, db: Session = Depends(get_db)):
    denied = admin_required(request)
    if denied:
        return denied

    account = db.query(Account).filter(Account.id == account_id).first()

    if not account:
        return {"success": False, "message": "Account not found"}

    account.banned = banned
    db.commit()

    return {
        "success": True,
        "message": "Account ban updated",
        "account_id": account.id,
        "banned": account.banned
    }


# =========================
# ADMIN APP MANAGEMENT
# =========================

@app.post("/api/v1/admin/create-app")
def create_app(data: CreateAppRequest, request: Request, db: Session = Depends(get_db)):
    denied = admin_required(request)
    if denied:
        return denied

    app_id = "app_" + uuid.uuid4().hex[:16]
    secret = "sec_" + uuid.uuid4().hex + uuid.uuid4().hex[:16]

    new_app = App(
        owner_id=data.owner_id,
        app_id=app_id,
        name=data.name,
        secret=secret,
        version=data.version,
        status="active"
    )

    db.add(new_app)
    db.commit()

    return {
        "success": True,
        "app_id": app_id,
        "app_secret": secret,
        "message": "App created"
    }


@app.get("/api/v1/admin/apps")
def list_apps(request: Request, owner_id: int | None = None, db: Session = Depends(get_db)):
    denied = admin_required(request)
    if denied:
        return denied

    q = db.query(App)

    if owner_id:
        q = q.filter(App.owner_id == owner_id)

    apps = q.order_by(App.id.desc()).all()

    return {
        "success": True,
        "apps": [
            {
                "id": a.id,
                "owner_id": a.owner_id,
                "app_id": a.app_id,
                "name": a.name,
                "version": a.version,
                "status": a.status,
                "created_at": str(a.created_at)
            }
            for a in apps
        ]
    }


@app.post("/api/v1/admin/delete-app")
def delete_app(data: DeleteAppRequest, request: Request, db: Session = Depends(get_db)):
    denied = admin_required(request)
    if denied:
        return denied

    app_data = db.query(App).filter(App.app_id == data.app_id).first()
    if not app_data:
        return {"success": False, "message": "App not found"}

    users = db.query(User).filter(User.app_id == data.app_id).all()

    for user in users:
        db.query(UserSession).filter(UserSession.user_id == user.id).delete()
        db.query(Log).filter(Log.user_id == user.id).delete()
        db.delete(user)

    db.query(License).filter(License.app_id == data.app_id).delete()
    db.query(Log).filter(Log.app_id == data.app_id).delete()

    db.delete(app_data)
    db.commit()

    return {"success": True, "message": "App, users, licenses, sessions and logs deleted"}


@app.post("/api/v1/admin/app-status")
def app_status(data: AppStatusRequest, request: Request, db: Session = Depends(get_db)):
    denied = admin_required(request)
    if denied:
        return denied

    if data.status not in ["active", "disabled"]:
        return {"success": False, "message": "Invalid status"}

    app_data = db.query(App).filter(App.app_id == data.app_id).first()

    if not app_data:
        return {"success": False, "message": "App not found"}

    app_data.status = data.status
    db.commit()

    return {"success": True, "message": "App status updated", "status": app_data.status}


@app.post("/api/v1/admin/create-license")
def create_license(
    app_id: str,
    request: Request,
    duration_days: int = 30,
    db: Session = Depends(get_db),
):
    denied = admin_required(request)
    if denied:
        return denied

    app_data = db.query(App).filter(App.app_id == app_id).first()
    if not app_data:
        return {"success": False, "message": "App not found"}

    key = "NOVA-" + uuid.uuid4().hex[:8].upper() + "-" + uuid.uuid4().hex[:8].upper()

    lic = License(app_id=app_id, license_key=key, duration_days=duration_days)

    db.add(lic)
    db.commit()

    return {"success": True, "license_key": key, "duration_days": duration_days}


@app.get("/api/v1/admin/licenses")
def list_licenses(request: Request, app_id: str | None = None, db: Session = Depends(get_db)):
    denied = admin_required(request)
    if denied:
        return denied

    q = db.query(License)

    if app_id:
        q = q.filter(License.app_id == app_id)

    licenses = q.order_by(License.id.desc()).all()

    return {
        "success": True,
        "licenses": [
            {
                "id": l.id,
                "app_id": l.app_id,
                "license_key": l.license_key,
                "used": l.used,
                "used_by": l.used_by,
                "duration_days": l.duration_days,
                "created_at": str(l.created_at)
            }
            for l in licenses
        ]
    }


@app.post("/api/v1/admin/delete-license")
def delete_license(data: DeleteLicenseRequest, request: Request, db: Session = Depends(get_db)):
    denied = admin_required(request)
    if denied:
        return denied

    lic = db.query(License).filter(License.id == data.license_id).first()
    if not lic:
        return {"success": False, "message": "License not found"}

    db.delete(lic)
    db.commit()

    return {"success": True, "message": "License deleted successfully"}


@app.get("/api/v1/admin/users")
def list_users(request: Request, app_id: str | None = None, db: Session = Depends(get_db)):
    denied = admin_required(request)
    if denied:
        return denied

    q = db.query(User)

    if app_id:
        q = q.filter(User.app_id == app_id)

    users = q.order_by(User.id.desc()).all()

    return {
        "success": True,
        "users": [
            {
                "id": u.id,
                "app_id": u.app_id,
                "username": u.username,
                "email": u.email,
                "hwid": u.hwid,
                "banned": u.banned,
                "expires_at": str(u.expires_at),
                "created_at": str(u.created_at)
            }
            for u in users
        ]
    }


@app.post("/api/v1/admin/ban-user")
def ban_user(data: BanUserRequest, request: Request, db: Session = Depends(get_db)):
    denied = admin_required(request)
    if denied:
        return denied

    user = db.query(User).filter(User.id == data.user_id).first()

    if not user:
        return {"success": False, "message": "User not found"}

    user.banned = data.banned
    db.commit()

    return {
        "success": True,
        "message": "User banned" if data.banned else "User unbanned",
        "user_id": user.id,
        "banned": user.banned
    }


@app.post("/api/v1/admin/delete-user")
def delete_user(data: DeleteUserRequest, request: Request, db: Session = Depends(get_db)):
    denied = admin_required(request)
    if denied:
        return denied

    user = db.query(User).filter(User.id == data.user_id).first()
    if not user:
        return {"success": False, "message": "User not found"}

    db.query(UserSession).filter(UserSession.user_id == user.id).delete()
    db.query(Log).filter(Log.user_id == user.id).delete()

    licenses = db.query(License).filter(License.used_by == user.id).all()
    for lic in licenses:
        lic.used = False
        lic.used_by = None

    db.delete(user)
    db.commit()

    return {"success": True, "message": "User deleted and license released"}


@app.post("/api/v1/admin/reset-hwid")
def reset_hwid(data: ResetHWIDRequest, request: Request, db: Session = Depends(get_db)):
    denied = admin_required(request)
    if denied:
        return denied

    user = db.query(User).filter(User.id == data.user_id).first()

    if not user:
        return {"success": False, "message": "User not found"}

    user.hwid = None
    db.commit()

    return {"success": True, "message": "HWID reset successful", "user_id": user.id}


@app.post("/api/v1/admin/extend-user")
def extend_user(data: ExtendUserRequest, request: Request, db: Session = Depends(get_db)):
    denied = admin_required(request)
    if denied:
        return denied

    user = db.query(User).filter(User.id == data.user_id).first()

    if not user:
        return {"success": False, "message": "User not found"}

    now = datetime.utcnow()

    if user.expires_at and user.expires_at > now:
        user.expires_at = user.expires_at + timedelta(days=data.days)
    else:
        user.expires_at = now + timedelta(days=data.days)

    db.commit()

    return {
        "success": True,
        "message": "User subscription extended",
        "user_id": user.id,
        "expires_at": str(user.expires_at)
    }


@app.get("/api/v1/admin/logs")
def list_logs(request: Request, app_id: str | None = None, db: Session = Depends(get_db)):
    denied = admin_required(request)
    if denied:
        return denied

    q = db.query(Log)

    if app_id:
        q = q.filter(Log.app_id == app_id)

    logs = q.order_by(Log.id.desc()).limit(200).all()

    return {
        "success": True,
        "logs": [
            {
                "id": log.id,
                "app_id": log.app_id,
                "user_id": log.user_id,
                "action": log.action,
                "ip": log.ip,
                "created_at": str(log.created_at)
            }
            for log in logs
        ]
    }


# =========================
# CLIENT APP AUTH
# =========================

@app.post("/api/v1/register")
def register(data: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    ip = get_ip(request)

    app_data, error = check_app(db, data.app_id, data.app_secret)
    if error:
        return {"success": False, "message": error}

    existing = db.query(User).filter(
        User.app_id == data.app_id,
        User.username == data.username
    ).first()

    if existing:
        return {"success": False, "message": "Username already exists"}

    license_data = db.query(License).filter(
        License.app_id == data.app_id,
        License.license_key == data.license_key
    ).first()

    if not license_data:
        return {"success": False, "message": "Invalid license key"}

    if license_data.used:
        return {"success": False, "message": "License already used"}

    expires_at = datetime.utcnow() + timedelta(days=license_data.duration_days)

    user = User(
        app_id=data.app_id,
        username=data.username,
        password_hash=hash_password(data.password),
        email=data.email,
        hwid=data.hwid,
        expires_at=expires_at
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    license_data.used = True
    license_data.used_by = user.id
    db.commit()

    token = create_token({
        "user_id": user.id,
        "username": user.username,
        "app_id": data.app_id
    })

    db.add(UserSession(user_id=user.id, token=token, ip=ip))
    db.commit()

    log_action(db, data.app_id, user.id, "register", ip)

    return {
        "success": True,
        "message": "Registered successfully",
        "token": token,
        "expires_at": str(expires_at)
    }


@app.post("/api/v1/login")
def login(data: LoginRequest, request: Request, db: Session = Depends(get_db)):
    ip = get_ip(request)

    app_data, error = check_app(db, data.app_id, data.app_secret)
    if error:
        return {"success": False, "message": error}

    user = db.query(User).filter(
        User.app_id == data.app_id,
        User.username == data.username
    ).first()

    if not user:
        return {"success": False, "message": "Invalid username or password"}

    if not verify_password(data.password, user.password_hash):
        return {"success": False, "message": "Invalid username or password"}

    if user.banned:
        return {"success": False, "message": "User banned"}

    if user.expires_at and user.expires_at < datetime.utcnow():
        return {"success": False, "message": "Subscription expired"}

    if user.hwid and user.hwid != data.hwid:
        return {"success": False, "message": "HWID mismatch"}

    if not user.hwid:
        user.hwid = data.hwid
        db.commit()

    token = create_token({
        "user_id": user.id,
        "username": user.username,
        "app_id": data.app_id
    })

    db.add(UserSession(user_id=user.id, token=token, ip=ip))
    db.commit()

    log_action(db, data.app_id, user.id, "login", ip)

    return {
        "success": True,
        "message": "Login successful",
        "token": token,
        "expires_at": str(user.expires_at)
    }


@app.post("/api/v1/validate")
def validate(data: ValidateRequest, db: Session = Depends(get_db)):
    payload = decode_token(data.token)

    if not payload:
        return {"success": False, "message": "Invalid or expired token"}

    user_id = payload.get("user_id")
    app_id = payload.get("app_id")

    session = db.query(UserSession).filter(
        UserSession.user_id == user_id,
        UserSession.token == data.token
    ).first()

    if not session:
        return {"success": False, "message": "Session not found"}

    app_data = db.query(App).filter(App.app_id == app_id).first()
    if not app_data or app_data.status != "active":
        return {"success": False, "message": "App disabled or not found"}

    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        return {"success": False, "message": "User not found"}

    if user.banned:
        return {"success": False, "message": "User banned"}

    if user.expires_at and user.expires_at < datetime.utcnow():
        return {"success": False, "message": "Subscription expired"}

    if user.hwid and user.hwid != data.hwid:
        return {"success": False, "message": "HWID mismatch"}

    return {
        "success": True,
        "message": "Session valid",
        "username": user.username,
        "app_id": user.app_id,
        "expires_at": str(user.expires_at)
    }


@app.post("/api/v1/logout")
def logout(data: LogoutRequest, db: Session = Depends(get_db)):
    session = db.query(UserSession).filter(UserSession.token == data.token).first()

    if not session:
        return {"success": False, "message": "Session not found"}

    db.delete(session)
    db.commit()

    return {"success": True, "message": "Logged out successfully"}