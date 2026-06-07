import os
import uuid
from datetime import datetime, timedelta

from dotenv import load_dotenv
from fastapi import FastAPI, Depends, Request
from sqlalchemy.orm import Session

from database import Base, engine, get_db
from models import App, User, License, Session as UserSession, Log
from schemas import (
    CreateAppRequest,
    RegisterRequest,
    LoginRequest,
    ValidateRequest,
    LogoutRequest,
    BanUserRequest,
    ResetHWIDRequest,
    ExtendUserRequest,
)
from auth import hash_password, verify_password, create_token, decode_token

load_dotenv()

app = FastAPI(title="NovaAuth API", version="1.1.0")

Base.metadata.create_all(bind=engine)

ADMIN_SECRET = os.getenv("ADMIN_SECRET", "NovaAuth_Admin_Secret_2026_ChangeMe")


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


def check_app(db: Session, app_id: str, secret: str):
    app_data = db.query(App).filter(App.app_id == app_id).first()

    if not app_data:
        return None, "App not found"

    if app_data.secret != secret:
        return None, "Invalid app secret"

    if app_data.status != "active":
        return None, "App disabled"

    return app_data, None


@app.get("/")
def home():
    return {"success": True, "message": "NovaAuth API is running"}


@app.get("/health")
def health():
    return {"status": "online"}


@app.post("/api/v1/admin/create-app")
def create_app(data: CreateAppRequest, request: Request, db: Session = Depends(get_db)):
    denied = admin_required(request)
    if denied:
        return denied

    app_id = "app_" + uuid.uuid4().hex[:16]
    secret = "sec_" + uuid.uuid4().hex + uuid.uuid4().hex[:16]

    new_app = App(app_id=app_id, name=data.name, secret=secret, version=data.version)

    db.add(new_app)
    db.commit()

    return {
        "success": True,
        "app_id": app_id,
        "app_secret": secret,
        "message": "App created",
    }


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


@app.get("/api/v1/admin/apps")
def list_apps(request: Request, db: Session = Depends(get_db)):
    denied = admin_required(request)
    if denied:
        return denied

    apps = db.query(App).order_by(App.id.desc()).all()

    return {
        "success": True,
        "apps": [
            {
                "id": a.id,
                "app_id": a.app_id,
                "name": a.name,
                "version": a.version,
                "status": a.status,
                "created_at": str(a.created_at),
            }
            for a in apps
        ],
    }


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
                "hwid": u.hwid,
                "banned": u.banned,
                "expires_at": str(u.expires_at),
                "created_at": str(u.created_at),
            }
            for u in users
        ],
    }


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
                "created_at": str(l.created_at),
            }
            for l in licenses
        ],
    }


@app.get("/api/v1/admin/logs")
def list_logs(request: Request, app_id: str | None = None, db: Session = Depends(get_db)):
    denied = admin_required(request)
    if denied:
        return denied

    q = db.query(Log)

    if app_id:
        q = q.filter(Log.app_id == app_id)

    logs = q.order_by(Log.id.desc()).limit(100).all()

    return {
        "success": True,
        "logs": [
            {
                "id": log.id,
                "app_id": log.app_id,
                "user_id": log.user_id,
                "action": log.action,
                "ip": log.ip,
                "created_at": str(log.created_at),
            }
            for log in logs
        ],
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
        "banned": user.banned,
    }


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
        "expires_at": str(user.expires_at),
    }


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
        hwid=data.hwid,
        expires_at=expires_at,
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
        "app_id": data.app_id,
    })

    db.add(UserSession(user_id=user.id, token=token, ip=ip))
    db.commit()

    log_action(db, data.app_id, user.id, "register", ip)

    return {
        "success": True,
        "message": "Registered successfully",
        "token": token,
        "expires_at": str(expires_at),
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
        "app_id": data.app_id,
    })

    db.add(UserSession(user_id=user.id, token=token, ip=ip))
    db.commit()

    log_action(db, data.app_id, user.id, "login", ip)

    return {
        "success": True,
        "message": "Login successful",
        "token": token,
        "expires_at": str(user.expires_at),
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
        "expires_at": str(user.expires_at),
    }


@app.post("/api/v1/logout")
def logout(data: LogoutRequest, db: Session = Depends(get_db)):
    session = db.query(UserSession).filter(UserSession.token == data.token).first()

    if not session:
        return {"success": False, "message": "Session not found"}

    db.delete(session)
    db.commit()

    return {"success": True, "message": "Logged out successfully"}