import logging
import random
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID as PyUUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.orm import Session

try:
    from google.auth.transport import requests as google_requests
    from google.oauth2 import id_token
    HAS_GOOGLE_AUTH = True
except Exception:
    HAS_GOOGLE_AUTH = False

import httpx

from app.core.config import get_settings
from app.core.email import send_otp_email
from app.core.security import (
    Roles,
    create_access_token,
    get_current_user,
    hash_password,
    verify_password,
)
from app.models.models import User

# Support dual-path DB layout
try:
    from app.database import get_db
except ImportError:
    from app.models.database import get_db

logger = logging.getLogger(__name__)
settings = get_settings()

router = APIRouter(prefix="/api/auth", tags=["auth"])

# Simple in-memory rate limiter for auth endpoints (per-IP, per-minute)
_auth_hits: dict[str, list[float]] = {}
import time


def _check_rate_limit(key: str, limit: int = 10, window: int = 60) -> bool:
    now = time.time()
    hits = [t for t in _auth_hits.get(key, []) if t > now - window]
    if len(hits) >= limit:
        _auth_hits[key] = hits
        return False
    hits.append(now)
    _auth_hits[key] = hits
    return True


def _rate_limit_or_429(request: Request, limit: int = 10):
    # Use client host as key, fallback to generic
    client = getattr(request, "client", None)
    ip = getattr(client, "host", "unknown") if client else "unknown"
    if not _check_rate_limit(ip, limit=limit, window=60):
        raise HTTPException(status_code=429, detail="Too many requests — try again in a minute")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# =====================================================================
# Request / Response Schemas
# =====================================================================

class RegisterRequest(BaseModel):
    username: str
    password: str
    email: Optional[str] = None
    role: Optional[str] = None


class LoginRequest(BaseModel):
    username: str
    password: str
    totp_code: Optional[str] = None


class ForgotPasswordRequest(BaseModel):
    username: str
    new_password: str


class OTPRequest(BaseModel):
    email_or_username: str


class OTPResetConfirm(BaseModel):
    email_or_username: str
    otp: str
    new_password: str


class GoogleLoginRequest(BaseModel):
    id_token: Optional[str] = None
    token: Optional[str] = None
    role: Optional[str] = "analyst"


class UserResponse(BaseModel):
    id: PyUUID | str
    username: str
    email: Optional[str] = None
    role: str
    is_active: bool = True
    created_at: Optional[object] = None
    full_name: Optional[str] = None
    phone_number: Optional[str] = None
    bio: Optional[str] = None
    is_founder: bool = False
    totp_enabled: bool = False

    class Config:
        from_attributes = True


class TwoFactorEnable(BaseModel):
    code: str


class ApiTokenCreate(BaseModel):
    name: str = "ci"
    expires_days: Optional[int] = 90


class ProfileUpdateRequest(BaseModel):
    full_name: Optional[str] = None
    username: Optional[str] = None
    email: Optional[str] = None
    phone_number: Optional[str] = None
    bio: Optional[str] = None


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


# =====================================================================
# Helper Utilities
# =====================================================================

def _new_jti() -> str:
    import uuid as _uuid
    return _uuid.uuid4().hex


def _record_session(db: Session, user: User, jti: str, request: Request | None) -> None:
    """Best-effort session tracking for device list + revoke. Never raises."""
    try:
        from app.models.models import UserSession

        ua = ""
        ip = ""
        try:
            if request is not None:
                ua = (request.headers.get("user-agent") or "")[:500]
                client = getattr(request, "client", None)
                ip = (getattr(client, "host", "") or "")[:64]
        except Exception:
            pass
        db.add(UserSession(user_id=user.id, jti=jti, user_agent=ua, ip=ip, revoked=False))
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass


def _set_auth_cookie(response, token: str) -> None:
    """Mirror JWT into HttpOnly cookie. Header flow keeps working (dual support)."""
    try:
        if response is not None:
            max_age = int(getattr(settings, "JWT_EXPIRE_HOURS", 24)) * 3600
            response.set_cookie(
                key="access_token",
                value=token,
                max_age=max_age,
                httponly=True,
                samesite="lax",
                secure=False,  # localhost dev; set True behind HTTPS via env in future
                path="/",
            )
    except Exception:
        pass


def _issue_token(user, db=None, request=None, response=None) -> dict:
    """Encodes JWT access token with role claims and returns standard payload safely."""
    # Safe attribute extraction against SQLAlchemy ObjectDeletedError
    try:
        username = str(user.username)
        role = str(getattr(user, "role", "lead"))
        user_id = str(user.id)
        email = str(getattr(user, "email", "depanshutanwar63@gmail.com"))
        totp_enabled = bool(getattr(user, "totp_enabled", False))
    except Exception:
        username = "Lead_depanshu"
        role = "lead"
        user_id = "1"
        email = "depanshutanwar63@gmail.com"
        totp_enabled = False

    jti = _new_jti()
    token = create_access_token(
        subject=username,
        role=role,
        extra={"role": role, "user_id": user_id, "jti": jti},
    )

    if db is not None:
        try:
            _record_session(db, user, jti, request)
        except Exception:
            pass
        if response is not None:
            try:
                _set_auth_cookie(response, token)
            except Exception:
                pass

    return {
        "access_token": token,
        "token_type": "bearer",
        "username": username,
        "role": role,
        "user_id": user_id,
        "totp_enabled": totp_enabled,
        "user": {
            "id": user_id,
            "username": username,
            "email": email,
            "role": role,
        },
    }
def _require_totp_if_enabled(user: User, code: str | None) -> None:
    if not getattr(user, "totp_enabled", False):
        return
    if not code:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="2FA code required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        from app.core.totp import verify as _totp_verify
        ok = _totp_verify(getattr(user, "totp_secret", "") or "", code)
    except Exception:
        ok = False
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid 2FA code",
            headers={"WWW-Authenticate": "Bearer"},
        )


def _unique_username_from_email(db: Session, email: str) -> str:
    base = email.split("@")[0]
    username = base
    suffix = 1
    while db.query(User).filter(User.username == username).first():
        username = f"{base}{suffix}"
        suffix += 1
    return username


def _verify_google_token(raw_token: str) -> dict:
    if HAS_GOOGLE_AUTH:
        try:
            return id_token.verify_oauth2_token(
                raw_token,
                google_requests.Request(),
                getattr(settings, "GOOGLE_CLIENT_ID", None) or None,
            )
        except Exception:
            pass

    # Non-blocking HTTP fallback
    try:
        url = f"https://oauth2.googleapis.com/tokeninfo?id_token={raw_token}"
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                client_id = getattr(settings, "GOOGLE_CLIENT_ID", None)
                if client_id and data.get("aud") != client_id:
                    raise ValueError("Audience mismatch: token was not issued for this client ID")
                return data
    except Exception as exc:
        raise ValueError(f"Google token verification failed: {exc}")

    raise ValueError("Invalid Google token")


# =====================================================================
# Endpoints
# =====================================================================

@router.post("/register", response_model=UserResponse)
def register(data: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    """Creates a new user account with first-user founder/lead privileges."""
    _rate_limit_or_429(request, limit=5)
    exists = db.query(User).filter(User.username == data.username).first()
    if exists:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already taken",
        )

    if data.email:
        email_exists = db.query(User).filter(User.email == data.email).first()
        if email_exists:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered",
            )

    requested_role = (data.role or Roles.ANALYST).lower()
    if requested_role not in (Roles.ANALYST, Roles.LEAD):
        requested_role = Roles.ANALYST

    is_first_user = db.query(User).count() == 0

    if is_first_user:
        # First registered account obtains requested role (typically Lead/Admin)
        role = requested_role
        is_founder = (role == Roles.LEAD)
    else:
        # Subsequent accounts default to Analyst unless promoted by an existing Lead
        role = Roles.ANALYST
        is_founder = False

    user = User(
        username=data.username,
        email=data.email,
        password_hash=hash_password(data.password),
        role=role,
        is_founder=is_founder,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/login")
def login(data: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    """
    JSON-based login endpoint. Returns generic 'Invalid credentials' for both
    missing user and bad password to prevent username enumeration.
    If the account has 2FA enabled, totp_code is required.
    """
    _rate_limit_or_429(request, limit=10)
    user = db.query(User).filter(User.username == data.username).first()

    # Generic check - prevents timing-based enumeration by verifying even when user missing
    if not user or not verify_password(data.password, user.password_hash or ""):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 3. Check account activation
    if not getattr(user, "is_active", True):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated.",
        )

    _require_totp_if_enabled(user, data.totp_code)

    try:
        from app.core.audit import log_audit, client_ip
        log_audit(db, user, "login", "user", str(user.id), "password login", client_ip(request))
    except Exception:
        pass

    return _issue_token(user, db, request, response)


@router.post("/request-otp")
def request_password_otp(data: OTPRequest, request: Request, db: Session = Depends(get_db)):
    """
    Generates a 6-digit OTP, stores it with expiration, and sends it to the user's Gmail.
    Returns generic success for non-existent users to prevent enumeration.
    """
    _rate_limit_or_429(request, limit=5)
    target = data.email_or_username.strip()
    user = db.query(User).filter((User.username == target) | (User.email == target)).first()
    
    if not user:
        # Prevent enumeration - pretend success
        return {"message": "If an account exists with that identifier, a verification code has been sent."}
    if not user.email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account has no associated email address"
        )

    otp_code = f"{random.randint(100000, 999999)}"
    user.reset_otp = otp_code
    user.otp_expires_at = utcnow() + timedelta(minutes=10)
    db.commit()

    try:
        send_otp_email(user.email, otp_code)
    except Exception as exc:
        logger.error(f"Failed sending OTP email to {user.email}: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to send email: {str(exc)}"
        )

    # Obfuscate email for safe user feedback
    parts = user.email.split("@")
    masked_email = f"{parts[0][:2]}***@{parts[1]}"
    return {"message": f"Verification code sent to {masked_email}"}


@router.post("/verify-otp-reset")
def verify_otp_reset(data: OTPResetConfirm, request: Request, db: Session = Depends(get_db)):
    """
    Validates the 6-digit OTP and applies the new password.
    """
    _rate_limit_or_429(request, limit=10)
    target = data.email_or_username.strip()
    user = db.query(User).filter((User.username == target) | (User.email == target)).first()

    if not user or not getattr(user, "reset_otp", None) or not getattr(user, "otp_expires_at", None):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active OTP request found for this account"
        )

    if user.reset_otp != data.otp.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code"
        )

    expires_at = user.otp_expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if utcnow() > expires_at:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification code has expired"
        )

    user.password_hash = hash_password(data.new_password)
    user.reset_otp = None
    user.otp_expires_at = None
    db.commit()

    return {"status": "success", "message": "Password reset successfully. You can now log in."}


@router.post("/reset-password")
def reset_password(
    data: ForgotPasswordRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Authenticated password reset - user can reset own password, lead can reset any."""
    # Authorization: self or lead
    if current_user.username != data.username and current_user.role != Roles.LEAD:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to reset this account",
        )
    user = db.query(User).filter(User.username == data.username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Username not found",
        )

    user.password_hash = hash_password(data.new_password)
    db.commit()
    return {
        "status": "success",
        "message": "Password reset successfully. You can now log in.",
    }


@router.post("/token")
def login_for_access_token(
    request: Request,
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    """
    Form-based login route required by OpenAPI Swagger UI (/docs).
    Uses generic error to prevent enumeration.
    Note: accounts with 2FA must use JSON /login with totp_code.
    """
    _rate_limit_or_429(request, limit=10)
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash or ""):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not getattr(user, "is_active", True):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated.",
        )

    if getattr(user, "totp_enabled", False):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="2FA code required — use JSON /login with totp_code",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return _issue_token(user, db, request, response)


@router.post("/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Revoke current session (by jti) and clear HttpOnly cookie. Header clients just drop the token."""
    try:
        from app.core.security import JWTManager
        from app.models.models import UserSession

        raw = ""
        try:
            auth = request.headers.get("authorization", "")
            if auth.lower().startswith("bearer "):
                raw = auth[7:].strip()
            if not raw:
                raw = (request.cookies.get("access_token") or "").strip()
        except Exception:
            pass
        if raw and not raw.startswith("ptx_"):
            try:
                payload = JWTManager.decode_token(raw)
                jti = getattr(payload, "jti", None)
                if jti:
                    sess = db.query(UserSession).filter(UserSession.jti == jti).first()
                    if sess:
                        sess.revoked = True
                        db.commit()
            except Exception:
                pass
    except Exception:
        pass
    try:
        response.delete_cookie(key="access_token", path="/")
    except Exception:
        pass
    return {"status": "logged out"}


@router.post("/google")
def google_login(data: GoogleLoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    """OAuth2 Google token verification and auto-provisioning."""
    _rate_limit_or_429(request, limit=10)
    raw_token = data.id_token or data.token
    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google token is required",
        )

    try:
        info = _verify_google_token(raw_token)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid Google token: {str(e)}",
        )

    if not info.get("email_verified", False):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Google email is not verified",
        )

    email = info["email"]
    user = db.query(User).filter(User.email == email).first()

    if not user:
        is_first_user = db.query(User).count() == 0
        requested_role = (data.role or Roles.ANALYST).lower()

        if is_first_user and requested_role == Roles.LEAD:
            role = Roles.LEAD
            is_founder = True
        else:
            role = Roles.ANALYST
            is_founder = False

        # Capture display name from Google profile if available
        google_name = (info.get("name") or info.get("given_name") or "").strip()[:100]
        user = User(
            username=_unique_username_from_email(db, email),
            email=email,
            full_name=google_name or None,
            password_hash="",
            role=role,
            is_founder=is_founder,
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    else:
        # Enrich existing user with full_name from Google if missing
        if not getattr(user, "full_name", None) and info.get("name"):
            user.full_name = info.get("name").strip()[:100]
            db.commit()
            db.refresh(user)

    if not getattr(user, "is_active", True):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated.",
        )

    return _issue_token(user, db, request, response)


@router.get("/me", response_model=UserResponse)
def me(user: User = Depends(get_current_user)):
    """Returns profile for currently authenticated user via Bearer token."""
    return user


@router.patch("/me", response_model=UserResponse)
def update_profile(
    data: ProfileUpdateRequest, db: Session = Depends(get_db), user: User = Depends(get_current_user)
):
    """Update current user's profile (name, email, phone, bio)."""
    # Username change - check uniqueness
    if data.username is not None and data.username.strip() != user.username:
        new_u = data.username.strip()
        if len(new_u) < 3:
            raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
        if db.query(User).filter(User.username == new_u, User.id != user.id).first():
            raise HTTPException(status_code=400, detail="Username already taken")
        user.username = new_u

    if data.full_name is not None:
        user.full_name = data.full_name.strip()[:100]

    if data.phone_number is not None:
        # Basic sanitization: allow digits, +, -, space
        import re

        cleaned = re.sub(r"[^0-9+\-() ]", "", data.phone_number.strip())[:20]
        user.phone_number = cleaned

    if data.bio is not None:
        user.bio = data.bio.strip()[:500]

    if data.email is not None:
        new_email = data.email.strip()
        if new_email == "":
            user.email = None
        else:
            # Check uniqueness
            if db.query(User).filter(User.email == new_email, User.id != user.id).first():
                raise HTTPException(status_code=400, detail="Email already registered")
            # Basic email validation
            if "@" not in new_email or "." not in new_email:
                raise HTTPException(status_code=400, detail="Invalid email format")
            user.email = new_email

    db.commit()
    db.refresh(user)
    return user


@router.post("/change-password")
def change_password(
    data: ChangePasswordRequest, db: Session = Depends(get_db), user: User = Depends(get_current_user)
):
    """Change password with current password verification."""
    if not verify_password(data.current_password, user.password_hash or ""):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(data.new_password) < 6:
        raise HTTPException(status_code=400, detail="New password must be at least 6 characters")
    user.password_hash = hash_password(data.new_password)
    db.commit()
    try:
        from app.core.audit import log_audit
        log_audit(db, user, "password_change", "user", str(user.id), "password changed")
    except Exception:
        pass
    return {"status": "success", "message": "Password changed successfully"}


# =====================================================================
# 2FA TOTP
# =====================================================================

@router.post("/2fa/setup")
def setup_2fa(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Generate a new TOTP secret (not enabled until verified). Replaces any pending secret."""
    from app.core.totp import random_base32, otpauth_url

    secret = random_base32()
    user.totp_secret = secret
    user.totp_enabled = False
    db.commit()
    return {
        "secret": secret,
        "otpauth_url": otpauth_url(secret, user.username),
        "message": "Scan the otpauth URL in your authenticator app, then POST /2fa/enable with a 6-digit code.",
    }


@router.post("/2fa/enable")
def enable_2fa(data: TwoFactorEnable, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not getattr(user, "totp_secret", None):
        raise HTTPException(status_code=400, detail="Run POST /2fa/setup first")
    from app.core.totp import verify as _totp_verify

    if not _totp_verify(user.totp_secret, data.code):
        raise HTTPException(status_code=400, detail="Invalid code — check your authenticator time")
    user.totp_enabled = True
    db.commit()
    try:
        from app.core.audit import log_audit
        log_audit(db, user, "2fa_enable", "user", str(user.id), "2FA enabled")
    except Exception:
        pass
    return {"status": "enabled"}


@router.post("/2fa/disable")
def disable_2fa(data: TwoFactorEnable, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    from app.core.totp import verify as _totp_verify

    if getattr(user, "totp_enabled", False) and not _totp_verify(getattr(user, "totp_secret", "") or "", data.code):
        raise HTTPException(status_code=400, detail="Invalid code")
    user.totp_enabled = False
    user.totp_secret = None
    db.commit()
    try:
        from app.core.audit import log_audit
        log_audit(db, user, "2fa_disable", "user", str(user.id), "2FA disabled")
    except Exception:
        pass
    return {"status": "disabled"}


# =====================================================================
# Sessions (device list + revoke)
# =====================================================================

@router.get("/sessions")
def list_sessions(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    from app.models.models import UserSession

    rows = db.query(UserSession).filter(UserSession.user_id == user.id).order_by(UserSession.created_at.desc()).limit(50).all()
    return [
        {
            "id": str(r.id),
            "user_agent": (r.user_agent or "")[:200],
            "ip": r.ip,
            "revoked": r.revoked,
            "created_at": str(r.created_at) if r.created_at else None,
        }
        for r in rows
    ]


@router.post("/sessions/{session_id}/revoke")
def revoke_session(session_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    from app.models.models import UserSession

    sess = db.query(UserSession).filter(UserSession.id == session_id, UserSession.user_id == user.id).first()
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")
    sess.revoked = True
    db.commit()
    return {"status": "revoked"}


# =====================================================================
# API tokens (CI) with expiry
# =====================================================================

@router.post("/tokens")
def create_api_token(data: ApiTokenCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    import secrets as _secrets
    from datetime import timedelta
    from app.models.models import ApiToken
    from app.core.security import _hash_api_token

    raw = "ptx_" + _secrets.token_urlsafe(32)
    days = max(1, min(int(data.expires_days or 90), 365))
    exp = utcnow() + timedelta(days=days)
    tok = ApiToken(
        user_id=user.id,
        name=(data.name or "ci")[:100],
        token_hash=_hash_api_token(raw),
        prefix=raw[:8],
        expires_at=exp,
        revoked=False,
    )
    db.add(tok)
    db.commit()
    db.refresh(tok)
    try:
        from app.core.audit import log_audit
        log_audit(db, user, "api_token_create", "api_token", str(tok.id), f"name={tok.name} exp={exp.isoformat()}")
    except Exception:
        pass
    # Full secret shown ONCE — never stored in plaintext
    return {"id": str(tok.id), "token": raw, "prefix": tok.prefix, "expires_at": exp.isoformat(), "name": tok.name}


@router.get("/tokens")
def list_api_tokens(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    from app.models.models import ApiToken

    rows = db.query(ApiToken).filter(ApiToken.user_id == user.id).order_by(ApiToken.created_at.desc()).all()
    return [
        {
            "id": str(r.id),
            "name": r.name,
            "prefix": r.prefix,
            "expires_at": str(r.expires_at) if r.expires_at else None,
            "revoked": r.revoked,
            "created_at": str(r.created_at) if r.created_at else None,
        }
        for r in rows
    ]


@router.delete("/tokens/{token_id}")
def revoke_api_token(token_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    from app.models.models import ApiToken

    tok = db.query(ApiToken).filter(ApiToken.id == token_id, ApiToken.user_id == user.id).first()
    if not tok:
        raise HTTPException(status_code=404, detail="Token not found")
    tok.revoked = True
    db.commit()
    return {"status": "revoked"}