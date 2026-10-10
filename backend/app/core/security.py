import base64
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Union

import bcrypt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.models import User

# Dynamic fallback to support both modular database package paths
try:
    from app.database import get_db
except ImportError:
    from app.models.database import get_db

logger = logging.getLogger(__name__)
settings = get_settings()

# auto_error=False so we can fall back to HttpOnly cookie + CI API tokens
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token", auto_error=False)
oauth2_scheme_optional = oauth2_scheme

# Work factor tuned to throttle brute-force attempts (2^12 = 4,096 rounds)
BCRYPT_ROUNDS = 12
BCRYPT_MAX_BYTES = 72


class Roles:
    ANALYST = "analyst"
    LEAD = "lead"
    ALL_ROLES = [ANALYST, LEAD]


class TokenPayload(BaseModel):
    """Standardized JWT claims container."""
    sub: str
    exp: datetime
    iat: datetime
    role: Optional[str] = None
    jti: Optional[str] = None


# =====================================================================
# Password Hashing & Verification (Native Bcrypt)
# =====================================================================

def _preprocess_password(password: str) -> bytes:
    """
    Prevents the 72-byte truncation limit in standard Bcrypt.
    If the password exceeds 72 bytes, pre-hash with SHA-256 and base64-encode
    down to a deterministic 44-byte buffer before salt application.
    """
    pw_bytes = password.encode("utf-8")
    if len(pw_bytes) > BCRYPT_MAX_BYTES:
        digest = hashlib.sha256(pw_bytes).digest()
        return base64.b64encode(digest)
    return pw_bytes


def hash_password(plain_password: str, rounds: int = BCRYPT_ROUNDS) -> str:
    """
    Hashes a plain password using native Bcrypt with CSPRNG salting.
    """
    if not plain_password:
        raise ValueError("Password cannot be empty.")

    prepared = _preprocess_password(plain_password)
    salt = bcrypt.gensalt(rounds=rounds)
    hashed = bcrypt.hashpw(prepared, salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plain password against an existing modular crypt hash ($2b$...).
    Utilizes constant-time byte comparison to eliminate timing attacks.
    """
    if not plain_password or not hashed_password:
        return False

    try:
        prepared = _preprocess_password(plain_password)
        return bcrypt.checkpw(prepared, hashed_password.encode("utf-8"))
    except Exception as exc:
        logger.error(f"Password verification encountered an error: {exc}")
        return False


# =====================================================================
# Stateless JWT Token Lifecycle Manager
# =====================================================================

class JWTManager:
    """Handles RFC 7519-compliant HS256 JWT encoding and claim verification."""

    @classmethod
    def create_access_token(
        cls,
        subject: str,
        role: Optional[str] = None,
        extra_claims: Optional[Dict[str, Any]] = None,
        expires_delta: Optional[timedelta] = None,
    ) -> str:
        now = datetime.now(timezone.utc)
        if expires_delta:
            expire = now + expires_delta
        else:
            expire_hours = getattr(settings, "JWT_EXPIRE_HOURS", 24)
            expire = now + timedelta(hours=expire_hours)

        payload: Dict[str, Any] = {
            "sub": str(subject),
            "exp": expire,
            "iat": now,
        }
        if role:
            payload["role"] = role
        if extra_claims:
            payload.update(extra_claims)

        return jwt.encode(
            payload,
            settings.JWT_SECRET,
            algorithm=getattr(settings, "JWT_ALGORITHM", "HS256"),
        )

    @classmethod
    def decode_token(cls, token: str) -> TokenPayload:
        algorithm = getattr(settings, "JWT_ALGORITHM", "HS256")
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[algorithm],
            options={"verify_exp": True, "verify_sub": True},
        )
        return TokenPayload(**payload)


# Convenience backward-compatible wrapper
def create_access_token(
    subject: str,
    extra: Optional[Dict[str, Any]] = None,
    role: Optional[str] = None,
) -> str:
    return JWTManager.create_access_token(subject=subject, role=role, extra_claims=extra)


# =====================================================================
# FastAPI Dependencies & RBAC Enforcement
# =====================================================================

def _hash_api_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _lookup_api_token_user(db: Session, raw: str) -> Optional[User]:
    """CI token fallback: ptx_<secret>. Only hash is stored; checks expiry + revoke."""
    try:
        if not raw or not raw.startswith("ptx_"):
            return None
        from datetime import datetime, timezone as _tz
        from app.models.models import ApiToken

        digest = _hash_api_token(raw)
        tok = db.query(ApiToken).filter(ApiToken.token_hash == digest).first()
        if not tok or tok.revoked:
            return None
        exp = getattr(tok, "expires_at", None)
        if exp is not None:
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=_tz.utc)
            if datetime.now(_tz.utc) > exp:
                return None
        return db.query(User).filter(User.id == tok.user_id).first()
    except Exception:
        return None


def get_current_user(
    request: Request = None,
    token: Optional[str] = Depends(oauth2_scheme_optional),
    db: Session = Depends(get_db),
) -> User:
    """
    Dependency extracting and validating the authenticated user.
    Order: Authorization Bearer header -> HttpOnly cookie -> CI API token.
    Old JWTs without jti keep working; sessions with revoked jti are rejected.
    """
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate authentication credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    raw = (token or "").strip()
    if not raw and request is not None:
        try:
            raw = (request.cookies.get("access_token") or "").strip()
        except Exception:
            raw = ""

    if not raw:
        raise credentials_exc

    # CI API token path (no JWT decode)
    if raw.startswith("ptx_"):
        user = _lookup_api_token_user(db, raw)
        if not user:
            raise credentials_exc
        if not getattr(user, "is_active", True):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is deactivated.",
            )
        return user

    try:
        token_data = JWTManager.decode_token(raw)
        username = token_data.sub
        if not username:
            raise credentials_exc
    except (JWTError, Exception):
        raise credentials_exc

    # Revoked session check (only for tokens carrying jti; old tokens pass through)
    try:
        jti = getattr(token_data, "jti", None)
        if jti:
            from app.models.models import UserSession

            sess = db.query(UserSession).filter(UserSession.jti == jti).first()
            if sess is not None and getattr(sess, "revoked", False):
                raise credentials_exc
    except HTTPException:
        raise
    except Exception:
        pass

    user: Optional[User] = db.query(User).filter(User.username == username).first()
    if not user:
        raise credentials_exc

    if not getattr(user, "is_active", True):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated.",
        )

    return user


def require_auth(user: User = Depends(get_current_user)) -> User:
    """Validates that the caller is an active authenticated user."""
    return user


def require_role(allowed_roles: Union[str, List[str]]) -> Callable[[User], User]:
    """
    Factory dependency checking that the user holds one of the required roles.
    Example: Depends(require_role(["lead", "admin"])) or Depends(require_role("lead"))
    """
    if isinstance(allowed_roles, str):
        roles_list = [allowed_roles]
    else:
        roles_list = list(allowed_roles)

    def role_checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles_list:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation requires role in {roles_list} — current role is '{user.role}'",
            )
        return user

    return role_checker


def require_lead(user: User = Depends(get_current_user)) -> User:
    """Strict authorization gate reserved for team leads and administrators."""
    if user.role != Roles.LEAD:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Action requires '{Roles.LEAD}' role — current role is '{user.role}'",
        )
    return user


def require_analyst(user: User = Depends(get_current_user)) -> User:
    """
    Authorization gate for analyst-level actions. Leads are included because
    a lead's permissions are expected to be a superset of an analyst's — a
    lead should never be blocked from something an analyst can do.

    If you want this restricted to analysts only (leads excluded), change
    the condition below to: `if user.role != Roles.ANALYST:`
    """
    if user.role not in (Roles.ANALYST, Roles.LEAD):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Action requires '{Roles.ANALYST}' role — current role is '{user.role}'",
        )
    return user