from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from uuid import UUID as PyUUID

from app.models.database import get_db
from app.models.models import User
from app.core.security import require_lead, Roles, get_current_user

router = APIRouter(prefix="/api/users", tags=["users"])


class UserSummary(BaseModel):
    id: PyUUID | str
    username: str
    email: Optional[str]
    role: str
    is_founder: bool = False
    full_name: Optional[str] = None
    phone_number: Optional[str] = None
    bio: Optional[str] = None
    is_active: bool = True
    created_at: Optional[object] = None

    class Config:
        from_attributes = True


class ProfileUpdate(BaseModel):
    full_name: Optional[str] = None
    username: Optional[str] = None
    email: Optional[str] = None
    phone_number: Optional[str] = None
    bio: Optional[str] = None


@router.get("/me", response_model=UserSummary)
def get_my_profile(user: User = Depends(get_current_user)):
    return user


@router.get("/profile", response_model=UserSummary)
def get_profile(user: User = Depends(get_current_user)):
    # keep backward compat, but recommend /api/auth/me
    return user


@router.patch("/me", response_model=UserSummary)
def update_my_profile(
    data: ProfileUpdate, db: Session = Depends(get_db), user: User = Depends(get_current_user)
):
    """Lead wrapper - delegates to auth logic but kept for RBAC parity. For general users use /api/auth/me."""
    # Reuse same logic: allow self-update
    if data.username is not None and data.username.strip() != user.username:
        new_u = data.username.strip()
        if db.query(User).filter(User.username == new_u, User.id != user.id).first():
            raise HTTPException(400, "Username already taken")
        user.username = new_u
    if data.full_name is not None:
        user.full_name = data.full_name.strip()[:100]
    if data.phone_number is not None:
        import re

        user.phone_number = re.sub(r"[^0-9+\-() ]", "", data.phone_number.strip())[:20]
    if data.bio is not None:
        user.bio = data.bio.strip()[:500]
    if data.email is not None:
        new_email = data.email.strip()
        if new_email == "" or new_email.lower() == "null":
            user.email = None
        else:
            if db.query(User).filter(User.email == new_email, User.id != user.id).first():
                raise HTTPException(400, "Email already registered")
            user.email = new_email
    db.commit()
    db.refresh(user)
    return user


@router.get("/", response_model=list[UserSummary])
def list_users(db: Session = Depends(get_db), _: User = Depends(require_lead)):
    """Lead-only: everyone on this install, so a lead can pick who to promote."""
    return db.query(User).order_by(User.username).all()


class TeamCreateRequest(BaseModel):
    username: str
    password: str
    email: Optional[str] = None
    role: Optional[str] = "analyst"


@router.post("/create", response_model=UserSummary)
def create_team_member(data: TeamCreateRequest, db: Session = Depends(get_db), current: User = Depends(require_lead)):
    """RootX flow: lead creates account for team, picks role. Member logs in with given credentials (no role select at login)."""
    from app.core.security import hash_password

    username = (data.username or "").strip()
    if len(username) < 3:
        raise HTTPException(400, "Username must be at least 3 characters")
    if len(data.password or "") < 6:
        raise HTTPException(400, "Password must be at least 6 characters")
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(400, "Username already taken")
    if data.email and db.query(User).filter(User.email == data.email.strip()).first():
        raise HTTPException(400, "Email already registered")
    requested = (data.role or Roles.ANALYST).lower()
    if requested not in (Roles.ANALYST, Roles.LEAD):
        requested = Roles.ANALYST
    # Only founder can create another lead; plain leads create analysts
    if requested == Roles.LEAD and not getattr(current, "is_founder", False):
        raise HTTPException(403, "Only founder can create a lead account")
    u = User(
        username=username,
        email=(data.email or "").strip() or None,
        password_hash=hash_password(data.password),
        role=requested,
        is_founder=False,
        is_active=True,
    )
    db.add(u)
    db.commit()
    db.refresh(u)
    try:
        from app.core.audit import log_audit
        log_audit(db, current, "team_create", "user", str(u.id), f"created {username} as {requested}")
    except Exception:
        pass
    return u


@router.post("/{user_id}/promote", response_model=UserSummary)
def promote_to_lead(user_id: str, db: Session = Depends(get_db), current: User = Depends(require_lead)):
    """Any lead can promote an analyst to lead."""
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(404, "User not found")
    target.role = Roles.LEAD
    db.commit()
    db.refresh(target)
    try:
        from app.core.audit import log_audit
        log_audit(db, current, "promote", "user", str(target.id), f"{target.username} -> lead")
    except Exception:
        pass
    return target


@router.post("/{user_id}/demote", response_model=UserSummary)
def demote_to_analyst(user_id: str, db: Session = Depends(get_db), current: User = Depends(require_lead)):
    """Any lead can demote another lead back to analyst — except the founder (including self-demote)."""
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(404, "User not found")
    if getattr(target, "is_founder", False):
        raise HTTPException(403, "The founder account can't be demoted — you are always Lead.")
    if str(target.id) == str(current.id):
        raise HTTPException(403, "You can't demote yourself. Ask another lead/founder.")
    target.role = Roles.ANALYST
    db.commit()
    db.refresh(target)
    try:
        from app.core.audit import log_audit
        log_audit(db, current, "demote", "user", str(target.id), f"{target.username} -> analyst")
    except Exception:
        pass
    return target


@router.get("/audit/list")
def list_audit(limit: int = 50, db: Session = Depends(get_db), _: User = Depends(require_lead)):
    """Lead-only audit trail (who approved what, when)."""
    from app.models.models import AuditLog

    rows = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(max(1, min(limit, 200))).all()
    return [
        {
            "id": str(r.id),
            "actor": r.actor_name,
            "action": r.action,
            "target_type": r.target_type,
            "target_id": (r.target_id or "")[:24],
            "detail": r.detail,
            "ip": r.ip,
            "created_at": str(r.created_at) if r.created_at else None,
        }
        for r in rows
    ]