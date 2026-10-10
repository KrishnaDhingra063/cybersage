from datetime import datetime, timezone, timedelta
from typing import Optional
from uuid import UUID as PyUUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.models.database import get_db
from app.models.models import (
    User, Engagement, Host, Finding, FixSuggestion,
    Group, GroupMember, GroupActivity, GroupMessage, GroupShare,
)
from app.core.security import require_auth, get_current_user

router = APIRouter(prefix="/api/groups", tags=["groups"])

MAX_COLEAD = 2


def utcnow():
    return datetime.now(timezone.utc)


# ── helpers ──
def _get_group_or_404(db: Session, group_id: str) -> Group:
    g = db.query(Group).filter(Group.id == group_id).first()
    if not g:
        raise HTTPException(404, "Group not found")
    return g


def _require_member(db: Session, group_id: str, user: User) -> GroupMember:
    m = db.query(GroupMember).filter(
        GroupMember.group_id == group_id,
        GroupMember.user_id == user.id,
        GroupMember.is_active == True,  # noqa: E712
    ).first()
    if not m:
        raise HTTPException(403, "Not a group member")
    return m


def _require_lead_or_colead(db: Session, group_id: str, user: User) -> GroupMember:
    m = _require_member(db, group_id, user)
    if m.role not in ("lead", "co_lead") and user.role != "lead":
        # global lead fallback keeps old behaviour working
        raise HTTPException(403, "Requires lead or co-lead in this group")
    return m


# ── schemas ──
class GroupCreate(BaseModel):
    engagement_id: str
    name: str


class GroupResponse(BaseModel):
    id: PyUUID | str
    name: str
    engagement_id: PyUUID | str
    lead_id: Optional[PyUUID | str] = None
    created_at: Optional[object] = None

    class Config:
        from_attributes = True


class MemberAdd(BaseModel):
    username_or_email: str


class MuteRequest(BaseModel):
    minutes: int = 30


class MessageCreate(BaseModel):
    message: str


class ShareCreate(BaseModel):
    payload_type: str  # finding | fix | log
    payload_id: str
    note: Optional[str] = ""


# ── CRUD ──
@router.post("/", response_model=GroupResponse)
def create_group(data: GroupCreate, db: Session = Depends(get_db), user: User = Depends(require_auth)):
    # Only founder/head lead can create, per spec
    if not getattr(user, "is_founder", False):
        raise HTTPException(403, "Only founder/head lead can create a group")
    eng = db.query(Engagement).filter(Engagement.id == data.engagement_id).first()
    if not eng:
        raise HTTPException(404, "Engagement not found")
    existing = db.query(Group).filter(Group.engagement_id == data.engagement_id).first()
    if existing:
        return existing
    g = Group(name=data.name.strip() or f"{eng.test_type or 'App'} — {eng.client_name}", engagement_id=data.engagement_id, lead_id=user.id)
    db.add(g)
    db.commit()
    db.refresh(g)
    # auto-add lead as member
    db.add(GroupMember(group_id=g.id, user_id=user.id, role="lead"))
    db.commit()
    return g


@router.get("/", response_model=list[GroupResponse])
def list_my_groups(db: Session = Depends(get_db), user: User = Depends(require_auth)):
    # Founder sees all, others see member groups
    if getattr(user, "is_founder", False):
        return db.query(Group).order_by(Group.created_at.desc()).all()
    member_rows = db.query(GroupMember).filter(GroupMember.user_id == user.id, GroupMember.is_active == True).all()  # noqa: E712
    gids = [m.group_id for m in member_rows]
    if not gids:
        return []
    return db.query(Group).filter(Group.id.in_(gids)).order_by(Group.created_at.desc()).all()


@router.get("/{group_id}")
def get_group_detail(group_id: str, db: Session = Depends(get_db), user: User = Depends(require_auth)):
    g = _get_group_or_404(db, group_id)
    _require_member(db, group_id, user)
    members = db.query(GroupMember).filter(GroupMember.group_id == group_id, GroupMember.is_active == True).all()  # noqa: E712
    member_out = []
    for m in members:
        u = db.query(User).filter(User.id == m.user_id).first()
        member_out.append({
            "user_id": str(m.user_id),
            "username": u.username if u else "?",
            "full_name": getattr(u, "full_name", None) if u else None,
            "email": getattr(u, "email", None) if u else None,
            "role": m.role,
            "muted_until": str(m.muted_until) if m.muted_until else None,
            "is_founder": bool(getattr(u, "is_founder", False)) if u else False,
        })
    lead = db.query(User).filter(User.id == g.lead_id).first() if g.lead_id else None
    hosts = db.query(Host).filter(Host.engagement_id == g.engagement_id).count()
    findings = db.query(Finding).filter(Finding.engagement_id == g.engagement_id).count()
    fixes = db.query(FixSuggestion).filter(FixSuggestion.engagement_id == g.engagement_id).count()
    return {
        "id": str(g.id),
        "name": g.name,
        "engagement_id": str(g.engagement_id),
        "lead_id": str(g.lead_id) if g.lead_id else None,
        "lead_name": (lead.full_name or lead.username) if lead else None,
        "created_at": str(g.created_at) if g.created_at else None,
        "members": member_out,
        "stats": {"hosts": hosts, "findings": findings, "fixes": fixes},
    }


@router.post("/{group_id}/members")
def add_member(group_id: str, data: MemberAdd, db: Session = Depends(get_db), user: User = Depends(require_auth)):
    g = _get_group_or_404(db, group_id)
    _require_lead_or_colead(db, group_id, user)
    key = data.username_or_email.strip()
    target = db.query(User).filter((User.username == key) | (User.email == key)).first()
    if not target:
        raise HTTPException(404, "User not found")
    existing = db.query(GroupMember).filter(GroupMember.group_id == group_id, GroupMember.user_id == target.id).first()
    if existing:
        existing.is_active = True
        db.commit()
        return {"status": "re-added", "user_id": str(target.id)}
    db.add(GroupMember(group_id=group_id, user_id=target.id, role="analyst"))
    db.commit()
    return {"status": "added", "user_id": str(target.id)}


@router.post("/{group_id}/co-lead/{user_id}")
def promote_colead(group_id: str, user_id: str, db: Session = Depends(get_db), user: User = Depends(require_auth)):
    g = _get_group_or_404(db, group_id)
    # Only group lead (or founder) can promote
    m_me = _require_member(db, group_id, user)
    if m_me.role != "lead" and not getattr(user, "is_founder", False):
        raise HTTPException(403, "Only group lead can promote co-lead")
    co_count = db.query(GroupMember).filter(GroupMember.group_id == group_id, GroupMember.role == "co_lead", GroupMember.is_active == True).count()  # noqa: E712
    if co_count >= MAX_COLEAD:
        raise HTTPException(400, f"Max {MAX_COLEAD} co-leads per group")
    target = db.query(GroupMember).filter(GroupMember.group_id == group_id, GroupMember.user_id == user_id).first()
    if not target:
        raise HTTPException(404, "Member not found in group")
    target.role = "co_lead"
    db.commit()
    return {"status": "promoted", "user_id": user_id}


@router.post("/{group_id}/demote/{user_id}")
def demote_colead(group_id: str, user_id: str, db: Session = Depends(get_db), user: User = Depends(require_auth)):
    _get_group_or_404(db, group_id)
    m_me = _require_member(db, group_id, user)
    if m_me.role != "lead" and not getattr(user, "is_founder", False):
        raise HTTPException(403, "Only group lead can demote")
    target = db.query(GroupMember).filter(GroupMember.group_id == group_id, GroupMember.user_id == user_id).first()
    if not target:
        raise HTTPException(404, "Member not found")
    # never demote group lead via this path
    if target.role == "lead":
        raise HTTPException(400, "Cannot demote group lead")
    target.role = "analyst"
    db.commit()
    return {"status": "demoted", "user_id": user_id}


@router.post("/{group_id}/mute/{user_id}")
def mute_member(group_id: str, user_id: str, data: MuteRequest, db: Session = Depends(get_db), user: User = Depends(require_auth)):
    _get_group_or_404(db, group_id)
    _require_lead_or_colead(db, group_id, user)
    target = db.query(GroupMember).filter(GroupMember.group_id == group_id, GroupMember.user_id == user_id).first()
    if not target:
        raise HTTPException(404, "Member not found")
    mins = max(1, min(int(data.minutes or 30), 60 * 24 * 7))
    target.muted_until = utcnow() + timedelta(minutes=mins)
    db.commit()
    return {"status": "muted", "user_id": user_id, "muted_until": str(target.muted_until)}


@router.post("/{group_id}/unmute/{user_id}")
def unmute_member(group_id: str, user_id: str, db: Session = Depends(get_db), user: User = Depends(require_auth)):
    _get_group_or_404(db, group_id)
    _require_lead_or_colead(db, group_id, user)
    target = db.query(GroupMember).filter(GroupMember.group_id == group_id, GroupMember.user_id == user_id).first()
    if not target:
        raise HTTPException(404, "Member not found")
    target.muted_until = None
    db.commit()
    return {"status": "unmuted"}


# ── Activity log ──
@router.get("/{group_id}/activity")
def list_activity(
    group_id: str,
    search: Optional[str] = Query(None),
    user_filter: Optional[str] = Query(None, alias="user"),
    tool: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    _get_group_or_404(db, group_id)
    _require_member(db, group_id, user)
    q = db.query(GroupActivity).filter(GroupActivity.group_id == group_id)
    if search:
        like = f"%{search}%"
        q = q.filter(
            (GroupActivity.action_type.ilike(like))
            | (GroupActivity.target.ilike(like))
            | (GroupActivity.tool.ilike(like))
            | (GroupActivity.result_summary.ilike(like))
        )
    if tool:
        q = q.filter(GroupActivity.tool == tool)
    if user_filter:
        # match username or full_name
        users = db.query(User).filter((User.username.ilike(f"%{user_filter}%"))).all()
        uids = [u.id for u in users]
        if uids:
            q = q.filter(GroupActivity.user_id.in_(uids))
        else:
            return []
    rows = q.order_by(GroupActivity.created_at.desc()).offset(offset).limit(limit).all()
    out = []
    for r in rows:
        u = db.query(User).filter(User.id == r.user_id).first() if r.user_id else None
        out.append({
            "id": str(r.id),
            "username": u.username if u else "?",
            "full_name": getattr(u, "full_name", None) if u else None,
            "action_type": r.action_type,
            "target": r.target,
            "tool": r.tool,
            "result_summary": r.result_summary,
            "job_id": str(r.job_id) if r.job_id else None,
            "created_at": str(r.created_at) if r.created_at else None,
        })
    return out


@router.post("/{group_id}/activity")
def _internal_log_activity(group_id: str, payload: dict, db: Session = Depends(get_db), user: User = Depends(require_auth)):
    # Internal hook, but exposed authenticated for manual analyst notes; keeps shape stable
    g = _get_group_or_404(db, group_id)
    _require_member(db, group_id, user)
    act = GroupActivity(
        group_id=group_id,
        user_id=user.id,
        engagement_id=g.engagement_id,
        action_type=payload.get("action_type", "note")[:50],
        target=payload.get("target", "")[:500],
        tool=payload.get("tool", "")[:50],
        parameters=payload.get("parameters", {}),
        result_summary=payload.get("result_summary", "")[:2000],
    )
    db.add(act)
    db.commit()
    db.refresh(act)
    return {"id": str(act.id)}


# ── Chat ──
@router.get("/{group_id}/messages")
def list_messages(group_id: str, limit: int = Query(50, ge=1, le=200), db: Session = Depends(get_db), user: User = Depends(require_auth)):
    _get_group_or_404(db, group_id)
    _require_member(db, group_id, user)
    rows = db.query(GroupMessage).filter(GroupMessage.group_id == group_id).order_by(GroupMessage.created_at.desc()).limit(limit).all()
    rows = list(reversed(rows))
    out = []
    for r in rows:
        u = db.query(User).filter(User.id == r.sender_id).first() if r.sender_id else None
        out.append({
            "id": str(r.id),
            "sender": u.username if u else "?",
            "full_name": getattr(u, "full_name", None) if u else None,
            "message": r.message,
            "notify": r.notify,
            "muted": (r.notify is False),
            "created_at": str(r.created_at) if r.created_at else None,
        })
    return out


@router.post("/{group_id}/messages")
def post_message(group_id: str, data: MessageCreate, db: Session = Depends(get_db), user: User = Depends(require_auth)):
    _get_group_or_404(db, group_id)
    me = _require_member(db, group_id, user)
    text = (data.message or "").strip()
    if not text:
        raise HTTPException(400, "Empty message")
    # Muted: still store + visible, but notify=False (no popup/notification)
    is_muted = False
    try:
        mu = me.muted_until
        if mu:
            if mu.tzinfo is None:
                mu = mu.replace(tzinfo=timezone.utc)
            is_muted = utcnow() < mu
    except Exception:
        is_muted = False
    msg = GroupMessage(group_id=group_id, sender_id=user.id, message=text[:2000], notify=(not is_muted))
    db.add(msg)
    db.commit()
    db.refresh(msg)
    return {"id": str(msg.id), "notify": msg.notify, "muted": is_muted}


# ── Shares ──
@router.post("/{group_id}/share")
def share_to_lead(group_id: str, data: ShareCreate, db: Session = Depends(get_db), user: User = Depends(require_auth)):
    g = _get_group_or_404(db, group_id)
    _require_member(db, group_id, user)
    if data.payload_type not in ("finding", "fix", "log"):
        raise HTTPException(400, "payload_type must be finding|fix|log")
    s = GroupShare(group_id=group_id, sender_id=user.id, lead_id=g.lead_id, payload_type=data.payload_type, payload_id=data.payload_id, note=(data.note or "")[:1000], status="pending")
    db.add(s)
    db.commit()
    db.refresh(s)
    return {"id": str(s.id), "status": "pending"}


@router.get("/{group_id}/shares")
def list_shares(group_id: str, db: Session = Depends(get_db), user: User = Depends(require_auth)):
    _get_group_or_404(db, group_id)
    # Analyst sees own shares, lead/co-lead sees inbox
    me = _require_member(db, group_id, user)
    if me.role in ("lead", "co_lead") or getattr(user, "is_founder", False):
        rows = db.query(GroupShare).filter(GroupShare.group_id == group_id).order_by(GroupShare.created_at.desc()).limit(50).all()
    else:
        rows = db.query(GroupShare).filter(GroupShare.group_id == group_id, GroupShare.sender_id == user.id).order_by(GroupShare.created_at.desc()).limit(50).all()
    out = []
    for r in rows:
        sender = db.query(User).filter(User.id == r.sender_id).first() if r.sender_id else None
        out.append({
            "id": str(r.id),
            "sender": sender.username if sender else "?",
            "payload_type": r.payload_type,
            "payload_id": r.payload_id,
            "note": r.note,
            "status": r.status,
            "created_at": str(r.created_at) if r.created_at else None,
        })
    return out


@router.post("/{group_id}/shares/{share_id}/seen")
def mark_share_seen(group_id: str, share_id: str, db: Session = Depends(get_db), user: User = Depends(require_auth)):
    _get_group_or_404(db, group_id)
    _require_lead_or_colead(db, group_id, user)
    s = db.query(GroupShare).filter(GroupShare.id == share_id, GroupShare.group_id == group_id).first()
    if not s:
        raise HTTPException(404, "Share not found")
    s.status = "seen"
    db.commit()
    return {"status": "seen"}
