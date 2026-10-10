from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from app.models.database import get_db
from app.models.models import Engagement, User, ReasoningLog
from app.core.security import require_auth
from app.agent.turn import execute_turn, AgentTurnError

router = APIRouter(prefix="/api/agent", tags=["agent"])


class TurnRequest(BaseModel):
    engagement_id: str
    message: str
    history: Optional[str] = None


@router.get("/history/{engagement_id}")
def get_history(
    engagement_id: str,
    limit: int = 100,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    """Chat history timeline for an engagement — user prompts + assistant replies.
    Sourced from ReasoningLog agent:prompt / agent:reply (already logged in turn.py).
    No new tables, fully backward compatible."""
    # Validate engagement exists (but don't auto-create on history fetch)
    rows = (
        db.query(ReasoningLog)
        .filter(
            ReasoningLog.engagement_id == engagement_id,
            ReasoningLog.action_type.in_(["agent:prompt", "agent:reply"]),
        )
        .order_by(ReasoningLog.timestamp.asc())
        .limit(max(1, min(limit, 200)))
        .all()
    )
    messages = []
    for r in rows:
        role = "user" if r.actor == "user" else "assistant"
        messages.append({
            "id": str(r.id),
            "role": role,
            "text": r.reasoning or "",
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            "tools": [],
        })
    return {"engagement_id": engagement_id, "messages": messages}


@router.delete("/history/{engagement_id}")
def clear_history(
    engagement_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    """Clear chat timeline for an engagement (only chat kinds, never tool logs)."""
    db.query(ReasoningLog).filter(
        ReasoningLog.engagement_id == engagement_id,
        ReasoningLog.action_type.in_(["agent:prompt", "agent:reply"]),
    ).delete(synchronize_session=False)
    db.commit()
    return {"status": "cleared", "engagement_id": engagement_id}


@router.post("/turn")
def run_turn(
    req: TurnRequest, db: Session = Depends(get_db), user: User = Depends(require_auth)
):
    """One conversational turn: operator message -> agent plan -> gated tool execution.
    Returns the assistant reply plus a list of tool events for inline cards.
    Auto-creates engagement if id is missing/invalid (TARGET UNBOUND case)."""
    # Delegate creation to turn.py handle for non-UUID ids like "default"/"demo-target"
    try:
        # Let execute_turn handle ensure; but keep check for valid UUID engagements
        # If engagement_id looks like a UUID, verify it exists for clearer error
        import uuid as _uuid
        try:
            _uuid.UUID(str(req.engagement_id))
            # valid UUID — check existence, but don't block auto-create path in turn.py
            pass
        except Exception:
            # Non-UUID (e.g. "default", "demo-target", "" ) — treat as request for auto engagement
            pass
        return execute_turn(db, req.engagement_id, req.message, req.history or "")
    except AgentTurnError as e:
        raise HTTPException(500, str(e))
    except HTTPException:
        raise
    except Exception as e:
        # Session may hold a failed transaction (UNIQUE/FK). Roll back
        # before retrying or the retry dies with PendingRollbackError and
        # logs to a ghost engagement with FOREIGN KEY failure.
        try:
            db.rollback()
        except Exception:
            pass
        # Fallback — try execute_turn anyway for creation
        try:
            return execute_turn(db, req.engagement_id, req.message, req.history or "")
        except AgentTurnError as e2:
            raise HTTPException(500, str(e2))
        except HTTPException:
            raise
        except Exception as e2:
            try:
                db.rollback()
            except Exception:
                pass
            raise HTTPException(500, f"Agent turn failed: {e2}")
