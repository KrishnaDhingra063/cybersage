"""Best-effort audit logging — never raises, never breaks the calling flow."""
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def log_audit(db, actor, action: str, target_type: str = "", target_id: str = "", detail: str = "", ip: str = "") -> None:
    try:
        from app.models.models import AuditLog

        actor_id = getattr(actor, "id", None) if actor is not None else None
        actor_name = getattr(actor, "username", "") if actor is not None else ""
        db.add(AuditLog(
            actor_id=actor_id,
            actor_name=actor_name or "",
            action=(action or "")[:60],
            target_type=(target_type or "")[:30],
            target_id=str(target_id or "")[:200],
            detail=(detail or "")[:2000],
            ip=(ip or "")[:64],
        ))
        db.commit()
    except Exception as exc:
        try:
            db.rollback()
        except Exception:
            pass
        logger.debug(f"audit log skipped ({action}): {exc}")


def client_ip(request) -> str:
    try:
        if request is None:
            return ""
        client = getattr(request, "client", None)
        return getattr(client, "host", "") if client else ""
    except Exception:
        return ""
