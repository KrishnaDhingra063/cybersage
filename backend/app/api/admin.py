from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
import io

from app.models.database import get_db
from app.models.models import User
from app.core.security import require_lead

router = APIRouter(prefix="/api/admin", tags=["admin"])


@router.get("/backup")
def download_backup(db: Session = Depends(get_db), user: User = Depends(require_lead)):
    """Founder/lead-only encrypted backup download. Key: BACKUP_KEY or JWT_SECRET-derived."""
    if not getattr(user, "is_founder", False) and user.role != "lead":
        raise HTTPException(status_code=403, detail="Lead only")
    try:
        from app.core.backup import build_snapshot, encrypt_snapshot
        from app.core.audit import log_audit

        blob = encrypt_snapshot(build_snapshot(db))
        log_audit(db, user, "backup_export", "system", "backup", f"{len(blob)} bytes encrypted")
        return StreamingResponse(
            io.BytesIO(blob),
            media_type="application/octet-stream",
            headers={"Content-Disposition": "attachment; filename=pentestai-backup.enc"},
        )
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Backup failed: {e}")
