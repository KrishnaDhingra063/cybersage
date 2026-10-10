import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from app.models.database import get_db
from app.models.models import Engagement, ScopeAuthorization, Host, Service, User
from app.core.security import require_auth, require_lead
from app.core.scope_gate import AutonomyLevels

router = APIRouter(prefix="/api/engagements", tags=["engagements"])


from uuid import UUID


class EngagementCreate(BaseModel):
    name: str
    client_name: Optional[str] = None
    test_type: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None


class EngagementResponse(BaseModel):
    id: UUID | str
    name: str
    client_name: Optional[str]
    status: str
    test_type: Optional[str]
    autonomy_level: Optional[str]
    start_date: Optional[datetime]
    end_date: Optional[datetime]
    created_at: Optional[datetime]

    class Config:
        from_attributes = True


class AutonomyRequest(BaseModel):
    level: str


@router.post("/{engagement_id}/autonomy")
def set_autonomy_level(
    engagement_id: str,
    data: AutonomyRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_lead),
):
    eng = db.query(Engagement).filter(Engagement.id == engagement_id).first()
    if not eng:
        raise HTTPException(404, "Engagement not found")

    level = data.level.lower()
    valid = {AutonomyLevels.SUGGEST_ONLY, AutonomyLevels.HUMAN_GATED, AutonomyLevels.AUTONOMOUS}
    if level not in valid:
        raise HTTPException(400, f"Invalid autonomy level '{level}'. Valid: {sorted(valid)}")

    eng.autonomy_level = level
    db.commit()
    return {"status": "updated", "autonomy_level": eng.autonomy_level}


class ScopeCreate(BaseModel):
    allowed_targets: list[str]
    excluded_targets: Optional[list[str]] = []
    allowed_window_start: datetime
    allowed_window_end: datetime
    rules_of_engagement: Optional[str] = None
    signed_by: Optional[str] = None


class ScopeResponse(BaseModel):
    id: UUID | str
    engagement_id: UUID | str
    allowed_targets: list[str]
    excluded_targets: list[str]
    allowed_window_start: datetime
    allowed_window_end: datetime
    rules_of_engagement: Optional[str]
    signed_by: Optional[str]
    approved: bool
    created_at: Optional[datetime]

    class Config:
        from_attributes = True


@router.post("/", response_model=EngagementResponse)
def create_engagement(
    data: EngagementCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    engagement = Engagement(
        name=data.name,
        client_name=data.client_name,
        test_type=data.test_type,
        start_date=data.start_date,
        end_date=data.end_date,
        status="draft",
    )
    db.add(engagement)
    db.commit()
    db.refresh(engagement)
    return engagement


@router.get("/", response_model=list[EngagementResponse])
def list_engagements(
    status: str = None,
    limit: int = None,
    offset: int = 0,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    query = db.query(Engagement)
    if status:
        query = query.filter(Engagement.status == status)
    query = query.order_by(Engagement.created_at.desc())
    if limit is not None:
        query = query.offset(offset).limit(min(limit, 100))
    return query.all()


@router.get("/{engagement_id}", response_model=EngagementResponse)
def get_engagement(
    engagement_id: str, db: Session = Depends(get_db), user: User = Depends(require_auth)
):
    eng = db.query(Engagement).filter(Engagement.id == engagement_id).first()
    if not eng:
        raise HTTPException(404, "Engagement not found")
    return eng


@router.patch("/{engagement_id}", response_model=EngagementResponse)
def update_engagement(
    engagement_id: str,
    data: EngagementCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    eng = db.query(Engagement).filter(Engagement.id == engagement_id).first()
    if not eng:
        raise HTTPException(404, "Engagement not found")
    for key, value in data.model_dump(exclude_unset=True).items():
        setattr(eng, key, value)
    db.commit()
    db.refresh(eng)
    return eng


@router.post("/{engagement_id}/scope", response_model=ScopeResponse)
def create_scope(
    engagement_id: str,
    data: ScopeCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    eng = db.query(Engagement).filter(Engagement.id == engagement_id).first()
    if not eng:
        raise HTTPException(404, "Engagement not found")

    # Guard against zero-length windows (would block every scan with "outside allowed window")
    _s, _e = data.allowed_window_start, data.allowed_window_end
    try:
        _s = _s.replace(tzinfo=_s.tzinfo or __import__("datetime").timezone.utc)
        _e = _e.replace(tzinfo=_e.tzinfo or __import__("datetime").timezone.utc)
    except Exception:
        pass
    if _e <= _s:
        raise HTTPException(400, "allowed_window_end must be after allowed_window_start")

    scope = ScopeAuthorization(
        engagement_id=engagement_id,
        allowed_targets=data.allowed_targets,
        excluded_targets=data.excluded_targets or [],
        allowed_window_start=data.allowed_window_start,
        allowed_window_end=data.allowed_window_end,
        rules_of_engagement=data.rules_of_engagement,
        signed_by=data.signed_by,
        approved=False,
    )
    db.add(scope)
    db.commit()
    db.refresh(scope)
    try:
        from app.core.safe_policy import sign_scope
        sign_scope(scope)
        db.commit()
        db.refresh(scope)
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
    return scope


@router.get("/{engagement_id}/scope", response_model=list[ScopeResponse])
def list_scopes(
    engagement_id: str, db: Session = Depends(get_db), user: User = Depends(require_auth)
):
    return (
        db.query(ScopeAuthorization)
        .filter(ScopeAuthorization.engagement_id == engagement_id)
        .all()
    )


@router.post("/{engagement_id}/scope/{scope_id}/approve")
def approve_scope(
    engagement_id: str,
    scope_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_lead),
):
    scope = (
        db.query(ScopeAuthorization)
        .filter(
            ScopeAuthorization.id == scope_id,
            ScopeAuthorization.engagement_id == engagement_id,
        )
        .first()
    )
    if not scope:
        raise HTTPException(404, "Scope authorization not found")

    scope.approved = True
    eng = db.query(Engagement).filter(Engagement.id == engagement_id).first()
    if eng and eng.status in ("draft", "authorized"):
        eng.status = "active"

    try:
        # Cryptographic scope pin: commit the HMAC over the exact approved
        # targets/window so later tampering invalidates dispatch (feature #3).
        from app.core.safe_policy import sign_scope
        sign_scope(scope)
    except Exception:
        pass
    db.commit()
    return {"status": "approved", "scope_id": str(scope_id)}


@router.post("/{engagement_id}/scope/{scope_id}/upload")
async def upload_authorization(
    engagement_id: str,
    scope_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(require_lead),
):
    scope = (
        db.query(ScopeAuthorization)
        .filter(
            ScopeAuthorization.id == scope_id,
            ScopeAuthorization.engagement_id == engagement_id,
        )
        .first()
    )
    if not scope:
        raise HTTPException(404, "Scope authorization not found")

    import os
    import re

    # MIME allowlist for RoE docs (pdf, images, text)
    allowed_ext = {".pdf", ".png", ".jpg", ".jpeg", ".txt", ".md"}
    allowed_mime = {"application/pdf", "image/png", "image/jpeg", "text/plain", "text/markdown"}
    safe_name = os.path.basename(file.filename or "document")
    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", safe_name)[:100]
    if not safe_name or safe_name.startswith("."):
        safe_name = "document.pdf"
    _, ext = os.path.splitext(safe_name.lower())
    if ext not in allowed_ext:
        raise HTTPException(400, f"File type {ext or '?'} not allowed (pdf/png/jpg/txt/md)")
    if file.content_type and file.content_type not in allowed_mime and not file.content_type.startswith("text/"):
        raise HTTPException(400, f"MIME {file.content_type} not allowed")
    # Size guard: 5 MB max
    content = await file.read()
    if len(content) > 5 * 1024 * 1024:
        raise HTTPException(400, "File too large (max 5 MB)")

    # Optional ClamAV scan if clamscan binary exists (best-effort, never blocks if absent)
    try:
        import shutil
        import subprocess
        import tempfile

        if shutil.which("clamscan"):
            with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
                tmp.write(content)
                tmp_path = tmp.name
            try:
                proc = subprocess.run(["clamscan", "--no-summary", tmp_path], capture_output=True, text=True, timeout=30)
                if proc.returncode == 1:
                    raise HTTPException(400, "File failed antivirus scan")
            finally:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass
    except HTTPException:
        raise
    except Exception:
        pass  # scanner absent/broken -> continue with validation above

    # S3 when configured (S3_BUCKET + AWS creds), else local disk (backward compatible)
    stored_path = ""
    try:
        import os as _os

        bucket = _os.getenv("S3_BUCKET", "").strip()
        if bucket:
            import boto3

            key = f"authorizations/{scope_id}_{safe_name}"
            s3 = boto3.client(
                "s3",
                endpoint_url=_os.getenv("S3_ENDPOINT_URL") or None,
                region_name=_os.getenv("S3_REGION") or None,
            )
            import io as _io

            s3.upload_fileobj(_io.BytesIO(content), bucket, key)
            stored_path = f"s3://{bucket}/{key}"
        else:
            raise RuntimeError("no bucket")
    except Exception:
        upload_dir = "uploads/authorizations"
        os.makedirs(upload_dir, exist_ok=True)
        stored_path = os.path.join(upload_dir, f"{scope_id}_{safe_name}")
        with open(stored_path, "wb") as f:
            f.write(content)

    scope.signed_document_path = stored_path
    db.commit()
    try:
        from app.core.audit import log_audit
        log_audit(db, user, "roe_upload", "scope", str(scope_id), safe_name)
    except Exception:
        pass
    return {"status": "uploaded", "path": stored_path}


# ── Host/Service Inventory (feature 8) ─────────────────────────────────
class HostResponse(BaseModel):
    id: UUID | str
    ip_address: str
    hostname: Optional[str]
    os_guess: Optional[str]
    status: Optional[str]
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]

    class Config:
        from_attributes = True


class ServiceResponse(BaseModel):
    id: UUID | str
    host_id: UUID | str
    port: int
    protocol: Optional[str]
    service_name: Optional[str]
    version: Optional[str]
    banner: Optional[str]

    class Config:
        from_attributes = True


@router.get("/{engagement_id}/hosts", response_model=list[HostResponse])
def list_hosts(engagement_id: str, db: Session = Depends(get_db), user: User = Depends(require_auth)):
    return db.query(Host).filter(Host.engagement_id == engagement_id).order_by(Host.last_seen.desc()).all()


@router.get("/{engagement_id}/services", response_model=list[ServiceResponse])
def list_services(engagement_id: str, db: Session = Depends(get_db), user: User = Depends(require_auth)):
    return (
        db.query(Service)
        .join(Host, Service.host_id == Host.id)
        .filter(Host.engagement_id == engagement_id)
        .order_by(Service.port.asc())
        .all()
    )


@router.get("/{engagement_id}/inventory")
def get_inventory(engagement_id: str, db: Session = Depends(get_db), user: User = Depends(require_auth)):
    hosts = db.query(Host).filter(Host.engagement_id == engagement_id).all()
    services = (
        db.query(Service)
        .join(Host, Service.host_id == Host.id)
        .filter(Host.engagement_id == engagement_id)
        .all()
    )
    # Group services by host
    svc_by_host = {}
    for s in services:
        svc_by_host.setdefault(str(s.host_id), []).append(
            {"id": str(s.id), "port": s.port, "protocol": s.protocol, "service_name": s.service_name, "version": s.version, "banner": (s.banner or "")[:200]}
        )
    return {
        "hosts": [
            {
                "id": str(h.id),
                "ip_address": h.ip_address,
                "hostname": h.hostname,
                "os_guess": h.os_guess,
                "status": h.status,
                "services": svc_by_host.get(str(h.id), []),
            }
            for h in hosts
        ],
        "total_hosts": len(hosts),
        "total_services": len(services),
    }
