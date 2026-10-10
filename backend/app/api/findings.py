from datetime import datetime
from uuid import UUID as PyUUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from app.models.database import get_db
from app.models.models import Finding, User
from app.core.security import require_auth

router = APIRouter(prefix="/api/findings", tags=["findings"])


class FindingResponse(BaseModel):
    # UUID/datetime types: pydantic serializes them to JSON strings, so the
    # frontend contract is unchanged (previously str-typed fields 500'd on
    # real UUID/datetime objects from SQLAlchemy).
    id: PyUUID | str
    engagement_id: PyUUID | str
    host_id: Optional[PyUUID | str] = None
    service_id: Optional[PyUUID | str] = None
    source_tool: Optional[str] = None
    vuln_type: Optional[str] = None
    parameter: Optional[str] = None
    severity: Optional[str] = None
    description: Optional[str] = None
    evidence: Optional[str] = None
    cvss_score: Optional[float] = None
    status: Optional[str] = None
    duplicate_of: Optional[PyUUID | str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    class Config:
        from_attributes = True


class FindingUpdate(BaseModel):
    status: Optional[str] = None
    duplicate_of: Optional[str] = None


class BulkUpdateRequest(BaseModel):
    ids: list[str]
    status: str


@router.get("/engagement/{engagement_id}", response_model=list[FindingResponse])
def list_findings(
    engagement_id: str,
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    vuln_type: Optional[str] = Query(None),
    source_tool: Optional[str] = Query(None),
    search: Optional[str] = Query(None, description="Search across vuln_type, parameter, description"),
    limit: Optional[int] = Query(None, ge=1, le=1000),
    offset: Optional[int] = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    query = db.query(Finding).filter(Finding.engagement_id == engagement_id)
    if severity:
        query = query.filter(Finding.severity == severity)
    if status:
        query = query.filter(Finding.status == status)
    if vuln_type:
        query = query.filter(Finding.vuln_type == vuln_type)
    if source_tool:
        query = query.filter(Finding.source_tool == source_tool)
    if search:
        like = f"%{search}%"
        query = query.filter(
            (Finding.vuln_type.ilike(like))
            | (Finding.parameter.ilike(like))
            | (Finding.description.ilike(like))
            | (Finding.source_tool.ilike(like))
        )
    query = query.order_by(Finding.first_seen.desc())
    if limit is not None:
        query = query.offset(offset).limit(limit)
    return query.all()


@router.post("/bulk-update")
def bulk_update(req: BulkUpdateRequest, db: Session = Depends(get_db), user: User = Depends(require_auth)):
    if not req.ids:
        raise HTTPException(400, "No ids provided")
    updated = 0
    for fid in req.ids:
        f = db.query(Finding).filter(Finding.id == fid).first()
        if f:
            f.status = req.status
            updated += 1
    db.commit()
    return {"updated": updated, "status": req.status}


@router.get("/engagement/{engagement_id}/export")
def export_findings(
    engagement_id: str,
    format: str = Query("csv", description="csv or sarif"),
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    from fastapi.responses import PlainTextResponse, JSONResponse
    import csv, io, json

    findings = db.query(Finding).filter(Finding.engagement_id == engagement_id).all()
    if format.lower() == "sarif":
        sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "PentestAI"}},
                    "results": [
                        {
                            "ruleId": f.vuln_type,
                            "level": "error" if f.severity in ("critical", "high") else "warning",
                            "message": {"text": f.description or ""},
                            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.parameter or "/"}}}],
                            "properties": {"severity": f.severity, "cvss": f.cvss_score},
                        }
                        for f in findings
                    ],
                }
            ],
        }
        return JSONResponse(content=sarif)
    # default csv
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "vuln_type", "severity", "cvss", "parameter", "tool", "status", "description"])
    for f in findings:
        writer.writerow([str(f.id), f.vuln_type, f.severity, f.cvss_score, f.parameter, f.source_tool, f.status, (f.description or "")[:200]])
    return PlainTextResponse(content=output.getvalue(), media_type="text/csv", headers={"Content-Disposition": f"attachment; filename=findings-{engagement_id}.csv"})


@router.get("/{finding_id}", response_model=FindingResponse)
def get_finding(
    finding_id: str, db: Session = Depends(get_db), user: User = Depends(require_auth)
):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    return finding


@router.patch("/{finding_id}", response_model=FindingResponse)
def update_finding(
    finding_id: str,
    data: FindingUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    for key, value in data.model_dump(exclude_unset=True).items():
        setattr(finding, key, value)
    db.commit()
    db.refresh(finding)
    return finding


@router.get("/engagement/{engagement_id}/summary")
def finding_summary(
    engagement_id: str, db: Session = Depends(get_db), user: User = Depends(require_auth)
):
    findings = db.query(Finding).filter(Finding.engagement_id == engagement_id).all()

    severity_counts = {}
    status_counts = {}
    tool_counts = {}
    type_counts = {}

    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        status_counts[f.status] = status_counts.get(f.status, 0) + 1
        tool_counts[f.source_tool] = tool_counts.get(f.source_tool, 0) + 1
        type_counts[f.vuln_type] = type_counts.get(f.vuln_type, 0) + 1

    return {
        "total": len(findings),
        "by_severity": severity_counts,
        "by_status": status_counts,
        "by_tool": tool_counts,
        "by_type": type_counts,
    }


@router.get("/engagement/{engagement_id}/duplicates")
def list_duplicates(
    engagement_id: str, db: Session = Depends(get_db), user: User = Depends(require_auth)
):
    dupes = (
        db.query(Finding)
        .filter(
            Finding.engagement_id == engagement_id,
            Finding.status == "confirmed_duplicate",
        )
        .all()
    )
    return [
        {
            "id": str(f.id),
            "vuln_type": f.vuln_type,
            "severity": f.severity,
            "description": f.description,
            "duplicate_of": str(f.duplicate_of) if f.duplicate_of else None,
        }
        for f in dupes
    ]
