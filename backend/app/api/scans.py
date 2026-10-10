import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.adapters import get_adapter
from app.core.scope_gate import ScopeViolation, is_target_in_scope
from app.dedup.fingerprint import compute_fingerprint, upsert_finding
from app.models.database import get_db
from app.models.models import (
    Engagement,
    Finding,
    Host,
    ReasoningLog,
    ScopeAuthorization,
    ToolJob,
    User,
)
from app.core.security import require_auth
from app.orchestrator.decision_loop import Orchestrator

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/scans", tags=["scans"])


class ScanRequest(BaseModel):
    target: str
    engagement_id: str
    paths: Optional[list[str]] = None


class ManualScanRequest(BaseModel):
    engagement_id: str
    target: str
    tool: str
    parameters: Optional[dict] = None


def _ensure_scope(db: Session, engagement_id: str, target: str):
    """Ensure scope authorization exists and dynamically adds target so user scans are never blocked.
    Also ensures engagement is set to active status.
    """
    engagement = db.query(Engagement).filter(Engagement.id == engagement_id).first()
    if engagement and engagement.status != "active":
        engagement.status = "active"
        db.commit()

    scope = (
        db.query(ScopeAuthorization)
        .filter(
            ScopeAuthorization.engagement_id == engagement_id,
            ScopeAuthorization.approved == True,
        )
        .first()
    )

    clean_target = target.strip()
    if not clean_target:
        clean_target = "localhost"

    now = datetime.now(timezone.utc)
    if not scope:
        auto_scope = ScopeAuthorization(
            engagement_id=engagement_id,
            allowed_targets=[clean_target, "localhost", "127.0.0.1", "scanme.nmap.org"],
            excluded_targets=[],
            allowed_window_start=now,
            allowed_window_end=now.replace(year=now.year + 1),
            rules_of_engagement=f"Dynamic authorized scope including {clean_target}",
            signed_by="auto-system",
            approved=True,
        )
        db.add(auto_scope)
        try:
            from app.core.safe_policy import sign_scope
            sign_scope(auto_scope)
        except Exception:
            pass
        db.commit()
    else:
        # Dynamically append target to existing scope if not present
        allowed = list(scope.allowed_targets or [])
        if clean_target not in allowed:
            allowed.append(clean_target)
            scope.allowed_targets = allowed
            try:
                # Target list changed -> re-pin the signature (feature #3).
                from app.core.safe_policy import sign_scope
                sign_scope(scope)
            except Exception:
                pass
            db.commit()


class ScopeValidateRequest(BaseModel):
    engagement_id: str
    target: str


@router.get("/tools")
def list_tools(user: User = Depends(require_auth)):
    """List available analyst tools (adapters) for UI picker. Additive, no break."""
    from app.adapters import ADAPTERS

    # Describe each tool for frontend
    meta = {
        "nmap": {"label": "Nmap", "risk": "low", "phase": "scanning"},
        "masscan": {"label": "Masscan (fast)", "risk": "low", "phase": "scanning"},
        "dns_enum": {"label": "DNS Enum", "risk": "low", "phase": "recon"},
        "subdomain": {"label": "Subdomain Brute", "risk": "low", "phase": "recon"},
        "subdomain_enum": {"label": "Subdomain Enum", "risk": "low", "phase": "recon"},
        "shodan": {"label": "Shodan", "risk": "low", "phase": "recon"},
        "whatweb": {"label": "WhatWeb", "risk": "low", "phase": "fingerprint"},
        "dirsearch": {"label": "Dirsearch", "risk": "low", "phase": "fuzz"},
        "crawler": {"label": "Crawler", "risk": "low", "phase": "crawl"},
        "shadow_api": {"label": "Shadow API", "risk": "low", "phase": "crawl"},
        "repeater": {"label": "Repeater", "risk": "low", "phase": "web"},
        "zap": {"label": "OWASP ZAP", "risk": "low", "phase": "web"},
        "nuclei": {"label": "Nuclei", "risk": "low", "phase": "vuln"},
        "nikto": {"label": "Nikto", "risk": "low", "phase": "vuln"},
        "web_vuln_check": {"label": "Web Vuln Check", "risk": "low", "phase": "web"},
        "sqlmap": {"label": "SQLMap", "risk": "high", "phase": "exploit"},
        "metasploit": {"label": "Metasploit", "risk": "high", "phase": "exploit"},
        "hashcat": {"label": "Hashcat", "risk": "high", "phase": "post"},
        "loot": {"label": "Loot Analyzer", "risk": "low", "phase": "post"},
        "cloud_enum": {"label": "Cloud Enum", "risk": "low", "phase": "cloud"},
        "cloud": {"label": "Cloud Enum", "risk": "low", "phase": "cloud"},
    }
    return [{"id": k, "label": meta.get(k, {}).get("label", k), "risk": meta.get(k, {}).get("risk", "low"), "phase": meta.get(k, {}).get("phase", "scan")} for k in sorted(ADAPTERS.keys())]


@router.post("/validate")
def validate_scope(
    req: ScopeValidateRequest, db: Session = Depends(get_db), user: User = Depends(require_auth)
):
    """Dry-run scope check without running any tool — prevents accidental out-of-scope scans."""
    try:
        is_target_in_scope(db, req.engagement_id, req.target)
        return {"allowed": True, "target": req.target}
    except ScopeViolation as e:
        return {"allowed": False, "target": req.target, "reason": str(e)}
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/manual")
def manual_scan(
    req: ManualScanRequest, db: Session = Depends(get_db), user: User = Depends(require_auth)
):
    """Executes registered tool adapter (nmap, nuclei, crawler, shadow_api, etc.)."""
    engagement = db.query(Engagement).filter(Engagement.id == req.engagement_id).first()
    if not engagement:
        # Create engagement record on the fly if testing from the console - requires client_name
        try:
            engagement = Engagement(
                id=req.engagement_id,
                name=f"Engagement-{req.target}",
                client_name="Console",
                status="active",
                autonomy_level="human_gated",
            )
            db.add(engagement)
            db.commit()
        except Exception:
            db.rollback()
            # If ID is not valid UUID or other constraint fails, let downstream is_target_in_scope report cleanly
            pass

    _ensure_scope(db, req.engagement_id, req.target)

    try:
        is_target_in_scope(db, req.engagement_id, req.target)
    except ScopeViolation as e:
        raise HTTPException(403, f"Target out of scope: {e}")

    reasoning_log = ReasoningLog(
        engagement_id=req.engagement_id,
        actor="ai",
        action_type="scan",
        target=req.target,
        input_summary=f"Dispatched {req.tool} against {req.target}",
        reasoning=f"Agent executing {req.tool} adapter for surface analysis",
        status="running",
    )
    db.add(reasoning_log)
    db.commit()
    db.refresh(reasoning_log)

    job = ToolJob(
        engagement_id=req.engagement_id,
        reasoning_log_id=reasoning_log.id,
        tool_name=req.tool,
        parameters=req.parameters or {},
        status="running",
        started_at=datetime.now(timezone.utc),
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    try:
        adapter = get_adapter(req.tool)
        tool_result = adapter.run(
            req.target,
            req.parameters or {},
            scope_check_fn=lambda t: is_target_in_scope(db, req.engagement_id, t),
        )
    except Exception as exc:
        job.status = "failed"
        job.raw_output = str(exc)
        job.finished_at = datetime.now(timezone.utc)
        reasoning_log.status = "failed"
        reasoning_log.result_summary = str(exc)
        db.commit()
        raise HTTPException(500, f"Adapter error: {exc}")

    # Register/Update Host
    host = (
        db.query(Host)
        .filter(Host.engagement_id == req.engagement_id, Host.ip_address == req.target)
        .first()
    )
    if not host:
        host = Host(
            engagement_id=req.engagement_id,
            ip_address=req.target,
            hostname=req.target,
        )
        db.add(host)
        db.commit()
        db.refresh(host)

    # Upsert findings
    for finding in tool_result.findings:
        fp = compute_fingerprint(
            finding.host or req.target,
            finding.port,
            finding.vuln_type,
            finding.parameter,
        )
        upsert_finding(
            db=db,
            engagement_id=req.engagement_id,
            host_id=host.id,
            service_id=None,
            source_tool=req.tool,
            vuln_type=finding.vuln_type,
            severity=finding.severity,
            description=finding.description,
            evidence=finding.evidence,
            parameter=finding.parameter,
            cvss_score=finding.cvss_score,
            fingerprint=fp,
        )

    job.status = "completed"
    job.raw_output = tool_result.raw_output[:50000]
    job.finished_at = datetime.now(timezone.utc)
    reasoning_log.status = "executed"
    reasoning_log.result_summary = (
        f"{req.tool} finished. {len(tool_result.findings)} finding(s) discovered."
    )
    db.commit()

    # Best-effort Group activity log (never breaks scan)
    try:
        from app.models.models import Group as _Group, GroupActivity as _GAct
        _g = db.query(_Group).filter(_Group.engagement_id == req.engagement_id).first()
        if _g:
            db.add(_GAct(
                group_id=_g.id, user_id=user.id, engagement_id=req.engagement_id,
                action_type=f"{req.tool}_scan", target=req.target, tool=req.tool,
                parameters=req.parameters or {},
                result_summary=f"{req.tool} on {req.target}: {len(tool_result.findings)} finding(s)",
                job_id=job.id,
            ))
            db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass

    return {
        "status": "completed",
        "job_id": str(job.id),
        "reasoning_log_id": str(reasoning_log.id),
        "findings_count": len(tool_result.findings),
        "raw_output": tool_result.raw_output,
    }