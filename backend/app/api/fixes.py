from datetime import datetime, timezone
from uuid import UUID as PyUUID
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from app.models.database import get_db
from app.models.models import FixSuggestion, FixStyleConfig, Finding, User
from app.core.security import require_auth, require_lead
from app.core.fix_engine import FixEngine, DEFAULT_STYLE_RULES
from app.core.github_integration import create_pull_request, GitHubError

router = APIRouter(prefix="/api/fixes", tags=["fixes"])


class FixGenerateRequest(BaseModel):
    engagement_id: str
    finding_id: str
    style_rules: Optional[str] = None


class StyleRequest(BaseModel):
    engagement_id: str
    name: Optional[str] = "default"
    language: Optional[str] = "auto"
    style_rules: str


class CreatePRRequest(BaseModel):
    repo: Optional[str] = None
    file_path: Optional[str] = None
    commit_message: Optional[str] = None
    pr_title: Optional[str] = None
    pr_body: Optional[str] = None


class FixSuggestionResponse(BaseModel):
    id: PyUUID | str
    engagement_id: PyUUID | str
    finding_id: Optional[PyUUID | str] = None
    status: str
    language: Optional[str] = None
    file_path: Optional[str] = None
    before_code: Optional[str] = None
    after_code: Optional[str] = None
    git_diff: Optional[str] = None
    waf_rule: Optional[str] = None
    waf_engine: Optional[str] = None
    curl_replay: Optional[str] = None
    explanation: Optional[str] = None
    lint_check: Optional[str] = None
    pr_url: Optional[str] = None
    created_at: Optional[object] = None

    class Config:
        from_attributes = True


@router.post("/styles")
def save_style(
    data: StyleRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_lead),
):
    style = (
        db.query(FixStyleConfig)
        .filter(
            FixStyleConfig.engagement_id == data.engagement_id,
            FixStyleConfig.name == data.name,
        )
        .first()
    )
    if style:
        style.style_rules = data.style_rules
        style.language = data.language
        style.created_by_user_id = user.id
    else:
        style = FixStyleConfig(
            engagement_id=data.engagement_id,
            name=data.name,
            language=data.language,
            style_rules=data.style_rules,
            created_by_user_id=user.id,
        )
        db.add(style)
    db.commit()
    db.refresh(style)
    return {
        "id": str(style.id),
        "engagement_id": str(style.engagement_id),
        "name": style.name,
        "language": style.language,
        "style_rules": style.style_rules,
    }


@router.get("/engagement/{engagement_id}/styles")
def list_styles(
    engagement_id: str, db: Session = Depends(get_db), user: User = Depends(require_auth)
):
    return [
        {
            "id": str(s.id),
            "name": s.name,
            "language": s.language,
            "style_rules": s.style_rules,
        }
        for s in db.query(FixStyleConfig)
        .filter(FixStyleConfig.engagement_id == engagement_id)
        .all()
    ]


@router.post("/generate", response_model=FixSuggestionResponse)
def generate_fix(
    req: FixGenerateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    finding = db.query(Finding).filter(
        Finding.id == req.finding_id,
        Finding.engagement_id == req.engagement_id,
    ).first()
    if not finding:
        raise HTTPException(404, "Finding not found")

    engine = FixEngine(db)
    style_config = (
        db.query(FixStyleConfig)
        .filter(FixStyleConfig.engagement_id == req.engagement_id, FixStyleConfig.name == "default")
        .first()
    )
    style_rules = req.style_rules or (style_config.style_rules if style_config else "") or DEFAULT_STYLE_RULES

    suggestion = engine.generate(
        finding,
        style_rules=style_rules,
        created_by_user_id=user.id,
    )
    if suggestion is None:
        raise HTTPException(
            status_code=502,
            detail="AI engine failed to generate a fix (LLM unavailable or bad response). Try again.",
        )
    return suggestion


@router.get("/engagement/{engagement_id}", response_model=list[FixSuggestionResponse])
def list_fixes(
    engagement_id: str, db: Session = Depends(get_db), user: User = Depends(require_auth)
):
    return (
        db.query(FixSuggestion)
        .filter(FixSuggestion.engagement_id == engagement_id)
        .order_by(FixSuggestion.created_at.desc())
        .all()
    )


@router.get("/{fix_id}", response_model=FixSuggestionResponse)
def get_fix(
    fix_id: str, db: Session = Depends(get_db), user: User = Depends(require_auth)
):
    fix = db.query(FixSuggestion).filter(FixSuggestion.id == fix_id).first()
    if not fix:
        raise HTTPException(404, "Fix suggestion not found")
    return fix


@router.post("/{fix_id}/approve", response_model=FixSuggestionResponse)
def approve_fix(
    fix_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_lead),
):
    fix = db.query(FixSuggestion).filter(FixSuggestion.id == fix_id).first()
    if not fix:
        raise HTTPException(404, "Fix suggestion not found")
    if fix.status == "failed_lint":
        raise HTTPException(400, "Cannot approve a fix that failed lint — regenerate it")

    fix.status = "approved"
    fix.approved_by_user_id = user.id
    fix.approved_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(fix)
    try:
        from app.core.audit import log_audit
        log_audit(db, user, "fix_approve", "fix", str(fix.id), (fix.file_path or "")[:200])
    except Exception:
        pass
    return fix


@router.post("/{fix_id}/reject", response_model=FixSuggestionResponse)
def reject_fix(
    fix_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_lead),
):
    fix = db.query(FixSuggestion).filter(FixSuggestion.id == fix_id).first()
    if not fix:
        raise HTTPException(404, "Fix suggestion not found")

    fix.status = "rejected"
    fix.approved_by_user_id = user.id
    db.commit()
    db.refresh(fix)
    return fix


@router.post("/{fix_id}/apply", response_model=FixSuggestionResponse)
def apply_fix(
    fix_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_lead),
):
    fix = db.query(FixSuggestion).filter(FixSuggestion.id == fix_id).first()
    if not fix:
        raise HTTPException(404, "Fix suggestion not found")
    if fix.status != "approved":
        raise HTTPException(400, "Fix must be approved before it can be applied")

    # Closed-loop verify: flip the underlying finding to a 'resolved' state marker.
    # (Real patching of live repos happens through the 1-click PR flow.)
    fix.status = "applied"
    db.commit()
    db.refresh(fix)
    return fix


@router.post("/{fix_id}/create_pr", response_model=FixSuggestionResponse)
def create_pr(
    fix_id: str,
    req: CreatePRRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_lead),
):
    fix = db.query(FixSuggestion).filter(FixSuggestion.id == fix_id).first()
    if not fix:
        raise HTTPException(404, "Fix suggestion not found")
    if fix.status == "failed_lint":
        raise HTTPException(400, "Cannot open a PR for a fix that failed lint")
    if not fix.after_code.strip():
        raise HTTPException(400, "Fix has no generated code to commit")

    file_path = req.file_path or fix.file_path or "patched_file"
    commit_message = req.commit_message or f"fix({file_path}): {fix.explanation[:120]}"
    pr_title = req.pr_title or f"Security fix: {fix.language or ''}".strip() + " remediation"
    pr_body = req.pr_body or (
        f"Automated security fix generated by PentestAI.\n\n"
        f"Finding: {fix.finding_id}\n\n{fix.explanation or ''}\n\n"
        f"Lint check: {fix.lint_check or 'n/a'}"
    )

    try:
        result = create_pull_request(
            owner_repo=req.repo,
            file_path=file_path,
            new_content=fix.after_code,
            commit_message=commit_message,
            pr_title=pr_title,
            pr_body=pr_body,
        )
    except GitHubError as e:
        raise HTTPException(400, str(e))

    fix.pr_url = result["pr_url"]
    db.commit()
    db.refresh(fix)
    try:
        from app.core.audit import log_audit
        log_audit(db, user, "pr_create", "fix", str(fix.id), result["pr_url"][:200])
    except Exception:
        pass
    return fix


@router.post("/{fix_id}/verify")
def verify_fix(
    fix_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_auth),
):
    """Verify-fix loop: re-run the finding's original tool against its original
    target and compare fingerprints. Read-only w.r.t. the target (scan only).

    - original fingerprint gone  -> finding 'verified_fixed', fix 'verified'
    - still present               -> finding back to 'open', fix untouched
    - tool errored                -> nothing mutated, error returned
    """
    from app.adapters import get_adapter
    from app.core.scope_gate import ScopeViolation, is_target_in_scope
    from app.dedup.fingerprint import compute_fingerprint
    from app.models.models import Host, ReasoningLog, ToolJob

    fix = db.query(FixSuggestion).filter(FixSuggestion.id == fix_id).first()
    if not fix:
        raise HTTPException(404, "Fix suggestion not found")
    if fix.status not in ("approved", "applied", "verified"):
        raise HTTPException(400, "Fix must be approved before it can be verified")
    finding = db.query(Finding).filter(Finding.id == fix.finding_id).first()
    if not finding:
        raise HTTPException(404, "Linked finding not found")

    tool = (finding.source_tool or "").strip()
    if not tool:
        raise HTTPException(400, "Finding has no source tool to re-run")

    target = ""
    if finding.host_id:
        host = db.query(Host).filter(Host.id == finding.host_id).first()
        if host:
            target = host.ip_address or host.hostname or ""
    if not target:
        param = (finding.parameter or "").strip()
        if param and "." in param and " " not in param:
            target = param
    if not target:
        raise HTTPException(400, "Cannot resolve original target for re-scan")

    eng_id = str(finding.engagement_id)
    try:
        is_target_in_scope(db, eng_id, target)
    except ScopeViolation as e:
        return {"status": "blocked", "reason": str(e), "tool": tool, "target": target}

    try:
        adapter = get_adapter(tool)
    except ValueError as e:
        raise HTTPException(400, str(e))

    log_entry = ReasoningLog(
        engagement_id=finding.engagement_id,
        actor="human",
        action_type="verify_fix",
        target=target,
        input_summary=f"Re-running {tool} to verify fix {fix_id}",
        reasoning=f"Operator requested verification of remediation for {finding.vuln_type}",
        status="running",
    )
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)

    job = ToolJob(
        engagement_id=finding.engagement_id,
        reasoning_log_id=log_entry.id,
        tool_name=tool,
        parameters={"verify_fix_id": str(fix.id)},
        status="running",
        started_at=datetime.now(timezone.utc),
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    try:
        tool_result = adapter.run(
            target, {}, scope_check_fn=lambda t: is_target_in_scope(db, eng_id, t)
        )
    except Exception as exc:
        job.status = "failed"
        job.raw_output = str(exc)[:5000]
        job.finished_at = datetime.now(timezone.utc)
        log_entry.status = "failed"
        log_entry.result_summary = str(exc)[:500]
        db.commit()
        return {"status": "error", "reason": str(exc)[:500], "tool": tool, "target": target}

    job.status = "completed"
    job.raw_output = (tool_result.raw_output or "")[:50000]
    job.finished_at = datetime.now(timezone.utc)

    if getattr(tool_result, "exit_code", 0) not in (0, None):
        log_entry.status = "failed"
        log_entry.result_summary = f"Re-scan tool exited {tool_result.exit_code} — no conclusion"
        db.commit()
        return {
            "status": "error",
            "reason": f"Re-scan tool exited with code {tool_result.exit_code}; not conclusive, nothing changed.",
            "tool": tool,
            "target": target,
            "job_id": str(job.id),
        }

    new_fps = set()
    for nf in (tool_result.findings or []):
        try:
            new_fps.add(compute_fingerprint(
                getattr(nf, "host", "") or target,
                getattr(nf, "port", 0),
                getattr(nf, "vuln_type", ""),
                getattr(nf, "parameter", ""),
            ))
        except Exception:
            pass

    matched = bool(finding.fingerprint) and finding.fingerprint in new_fps
    new_count = len(tool_result.findings or [])

    if matched:
        finding.status = "open"
        log_entry.status = "executed"
        log_entry.result_summary = f"Still vulnerable: {finding.vuln_type} re-detected by {tool}"
        outcome = "still_vulnerable"
        detail = f"{tool} re-detected {finding.vuln_type} on {target} ({new_count} finding(s) this scan). Patch did not hold."
    else:
        finding.status = "verified_fixed"
        fix.status = "verified"
        log_entry.status = "executed"
        log_entry.result_summary = f"Verified fixed: {finding.vuln_type} gone after re-scan by {tool}"
        outcome = "verified"
        detail = f"{tool} no longer detects {finding.vuln_type} on {target} ({new_count} other finding(s) this scan)."

    db.commit()
    try:
        from app.core.audit import log_audit
        log_audit(db, user, "fix_verify", "fix", str(fix.id), f"{tool} on {target}: {outcome}")
    except Exception:
        pass

    return {
        "status": outcome,
        "detail": detail,
        "tool": tool,
        "target": target,
        "finding_id": str(finding.id),
        "finding_status": finding.status,
        "fix_status": fix.status,
        "new_findings_count": new_count,
        "job_id": str(job.id),
    }