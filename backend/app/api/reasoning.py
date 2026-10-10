import asyncio
import json
from datetime import datetime
from uuid import UUID as PyUUID

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from app.models.database import get_db, SessionLocal
from app.models.models import ReasoningLog, ToolJob, User, Finding
from app.core.security import require_auth, require_lead
from app.tasks.tasks import run_orchestration_cycle, execute_tool_job, continuous_pentest

router = APIRouter(prefix="/api/reasoning", tags=["reasoning"])


class ReasoningLogResponse(BaseModel):
    # UUID/datetime types serialize to JSON strings (same frontend contract).
    id: PyUUID | str
    engagement_id: PyUUID | str
    parent_event_id: Optional[PyUUID | str] = None
    timestamp: Optional[datetime] = None
    actor: Optional[str] = None
    action_type: Optional[str] = None
    target: Optional[str] = None
    reasoning: Optional[str] = None
    proposed_action: Optional[str] = None
    status: Optional[str] = None
    result_summary: Optional[str] = None
    linked_finding_id: Optional[PyUUID | str] = None

    class Config:
        from_attributes = True


class ApprovalDecision(BaseModel):
    approved: bool
    notes: Optional[str] = None


class ToolJobResponse(BaseModel):
    id: PyUUID | str
    engagement_id: PyUUID | str
    reasoning_log_id: Optional[PyUUID | str] = None
    tool_name: Optional[str] = None
    parameters: Optional[dict] = None
    status: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None

    class Config:
        from_attributes = True


@router.get("/engagement/{engagement_id}", response_model=list[ReasoningLogResponse])
def get_reasoning_trail(
    engagement_id: str, db: Session = Depends(get_db), user: User = Depends(require_auth)
):
    return (
        db.query(ReasoningLog)
        .filter(ReasoningLog.engagement_id == engagement_id)
        .order_by(ReasoningLog.timestamp.asc())
        .all()
    )


@router.get("/{log_id}", response_model=ReasoningLogResponse)
def get_reasoning_entry(
    log_id: str, db: Session = Depends(get_db), user: User = Depends(require_auth)
):
    entry = db.query(ReasoningLog).filter(ReasoningLog.id == log_id).first()
    if not entry:
        raise HTTPException(404, "Reasoning log entry not found")
    return entry


@router.post("/engagement/{engagement_id}/cycle")
def trigger_cycle(
    engagement_id: str, user: User = Depends(require_auth)
):
    result = run_orchestration_cycle.delay(engagement_id)
    return {"task_id": result.id, "status": "queued"}


@router.post("/engagement/{engagement_id}/continuous")
def start_continuous(
    engagement_id: str, max_cycles: int = 20, user: User = Depends(require_auth)
):
    result = continuous_pentest.delay(engagement_id, max_cycles)
    return {"task_id": result.id, "status": "started", "max_cycles": max_cycles}


@router.post("/{log_id}/approve")
def approve_action(
    log_id: str,
    decision: ApprovalDecision,
    db: Session = Depends(get_db),
    user: User = Depends(require_lead),
):
    entry = db.query(ReasoningLog).filter(ReasoningLog.id == log_id).first()
    if not entry:
        raise HTTPException(404, "Reasoning log entry not found")

    if entry.status != "proposed":
        raise HTTPException(400, f"Entry status is '{entry.status}', expected 'proposed'")

    if decision.approved:
        entry.status = "approved"
        entry.approved_by_user_id = user.id
        entry.result_summary = f"Approved by {user.username}"
        db.commit()

        engagement_id = str(entry.engagement_id)
        import json
        try:
            action_data = json.loads(entry.proposed_action)
        except (json.JSONDecodeError, TypeError):
            action_data = {}

        job = ToolJob(
            engagement_id=entry.engagement_id,
            reasoning_log_id=entry.id,
            tool_name=action_data.get("tool", ""),
            parameters=action_data.get("parameters", {}),
            status="queued",
        )
        db.add(job)
        db.commit()
        db.refresh(job)

        task = execute_tool_job.delay(
            str(job.id), engagement_id, str(entry.id)
        )

        try:
            from app.core.audit import log_audit
            log_audit(db, user, "exploit_approve", "reasoning_log", str(entry.id), f"tool={action_data.get('tool','')} target={entry.target or ''}")
        except Exception:
            pass

        return {
            "status": "approved",
            "job_id": str(job.id),
            "task_id": task.id,
        }
    else:
        entry.status = "rejected"
        entry.approved_by_user_id = user.id
        entry.result_summary = f"Rejected by {user.username}: {decision.notes or 'No notes'}"
        db.commit()
        try:
            from app.core.audit import log_audit
            log_audit(db, user, "exploit_reject", "reasoning_log", str(entry.id), decision.notes or "")
        except Exception:
            pass
        return {"status": "rejected"}


@router.get("/engagement/{engagement_id}/graph")
def get_attack_graph(
    engagement_id: str, db: Session = Depends(get_db), user: User = Depends(require_auth)
):
    """Builds a graph of the engagement's reasoning/attack path for React Flow.

    Nodes: hosts + findings + AI decisions. Edges: parent->child event links
    and event->finding links, so users can see WHY each step was taken.
    """
    trail = (
        db.query(ReasoningLog)
        .filter(ReasoningLog.engagement_id == engagement_id)
        .order_by(ReasoningLog.timestamp.asc())
        .all()
    )

    nodes = []
    edges = []

    event_index = {}
    for entry in trail:
        node_id = f"event:{entry.id}"
        event_index[str(entry.id)] = node_id
        label = f"{entry.action_type or '?'}\n{entry.target or ''}"
        nodes.append({
            "id": node_id,
            "type": "reasoning",
            "data": {
                "label": label,
                "status": entry.status,
                "reasoning": entry.reasoning or "",
                "result": entry.result_summary or "",
            },
            "position": {"x": 0, "y": 0},
        })
        if entry.parent_event_id and str(entry.parent_event_id) in event_index:
            edges.append({
                "id": f"edge-{entry.id}",
                "source": event_index[str(entry.parent_event_id)],
                "target": node_id,
            })

    if trail:
        for i in range(1, len(trail)):
            parent = f"event:{trail[i-1].id}"
            child = f"event:{trail[i].id}"
            if not any(e["source"] == parent and e["target"] == child for e in edges):
                edges.append({"id": f"seq-{trail[i].id}", "source": parent, "target": child})

    findings = (
        db.query(Finding)
        .filter(Finding.engagement_id == engagement_id, Finding.status != "false_positive")
        .all()
    )
    for f in findings:
        node_id = f"finding:{f.id}"
        source = None
        for entry in trail:
            if entry.linked_finding_id and str(entry.linked_finding_id) == str(f.id):
                source = event_index.get(str(entry.id))
                break
        nodes.append({
            "id": node_id,
            "type": "finding",
            "data": {
                "label": f"{f.vuln_type or 'finding'} [{f.severity or 'info'}]",
                "severity": f.severity,
                "description": (f.description or "")[:200],
                "parameter": f.parameter or "",
            },
            "position": {"x": 0, "y": 0},
        })
        if source:
            edges.append({"id": f"link-{f.id}", "source": source, "target": node_id})

    return {"nodes": nodes, "edges": edges}


@router.get("/engagement/{engagement_id}/queue")
def get_approval_queue(
    engagement_id: str, db: Session = Depends(get_db), user: User = Depends(require_auth)
):
    proposed = (
        db.query(ReasoningLog)
        .filter(
            ReasoningLog.engagement_id == engagement_id,
            ReasoningLog.status == "proposed",
        )
        .order_by(ReasoningLog.timestamp.asc())
        .all()
    )
    return [
        {
            "id": str(entry.id),
            "action_type": entry.action_type,
            "target": entry.target,
            "reasoning": entry.reasoning,
            "proposed_action": entry.proposed_action,
            "timestamp": str(entry.timestamp) if entry.timestamp else None,
        }
        for entry in proposed
    ]


@router.get("/engagement/{engagement_id}/jobs", response_model=list[ToolJobResponse])
def get_tool_jobs(
    engagement_id: str, db: Session = Depends(get_db), user: User = Depends(require_auth)
):
    return (
        db.query(ToolJob)
        .filter(ToolJob.engagement_id == engagement_id)
        .order_by(ToolJob.started_at.desc())
        .all()
    )


@router.get("/jobs/{job_id}/output")
def get_job_output(
    job_id: str, db: Session = Depends(get_db), user: User = Depends(require_auth)
):
    job = db.query(ToolJob).filter(ToolJob.id == job_id).first()
    if not job:
        raise HTTPException(404, "Job not found")
    return {
        "id": str(job.id),
        "tool_name": job.tool_name,
        "status": job.status,
        "raw_output": job.raw_output,
        "parameters": job.parameters,
    }


@router.get("/engagement/{engagement_id}/stream")
async def stream_reasoning(
    engagement_id: str, db: Session = Depends(get_db), user: User = Depends(require_auth)
):
    """SSE stream for live telemetry — sends tool_jobs status every 2s for 60s, fallback to polling if SSE fails."""
    async def event_gen():
        # Use fresh session per iteration to avoid stale data
        for _ in range(30):  # 60s total
            # need new session because db is request-scoped and will close
            with SessionLocal() as s:
                jobs = (
                    s.query(ToolJob)
                    .filter(ToolJob.engagement_id == engagement_id)
                    .order_by(ToolJob.started_at.desc())
                    .limit(10)
                    .all()
                )
                trail = (
                    s.query(ReasoningLog)
                    .filter(ReasoningLog.engagement_id == engagement_id)
                    .order_by(ReasoningLog.timestamp.desc())
                    .limit(5)
                    .all()
                )
                payload = {
                    "jobs": [
                        {"id": str(j.id), "tool": j.tool_name, "status": j.status, "started_at": str(j.started_at) if j.started_at else None}
                        for j in jobs
                    ],
                    "trail": [
                        {"id": str(t.id), "action": t.action_type, "status": t.status, "target": t.target}
                        for t in trail
                    ],
                }
            yield f"data: {json.dumps(payload)}\n\n"
            await asyncio.sleep(2)
        yield "data: {\"done\": true}\n\n"

    return StreamingResponse(event_gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
