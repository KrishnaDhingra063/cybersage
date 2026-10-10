import logging
from datetime import datetime, timezone
from app.tasks.celery_app import celery_app
from app.models.database import SessionLocal
from app.models.models import ToolJob, ReasoningLog
from app.adapters import get_adapter
from app.core.scope_gate import is_target_in_scope, ScopeViolation
from app.orchestrator.decision_loop import Orchestrator
import time
from app.core.autonomy_policy import evaluate_execution_policy
from app.models.models import Engagement, ReasoningLog

def process_decision_action(db, engagement_id: str, decision: dict):
    engagement = db.query(Engagement).filter(Engagement.id == engagement_id).first()
    autonomy = engagement.autonomy_level or "human_gated"

    policy_result = evaluate_execution_policy(
        autonomy_level=autonomy,
        tool_name=decision.get("tool"),
        action_type=decision.get("action_type", "scan"),
        risk_level=decision.get("risk_level", "medium"),
    )

    log_entry = ReasoningLog(
        engagement_id=engagement_id,
        tool=decision.get("tool"),
        parameters=decision.get("parameters"),
        status=policy_result["status"],
        requires_approval=policy_result["requires_approval"],
        reasoning=decision.get("reasoning"),
    )
    db.add(log_entry)
    db.commit()

    if policy_result["can_execute"]:
        # Dispatch Celery worker execution
        execute_tool_job.delay(
            engagement_id=engagement_id,
            tool=decision.get("tool"),
            params=decision.get("parameters"),
        )
        return {"status": "executed", "details": policy_result["reason"]}
    
    return {"status": policy_result["status"], "details": policy_result["reason"]}

@celery_app.task(name="tasks.continuous_pentest")
def continuous_pentest(engagement_id: str, max_cycles: int = 20):
    db = SessionLocal()
    try:
        orchestrator = Orchestrator(db)

        for i in range(max_cycles):
            logger.info(f"Engagement {engagement_id}: Running autonomous cycle {i+1}/{max_cycles}")
            result = orchestrator.run_decision_cycle(engagement_id)

            status = result.get("status")
            action_type = result.get("action_type")
            requires_approval = result.get("requires_approval", False)

            # 1. Autonomous Stop Detection triggered
            if status in ("stopped", "completed") or action_type == "stop":
                logger.info(f"Pentest completed safely after {i+1} cycles: {result.get('reasoning')}")
                break

            # 2. Critical error encountered
            if status in ("error", "failed"):
                logger.error(f"Pentest halted due to error on cycle {i+1}: {result.get('message')}")
                break

            # 3. High-Risk Human-in-the-Loop Gate triggered
            if status in ("awaiting_approval", "proposed") or requires_approval:
                logger.info(f"Cycle {i+1} paused: High-risk action gated for Lead approval.")
                break

            # 4. Pace consecutive iterations to let tool jobs register
            time.sleep(3)

        return {"status": "finished", "cycles_run": i + 1}

    except Exception as e:
        logger.exception(f"Continuous pentest failed for {engagement_id}")
        return {"status": "error", "error": str(e)}
    finally:
        db.close()


logger = logging.getLogger(__name__)


@celery_app.task(bind=True, name="tasks.execute_tool_job")
def execute_tool_job(self, job_id: str, engagement_id: str, reasoning_log_id: str):
    db = SessionLocal()
    try:
        job = db.query(ToolJob).filter(ToolJob.id == job_id).first()
        if not job:
            logger.error(f"Job {job_id} not found")
            return

        job.status = "running"
        job.started_at = datetime.now(timezone.utc)
        db.commit()

        target = job.parameters.get("target", "")
        try:
            is_target_in_scope(db, engagement_id, target)
        except ScopeViolation as e:
            job.status = "failed"
            job.raw_output = f"SCOPE VIOLATION: {e}"
            db.commit()
            _update_log(db, reasoning_log_id, "rejected", str(e))
            return

        adapter = get_adapter(job.tool_name)
        tool_result = adapter.run(target, job.parameters)

        job.status = "completed"
        job.raw_output = tool_result.raw_output[:50000]
        job.finished_at = datetime.now(timezone.utc)
        db.commit()

        orchestrator = Orchestrator(db)
        orchestrator._store_tool_results(engagement_id, tool_result)

        _update_log(db, reasoning_log_id, "executed", f"Completed: {job.tool_name}")

        logger.info(f"Job {job_id} completed: {len(tool_result.findings)} findings")

    except Exception as e:
        logger.exception(f"Job {job_id} failed")
        if job:
            job.status = "failed"
            job.raw_output = str(e)
            db.commit()
        _update_log(db, reasoning_log_id, "failed", str(e))
    finally:
        db.close()


@celery_app.task(name="tasks.run_orchestration_cycle")
def run_orchestration_cycle(engagement_id: str):
    db = SessionLocal()
    try:
        orchestrator = Orchestrator(db)
        result = orchestrator.run_decision_cycle(engagement_id)
        logger.info(f"Orchestration cycle result: {result.get('status')}")
        return result
    except Exception as e:
        logger.exception(f"Orchestration cycle failed for {engagement_id}")
        return {"status": "error", "message": str(e)}
    finally:
        db.close()


@celery_app.task(name="tasks.interpret_tool_output")
def interpret_tool_output(engagement_id: str, tool_name: str, raw_output: str):
    db = SessionLocal()
    try:
        orchestrator = Orchestrator(db)
        result = orchestrator.interpret_output(engagement_id, tool_name, raw_output)
        logger.info(f"Interpretation complete: {len(result.get('new_findings', []))} findings")
        return result
    except Exception as e:
        logger.exception(f"Interpretation failed for {engagement_id}")
        return {"error": str(e)}
    finally:
        db.close()


@celery_app.task(name="tasks.continuous_pentest")
def continuous_pentest(engagement_id: str, max_cycles: int = 20):
    db = SessionLocal()
    try:
        orchestrator = Orchestrator(db)

        for i in range(max_cycles):
            result = orchestrator.run_decision_cycle(engagement_id)

            if result.get("status") in ("stopped", "error"):
                logger.info(f"Pentest stopped after {i+1} cycles: {result}")
                break

            if result.get("status") == "awaiting_approval":
                logger.info(f"Waiting for approval on cycle {i+1}")
                break

    except Exception as e:
        logger.exception(f"Continuous pentest failed for {engagement_id}")
    finally:
        db.close()


def _update_log(db, log_id: str, status: str, result_summary: str = ""):
    if not log_id:
        return
    log = db.query(ReasoningLog).filter(ReasoningLog.id == log_id).first()
    if log:
        log.status = status
        log.result_summary = result_summary
        db.commit()
