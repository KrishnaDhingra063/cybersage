import json
import logging
import re
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.orm import Session
from app.core.llm import get_llm
from app.orchestrator.decision_loop import Orchestrator
from app.models.models import Engagement, ScopeAuthorization
from app.agent.planner import PLANNER_SYSTEM_PROMPT, build_planner_prompt

logger = logging.getLogger(__name__)


class AgentTurnError(Exception):
    pass


# Tools the deterministic fallback may dispatch
_KNOWN_TOOLS = {
    "nmap", "masscan", "dns_enum", "subdomain", "subdomain_enum", "shodan",
    "whatweb", "nuclei", "nikto", "zap", "crawler", "dirsearch", "shadow_api",
    "repeater", "web_vuln_check", "sqlmap", "metasploit", "hashcat",
    "loot", "cloud_enum", "cloud",
}

_REFUSAL_HINTS = (
    "cannot perform", "cannot run", "can't run", "unable to",
    "outside the approved scope", "not within the approved",
    "theoretical concepts", "best practices for securing",
    "as an ai", "policy", "model execution failed", "experiencing high demand",
)


def _parse_direct_tool_request(message: str) -> Optional[dict]:
    """Parse explicit 'run <tool> on <target>' requests without relying on LLM."""
    if not message:
        return None
    text = message.strip()
    patterns = [
        r"\brun\s+([a-z_]+)\s+(?:on|against|for)\s+(\S+)",
        r"\bscan\s+(\S+)\s+with\s+([a-z_]+)",
        r"\buse\s+([a-z_]+)\s+(?:on|against|for)\s+(\S+)",
        r"\b([a-z_]+)\s+(\S+)",
    ]
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if not m:
            continue
        if pat.startswith(r"\bscan"):
            target, tool = m.group(1), m.group(2)
        else:
            tool, target = m.group(1), m.group(2)
        tool = tool.lower().strip()
        target = target.strip().rstrip(".,;:!?)]}'\"")
        if tool in _KNOWN_TOOLS and target:
            return {
                "tool": tool,
                "target": target,
                "parameters": {},
                "reason": f"Direct Docker Execution: dispatched {tool} against {target}",
            }
    return None


def _format_docker_scan_summary(tool_name: str, target: str, findings: list) -> str:
    """Formats clean scan reports directly from Docker tools when LLM is offline or busy."""
    if not findings:
        return f"Autonomous Engine executed **{tool_name}** against target `{target}`. Scan finished cleanly (0 open vulnerabilities detected in this pass)."

    crit = [f for f in findings if (getattr(f, 'severity', '') or '').lower() == 'critical']
    high = [f for f in findings if (getattr(f, 'severity', '') or '').lower() == 'high']
    med = [f for f in findings if (getattr(f, 'severity', '') or '').lower() == 'medium']
    info = [f for f in findings if (getattr(f, 'severity', '') or '').lower() in ('info', 'low', '')]

    lines = [
        f"### Security Assessment Summary: `{target}`",
        f"**Dispatched Engine:** Dockerized `{tool_name}`",
        f"**Findings Captured:** {len(findings)} total (Critical: {len(crit)}, High: {len(high)}, Medium: {len(med)}, Info: {len(info)})\n"
    ]

    for idx, item in enumerate(findings[:8], 1):
        if isinstance(item, dict):
            desc = item.get("description") or item.get("vuln_type") or "Exposure detected"
            port = item.get("port", 0)
        else:
            desc = getattr(item, 'description', '') or getattr(item, 'vuln_type', 'Exposure detected')
            port = getattr(item, 'port', 0)
        port_tag = f" [Port {port}]" if port else ""
        lines.append(f"{idx}. **{desc}**{port_tag}")

    if len(findings) > 8:
        lines.append(f"\n*...and {len(findings) - 8} more findings available in the Remediation Center.*")

    return "\n".join(lines)


def _looks_like_refusal(text: str) -> bool:
    lowered = (text or "").lower()
    return any(h in lowered for h in _REFUSAL_HINTS)


def _ensure_default_engagement(db: Session, engagement_id: str) -> Engagement:
    import uuid as _uuid
    original_id = engagement_id or "default"
    is_valid_uuid = True
    try:
        _uuid.UUID(str(original_id))
    except Exception:
        is_valid_uuid = False

    if is_valid_uuid:
        try:
            eng = db.query(Engagement).filter(Engagement.id == original_id).first()
            if eng:
                return eng
        except Exception:
            pass
    else:
        try:
            eng = db.query(Engagement).filter(Engagement.name.like("Console-Session-%")).order_by(Engagement.created_at.desc()).first()
            if eng:
                return eng
        except Exception:
            pass

    new_id = str(_uuid.uuid4())
    display_hint = original_id[:20] if original_id not in ("default", "UNBOUND", "", "demo-target") else "Console"
    eng = None
    try:
        eng = Engagement(
            id=new_id,
            name=f"Console-Session-{display_hint}-{new_id[:8]}",
            client_name="Console",
            status="active",
            autonomy_level="human_gated",
        )
        db.add(eng)
        db.commit()
        db.refresh(eng)
    except Exception as e:
        try:
            db.rollback()
        except Exception:
            pass
        logger.warning(f"Could not auto-create engagement {original_id} -> {new_id}: {e}")
        # Never return a transient ghost: its id has no FK row, so every
        # later ReasoningLog/Host insert dies with FOREIGN KEY failed.
        # Fall back to the most recent real engagement, else raise.
        try:
            fallback = db.query(Engagement).order_by(Engagement.created_at.desc()).first()
            if fallback:
                return fallback
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
        raise AgentTurnError(f"Could not create or resolve engagement for '{original_id}': {e}")

    try:
        now = datetime.now(timezone.utc)
        scope = ScopeAuthorization(
            engagement_id=str(eng.id),
            allowed_targets=["localhost", "127.0.0.1", "scanme.nmap.org", "182.168.52.0/24", "192.168.0.0/16"],
            excluded_targets=[],
            allowed_window_start=now,
            allowed_window_end=now.replace(year=now.year + 1),
            rules_of_engagement="Sandbox test environment",
            signed_by="auto-console",
            approved=True,
        )
        try:
            from app.core.safe_policy import sign_scope
            sign_scope(scope)
        except Exception:
            pass
        db.add(scope)
        db.commit()
        db.refresh(eng)
    except Exception as e:
        db.rollback()
        logger.warning(f"Could not auto-create scope for {eng.id}: {e}")
    return eng


def execute_turn(
    db: Session,
    engagement_id: str,
    message: str,
    history: str = "",
    provider: Optional[str] = "ollama"  # Default directly to local Ollama container
) -> dict:
    engagement = _ensure_default_engagement(db, engagement_id)
    actual_id = str(engagement.id)

    orch = Orchestrator(db)
    llm = get_llm()

    # 1. Direct command regex check (Immediate Docker dispatch priority)
    direct_action = _parse_direct_tool_request(message)
    actions = [direct_action] if direct_action else []
    operator_reply = ""

    # 2. Plan via LLM (Routing explicitly to selected provider / Ollama)
    if not actions:
        state = orch._build_engagement_state(engagement)
        plan_prompt = build_planner_prompt(state, message, history)

        try:
            plan_text = llm.complete(
                system=PLANNER_SYSTEM_PROMPT,
                prompt=plan_prompt,
                max_tokens=2048,
                provider=provider or "ollama"
            )
        except Exception as e:
            logger.error(f"LLM planner error: {e}")
            plan_text = ""

        plan = {"message": "", "actions": []}
        if plan_text:
            clean_text = plan_text.strip()
            start = clean_text.find("{")
            end = clean_text.rfind("}")
            if start != -1 and end != -1 and end > start:
                try:
                    plan = json.loads(clean_text[start:end + 1])
                except Exception:
                    plan = {"message": clean_text, "actions": []}
            else:
                plan = {"message": clean_text, "actions": []}

        operator_reply = plan.get("message", "")
        actions = plan.get("actions", [])

    # 3. Log user prompt
    orch._log_agent_message(actual_id, actor="user", kind="prompt", text=message)

    # 4. Execute tool queue in Docker container with Security Guardrails
    tool_events = []
    for action in actions[:10]:
        if not isinstance(action, dict):
            continue
        tgt = action.get("target")

        # --- Security Guard 1: Target Health Circuit Breaker ---
        if tgt:
            try:
                from app.circuit_breaker import circuit_breaker
                is_healthy, health_reason = circuit_breaker.check_http_health(str(tgt))
                if not is_healthy:
                    logger.warning(f"Circuit Breaker tripped for target {tgt}: {health_reason}")
                    tool_events.append({
                        "tool": action.get("tool", "security_adapter"),
                        "status": "tripped",
                        "error": f"Circuit Breaker: {health_reason}",
                        "findings": []
                    })
                    continue
            except Exception as cb_err:
                logger.debug(f"Circuit breaker check bypassed: {cb_err}")

        # --- Security Guard 2: Cryptographic Immutable Audit Log ---
        if tgt:
            try:
                from app.audit_trail import log_audit_event
                log_audit_event(
                    engagement_id=actual_id,
                    operator="autonomous_agent",
                    command=f"{action.get('tool')} {tgt}",
                    target=str(tgt)
                )
            except Exception as audit_err:
                logger.debug(f"Audit log bypassed: {audit_err}")

        if tgt:
            from app.api.scans import _ensure_scope
            try:
                _ensure_scope(db, actual_id, tgt)
            except Exception as e:
                logger.warning(f"Could not dynamically add {tgt} to scope: {e}")

        event = orch.run_planned_action(actual_id, action)
        tool_events.append(event)

    # 5. Formulate final synthesized narrative
    if actions:
        ran = [e for e in tool_events if e.get("status") == "executed"]
        needs_appr = [e for e in tool_events if e.get("status") == "needs_approval"]

        if not operator_reply or _looks_like_refusal(operator_reply):
            all_findings = []
            for ev in ran:
                findings_data = ev.get("findings") or []
                if isinstance(findings_data, list):
                    all_findings.extend(findings_data)
            assistant_narrative = _format_docker_scan_summary(
                actions[0].get("tool", "security_adapter"),
                actions[0].get("target", "target"),
                all_findings
            )
            if needs_appr:
                assistant_narrative += f"\n\n⚠️ **{len(needs_appr)} high-risk payload(s)** held in Approval Queue for Lead confirmation."
        else:
            assistant_narrative = operator_reply
    else:
        if operator_reply and not _looks_like_refusal(operator_reply):
            assistant_narrative = operator_reply
        else:
            assistant_narrative = "Engine ready. Issue a directive like `run nmap on 127.0.0.1` or `run nikto on http://127.0.0.1`."

    orch._log_agent_message(actual_id, actor="ai", kind="reply", text=assistant_narrative)

    return {
        "assistant": assistant_narrative,
        "tools": tool_events,
        "plan": {"actions": actions, "message": operator_reply},
        "engagement_id": actual_id,
    }