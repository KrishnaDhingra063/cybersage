import json
import logging
from typing import Dict, Any, List
from sqlalchemy.orm import Session

from app.models.models import (
    Engagement,
    ScopeAuthorization,
    Host,
    Service,
    Finding,
    Credential,
    ReasoningLog,
)
from app.orchestrator.prompts import ENGAGEMENT_STATE_PROMPT

logger = logging.getLogger(__name__)


class StateAssessmentEngine:
    def __init__(self, db: Session):
        self.db = db

    def get_structured_state(self, engagement_id: str) -> Dict[str, Any]:
        """
        Gathers live relational data and returns a structured dictionary
        representing the attack surface graph.
        """
        engagement = self.db.query(Engagement).filter(Engagement.id == engagement_id).first()
        if not engagement:
            raise ValueError(f"Engagement '{engagement_id}' not found.")

        auth = self.db.query(ScopeAuthorization).filter(
            ScopeAuthorization.engagement_id == engagement_id,
            ScopeAuthorization.approved == True,
        ).first()

        hosts = self.db.query(Host).filter(Host.engagement_id == engagement_id).all()
        services = self.db.query(Service).join(Host).filter(Host.engagement_id == engagement_id).all()
        findings = self.db.query(Finding).filter(
            Finding.engagement_id == engagement_id, Finding.status == "open"
        ).all()
        creds = self.db.query(Credential).filter(Credential.engagement_id == engagement_id).all()
        trail = (
            self.db.query(ReasoningLog)
            .filter(ReasoningLog.engagement_id == engagement_id)
            .order_by(ReasoningLog.timestamp.desc())
            .limit(6)
            .all()
        )

        return {
            "engagement_name": engagement.name,
            "test_type": engagement.test_type or "standard",
            "autonomy_level": engagement.autonomy_level or "human_gated",
            "allowed_targets": auth.allowed_targets if auth else ["localhost"],
            "excluded_targets": auth.excluded_targets if auth else [],
            "rules_of_engagement": auth.rules_of_engagement if auth else "Sandbox Policy",
            "hosts": [
                {"ip": h.ip_address, "hostname": h.hostname or "unknown", "os": h.os_guess or "unknown"}
                for h in hosts
            ],
            "services": [
                {"port": s.port, "protocol": s.protocol, "service": s.service_name or "unknown"}
                for s in services
            ],
            "findings": [
                {"severity": f.severity, "vuln_type": f.vuln_type, "target": f.parameter or "endpoint"}
                for f in findings
            ],
            "credentials": [
                {"username": c.username, "type": c.credential_type or "plaintext"}
                for c in creds
            ],
            "recent_actions": [
                {"status": r.status, "action": r.action_type, "summary": (r.reasoning or "")[:80]}
                for r in reversed(trail)
            ],
        }

    def format_prompt(self, engagement_id: str) -> str:
        """
        Compresses the structured state into the system prompt template
        ready for immediate LLM inference.
        """
        state = self.get_structured_state(engagement_id)

        hosts_summary = (
            "\n".join(f"  - {h['ip']} ({h['hostname']}) [OS: {h['os']}]" for h in state["hosts"])
            or "  None discovered yet"
        )
        services_summary = (
            "\n".join(f"  - Port {s['port']}/{s['protocol']} ({s['service']})" for s in state["services"])
            or "  None mapped yet"
        )
        findings_summary = (
            "\n".join(f"  - [{f['severity']}] {f['vuln_type']} on {f['target']}" for f in state["findings"])
            or "  No confirmed vulnerabilities yet"
        )
        creds_summary = (
            "\n".join(f"  - User '{c['username']}' ({c['type']})" for c in state["credentials"])
            or "  No credentials dumped"
        )
        trail_summary = (
            "\n".join(f"  - [{a['status']}] {a['action']}: {a['summary']}" for a in state["recent_actions"])
            or "  Fresh execution - no prior actions"
        )

        return ENGAGEMENT_STATE_PROMPT.format(
            engagement_name=state["engagement_name"],
            allowed_targets=state["allowed_targets"],
            excluded_targets=state["excluded_targets"],
            rules_of_engagement=state["rules_of_engagement"],
            test_type=state["test_type"],
            autonomy_level=state["autonomy_level"],
            host_count=len(state["hosts"]),
            hosts_summary=hosts_summary,
            service_count=len(state["services"]),
            services_summary=services_summary,
            finding_count=len(state["findings"]),
            findings_summary=findings_summary,
            cred_count=len(state["credentials"]),
            creds_summary=creds_summary,
            trail_count=len(state["recent_actions"]),
            trail_summary=trail_summary,
        )