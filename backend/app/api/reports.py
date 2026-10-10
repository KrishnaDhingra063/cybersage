from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.security import get_current_user, require_analyst
from app.models.models import Engagement, Finding, FixSuggestion, Host, ReasoningLog, User

# Dual-path DB import support
try:
    from app.database import get_db
except ImportError:
    from app.models.database import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/reports", tags=["reports"])


# =====================================================================
# Request / Response Schemas
# =====================================================================

class ReportRequest(BaseModel):
    engagement_id: str
    report_type: str = "technical"  # executive / technical / both


class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ReportResponse(BaseModel):
    engagement_id: str
    engagement_name: str
    report_type: str
    generated_at: str
    overall_risk_score: float
    risk_level: str
    severity_distribution: SeverityCounts
    findings_count: int
    remediations_available: int
    markdown: str


# =====================================================================
# Compliance Standards Mapping
# =====================================================================

COMPLIANCE_MAP = {
    "reflected_xss": ["PCI-DSS 6.5.7", "ISO27001 A.14.2", "NIST SA-11"],
    "stored_xss": ["PCI-DSS 6.5.7", "ISO27001 A.14.2", "NIST SA-11"],
    "sql_injection": ["PCI-DSS 6.5.1", "ISO27001 A.14.2", "NIST SA-11"],
    "sql_injection_boolean_based": ["PCI-DSS 6.5.1", "ISO27001 A.14.2", "NIST SA-11"],
    "sql_injection_error_based": ["PCI-DSS 6.5.1", "ISO27001 A.14.2", "NIST SA-11"],
    "sql_injection_time_based": ["PCI-DSS 6.5.1", "ISO27001 A.14.2", "NIST SA-11"],
    "open_port": ["PCI-DSS 2.2", "ISO27001 A.13.1"],
    "default_credentials": ["PCI-DSS 8.1.1", "ISO27001 A.9.2"],
    "password_cracked": ["PCI-DSS 8.2", "ISO27001 A.9.4"],
    "directory_listing": ["PCI-DSS 6.5.8", "ISO27001 A.14.2"],
    "ssl_weak_cipher": ["PCI-DSS 4.1", "ISO27001 A.14.1"],
    "exploit_success": ["PCI-DSS 6.5", "ISO27001 A.14.2", "NIST SA-11"],
}


# =====================================================================
# Report Generation Logic
# =====================================================================

def _compute_metrics(findings: List[Finding]) -> tuple[SeverityCounts, float, str]:
    counts = SeverityCounts()
    cvss_scores: List[float] = []

    for f in findings:
        sev = (f.severity or "info").lower()
        if sev == "critical":
            counts.critical += 1
        elif sev == "high":
            counts.high += 1
        elif sev == "medium":
            counts.medium += 1
        elif sev == "low":
            counts.low += 1
        else:
            counts.info += 1

        if f.cvss_score is not None:
            cvss_scores.append(float(f.cvss_score))

    max_cvss = max(cvss_scores) if cvss_scores else 0.0
    avg_cvss = round(sum(cvss_scores) / len(cvss_scores), 2) if cvss_scores else 0.0

    if counts.critical > 0 or max_cvss >= 9.0:
        risk_level = "CRITICAL"
    elif counts.high > 0 or max_cvss >= 7.0:
        risk_level = "HIGH"
    elif counts.medium > 0 or max_cvss >= 4.0:
        risk_level = "MEDIUM"
    elif counts.low > 0:
        risk_level = "LOW"
    else:
        risk_level = "INFORMATIONAL"

    return counts, avg_cvss, risk_level


def _resolve_target_scope(engagement_id: str, db: Session) -> str:
    """Safe scope resolution - engagement has no target_scope column, derive from ScopeAuthorization."""
    try:
        from app.models.models import ScopeAuthorization

        scopes = (
            db.query(ScopeAuthorization)
            .filter(ScopeAuthorization.engagement_id == engagement_id)
            .all()
        )
        if scopes:
            targets = []
            for s in scopes:
                targets.extend(s.allowed_targets or [])
            if targets:
                return ", ".join(targets[:5])
    except Exception:
        pass
    return "N/A"


def _build_markdown(
    engagement: Engagement,
    findings: List[Finding],
    reasoning: List[ReasoningLog],
    hosts: List[Host],
    fixes_map: Dict[Any, FixSuggestion],
    severity_counts: SeverityCounts,
    avg_cvss: float,
    risk_level: str,
    report_type: str,
    db: Session = None,
) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    scope_str = _resolve_target_scope(str(engagement.id), db) if db is not None else "N/A"
    lines = [
        f"# Penetration Test Report — {engagement.name}\n",
        f"**Assessment Date:** {timestamp}",
        f"**Target Scope:** `{scope_str}`",
        f"**Status:** `{engagement.status}`",
        f"**Overall Posture:** **{risk_level}** (Average CVSS: `{avg_cvss}`)",
        "",
    ]

    # --- Executive Summary Section ---
    if report_type in ("executive", "both"):
        lines.extend([
            "## 1. Executive Summary\n",
            f"An autonomous offensive evaluation was executed across **{len(hosts)} target host(s)**. "
            f"The engagement identified a total of **{len(findings)} verified vulnerability finding(s)**.",
            "",
            f"The overall organizational risk posture is evaluated as **{risk_level}**.",
            "",
            "### Vulnerability Severity Breakdown\n",
            "| Severity Level | Total Findings | Action Window |",
            "| :--- | :--- | :--- |",
            f"| **Critical** | {severity_counts.critical} | Remediate within 24 hours |",
            f"| **High** | {severity_counts.high} | Remediate within 7 days |",
            f"| **Medium** | {severity_counts.medium} | Remediate within 30 days |",
            f"| **Low** | {severity_counts.low} | Standard release cycle |",
            f"| **Informational** | {severity_counts.info} | Architectural review |",
            "",
            "### Scope Asset Inventory\n",
        ])
        for host in hosts:
            lines.append(f"- `{host.ip_address or 'Unknown IP'}` ({host.hostname or 'No hostname'}) — Status: `{host.status}`")

        lines.extend([
            "",
            "### Key Remediation Recommendations",
            "1. **Perimeter Virtual Patching**: Deploy immediate edge WAF protections for verified injection routes.",
            "2. **Codebase Remediations**: Apply and merge generated AST-validated patches through the GitHub integration pipeline.",
            "3. **Verification Testing**: Run automated cURL replay commands to verify remediation efficacy.",
            "",
        ])

    # --- Technical Dossier Section ---
    if report_type in ("technical", "both"):
        lines.extend([
            "## 2. Technical Vulnerabilities & Remediation Dossier\n",
        ])

        for idx, f in enumerate(findings, 1):
            vuln_type = f.vuln_type or "Unknown Vulnerability"
            severity = (f.severity or "info").upper()
            cvss = f.cvss_score or "N/A"
            param = f.parameter or "/"
            tool = f.source_tool or "Autonomous Pentest Agent"
            desc = f.description or "No description provided."
            evidence = f.evidence or "No reproduction payload stored."

            compliance = COMPLIANCE_MAP.get(f.vuln_type, [])
            compliance_str = f" | **Compliance:** `{', '.join(compliance)}`" if compliance else ""

            lines.extend([
                f"### Finding #{idx}: {vuln_type} ({severity})",
                f"* **CVSS Score:** `{cvss}`{compliance_str}",
                f"* **Target Parameter / Path:** `{param}`",
                f"* **Detection Tool:** `{tool}`",
                f"* **Status:** `{f.status}`",
                "",
                "#### Description",
                f"{desc}",
                "",
                "#### Proof of Concept Evidence",
                f"```http\n{evidence[:2000]}\n```",
                "",
            ])

            # Attach latest remediation fix if available
            fix = fixes_map.get(f.id)
            if fix:
                waf_engine = fix.waf_engine or "nginx"
                waf_rule = fix.waf_rule or "# No WAF rule generated."
                git_diff = fix.git_diff or "# No git diff available."
                curl_replay = fix.curl_replay or "# No curl replay available."
                pr_link = f"[{fix.pr_url}]({fix.pr_url})" if fix.pr_url else "Not opened yet"

                lines.extend([
                    "#### Verified AI Remediation",
                    f"- **Target File:** `{fix.file_path}`",
                    f"- **Status:** `{fix.status}`",
                    f"- **PR URL:** {pr_link}",
                    "",
                    "##### Git Unified Diff",
                    f"```diff\n{git_diff}\n```",
                    "",
                    "##### Exploit Reproduction Command",
                    f"```bash\n{curl_replay}\n```",
                    "",
                    f"##### Perimeter WAF Rule ({waf_engine})",
                    f"```{waf_engine}\n{waf_rule}\n```",
                    "",
                ])
            else:
                lines.extend(["*No AI remediation generated for this finding.*", ""])

            lines.append("---\n")

    return "\n".join(lines)


def _generate_report_payload(
    db: Session, engagement_id: str, report_type: str
) -> ReportResponse:
    engagement = db.query(Engagement).filter(Engagement.id == engagement_id).first()
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")

    findings = db.query(Finding).filter(Finding.engagement_id == engagement_id).all()
    reasoning = db.query(ReasoningLog).filter(ReasoningLog.engagement_id == engagement_id).all()
    hosts = db.query(Host).filter(Host.engagement_id == engagement_id).all()

    fixes = db.query(FixSuggestion).filter(FixSuggestion.engagement_id == engagement_id).all()
    fixes_map = {f.finding_id: f for f in fixes}

    severity_counts, avg_cvss, risk_level = _compute_metrics(findings)
    markdown = _build_markdown(
        engagement, findings, reasoning, hosts, fixes_map, severity_counts, avg_cvss, risk_level, report_type, db
    )

    return ReportResponse(
        engagement_id=str(engagement.id),
        engagement_name=engagement.name,
        report_type=report_type,
        generated_at=datetime.now(timezone.utc).isoformat(),
        overall_risk_score=avg_cvss,
        risk_level=risk_level,
        severity_distribution=severity_counts,
        findings_count=len(findings),
        remediations_available=len(fixes),
        markdown=markdown,
    )


@router.post("/generate", response_model=ReportResponse)
def generate_report(
    req: ReportRequest, db: Session = Depends(get_db), user: User = Depends(require_analyst)
):
    if req.report_type not in ("executive", "technical", "both"):
        raise HTTPException(status_code=400, detail="Invalid report_type")
    return _generate_report_payload(db, req.engagement_id, req.report_type)


@router.get("/engagement/{engagement_id}/preview", response_model=ReportResponse)
def preview_report(
    engagement_id: str,
    report_type: str = "technical",
    db: Session = Depends(get_db),
    user: User = Depends(require_analyst),
):
    if report_type not in ("executive", "technical", "both"):
        report_type = "technical"
    return _generate_report_payload(db, engagement_id, report_type)


@router.get("/engagement/{engagement_id}/pdf")
def download_pdf(
    engagement_id: str,
    report_type: str = "technical",
    db: Session = Depends(get_db),
    user: User = Depends(require_analyst),
):
    """Generate PDF via weasyprint from markdown. Falls back to HTML if weasyprint not available."""
    payload = _generate_report_payload(db, engagement_id, report_type)
    # Convert markdown to simple HTML
    try:
        import markdown as md_lib

        html_body = md_lib.markdown(payload.markdown, extensions=["fenced_code", "tables"])
    except Exception:
        html_body = f"<pre>{payload.markdown}</pre>"

    html = f"""<!doctype html><html><head><meta charset="utf-8"><style>
    body{{font-family:Inter,system-ui,sans-serif;padding:40px;color:#0f172a;}}
    h1{{color:#0e7490;border-bottom:2px solid #06b6d4;padding-bottom:8px;}}
    h2{{color:#334155;margin-top:24px;}} pre{{background:#f1f5f9;padding:12px;border-radius:8px;overflow:auto;}}
    code{{font-family:ui-monospace,monospace;font-size:12px;}}
    </style></head><body>{html_body}<hr><p style="font-size:10px;color:#64748b">Generated {payload.generated_at} · {payload.risk_level} · {payload.findings_count} findings</p></body></html>"""

    try:
        from weasyprint import HTML
        import io

        pdf_bytes = HTML(string=html).write_pdf()
        from fastapi.responses import StreamingResponse

        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=report-{engagement_id}-{report_type}.pdf"},
        )
    except Exception as e:
        # Fallback to HTML if weasyprint fails (e.g., missing cairo)
        from fastapi.responses import HTMLResponse

        return HTMLResponse(content=html, headers={"Content-Disposition": f"inline; filename=report-{engagement_id}.html"})