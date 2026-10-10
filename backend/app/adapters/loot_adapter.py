import logging
import re
from typing import Optional, Callable
from app.adapters.base import ToolAdapter, ToolResult, NormalizedFinding

logger = logging.getLogger(__name__)

class LootAdapter(ToolAdapter):
    name = "loot"

    def build_command(self, target: str, params: dict) -> list[str]:
        return []

    def parse(self, raw_output: str) -> ToolResult:
        return ToolResult(raw_output=raw_output)

    def run(self, target: str, params: dict, scope_check_fn: Optional[Callable[[str], None]] = None) -> ToolResult:
        if scope_check_fn:
            scope_check_fn(target)
        # target is evidence dump or file content, params may contain previous raw_output
        raw_input = params.get("raw_output") or params.get("data") or params.get("evidence") or target
        raw_lines = [f"[loot] Analyzing data for secrets ({len(str(raw_input))} chars)"]
        findings = []
        text = str(raw_input)
        # Regexes for common secrets
        patterns = {
            "aws_key": (r"AKIA[0-9A-Z]{16}", "AWS Access Key exposure", "high", 7.5),
            "aws_secret": (r"aws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+=]{20,}", "AWS Secret exposure", "critical", 9.0),
            "private_key": (r"-----BEGIN (RSA )?PRIVATE KEY-----", "Private key exposure", "critical", 9.5),
            "jwt": (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "JWT token exposure", "high", 7.0),
            "password": (r"(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{3,}['\"]", "Hardcoded password", "high", 7.0),
            "api_key": (r"api[_-]?key\s*[:=]\s*['\"][A-Za-z0-9_-]{16,}['\"]", "API key exposure", "high", 7.0),
            "bearer": (r"Bearer\s+[A-Za-z0-9\-_\.]{20,}", "Bearer token exposure", "high", 7.0),
        }
        for name, (pat, desc, sev, cvss) in patterns.items():
            if re.search(pat, text, re.I):
                m = re.search(pat, text, re.I)
                snippet = text[m.start()-20:m.end()+20] if m else ""
                # Enterprise safety feature #7: prove the exposure class without
                # persisting the secret itself — mask values, keep the shape.
                from app.core.safe_policy import redact_secrets
                masked = redact_secrets(snippet[:80])
                raw_lines.append(f"FOUND {name}: {masked} (value redacted, shape kept)")
                findings.append(NormalizedFinding(
                    host=target, vuln_type=name, severity=sev,
                    description=f"{desc} (secret value redacted — rotate this credential)",
                    evidence=redact_secrets(snippet[:500]), parameter=name, cvss_score=cvss
                ))
        if not findings:
            raw_lines.append("No loot patterns matched")
            findings.append(NormalizedFinding(host=target, vuln_type="loot_clean", severity="info", description="No secrets found in analyzed data", evidence="\n".join(raw_lines), parameter=target))
        # Also store as credential-like finding
        raw_output = "\n".join(raw_lines)
        return ToolResult(raw_output=raw_output, findings=findings, hosts=[])
