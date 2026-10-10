import logging
import re
from typing import Optional, Callable
from app.adapters.base import ToolAdapter, ToolResult, NormalizedFinding
import httpx

logger = logging.getLogger(__name__)

class WhatWebAdapter(ToolAdapter):
    name = "whatweb"

    def build_command(self, target: str, params: dict) -> list[str]:
        return []

    def parse(self, raw_output: str) -> ToolResult:
        return ToolResult(raw_output=raw_output)

    def run(self, target: str, params: dict, scope_check_fn: Optional[Callable[[str], None]] = None) -> ToolResult:
        if scope_check_fn:
            scope_check_fn(target)
        url = target if target.startswith("http") else f"http://{target}"
        raw_lines = [f"[whatweb] Target: {url}"]
        findings = []
        try:
            with httpx.Client(timeout=8.0, follow_redirects=True) as client:
                from app.core.safe_policy import scanner_headers
                r = client.get(url, headers=scanner_headers("whatweb"))
                raw_lines.append(f"HTTP {r.status_code} {r.headers.get('content-type','')}")
                headers = {k.lower(): v for k, v in r.headers.items()}
                body = r.text[:8000]
                # Fingerprint via headers
                techs = []
                if "x-powered-by" in headers:
                    techs.append(f"X-Powered-By: {headers['x-powered-by']}")
                    findings.append(NormalizedFinding(host=url, vuln_type="tech_exposure", severity="info", description=f"X-Powered-By reveals {headers['x-powered-by']}", evidence=headers['x-powered-by'], parameter="x-powered-by"))
                if "server" in headers:
                    techs.append(f"Server: {headers['server']}")
                # HTML clues
                clues = [
                    (r"wp-content", "WordPress"),
                    (r"react", "React"),
                    (r"angular", "Angular"),
                    (r"vue", "Vue"),
                    (r"laravel", "Laravel"),
                    (r"django", "Django"),
                    (r"express", "Express"),
                    (r"nginx", "Nginx"),
                    (r"apache", "Apache"),
                ]
                for pat, name in clues:
                    if re.search(pat, body, re.I) or re.search(pat, str(headers), re.I):
                        techs.append(name)
                raw_lines.append(f"Techs: {techs}")
                raw_lines.append(f"Body snippet: {body[:300]}")
                if techs:
                    findings.append(NormalizedFinding(host=url, vuln_type="tech_stack", severity="info", description=f"Stack fingerprint: {', '.join(set(techs))}", evidence="\n".join(raw_lines), parameter=url))
                # Check for missing security headers
                if "content-security-policy" not in headers:
                    findings.append(NormalizedFinding(host=url, vuln_type="missing_csp", severity="low", description="Missing Content-Security-Policy header", evidence="\n".join(raw_lines), parameter=url, cvss_score=2.0))
                if "x-frame-options" not in headers:
                    findings.append(NormalizedFinding(host=url, vuln_type="clickjacking", severity="low", description="Missing X-Frame-Options header", evidence="\n".join(raw_lines), parameter=url, cvss_score=2.5))
        except Exception as e:
            raw_lines.append(f"ERROR: {e}")
            findings.append(NormalizedFinding(host=url, vuln_type="whatweb_error", severity="info", description=str(e), evidence="\n".join(raw_lines), parameter=url))
        return ToolResult(raw_output="\n".join(raw_lines), findings=findings, hosts=[])
