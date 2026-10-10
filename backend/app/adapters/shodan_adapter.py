import logging
import os
from typing import Optional, Callable
from app.adapters.base import ToolAdapter, ToolResult, NormalizedFinding
import httpx

logger = logging.getLogger(__name__)

class ShodanAdapter(ToolAdapter):
    name = "shodan"

    def build_command(self, target: str, params: dict) -> list[str]:
        return []

    def parse(self, raw_output: str) -> ToolResult:
        return ToolResult(raw_output=raw_output)

    def run(self, target: str, params: dict, scope_check_fn: Optional[Callable[[str], None]] = None) -> ToolResult:
        if scope_check_fn:
            scope_check_fn(target)
        host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        api_key = os.getenv("SHODAN_API_KEY") or params.get("api_key", "")
        raw_lines = [f"[shodan] Target: {host}"]
        findings = []
        hosts = []
        if not api_key:
            raw_lines.append("No SHODAN_API_KEY set — returning simulated Shodan enrichment (safe fallback)")
            # Simulate: if host looks like public IP, flag
            findings.append(NormalizedFinding(
                host=host, vuln_type="shodan_exposure", severity="info",
                description=f"Shodan enrichment simulated for {host}. Configure SHODAN_API_KEY for live data.",
                evidence="\n".join(raw_lines), parameter=host, cvss_score=0.0
            ))
            return ToolResult(raw_output="\n".join(raw_lines), findings=findings, hosts=hosts)
        try:
            # Real Shodan host lookup
            url = f"https://api.shodan.io/shodan/host/{host}?key={api_key}"
            with httpx.Client(timeout=10.0) as client:
                r = client.get(url)
                raw_lines.append(f"HTTP {r.status_code}")
                if r.status_code == 200:
                    data = r.json()
                    ports = data.get("ports", [])
                    raw_lines.append(f"Ports: {ports}")
                    raw_lines.append(f"OS: {data.get('os','')}")
                    for p in ports[:10]:
                        hosts.append({"ip_address": host, "hostname": host, "os_guess": data.get("os","")})
                        findings.append(NormalizedFinding(
                            host=host, port=int(p) if str(p).isdigit() else 0, vuln_type="open_port", severity="info",
                            description=f"Shodan reports open port {p} on {host}", evidence=str(data)[:1000], parameter=str(p), cvss_score=0.0
                        ))
                else:
                    raw_lines.append(r.text[:500])
                    findings.append(NormalizedFinding(host=host, vuln_type="shodan_lookup_failed", severity="info", description=f"Shodan lookup failed: {r.text[:200]}", evidence="\n".join(raw_lines), parameter=host))
        except Exception as e:
            raw_lines.append(f"ERROR: {e}")
            findings.append(NormalizedFinding(host=host, vuln_type="shodan_error", severity="info", description=str(e), evidence="\n".join(raw_lines), parameter=host))
        return ToolResult(raw_output="\n".join(raw_lines), findings=findings, hosts=hosts)
