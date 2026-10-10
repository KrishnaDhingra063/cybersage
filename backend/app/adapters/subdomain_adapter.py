import socket
import logging
from typing import Optional, Callable
from app.adapters.base import ToolAdapter, ToolResult, NormalizedFinding

logger = logging.getLogger(__name__)

COMMON_SUBS = ["www", "api", "admin", "app", "dev", "test", "staging", "beta", "mail", "vpn", "portal", "internal", "manage", "secure", "shop", "blog", "m", "mobile", "cdn", "assets"]

class SubdomainAdapter(ToolAdapter):
    name = "subdomain"

    def build_command(self, target: str, params: dict) -> list[str]:
        return []

    def parse(self, raw_output: str) -> ToolResult:
        return ToolResult(raw_output=raw_output)

    def run(self, target: str, params: dict, scope_check_fn: Optional[Callable[[str], None]] = None) -> ToolResult:
        if scope_check_fn:
            scope_check_fn(target)
        domain = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].strip().lstrip("*.")
        wordlist = params.get("wordlist") or COMMON_SUBS
        if isinstance(wordlist, str):
            wordlist = [w.strip() for w in wordlist.split(",")]
        wordlist = wordlist[:30]  # cap
        raw_lines = [f"[subdomain] Base: {domain}, wordlist: {len(wordlist)}"]
        findings = []
        hosts = []
        found = []
        for sub in wordlist:
            fqdn = f"{sub}.{domain}"
            # scope check per subdomain
            if scope_check_fn:
                try:
                    scope_check_fn(fqdn)
                except Exception:
                    raw_lines.append(f"SKIP {fqdn} (out of scope)")
                    continue
            try:
                ip = socket.gethostbyname(fqdn)
                raw_lines.append(f"FOUND {fqdn} -> {ip}")
                hosts.append({"ip_address": ip, "hostname": fqdn, "os_guess": ""})
                found.append(fqdn)
            except Exception:
                raw_lines.append(f" - {fqdn} no record")
        if found:
            findings.append(NormalizedFinding(
                host=domain, vuln_type="subdomain_takeover_candidate", severity="medium" if len(found) > 3 else "low",
                description=f"Discovered {len(found)} subdomains: {', '.join(found[:5])}",
                evidence="\n".join(raw_lines), parameter=domain, cvss_score=4.0
            ))
        raw_output = "\n".join(raw_lines)
        return ToolResult(raw_output=raw_output, findings=findings, hosts=hosts)
