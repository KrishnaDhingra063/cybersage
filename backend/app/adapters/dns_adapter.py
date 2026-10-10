import socket
import logging
from typing import Optional, Callable
from app.adapters.base import ToolAdapter, ToolResult, NormalizedFinding

logger = logging.getLogger(__name__)

class DnsAdapter(ToolAdapter):
    name = "dns_enum"

    def build_command(self, target: str, params: dict) -> list[str]:
        # Pure Python, no binary — return empty to indicate native execution
        return []

    def parse(self, raw_output: str) -> ToolResult:
        # Not used — run overrides
        return ToolResult(raw_output=raw_output)

    def run(self, target: str, params: dict, scope_check_fn: Optional[Callable[[str], None]] = None) -> ToolResult:
        if scope_check_fn:
            scope_check_fn(target)
        # Strip URL to hostname
        host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].strip()
        raw_lines = [f"[dns_enum] Target: {host}"]
        findings = []
        hosts = []
        try:
            # A record
            try:
                ip = socket.gethostbyname(host)
                raw_lines.append(f"A {host} -> {ip}")
                hosts.append({"ip_address": ip, "hostname": host, "os_guess": ""})
            except Exception as e:
                raw_lines.append(f"A lookup failed: {e}")
            # getaddrinfo for all
            try:
                infos = socket.getaddrinfo(host, None)
                ips = list({info[4][0] for info in infos})
                raw_lines.append(f"ADDR {ips}")
            except Exception as e:
                raw_lines.append(f"getaddrinfo failed: {e}")
            # Reverse DNS
            try:
                rev = socket.gethostbyaddr(ip)[0] if 'ip' in locals() else ""
                if rev:
                    raw_lines.append(f"PTR {ip} -> {rev}")
            except Exception:
                pass
            # Simple zone transfer attempt note
            raw_lines.append("NS/MX/TXT enumeration requires dnspython; using socket fallback")
            # If host looks like internal, flag
            if host.endswith(".local") or host.startswith("10.") or host.startswith("192.168."):
                findings.append(NormalizedFinding(
                    host=host, vuln_type="internal_host_exposure", severity="low",
                    description=f"Internal hostname {host} enumerated via DNS",
                    evidence="\n".join(raw_lines), parameter=host, cvss_score=2.0
                ))
        except Exception as exc:
            raw_lines.append(f"ERROR: {exc}")
            logger.warning(f"dns_enum error for {target}: {exc}")

        raw_output = "\n".join(raw_lines)
        return ToolResult(raw_output=raw_output, findings=findings, hosts=hosts)
