import socket
import logging
from typing import Optional, Callable
from app.adapters.base import ToolAdapter, ToolResult, NormalizedFinding

logger = logging.getLogger(__name__)

TOP_PORTS = [21,22,23,25,53,80,110,111,139,443,445,3306,3389,5432,6379,8080,8443,27017,9200]

class MasscanAdapter(ToolAdapter):
    name = "masscan"

    def build_command(self, target: str, params: dict) -> list[str]:
        return []

    def parse(self, raw_output: str) -> ToolResult:
        return ToolResult(raw_output=raw_output)

    def run(self, target: str, params: dict, scope_check_fn: Optional[Callable[[str], None]] = None) -> ToolResult:
        if scope_check_fn:
            scope_check_fn(target)
        host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        ports = params.get("ports") or TOP_PORTS
        if isinstance(ports, str):
            ports = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()]
        ports = ports[:30]
        # Enterprise safety feature #4: packet-rate ceiling (MASSCAN_MAX_RATE).
        from app.core.safe_policy import clamp_masscan_rate
        rate = clamp_masscan_rate(params.get("rate", 1000))
        raw_lines = [f"[masscan] Fast scan {host} ports {ports} rate {rate}"]
        findings = []
        hosts = []
        open_ports = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.6)
                res = sock.connect_ex((host, int(port)))
                sock.close()
                if res == 0:
                    raw_lines.append(f"OPEN {host}:{port}")
                    open_ports.append(port)
                    findings.append(NormalizedFinding(
                        host=host, port=int(port), vuln_type="open_port", severity="low",
                        description=f"Masscan fast probe found open port {port} on {host}",
                        evidence=f"masscan {host} -p{port} open", parameter=str(port), cvss_score=2.5
                    ))
                else:
                    raw_lines.append(f"closed {port}")
            except Exception as e:
                raw_lines.append(f"err {port}: {e}")
        if open_ports:
            raw_lines.append(f"Masscan summary: {len(open_ports)} open")
            # One host row per IP — never one per port (hosts has UNIQUE(engagement_id, ip_address))
            hosts.append({"ip_address": host, "hostname": host, "os_guess": ""})
        else:
            raw_lines.append("No open ports in fast scan (try nmap deep)")
        return ToolResult(raw_output="\n".join(raw_lines), findings=findings, hosts=hosts)
