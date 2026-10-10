import json
import re
import urllib.parse
from typing import List, Dict, Any, Tuple
from app.adapters.base import ToolAdapter, ToolResult, NormalizedFinding


class NiktoAdapter(ToolAdapter):
    """
    Adapter for Nikto web server vulnerability scanner.
    Identifies misconfigurations, outdated software components,
    and sensitive web files.
    """
    name = "nikto"

    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = ["nikto", "-h", target, "-Format", "json", "-output", "-"]

        port = params.get("port")
        if port:
            cmd.extend(["-p", str(port)])

        # Handle explicit SSL requests or HTTPS targets
        is_ssl = params.get("ssl", False) or target.startswith("https://") or port == 443
        if is_ssl:
            cmd.append("-ssl")

        # Tuning options (e.g., 1=Interesting files, 2=Misconfigurations, etc.)
        tuning = params.get("tuning")
        if tuning:
            cmd.extend(["-Tuning", str(tuning)])

        return cmd

    def _map_severity(self, description: str) -> Tuple[str, float]:
        """Infers finding severity and baseline CVSS score from Nikto heuristics."""
        desc_lower = description.lower()
        if any(term in desc_lower for term in ["remote code execution", "rce", "sql injection"]):
            return "critical", 9.0
        if any(term in desc_lower for term in ["vulnerable", "exploit", "unauthenticated", "directory traversal", "file upload"]):
            return "high", 7.5
        if any(term in desc_lower for term in ["outdated", "cross-site scripting", "xss", "leak", "information disclosure"]):
            return "medium", 5.0
        if any(term in desc_lower for term in ["header missing", "x-frame-options", "content-security-policy", "x-content-type-options"]):
            return "low", 3.0
        return "info", 0.0

    def parse(self, raw_output: str) -> ToolResult:
        result = ToolResult(raw_output=raw_output)

        # Locate outer JSON boundaries
        start_idx = raw_output.find("{")
        end_idx = raw_output.rfind("}")
        if start_idx == -1 or end_idx == -1 or end_idx <= start_idx:
            return result

        try:
            data = json.loads(raw_output[start_idx : end_idx + 1])
        except json.JSONDecodeError:
            # Fallback regex search for embedded items structure
            json_match = re.search(r"(\{.*\"items\":.*\})", raw_output, re.DOTALL)
            if not json_match:
                return result
            try:
                data = json.loads(json_match.group(1))
            except json.JSONDecodeError:
                return result

        host = str(data.get("host", ""))
        port = int(data.get("port", 80))
        banner = str(data.get("banner", ""))

        if host:
            result.hosts.append({
                "ip_address": host,
                "hostname": data.get("ip", host),
                "os_guess": "",
            })
            result.services.append({
                "host": host,
                "port": port,
                "protocol": "tcp",
                "service_name": "https" if port == 443 else "http",
                "version": banner,
            })

        items = data.get("items", [])
        for item in items:
            description = item.get("description", "").strip()
            uri = item.get("uri", "")
            method = item.get("method", "GET")
            osvdb_id = item.get("OSVDB", "")

            severity, cvss = self._map_severity(description)

            finding = NormalizedFinding(
                host=host,
                port=port,
                vuln_type="web_misconfiguration",
                parameter=uri,
                severity=severity,
                description=description,
                evidence=f"Method: {method} | URI: {uri} | OSVDB: {osvdb_id}".strip(),
                cvss_score=cvss,
                service_name="http",
                version=banner,
            )
            result.findings.append(finding)

        return result