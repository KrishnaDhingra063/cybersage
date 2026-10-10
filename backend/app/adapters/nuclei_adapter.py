import json
import urllib.parse
from typing import Any, Dict, List
from app.adapters.base import ToolAdapter, ToolResult, NormalizedFinding


class NucleiAdapter(ToolAdapter):
    """
    Adapter for ProjectDiscovery's Nuclei template engine.
    Executes vulnerability and misconfiguration checks via JSONL streaming.
    """
    name = "nuclei"

    def build_command(self, target: str, params: dict) -> list[str]:
        severity = params.get("severity", "low,medium,high,critical")
        templates = params.get("templates", "")
        tags = params.get("tags", "")
        rate_limit = params.get("rate_limit", 150)

        # -jsonl enforces one JSON object per line on stdout
        cmd = [
            "nuclei",
            "-u", target,
            "-jsonl",
            "-severity", str(severity),
            "-rate-limit", str(rate_limit),
            "-silent",
        ]

        if templates:
            cmd.extend(["-t", str(templates)])

        if tags:
            cmd.extend(["-tags", str(tags)])

        return cmd

    def parse(self, raw_output: str) -> ToolResult:
        result = ToolResult(raw_output=raw_output)

        for line in raw_output.strip().splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue

            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = item.get("info", {})
            template_id = item.get("template-id", "unknown")
            template_name = info.get("name", template_id)
            severity = info.get("severity", "info").lower()
            if severity not in ("info", "low", "medium", "high", "critical"):
                severity = "info"

            # 1. Resolve host and port
            matched_at = item.get("matched-at", "")
            raw_host = item.get("host", "")
            ip = item.get("ip", "")

            parsed_url = urllib.parse.urlparse(matched_at if matched_at else raw_host)
            host_name = parsed_url.hostname or ip or raw_host
            
            port = item.get("port")
            if not port:
                port = parsed_url.port or (443 if parsed_url.scheme == "https" else (80 if parsed_url.scheme == "http" else 0))
            else:
                try:
                    port = int(port)
                except (ValueError, TypeError):
                    port = 0

            # Register host and service
            if host_name:
                result.hosts.append({
                    "ip_address": ip or host_name,
                    "hostname": host_name,
                    "matched_at": matched_at,
                })
                result.services.append({
                    "host": host_name,
                    "port": port,
                    "protocol": "tcp",
                    "service_name": parsed_url.scheme or item.get("type", "http"),
                    "version": "",
                })

            # 2. Extract CVSS score safely
            cvss_raw = info.get("classification", {}).get("cvss-score", 0.0)
            try:
                cvss_score = float(cvss_raw) if cvss_raw is not None else 0.0
            except (ValueError, TypeError):
                cvss_score = 0.0

            # 3. Compact evidence payload
            extracted_results = item.get("extracted-results", [])
            curl_cmd = item.get("curl-command", "")
            evidence_parts = [f"Matched: {matched_at}"]
            if extracted_results:
                evidence_parts.append(f"Extracted: {extracted_results}")
            if curl_cmd:
                evidence_parts.append(f"Curl: {curl_cmd[:400]}")
            evidence = " | ".join(evidence_parts)

            result.findings.append(NormalizedFinding(
                host=host_name,
                port=port,
                vuln_type=f"nuclei_{template_id}",
                parameter=parsed_url.path or matched_at,
                severity=severity,
                description=info.get("description") or f"{template_name} ({template_id})",
                evidence=evidence[:1200],
                cvss_score=cvss_score,
                service_name=parsed_url.scheme or "http",
                version="",
            ))

        return result