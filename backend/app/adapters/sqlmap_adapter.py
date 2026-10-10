import os
import re
import tempfile
import urllib.parse
from typing import List, Dict, Any
from app.adapters.base import ToolAdapter, ToolResult, NormalizedFinding


class SqlmapAdapter(ToolAdapter):
    """
    Adapter for SQLmap SQL injection detection and database takeover tool.
    Approval-gated under HIGH_RISK_TOOLS policy.
    """
    name = "sqlmap"

    def build_command(self, target: str, params: dict) -> list[str]:
        # Enterprise safety feature #1: detection-only sqlmap. Exfiltration /
        # OS-execution params (--dump, --os-shell, ...) raise ValueError here
        # instead of ever reaching the command line; level/risk are coerced.
        from app.core.safe_policy import validate_sqlmap_params
        params = validate_sqlmap_params(params)
        temp_dir = os.path.join(tempfile.gettempdir(), "sqlmap_audit")
        os.makedirs(temp_dir, exist_ok=True)

        cmd = [
            "sqlmap",
            "-u", target,
            "--batch",
            f"--output-dir={temp_dir}",
            "--level", str(params.get("level", 1)),
            "--risk", str(params.get("risk", 1)),
            "--flush-session",
        ]

        param_to_test = params.get("parameter") or params.get("param")
        if param_to_test:
            cmd.extend(["-p", str(param_to_test)])

        if params.get("forms"):
            cmd.append("--forms")

        if params.get("cookie"):
            cmd.extend(["--cookie", str(params["cookie"])])

        if params.get("data"):
            cmd.extend(["--data", str(params["data"])])

        if params.get("technique"):
            cmd.extend(["--technique", str(params["technique"])])

        if params.get("random_agent"):
            cmd.append("--random-agent")

        if params.get("user_agent"):
            cmd.extend(["--user-agent", str(params["user_agent"])])

        if params.get("dbs"):
            cmd.append("--dbs")

        return cmd

    def parse(self, raw_output: str) -> ToolResult:
        result = ToolResult(raw_output=raw_output)

        # 1. Resolve host and port from URL match in raw output
        target_match = re.search(r"testing connection to the target URL:\s*([^\r\n]+)", raw_output, re.I)
        target_url = target_match.group(1).strip() if target_match else ""

        parsed = urllib.parse.urlparse(target_url) if target_url else None
        host = parsed.hostname if parsed and parsed.hostname else "target"
        port = parsed.port if parsed and parsed.port else (443 if parsed and parsed.scheme == "https" else 80)

        if host != "target":
            result.hosts.append({"ip_address": host, "target": target_url})
            result.services.append({
                "host": host,
                "port": port,
                "protocol": "tcp",
                "service_name": "http",
                "version": "",
            })

        # 2. Extract backend DBMS if fingerprinted
        dbms_match = re.search(r"back-end DBMS:\s*([^\r\n]+)", raw_output, re.IGNORECASE)
        dbms_banner = dbms_match.group(1).strip() if dbms_match else "Unknown DBMS"

        # 3. Detect vulnerable parameters and injection techniques
        vuln_patterns = {
            "boolean_based": r"\(Boolean-based blind\)",
            "error_based": r"\(Error-based\)",
            "time_based": r"\(Time-based blind\)",
            "union_based": r"\(UNION query\)",
            "inline_query": r"\(Inline query\)",
            "stacked_queries": r"\(Stacked queries\)",
        }

        current_param = ""
        found_injections = False

        for line in raw_output.splitlines():
            line_clean = line.strip()
            param_match = re.search(r"Parameter:\s+([^\s\(]+)", line_clean)
            if param_match:
                current_param = param_match.group(1)

            for vuln_type, pattern in vuln_patterns.items():
                if re.search(pattern, line_clean):
                    found_injections = True
                    result.findings.append(NormalizedFinding(
                        host=host,
                        port=port,
                        vuln_type=f"sql_injection_{vuln_type}",
                        parameter=current_param,
                        severity="critical",
                        description=f"Verified SQL Injection ({vuln_type}) on parameter '{current_param}' ({dbms_banner})",
                        evidence=line_clean[:600],
                        cvss_score=9.8,
                        service_name="database",
                        version=dbms_banner,
                    ))

        # 4. Fallback confirmation check
        if not found_injections and ("is vulnerable" in raw_output.lower() or "sqlmap identified the following injection points" in raw_output.lower()):
            result.findings.append(NormalizedFinding(
                host=host,
                port=port,
                vuln_type="sql_injection",
                parameter=current_param or "unspecified",
                severity="critical",
                description=f"Confirmed SQL Injection vulnerability detected ({dbms_banner})",
                evidence=raw_output[-1200:],
                cvss_score=9.8,
                service_name="database",
                version=dbms_banner,
            ))

        # 5. Extract enumerated databases safely
        if "available databases [" in raw_output:
            dbs_block = re.search(r"available databases \[\d+\]:\s*\n((?:\[\*\][^\n]+\n)+)", raw_output)
            if dbs_block:
                discovered_dbs = re.findall(r"\[\*\]\s*([^\r\n]+)", dbs_block.group(1))
                if discovered_dbs:
                    result.findings.append(NormalizedFinding(
                        host=host,
                        port=port,
                        vuln_type="database_enumeration",
                        parameter="dbs",
                        severity="high",
                        description=f"Enumerated databases ({len(discovered_dbs)}): {', '.join(discovered_dbs[:8])}",
                        evidence=", ".join(discovered_dbs),
                        cvss_score=7.5,
                        service_name="database",
                        version=dbms_banner,
                    ))

        return result