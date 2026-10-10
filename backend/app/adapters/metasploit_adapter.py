import logging
import time
from typing import Dict, Any, List, Optional
from app.adapters.base import ToolAdapter, ToolResult, NormalizedFinding

logger = logging.getLogger(__name__)

try:
    from pymetasploit3.msfrpc import MsfRpcClient
except ImportError:
    MsfRpcClient = None


class MetasploitAdapter(ToolAdapter):
    """
    Adapter for interfacing with Metasploit RPC (MSFRPC) to perform
    non-destructive vulnerability verification checks.
    Approval-gated under HIGH_RISK_TOOLS policy.
    """
    name = "metasploit"

    def __init__(self, rpc_host: Optional[str] = None, rpc_port: Optional[int] = None,
                 password: Optional[str] = None, username: Optional[str] = None,
                 ssl: Optional[bool] = None):
        # Connection comes from explicit args -> per-scan params -> env.
        # Env (backend/.env): MSF_RPC_HOST, MSF_RPC_PORT, MSF_RPC_USER,
        # MSF_RPC_PASS, MSF_RPC_SSL. Defaults preserve old localhost behavior.
        import os
        self.rpc_host = rpc_host or os.getenv("MSF_RPC_HOST", "127.0.0.1")
        self.rpc_port = int(rpc_port or os.getenv("MSF_RPC_PORT", "55553"))
        self.username = username or os.getenv("MSF_RPC_USER", "msf")
        self.password = password if password is not None else os.getenv("MSF_RPC_PASS", "")
        if ssl is None:
            self.use_ssl = os.getenv("MSF_RPC_SSL", "true").lower() not in ("0", "false", "no")
        else:
            self.use_ssl = bool(ssl)

    def build_command(self, target: str, params: dict) -> list[str]:
        # Represents the symbolic operation for execution logging and auditing
        module = params.get("module", "auxiliary/scanner/portscan/tcp")
        return ["msfrpc", f"--server={self.rpc_host}:{self.rpc_port}", f"--module={module}", f"--target={target}"]

    def run(self, target: str, params: dict, scope_check_fn: Optional[Any] = None) -> ToolResult:
        if scope_check_fn:
            scope_check_fn(target)

        if MsfRpcClient is None:
            return ToolResult(
                raw_output="ERROR: pymetasploit3 library is not installed.",
                exit_code=1
            )

        module_type = params.get("module_type", "auxiliary")  # 'auxiliary' or 'exploit'
        module_name = params.get("module", "")
        options = params.get("options", {})

        if not module_name:
            return ToolResult(raw_output="ERROR: No Metasploit module specified.", exit_code=1)

        # Per-scan overrides (chat/API) win over adapter/env defaults.
        rpc_host = params.get("rpc_host", self.rpc_host)
        rpc_port = int(params.get("rpc_port", self.rpc_port))
        rpc_user = params.get("rpc_user", self.username)
        rpc_pass = params.get("rpc_pass", self.password)
        rpc_ssl = params.get("rpc_ssl", self.use_ssl)

        try:
            client = MsfRpcClient(rpc_pass, username=rpc_user, server=rpc_host, port=rpc_port, ssl=rpc_ssl)
        except Exception as conn_err:
            logger.error(f"Failed to connect to MSFRPC daemon: {conn_err}")
            return ToolResult(raw_output=f"ERROR: MSFRPC connection failure: {str(conn_err)}", exit_code=1)

        try:
            # Instantiate the requested module
            mod = client.modules.use(module_type, module_name)
            mod["RHOSTS"] = target

            for key, val in options.items():
                if key in mod.options:
                    mod[key] = val

            # Perform verification check rather than executing weaponized payloads
            if module_type == "exploit" and hasattr(mod, "check"):
                check_result = mod.check()
                raw_log = f"Module: {module_name}\nTarget: {target}\nCheck Result: {check_result}"
                
                # Check status typically returns strings like: 'The target is vulnerable.', 'The target is not vulnerable.'
                is_vuln = "vulnerable" in str(check_result).lower() and "not vulnerable" not in str(check_result).lower()
                severity = "critical" if is_vuln else "info"

                finding = NormalizedFinding(
                    host=target,
                    port=int(options.get("RPORT", 0)),
                    vuln_type="verified_cve_check",
                    parameter=module_name,
                    severity=severity,
                    description=f"Metasploit vulnerability check report: {check_result}",
                    evidence=raw_log,
                    cvss_score=8.5 if is_vuln else 0.0,
                    service_name="msf_check",
                )
                return ToolResult(raw_output=raw_log, findings=[finding], exit_code=0)

            elif module_type == "auxiliary":
                # Execute auxiliary reconnaissance/scanner modules
                execution_job = mod.execute()
                raw_log = f"Auxiliary Module Started: {module_name}\nJob ID: {execution_job.get('job_id')}"
                
                return ToolResult(
                    raw_output=raw_log,
                    findings=[NormalizedFinding(
                        host=target,
                        port=int(options.get("RPORT", 0)),
                        vuln_type="auxiliary_scanner_run",
                        parameter=module_name,
                        severity="info",
                        description=f"Metasploit auxiliary scanner '{module_name}' dispatched.",
                        evidence=raw_log,
                        cvss_score=0.0,
                        service_name="msf_auxiliary",
                    )],
                    exit_code=0
                )
            else:
                return ToolResult(
                    raw_output=f"Module '{module_name}' does not support non-destructive check evaluation.",
                    exit_code=1
                )

        except Exception as exec_err:
            logger.exception(f"Error executing Metasploit module '{module_name}'")
            return ToolResult(raw_output=f"EXECUTION_ERROR: {str(exec_err)}", exit_code=-1)

    def parse(self, raw_output: str) -> ToolResult:
        return ToolResult(raw_output=raw_output)