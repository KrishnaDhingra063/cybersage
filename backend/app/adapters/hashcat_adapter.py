import os
import re
import tempfile
from typing import Dict, List, Any
from app.adapters.base import ToolAdapter, ToolResult, NormalizedFinding


class HashcatAdapter(ToolAdapter):
    """
    Adapter for password hash auditing and strength verification.
    Approval-gated under HIGH_RISK_TOOLS policy.
    """
    name = "hashcat"

    # Standard Hashcat mode mappings (-m)
    HASH_MODES: Dict[str, int] = {
        "md5": 0,
        "sha1": 100,
        "ntlm": 1000,
        "sha256": 1400,
        "sha512": 1700,
        "sha512crypt": 1800,
        "bcrypt": 3200,
        "sha256crypt": 7400,
    }

    def build_command(self, target: str, params: dict) -> list[str]:
        """
        Builds tokenized CLI parameters.
        `target` can be the target hash file or passed via params.
        """
        temp_dir = tempfile.gettempdir()
        default_potfile = os.path.join(temp_dir, "pentestai_hashcat.pot")

        hash_file = target or params.get("hash_file", "")
        hash_type = str(params.get("hash_type", "md5")).lower().strip()
        attack_mode = str(params.get("attack_mode", "0"))
        wordlist = params.get("wordlist", "")
        rules = params.get("rules", "")

        hash_mode = self.HASH_MODES.get(hash_type, 0)

        cmd = [
            "hashcat",
            "-m", str(hash_mode),
            "-a", attack_mode,
            "--status",
            "--status-timer=5",
            f"--potfile-path={default_potfile}",
        ]

        if rules:
            cmd.extend(["-r", str(rules)])

        if hash_file:
            cmd.append(str(hash_file))

        if wordlist:
            cmd.append(str(wordlist))

        return cmd

    def parse(self, raw_output: str) -> ToolResult:
        result = ToolResult(raw_output=raw_output)

        # 1. Match cracked credentials (standard Hashcat format: hash:plain)
        cracked_matches = re.findall(r"^([a-fA-F0-9\$\.\/]{16,}):(.+)$", raw_output, re.MULTILINE)
        for hash_val, plaintext in cracked_matches:
            result.findings.append(
                NormalizedFinding(
                    host="credential_audit",
                    port=0,
                    vuln_type="weak_password_hash",
                    parameter=f"{hash_val[:12]}...",
                    severity="high",
                    description="Identified weak password hash meeting dictionary criteria.",
                    evidence=f"Hash: {hash_val[:12]}... (Plaintext redacted for compliance audit)",
                    cvss_score=7.5,
                    service_name="auth",
                    version="",
                )
            )

        # 2. Extract execution completion / exhaustion status
        status_match = re.search(r"Status\s*:\s*([^\r\n]+)", raw_output)
        if status_match:
            status_text = status_match.group(1).strip()
            if "Cracked" in status_text:
                result.findings.append(
                    NormalizedFinding(
                        host="credential_audit",
                        port=0,
                        vuln_type="hashcat_status",
                        parameter="audit_complete",
                        severity="info",
                        description=f"Hashcat audit completed with status: {status_text}",
                        evidence=status_text,
                        cvss_score=0.0,
                        service_name="auth",
                    )
                )

        return result