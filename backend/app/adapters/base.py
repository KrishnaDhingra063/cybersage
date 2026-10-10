import os
import shutil
import subprocess
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Callable, Optional, Tuple, List
from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


def execute_in_docker_sandbox(
    command: List[str],
    image_name: str = "kali-tools",
    timeout: int = 120,
    memory_limit: str = "512m",
    cpu_limit: str = "1.0"
) -> Tuple[str, int]:
    """
    Spins up an ephemeral, resource-bounded, unprivileged Docker container to run the tool.
    Automatically destroys the container upon completion or failure.

    Enterprise hardening (features #2 + #9, toggles in core/config.py):
      * --cap-drop=ALL + no-new-privileges — no escape primitives, no setuid
        escalation. Raw-socket scans (SYN stealth) are intentionally
        unavailable; connect scans (-sT, the adapter default) are unaffected.
      * --pids-limit — fork-bomb containment (DOCKER_PIDS_LIMIT).
      * --read-only + /tmp tmpfs — immutable filesystem; only /tmp writable.
      * --user 65534 (nobody) + HOME=/tmp — rootless execution (DOCKER_ROOTLESS).
    """
    hardened = getattr(settings, "DOCKER_HARDENED", True)
    rootless = getattr(settings, "DOCKER_ROOTLESS", True)
    try:
        pids_limit = int(getattr(settings, "DOCKER_PIDS_LIMIT", 256) or 256)
    except (TypeError, ValueError):
        pids_limit = 256
    docker_cmd = [
        "docker", "run",
        "--rm",                             # Destroy container immediately on exit (Ephemeral)
        "--security-opt=no-new-privileges", # Blocks root privilege escalation
        "--cap-drop=ALL",                   # Strips all dangerous Linux kernel capabilities
        f"--memory={memory_limit}",         # Hard memory ceiling to protect 8 GB RAM host
        f"--cpus={cpu_limit}",              # Limit CPU utilization to prevent system lag
        "--network=host",                   # Shares network stack to reach localhost/targets
    ]
    if hardened:
        docker_cmd += [
            f"--pids-limit={pids_limit}",    # Fork-bomb containment
            "--read-only",                    # Immutable filesystem ...
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=256m",  # ... except /tmp
        ]
    if rootless:
        docker_cmd += ["--user", "65534:65534", "-e", "HOME=/tmp", "-e", "TMPDIR=/tmp"]
    docker_cmd += [image_name] + command

    try:
        logger.info(f"Launching ephemeral container: {' '.join(docker_cmd[:8])} [...]")
        run_env = None
        try:
            _dh = (getattr(settings, "DOCKER_HOST", "") or "").strip()
            if _dh:
                run_env = dict(os.environ)
                run_env["DOCKER_HOST"] = _dh
        except Exception:
            run_env = None
            
        result = subprocess.run(
            docker_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            env=run_env,
        )
        output = (result.stdout or "") + (result.stderr or "")
        return output, result.returncode

    except subprocess.TimeoutExpired:
        logger.error(f"Docker container timed out after {timeout}s.")
        return f"TIMEOUT: Dockerized execution exceeded {timeout}s limit.", -1
    except FileNotFoundError:
        return "ERROR: Docker daemon executable not found on system PATH.", 127
    except Exception as exc:
        return f"DOCKER_EXECUTION_ERROR: {str(exc)}", -1


@dataclass
class NormalizedFinding:
    host: str = ""
    port: int = 0
    vuln_type: str = ""
    parameter: str = ""
    severity: str = "info"
    description: str = ""
    evidence: str = ""
    cvss_score: float = 0.0
    service_name: str = ""
    version: str = ""


@dataclass
class ToolResult:
    raw_output: str = ""
    findings: list[NormalizedFinding] = field(default_factory=list)
    hosts: list = field(default_factory=list)
    services: list = field(default_factory=list)
    exit_code: int = 0


class ToolAdapter(ABC):
    name: str = "base"

    @abstractmethod
    def build_command(self, target: str, params: dict) -> list[str]:
        """Constructs the command as an argument list (tokenized, no shell=True)."""
        ...

    @abstractmethod
    def parse(self, raw_output: str) -> ToolResult:
        """Parses raw tool output into normalized findings and host/service records."""
        ...

    def run(self, target: str, params: dict, scope_check_fn: Optional[Callable[[str], None]] = None) -> ToolResult:
        """
        Main entrypoint: validates scope, constructs commands, 
        and dispatches via native or containerized engine.
        """
        # 1. Deterministic Pre-Execution Scope Verification
        if scope_check_fn:
            scope_check_fn(target)

        # 2. Build structured command array
        command = self.build_command(target, params)

        # 3. Environment Check: Zero-Docker Native vs Containerized
        use_docker = getattr(settings, "USE_DOCKER", False)
        if use_docker:
            raw_output, exit_code = self._execute_docker(command)
        else:
            raw_output, exit_code = self._execute_local(command)

        # 4. Ingest and normalize output
        result = self.parse(raw_output)
        result.exit_code = exit_code
        return result

    def _resolve_binary(self, binary_name: str) -> Optional[str]:
        """
        Resolves executable paths across Windows and Linux environments,
        including scripts with .bat, .cmd, .exe, or .py extensions and
        common tool installation directories on Windows.
        """
        # 1. Standard environment PATH check
        resolved = shutil.which(binary_name)
        if resolved:
            return resolved

        # 2. Windows-specific extension checks
        if os.name == "nt":
            for ext in [".exe", ".bat", ".cmd", ".py"]:
                candidate = shutil.which(f"{binary_name}{ext}")
                if candidate:
                    return candidate

            # Fallback search for default tool installation paths on Windows
            windows_known_directories = [
                r"C:\Program Files (x86)\Nmap",
                r"C:\Program Files\Nmap",
                r"C:\Program Files\Wireshark",
                r"C:\Tools",
                r"C:\ProgramData\chocolatey\bin",
            ]
            for folder in windows_known_directories:
                for ext in ["", ".exe", ".bat", ".cmd"]:
                    full_target = os.path.join(folder, f"{binary_name}{ext}")
                    if os.path.exists(full_target):
                        return full_target

        # 3. Direct local file check
        if os.path.exists(binary_name):
            return binary_name

        return None

    def _execute_local(self, command: List[str]) -> Tuple[str, int]:
        """Executes binary natively on the host system without shell=True."""
        if not command:
            return "ERROR: Empty command list generated.", -1

        raw_binary = command[0]
        resolved_binary = self._resolve_binary(raw_binary)

        if not resolved_binary:
            return (
                f"ERROR: Tool executable '{raw_binary}' not found on system PATH or standard folders. "
                f"Ensure {self.name} is installed locally or toggle USE_DOCKER=True.",
                127,
            )

        # Swap in the fully resolved binary path
        exec_cmd = [resolved_binary] + command[1:]

        # Handle Python script targets on Windows if directly referenced
        if resolved_binary.endswith(".py") and not exec_cmd[0].endswith("python.exe"):
            exec_cmd = ["python", resolved_binary] + command[1:]

        timeout = getattr(settings, "TOOL_TIMEOUT_SECONDS", 180)

        try:
            # shell=False prevents shell-injection metacharacters
            result = subprocess.run(
                exec_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False
            )
            output = (result.stdout or "") + (result.stderr or "")
            return output, result.returncode

        except subprocess.TimeoutExpired:
            return f"TIMEOUT: Execution of {self.name} exceeded {timeout}s limit.", -1
        except Exception as exc:
            return f"EXECUTION_ERROR: {str(exc)}", -1

    def _execute_docker(self, command: List[str]) -> Tuple[str, int]:
        """Routes execution to the ephemeral Docker sandbox."""
        timeout = getattr(settings, "TOOL_TIMEOUT_SECONDS", 180)
        image = getattr(settings, "DOCKER_IMAGE_NAME", "kali-tools")
        return execute_in_docker_sandbox(
            command=command,
            image_name=image,
            timeout=timeout
        )