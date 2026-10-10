import re
import shlex
import urllib.parse
from typing import Dict, Optional


class CurlReplayGenerator:
    """
    Generates deterministic, safe, copy-pasteable cURL reproduction commands
    from vulnerability findings and raw scanner evidence.
    """

    @classmethod
    def generate(
        cls,
        target_host: str,
        port: int = 80,
        parameter: str = "",
        evidence: str = "",
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
    ) -> str:
        """
        Constructs an RFC-compliant cURL execution string.
        """
        # 1. Base URL construction
        base_url = cls._build_target_url(target_host, port, parameter)

        # 2. Extract potential attack payload from evidence
        payload = cls._extract_payload(evidence)

        # 3. Assemble command tokens safely using shlex
        cmd_tokens = ["curl", "-sk", "-i"]

        # Add custom inspection headers
        default_headers = {
            "User-Agent": "PentestAI-Replay/1.0",
            "Accept": "*/*",
        }
        if headers:
            default_headers.update(headers)

        for header_name, header_value in default_headers.items():
            cmd_tokens.extend(["-H", f"{header_name}: {header_value}"])

        # 4. Handle HTTP method and payload injection
        clean_method = method.upper().strip()
        if clean_method == "POST":
            cmd_tokens.extend(["-X", "POST"])
            if payload:
                cmd_tokens.extend(["--data", payload])
            cmd_tokens.append(base_url)
        else:
            # Default to GET; if payload exists and isn't in URL, append via URL encoding
            if payload and payload not in base_url:
                cmd_tokens.append(base_url)
                param_key = cls._extract_param_key(parameter) or "q"
                cmd_tokens.extend(["--get", "--data-urlencode", f"{param_key}={payload}"])
            else:
                cmd_tokens.append(base_url)

        # Append terminal status formatting
        cmd_tokens.extend(["-w", "\n\nHTTP_STATUS: %{http_code}\nTIME_TOTAL: %{time_total}s\n"])

        # Render tokenized string
        return " ".join(shlex.quote(token) if any(c in token for c in " \t\n*?[]#$&;`|<>~") else token for token in cmd_tokens)

    @classmethod
    def _build_target_url(cls, host: str, port: int, parameter: str) -> str:
        clean_host = host.strip()
        if not clean_host.startswith(("http://", "https://")):
            scheme = "https" if port == 443 else "http"
            clean_host = f"{scheme}://{clean_host}"

        parsed = urllib.parse.urlparse(clean_host)
        hostname = parsed.hostname or clean_host
        scheme = parsed.scheme or "http"

        # Apply explicit port only if non-standard
        port_suffix = ""
        if port and port not in (80, 443):
            port_suffix = f":{port}"

        path = parameter.strip()
        if "://" in path:
            parsed_path = urllib.parse.urlparse(path)
            path = parsed_path.path
            if parsed_path.query:
                path += f"?{parsed_path.query}"

        if not path.startswith("/"):
            path = f"/{path}"

        return f"{scheme}://{hostname}{port_suffix}{path}"

    @classmethod
    def _extract_payload(cls, evidence: str) -> Optional[str]:
        """Extracts the proof-of-concept injection string from raw tool evidence."""
        if not evidence:
            return None

        # Matches common scanner evidence labels: 'Payload: ...', 'matched: ...', 'Vector: ...'
        patterns = [
            r"(?:payload|vector|probe|input)[:=\s]+[\"']?([^\r\n\"']+)[\"']?",
            r"(?:q|id|param|search)=([^&\s\r\n]+)",
        ]
        for pattern in patterns:
            match = re.search(pattern, evidence, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return None

    @classmethod
    def _extract_param_key(cls, parameter: str) -> str:
        """Extracts query parameter name if parameter is formatted as key/path."""
        if not parameter:
            return ""
        if "=" in parameter:
            return parameter.split("=")[0].split("?")[-1]
        if not parameter.startswith("/"):
            return parameter
        return ""