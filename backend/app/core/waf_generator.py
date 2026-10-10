import re
import urllib.parse
from typing import Dict, Optional, Tuple


class WafRuleGenerator:
    """
    Generates ready-to-deploy perimeter mitigation rules
    for Nginx and Cloudflare WAF engines.
    """

    # Core attack signature regexes
    SIGNATURES = {
        "sqli": (
            r"(union[\s]+select|select[\s]+.*from|insert[\s]+into|"
            r"drop[\s]+table|exec[\s]*\(|information_schema|--[\s]+)"
        ),
        "xss": (
            r"(<script|javascript:|onerror[\s]*=|onload[\s]*=|"
            r"eval\s*\(|document\.cookie|<img\s+src=)"
        ),
        "traversal": r"(\.\./|\.\.\\|%2e%2e/|%2e%2e\\|/etc/passwd)",
        "ssrf": r"(https?://(127\.0\.0\.1|localhost|169\.254\.169\.254|0\.0\.0\.0|\[::1\]))",
        "rce": r"(;|\||`|\$\(|\/bin\/sh|\/bin\/bash|cmd\.exe|powershell)",
    }

    @classmethod
    def _normalize_parameter(cls, parameter: Optional[str]) -> Tuple[str, str]:
        """
        Extracts clean path and query param name from a parameter or URL.
        Returns: (path, param_name)
        """
        if not parameter:
            return "/", ""

        param_clean = parameter.strip()
        if "://" in param_clean:
            parsed = urllib.parse.urlparse(param_clean)
            path = parsed.path or "/"
            query = urllib.parse.parse_qs(parsed.query)
            param_name = list(query.keys())[0] if query else ""
            return path, param_name

        if param_clean.startswith("/"):
            return param_clean.split("?")[0], ""

        # Just a raw parameter name like "q" or "user_id"
        return "", param_clean

    @classmethod
    def _categorize_vuln(cls, vuln_type: str) -> str:
        """Maps canonical or tool-specific vuln types to signature families."""
        v = (vuln_type or "").lower().strip()
        if any(term in v for term in ["sql", "sqli"]):
            return "sqli"
        if any(term in v for term in ["xss", "script", "reflection"]):
            return "xss"
        if any(term in v for term in ["travers", "lfi", "rfi", "path"]):
            return "traversal"
        if any(term in v for term in ["ssrf", "request_forgery"]):
            return "ssrf"
        if any(term in v for term in ["rce", "exec", "command_injection"]):
            return "rce"
        return "generic"

    @classmethod
    def generate_nginx(cls, vuln_type: str, parameter: str) -> str:
        """Generates an Nginx virtual patch snippet."""
        category = cls._categorize_vuln(vuln_type)
        path, param_name = cls._normalize_parameter(parameter)
        regex = cls.SIGNATURES.get(category)
        path_escaped = re.escape(path) if path else ""

        lines = [
            f"# Virtual Patch: Mitigate {vuln_type.upper()} ({category.upper()})",
        ]

        if path_escaped:
            lines.append(f"location ~ ^{path_escaped} {{")
        else:
            lines.append("location / {")

        if regex:
            # Check both query string and request body
            lines.append(f'    if ($query_string ~* "{regex}") {{ return 403; }}')
            lines.append(f'    if ($request_uri ~* "{regex}") {{ return 403; }}')
        else:
            # Defensive deny on sensitive file/route exposure
            lines.append("    deny all;")
            lines.append("    return 403;")

        lines.append("    proxy_pass http://upstream_backend;")
        lines.append("}")
        return "\n".join(lines)

    @classmethod
    def generate_cloudflare(cls, vuln_type: str, parameter: str) -> str:
        """Generates a Cloudflare WAF Expression (Wirefilter syntax)."""
        category = cls._categorize_vuln(vuln_type)
        path, param_name = cls._normalize_parameter(parameter)
        regex = cls.SIGNATURES.get(category)

        conditions = []

        if path and path != "/":
            conditions.append(f'(http.request.uri.path eq "{path}")')

        if regex:
            # Cloudflare Wirefilter regex match operator is `matches`
            conditions.append(f'(http.request.uri.query matches "{regex}")')
            if category == "traversal":
                conditions.append('(http.request.uri.path contains "..")')
        else:
            if path:
                conditions.append(f'(http.request.uri.path eq "{path}")')
            else:
                conditions.append('(http.request.uri.query contains "admin")')

        joined_conditions = " and ".join(conditions)
        return (
            f"# Cloudflare Firewall Expression (Action: Block)\n"
            f"{joined_conditions}"
        )

    @classmethod
    def generate_all(cls, vuln_type: str, parameter: str) -> Dict[str, str]:
        """Convenience method returning rules for all supported engines."""
        return {
            "nginx": cls.generate_nginx(vuln_type, parameter),
            "cloudflare": cls.generate_cloudflare(vuln_type, parameter),
        }