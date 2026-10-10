import urllib.parse
from typing import Any, Dict, List
import httpx
from app.adapters.base import ToolAdapter, ToolResult, NormalizedFinding


class WebVulnAdapter(ToolAdapter):
    """
    Lightweight web security auditor for application hygiene,
    defensive headers, sensitive file exposure, and directory listings.
    """
    name = "web_vuln"

    def build_command(self, target: str, params: dict) -> list[str]:
        return ["web_vuln", target]

    def parse(self, raw_output: str) -> ToolResult:
        return ToolResult(raw_output=raw_output)

    def run(self, target: str, params: dict, scope_check_fn=None) -> ToolResult:
        if scope_check_fn:
            scope_check_fn(target)

        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"

        parsed_url = urllib.parse.urlparse(target)
        host = parsed_url.hostname or target
        port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
        scheme = parsed_url.scheme or "http"

        findings: List[NormalizedFinding] = []
        sections: List[str] = []

        try:
            from app.core.config import get_settings as _get_settings
            _identity = _get_settings().SCANNER_IDENTITY
        except Exception:
            _identity = "PentestAI-Authorized-Scan"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PentestAI-Auditor/1.0",
            "Accept": "*/*",
            # Enterprise safety feature #8: calling card for SOC allowlisting.
            "X-PentestAI-Authorized-Scan": _identity,
        }

        with httpx.Client(timeout=8.0, verify=False, follow_redirects=True, headers=headers) as client:
            self._check_headers(client, target, host, port, scheme, findings, sections)
            self._check_sql_errors(client, target, host, port, scheme, params, findings, sections)
            self._check_xss_reflection(client, target, host, port, scheme, params, findings, sections)
            self._check_info_disclosure(client, target, host, port, scheme, findings, sections)
            self._check_directory_listing(client, target, host, port, scheme, findings, sections)
            self._check_common_paths(client, target, host, port, scheme, findings, sections)

        raw_output = "\n\n".join(sections)
        result = ToolResult(raw_output=raw_output, findings=findings, exit_code=0)

        result.hosts.append({"ip_address": host, "target": target})
        result.services.append({
            "host": host,
            "port": port,
            "protocol": "tcp",
            "service_name": scheme,
            "version": "",
        })

        return result

    def _check_headers(
        self, client: httpx.Client, target: str, host: str, port: int,
        scheme: str, findings: list, sections: list
    ):
        section = ["=== SECURITY HEADER ANALYSIS ===", f"Target: {target}"]
        try:
            resp = client.get(target)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            section.append(f"Status: {resp.status_code}")

            security_headers = {
                "strict-transport-security": ("Strict-Transport-Security missing", "low", 3.1),
                "x-frame-options": ("Clickjacking risk: X-Frame-Options missing", "low", 3.7),
                "x-content-type-options": ("MIME-sniffing risk: X-Content-Type-Options missing", "info", 0.0),
                "content-security-policy": ("Content-Security-Policy missing", "medium", 4.3),
            }

            for header_key, (desc, sev, cvss) in security_headers.items():
                if header_key not in headers:
                    findings.append(NormalizedFinding(
                        host=host,
                        port=port,
                        vuln_type="missing_security_header",
                        parameter=header_key,
                        severity=sev,
                        description=desc,
                        evidence=f"Header '{header_key}' absent in HTTP response.",
                        cvss_score=cvss,
                        service_name=scheme,
                    ))

            server = resp.headers.get("Server", "")
            if server:
                section.append(f"Server header exposes: {server}")
                findings.append(NormalizedFinding(
                    host=host,
                    port=port,
                    vuln_type="information_disclosure",
                    parameter="Server",
                    severity="low",
                    description=f"Server header exposes software banner: {server}",
                    evidence=f"Server: {server}",
                    cvss_score=2.6,
                    service_name=scheme,
                    version=server,
                ))

            x_powered = resp.headers.get("X-Powered-By", "")
            if x_powered:
                section.append(f"X-Powered-By exposes: {x_powered}")
                findings.append(NormalizedFinding(
                    host=host,
                    port=port,
                    vuln_type="information_disclosure",
                    parameter="X-Powered-By",
                    severity="low",
                    description=f"X-Powered-By reveals runtime technology: {x_powered}",
                    evidence=f"X-Powered-By: {x_powered}",
                    cvss_score=2.6,
                    service_name=scheme,
                ))

        except httpx.RequestError as exc:
            section.append(f"Connection check failed: {exc}")

        sections.append("\n".join(section))

    def _check_sql_errors(
        self, client: httpx.Client, target: str, host: str, port: int,
        scheme: str, params: dict, findings: list, sections: list
    ):
        section = ["=== DATABASE ERROR SIGNATURE CHECK ==="]
        test_paths = params.get("paths", ["/search", "/login", "/api/query"])
        test_probes = ["'", "\"", "1'"]

        error_signatures = [
            "you have an error in your sql syntax",
            "warning: mysql",
            "unclosed quotation mark",
            "microsoft ole db provider for odbc drivers",
            "postgresql",
            "sqlite3",
            "ora-01756",
            "quoted string not properly terminated",
        ]

        found_err = False
        for path in test_paths:
            url = urllib.parse.urljoin(target, path.lstrip("/"))
            for probe in test_probes:
                try:
                    resp = client.get(url, params={"q": probe, "id": probe})
                    body_lower = resp.text.lower()
                    for sig in error_signatures:
                        if sig in body_lower:
                            found_err = True
                            section.append(f"[!] Database error signature on {url} with parameter '{probe}': {sig}")
                            findings.append(NormalizedFinding(
                                host=host,
                                port=port,
                                vuln_type="db_syntax_error_disclosure",
                                parameter=path,
                                severity="high",
                                description=f"Database error disclosed on {path} via probe syntax",
                                evidence=f"URL: {url} | Signature: {sig}",
                                cvss_score=7.5,
                                service_name=scheme,
                            ))
                            break
                except httpx.RequestError:
                    continue

        if not found_err:
            section.append("No common database syntax error signatures observed.")
        sections.append("\n".join(section))

    def _check_xss_reflection(
        self, client: httpx.Client, target: str, host: str, port: int,
        scheme: str, params: dict, findings: list, sections: list
    ):
        section = ["=== REFLECTED INPUT HYGIENE CHECK ==="]
        test_paths = params.get("paths", ["/search", "/comments", "/page"])
        probe = "test<tag>probe"

        found_reflection = False
        for path in test_paths:
            url = urllib.parse.urljoin(target, path.lstrip("/"))
            try:
                resp = client.get(url, params={"q": probe, "query": probe})
                if probe in resp.text:
                    found_reflection = True
                    section.append(f"[!] Unescaped input reflection observed on {url}")
                    findings.append(NormalizedFinding(
                        host=host,
                        port=port,
                        vuln_type="input_reflection",
                        parameter=path,
                        severity="medium",
                        description=f"User input reflected unescaped at {path}",
                        evidence=f"Reflected value '{probe}' on {url}",
                        cvss_score=5.4,
                        service_name=scheme,
                    ))
            except httpx.RequestError:
                continue

        if not found_reflection:
            section.append("No unescaped reflection detected on sample endpoints.")
        sections.append("\n".join(section))

    def _check_info_disclosure(
        self, client: httpx.Client, target: str, host: str, port: int,
        scheme: str, findings: list, sections: list
    ):
        section = ["=== SENSITIVE PATH / DEBUG CHECK ==="]
        paths = ["/debug", "/admin", "/.env", "/config", "/actuator", "/swagger-ui.html"]

        for path in paths:
            url = urllib.parse.urljoin(target, path.lstrip("/"))
            try:
                resp = client.get(url)
                if resp.status_code == 200 and len(resp.text) > 40:
                    section.append(f"[+] Sensitive path accessible: {path} (status {resp.status_code})")
                    findings.append(NormalizedFinding(
                        host=host,
                        port=port,
                        vuln_type="sensitive_path_exposure",
                        parameter=path,
                        severity="high" if path in ("/.env", "/config") else "medium",
                        description=f"Accessible administrative or debug path: {path}",
                        evidence=f"Status: {resp.status_code} | Bytes: {len(resp.text)} | URL: {url}",
                        cvss_score=7.0 if path in ("/.env", "/config") else 5.3,
                        service_name=scheme,
                    ))
            except httpx.RequestError:
                continue

        sections.append("\n".join(section))

    def _check_directory_listing(
        self, client: httpx.Client, target: str, host: str, port: int,
        scheme: str, findings: list, sections: list
    ):
        section = ["=== DIRECTORY LISTING CHECK ==="]
        paths = ["/static/", "/uploads/", "/files/", "/backup/"]

        for path in paths:
            url = urllib.parse.urljoin(target, path.lstrip("/"))
            try:
                resp = client.get(url)
                body_lower = resp.text.lower()
                if resp.status_code == 200 and ("index of" in body_lower or "directory listing" in body_lower):
                    section.append(f"[!] Directory index listing exposed at {path}")
                    findings.append(NormalizedFinding(
                        host=host,
                        port=port,
                        vuln_type="directory_indexing",
                        parameter=path,
                        severity="medium",
                        description=f"Directory index listing is publicly readable at {path}",
                        evidence=f"URL: {url} returned Directory Index",
                        cvss_score=5.3,
                        service_name=scheme,
                    ))
            except httpx.RequestError:
                continue

        sections.append("\n".join(section))

    def _check_common_paths(
        self, client: httpx.Client, target: str, host: str, port: int,
        scheme: str, findings: list, sections: list
    ):
        section = ["=== COMMON EXPOSURE CHECK ==="]
        paths = ["/robots.txt", "/.git/HEAD", "/.DS_Store"]

        for path in paths:
            url = urllib.parse.urljoin(target, path.lstrip("/"))
            try:
                resp = client.get(url)
                if resp.status_code == 200 and len(resp.text) > 0:
                    is_git = ".git" in path
                    section.append(f"[+] Found exposure: {path} ({resp.status_code})")
                    findings.append(NormalizedFinding(
                        host=host,
                        port=port,
                        vuln_type="exposed_configuration_file",
                        parameter=path,
                        severity="high" if is_git else "info",
                        description=f"Exposed repository metadata or site file at {path}",
                        evidence=f"URL: {url} | Content-Length: {len(resp.text)}",
                        cvss_score=7.5 if is_git else 0.0,
                        service_name=scheme,
                    ))
            except httpx.RequestError:
                continue

        sections.append("\n".join(section))