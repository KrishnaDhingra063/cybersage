import logging
from typing import Optional, Callable
from app.adapters.base import ToolAdapter, ToolResult, NormalizedFinding
import httpx

logger = logging.getLogger(__name__)

DEFAULT_WORDLIST = ["admin", "login", "backup", "config", "api", "test", "dev", "old", "tmp", "hidden", "secret", "dashboard", "console", "manage", "wp-admin", ".env", ".git", "swagger", "openapi", "v1", "v2"]

class DirsearchAdapter(ToolAdapter):
    name = "dirsearch"

    def build_command(self, target: str, params: dict) -> list[str]:
        return []

    def parse(self, raw_output: str) -> ToolResult:
        return ToolResult(raw_output=raw_output)

    def run(self, target: str, params: dict, scope_check_fn: Optional[Callable[[str], None]] = None) -> ToolResult:
        if scope_check_fn:
            scope_check_fn(target)
        base = target if target.startswith("http") else f"http://{target}"
        base = base.rstrip("/")
        wordlist = params.get("wordlist") or DEFAULT_WORDLIST
        if isinstance(wordlist, str):
            wordlist = [w.strip() for w in wordlist.split(",")]
        wordlist = wordlist[:25]
        ext = params.get("extension", "")
        raw_lines = [f"[dirsearch] Base: {base} wordlist {len(wordlist)} ext {ext}"]
        findings = []
        try:
            with httpx.Client(timeout=6.0, follow_redirects=False) as client:
                for word in wordlist:
                    path = f"/{word}{ext}"
                    url = f"{base}{path}"
                    if scope_check_fn:
                        try:
                            scope_check_fn(url)
                        except Exception:
                            raw_lines.append(f"SKIP {url} out of scope")
                            continue
                    try:
                        # Enterprise safety feature #8: official calling card so
                        # the client SOC can allowlist authorized scan traffic.
                        from app.core.safe_policy import scanner_headers
                        r = client.get(url, headers=scanner_headers("dirsearch"))
                        raw_lines.append(f"{r.status_code} {path}")
                        if r.status_code in (200, 301, 302, 403):
                            # 403 still interesting
                            sev = "medium" if r.status_code == 200 and word in ("admin",".env",".git","backup") else "low"
                            findings.append(NormalizedFinding(
                                host=base, vuln_type="exposed_path", severity=sev,
                                description=f"Discovered path {path} returned {r.status_code}",
                                evidence=f"GET {url} -> {r.status_code} {r.headers.get('content-length','')}",
                                parameter=path, cvss_score=4.0 if sev=="medium" else 2.0
                            ))
                    except Exception as e:
                        raw_lines.append(f"err {path}: {e}")
        except Exception as e:
            raw_lines.append(f"ERROR: {e}")
        return ToolResult(raw_output="\n".join(raw_lines), findings=findings, hosts=[])
