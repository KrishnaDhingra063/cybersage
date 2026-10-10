import logging
import json
from typing import Optional, Callable
from app.adapters.base import ToolAdapter, ToolResult, NormalizedFinding
import httpx

logger = logging.getLogger(__name__)

class RepeaterAdapter(ToolAdapter):
    name = "repeater"

    def build_command(self, target: str, params: dict) -> list[str]:
        return []

    def parse(self, raw_output: str) -> ToolResult:
        return ToolResult(raw_output=raw_output)

    def run(self, target: str, params: dict, scope_check_fn: Optional[Callable[[str], None]] = None) -> ToolResult:
        # target is URL, params: method, headers, body, payloads
        if scope_check_fn:
            scope_check_fn(target)
        method = (params.get("method") or "GET").upper()
        headers = params.get("headers") or {}
        try:
            # Enterprise safety feature #8: stamp the calling card without
            # overriding operator-supplied headers.
            from app.core.safe_policy import scanner_headers
            headers = {**scanner_headers("repeater"), **headers}
        except Exception:
            pass
        body = params.get("body") or params.get("data") or ""
        url = target if target.startswith("http") else f"http://{target}"
        raw_lines = [f"[repeater] {method} {url}"]
        findings = []
        try:
            with httpx.Client(timeout=8.0, follow_redirects=False) as client:
                # Baseline
                r0 = client.request(method, url, headers=headers, content=body if isinstance(body,str) else json.dumps(body))
                raw_lines.append(f"Baseline {r0.status_code} len {len(r0.content)}")
                raw_lines.append(f"Headers: {dict(r0.headers)}")
                raw_lines.append(f"Body snippet: {r0.text[:600]}")
                # Try payloads if provided
                payloads = params.get("payloads") or params.get("payload") or []
                if isinstance(payloads, str):
                    payloads = [payloads]
                for p in payloads[:5]:
                    test_url = url
                    test_body = body
                    # simple injection: append payload to URL or body
                    if "?" in url:
                        test_url = url + p
                    elif body:
                        test_body = (body + p) if isinstance(body,str) else body
                    else:
                        test_url = url + ("?q=" + p if "?" not in url else p)
                    if scope_check_fn:
                        try:
                            scope_check_fn(test_url)
                        except Exception:
                            continue
                    r = client.request(method, test_url, headers=headers, content=test_body if isinstance(test_body,str) else json.dumps(test_body))
                    raw_lines.append(f"Payload {p[:30]} -> {r.status_code} len {len(r.content)} diff {len(r.content)-len(r0.content)}")
                    # Heuristic: if payload changes length significantly or reflects payload, flag
                    if p.lower() in r.text.lower() and method == "GET":
                        findings.append(NormalizedFinding(
                            host=url, vuln_type="reflected_input", severity="medium",
                            description=f"Payload {p[:30]} reflected in response",
                            evidence=f"Request {test_url} reflected payload", parameter=p, cvss_score=5.0
                        ))
                    if r.status_code == 500 and r0.status_code != 500:
                        findings.append(NormalizedFinding(
                            host=url, vuln_type="server_error_on_payload", severity="low",
                            description=f"Payload caused 500 error: {p[:30]}", evidence=r.text[:500], parameter=p
                        ))
                # Check for missing security headers in baseline
                if "content-security-policy" not in {k.lower():v for k,v in r0.headers.items()}:
                    findings.append(NormalizedFinding(host=url, vuln_type="missing_csp", severity="low", description="Missing CSP on repeater target", evidence=str(r0.headers), parameter=url))
        except Exception as e:
            raw_lines.append(f"ERROR: {e}")
            findings.append(NormalizedFinding(host=url, vuln_type="repeater_error", severity="info", description=str(e), evidence="\n".join(raw_lines), parameter=url))
        return ToolResult(raw_output="\n".join(raw_lines), findings=findings, hosts=[])
