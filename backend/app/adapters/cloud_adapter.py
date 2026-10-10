import logging
import re
from typing import Optional, Callable
from app.adapters.base import ToolAdapter, ToolResult, NormalizedFinding
import httpx

logger = logging.getLogger(__name__)

class CloudAdapter(ToolAdapter):
    name = "cloud_enum"

    def build_command(self, target: str, params: dict) -> list[str]:
        return []

    def parse(self, raw_output: str) -> ToolResult:
        return ToolResult(raw_output=raw_output)

    def run(self, target: str, params: dict, scope_check_fn: Optional[Callable[[str], None]] = None) -> ToolResult:
        if scope_check_fn:
            scope_check_fn(target)
        # target is base domain or cloud resource, e.g., example.com or s3 bucket name
        cloud = (params.get("provider") or "aws").lower()
        raw_lines = [f"[cloud_enum] Provider: {cloud} Target: {target}"]
        findings = []
        # Try to enumerate S3-like buckets via common names
        base = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        bucket_candidates = params.get("buckets") or [f"{base.split('.')[0]}-prod", f"{base.split('.')[0]}-dev", f"{base.split('.')[0]}-backup", "test", "admin"]
        if isinstance(bucket_candidates, str):
            bucket_candidates = [b.strip() for b in bucket_candidates.split(",")]
        for bucket in bucket_candidates[:8]:
            # Check if bucket URL is in scope
            bucket_url = f"https://{bucket}.s3.amazonaws.com"
            if scope_check_fn:
                try:
                    scope_check_fn(bucket_url)
                except Exception:
                    raw_lines.append(f"SKIP {bucket} out of scope")
                    continue
            try:
                with httpx.Client(timeout=5.0) as client:
                    r = client.get(bucket_url)
                    raw_lines.append(f"Bucket {bucket}: {r.status_code}")
                    if r.status_code == 200:
                        findings.append(NormalizedFinding(
                            host=bucket_url, vuln_type="public_s3_bucket", severity="high",
                            description=f"S3 bucket {bucket} is publicly listable",
                            evidence=r.text[:600], parameter=bucket, cvss_score=7.5
                        ))
                    elif r.status_code == 403:
                        raw_lines.append(f"Bucket {bucket} exists but private (403) — info")
                    elif r.status_code in (301, 302):
                        findings.append(NormalizedFinding(host=bucket_url, vuln_type="s3_redirect", severity="info", description=f"S3 bucket {bucket} redirect", evidence=str(r.headers), parameter=bucket))
            except Exception as e:
                raw_lines.append(f"err {bucket}: {e}")
        # Check for exposed .env via cloud front
        try:
            check_url = f"https://{base}/.env"
            if scope_check_fn:
                try:
                    scope_check_fn(check_url)
                except Exception:
                    pass
                else:
                    with httpx.Client(timeout=5.0) as client:
                        r = client.get(check_url)
                        if r.status_code == 200 and "APP_KEY" in r.text:
                            raw_lines.append("FOUND exposed .env")
                            findings.append(NormalizedFinding(host=check_url, vuln_type="exposed_env", severity="critical", description="Exposed .env file with secrets", evidence=r.text[:600], parameter="/.env", cvss_score=9.0))
        except Exception as e:
            raw_lines.append(f"env check err: {e}")
        if not findings:
            raw_lines.append("No cloud misconfigurations found in sampled checks")
        return ToolResult(raw_output="\n".join(raw_lines), findings=findings, hosts=[])
