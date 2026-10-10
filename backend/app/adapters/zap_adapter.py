import json
import logging
import time
import urllib.parse
from typing import Any, Dict, List, Optional
import httpx
from app.adapters.base import ToolAdapter, ToolResult, NormalizedFinding

logger = logging.getLogger(__name__)


class ZapAdapter(ToolAdapter):
    """
    Adapter for OWASP ZAP API daemon.
    Executes automated spidering and active vulnerability assessments.
    """
    name = "zap"

    def __init__(self, zap_api_url: str = "http://localhost:8080", api_key: str = ""):
        self.api_url = zap_api_url.rstrip("/")
        self.api_key = api_key

    def build_command(self, target: str, params: dict) -> list[str]:
        # Represents symbolic execution vector for pipeline logging
        return ["zap", f"--target={target}", f"--scan-type={params.get('scan_type', 'active')}"]

    def parse(self, raw_output: str) -> ToolResult:
        result = ToolResult(raw_output=raw_output)
        try:
            data = json.loads(raw_output)
        except Exception:
            return result

        target = data.get("target", "")
        alerts = data.get("alerts", [])
        return self._normalize_alerts(alerts, target, raw_output)

    def run(self, target: str, params: dict, scope_check_fn: Optional[Any] = None) -> ToolResult:
        if scope_check_fn:
            scope_check_fn(target)

        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"

        scan_type = params.get("scan_type", "active").lower()
        timeout = int(params.get("timeout", 300))

        # Fast-fail when no ZAP daemon is listening (avoids 15s hang in demos).
        # Pure connection check, no behavior change when daemon is up.
        try:
            import socket as _socket

            _parsed = urllib.parse.urlparse(self.api_url)
            _host = _parsed.hostname or "localhost"
            _port = _parsed.port or 8080
            _sock = _socket.create_connection((_host, _port), timeout=2)
            _sock.close()
        except Exception:
            return ToolResult(
                raw_output=(
                    f"ERROR: ZAP daemon not reachable at {self.api_url} "
                    f"(checked in 2s). Start ZAP (zaproxy/zap-stable) or use "
                    f"nuclei / web_vuln_check instead."
                ),
                exit_code=127,
            )

        client_headers = {}
        if self.api_key:
            client_headers["X-ZAP-API-Key"] = self.api_key

        # 1. Healthcheck with SHORT timeout — port 8080 is often squatted by
        # non-ZAP services that accept TCP but never answer HTTP (hangs long timeouts).
        try:
            with httpx.Client(base_url=self.api_url, timeout=5.0, headers=client_headers) as probe:
                ver_resp = probe.get("/JSON/core/view/version/")
            if ver_resp.status_code != 200:
                return ToolResult(
                    raw_output=f"ERROR: ZAP daemon returned status {ver_resp.status_code}: {ver_resp.text}",
                    exit_code=1,
                )
            try:
                ver_resp.json()
            except Exception:
                return ToolResult(
                    raw_output=(
                        f"ERROR: Something answers at {self.api_url} but is not a ZAP daemon "
                        f"(non-JSON version reply). Use nuclei / web_vuln_check instead."
                    ),
                    exit_code=127,
                )
        except httpx.RequestError as exc:
            return ToolResult(
                raw_output=f"ERROR: Could not connect to ZAP daemon at {self.api_url}: {str(exc)}",
                exit_code=127,
            )

        with httpx.Client(base_url=self.api_url, timeout=15.0, headers=client_headers) as client:

            # 2. Add target to context / include in scope
            self._include_target(client, target)

            # 3. Trigger Spider
            spider_id = self._start_spider(client, target)
            self._poll_status(client, "/JSON/spider/view/status/", "scan", spider_id, timeout=timeout // 2)

            # 4. Trigger Active Scan if requested
            if scan_type != "spider":
                ascan_id = self._start_ascan(client, target)
                self._poll_status(client, "/JSON/ascan/view/status/", "scan", ascan_id, timeout=timeout)

            # 5. Fetch alerts
            alerts = self._fetch_alerts(client, target)

        raw_payload = json.dumps({"target": target, "alerts": alerts}, indent=2)
        return self._normalize_alerts(alerts, target, raw_payload)

    def _include_target(self, client: httpx.Client, url: str):
        try:
            client.get("/JSON/core/action/accessUrl/", params={"url": url, "followRedirects": "true"})
        except httpx.RequestError as e:
            logger.warning(f"ZAP failed accessUrl init for {url}: {e}")

    def _start_spider(self, client: httpx.Client, url: str) -> str:
        resp = client.get(
            "/JSON/spider/action/scan/",
            params={"url": url, "maxChildren": "10", "recurse": "true", "subtreeOnly": "true"},
        )
        return str(resp.json().get("scan", "0"))

    def _start_ascan(self, client: httpx.Client, url: str) -> str:
        resp = client.get(
            "/JSON/ascan/action/scan/",
            params={"url": url, "recurse": "true", "inScopeOnly": "false"},
        )
        return str(resp.json().get("scan", "0"))

    def _poll_status(self, client: httpx.Client, endpoint: str, key: str, scan_id: str, timeout: int = 300):
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                resp = client.get(endpoint, params={"scanId": scan_id})
                progress = resp.json().get("status", "100")
                if str(progress) == "100":
                    break
            except Exception:
                pass
            time.sleep(3)

    def _fetch_alerts(self, client: httpx.Client, base_url: str) -> List[Dict[str, Any]]:
        try:
            resp = client.get(
                "/JSON/core/view/alerts/",
                params={"baseurl": base_url, "start": "0", "count": "500"},
            )
            return resp.json().get("alerts", [])
        except Exception as exc:
            logger.error(f"Failed to retrieve alerts from ZAP: {exc}")
            return []

    def _normalize_alerts(self, alerts: List[Dict[str, Any]], target: str, raw_payload: str) -> ToolResult:
        parsed_target = urllib.parse.urlparse(target)
        host = parsed_target.hostname or target
        port = parsed_target.port or (443 if parsed_target.scheme == "https" else 80)

        result = ToolResult(raw_output=raw_payload, exit_code=0)
        result.hosts.append({"ip_address": host, "target": target})
        result.services.append({
            "host": host,
            "port": port,
            "protocol": "tcp",
            "service_name": parsed_target.scheme or "http",
            "version": "",
        })

        severity_map = {
            "High": ("high", 7.5),
            "Medium": ("medium", 5.0),
            "Low": ("low", 3.0),
            "Informational": ("info", 0.0),
        }

        for alert in alerts:
            risk_label = alert.get("risk", "Informational")
            sev, cvss = severity_map.get(risk_label, ("info", 0.0))

            alert_url = alert.get("url", target)
            alert_parsed = urllib.parse.urlparse(alert_url)
            alert_port = alert_parsed.port or port

            result.findings.append(NormalizedFinding(
                host=alert_parsed.hostname or host,
                port=alert_port,
                vuln_type=f"zap_{alert.get('pluginId', 'alert')}",
                parameter=alert.get("param") or alert_parsed.path,
                severity=sev,
                description=alert.get("name") or alert.get("description", "ZAP Alert"),
                evidence=f"URL: {alert_url} | Method: {alert.get('method', 'GET')} | Evidence: {alert.get('evidence', '')[:400]}",
                cvss_score=cvss,
                service_name=alert_parsed.scheme or "http",
                version="",
            ))

        return result