import ast
import json
import os
import re
from typing import Any, Dict, List, Optional, Set
from app.adapters.base import ToolAdapter, ToolResult, NormalizedFinding

SENSITIVE_HINTS = (
    "admin", "debug", "hidden", "internal", "backup", "dev", "staging",
    "test", "console", "superuser", "unlisted", "private", "debugger",
    "actuator", "swagger", "graphql"
)


class ShadowApiAdapter(ToolAdapter):
    """
    Statically inspects codebase files or provided source snippets
    using Python AST and pattern analysis to uncover hidden or undocumented API endpoints.
    """
    name = "shadow_api"

    JS_PATTERNS = [
        r'(?:app|router|server|api|handler)\.(?:get|post|put|patch|delete|all|route)\(\s*["\']([^"\']+)["\']',
        r'\.(?:get|post|put|patch|delete)\(\s*["\']([^"\']+)["\']\s*,',
    ]

    def build_command(self, target: str, params: dict) -> list[str]:
        return ["shadow_api", target]

    def parse(self, raw_output: str) -> ToolResult:
        result = ToolResult(raw_output=raw_output)
        start_idx = raw_output.find("{")
        end_idx = raw_output.rfind("}")
        if start_idx == -1 or end_idx == -1:
            return result

        try:
            data = json.loads(raw_output[start_idx : end_idx + 1])
        except json.JSONDecodeError:
            return result

        target = data.get("target", "localhost")
        endpoints = data.get("endpoints", [])

        result.hosts.append({"ip_address": target, "hostname": target})
        result.services.append({
            "host": target,
            "port": 0,
            "protocol": "tcp",
            "service_name": "api_backend",
            "version": "",
        })

        for ep in endpoints:
            path = ep.get("path", "")
            method = ep.get("method", "ANY")
            source = ep.get("source", "code_snippet")
            sensitive = any(hint in path.lower() for hint in SENSITIVE_HINTS)

            result.findings.append(
                NormalizedFinding(
                    host=target,
                    port=0,
                    vuln_type="shadow_api_endpoint",
                    parameter=path,
                    severity="medium" if sensitive else "info",
                    description=f"Static Code Extraction: {method} {path} ({source})"
                    + (" [Sensitive Keyword Detected]" if sensitive else ""),
                    evidence=json.dumps(ep),
                    service_name="api",
                )
            )

        return result

    def run(self, target: str, params: dict, scope_check_fn=None) -> ToolResult:
        # Static source analysis; no external active network request is dispatched
        endpoints: List[Dict[str, str]] = []

        # 1. Check if target or params specify an existing directory or file path
        scan_path = params.get("path") or target
        if os.path.exists(scan_path):
            endpoints.extend(self._scan_filesystem(scan_path))

        # 2. Check if raw code was passed directly
        raw_code = params.get("code") or params.get("source") or ""
        source_files = params.get("source_files", {})
        if isinstance(source_files, dict):
            for filename, content in source_files.items():
                endpoints.extend(self._extract_from_code(content, filename=filename))

        if raw_code:
            endpoints.extend(self._extract_from_code(raw_code, filename="direct_input"))

        # Deduplicate results by path and method
        unique_endpoints = []
        seen = set()
        for ep in endpoints:
            norm_path = self._normalize_path(ep.get("path", ""))
            if not norm_path:
                continue
            key = (norm_path, ep.get("method", "ANY"))
            if key not in seen:
                seen.add(key)
                unique_endpoints.append({
                    "method": ep.get("method", "ANY"),
                    "path": norm_path,
                    "source": ep.get("source", "unknown"),
                })

        payload = {
            "target": target,
            "total_extracted": len(unique_endpoints),
            "endpoints": unique_endpoints,
        }

        json_repr = json.dumps(payload, indent=2)
        result = self.parse(json_repr)
        result.raw_output = f"=== SHADOW API STATIC EXTRACTION REPORT ===\nTarget: {target}\n" + json_repr
        return result

    def _scan_filesystem(self, base_path: str) -> List[Dict[str, str]]:
        found = []
        if os.path.isfile(base_path):
            with open(base_path, "r", encoding="utf-8", errors="ignore") as f:
                return self._extract_from_code(f.read(), filename=base_path)

        for root, _, files in os.walk(base_path):
            for file in files:
                if file.endswith((".py", ".js", ".ts")):
                    full_p = os.path.join(root, file)
                    try:
                        with open(full_p, "r", encoding="utf-8", errors="ignore") as f:
                            found.extend(self._extract_from_code(f.read(), filename=full_p))
                    except Exception:
                        pass
        return found

    def _extract_from_code(self, code: str, filename: str) -> List[Dict[str, str]]:
        if filename.endswith(".py") or self._looks_like_python(code):
            return self._extract_python_ast(code, filename)
        return self._extract_regex(code, filename)

    def _extract_python_ast(self, code: str, filename: str) -> List[Dict[str, str]]:
        extracted = []
        try:
            tree = ast.parse(code)
        except Exception:
            # Fallback to regex if code is partial or malformed
            return self._extract_regex(code, filename)

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    route_info = self._inspect_decorator(dec, filename)
                    if route_info:
                        extracted.append(route_info)
        return extracted

    def _inspect_decorator(self, dec: ast.AST, filename: str) -> Optional[Dict[str, str]]:
        if not isinstance(dec, ast.Call):
            return None

        # Matches @app.get("/path"), @router.post("/path"), @bp.route("/path")
        func = dec.func
        if isinstance(func, ast.Attribute):
            method = func.attr.upper()
            if method in ("GET", "POST", "PUT", "DELETE", "PATCH", "ROUTE", "ALL"):
                if dec.args and isinstance(dec.args[0], ast.Constant):
                    return {
                        "method": "ANY" if method == "ROUTE" else method,
                        "path": str(dec.args[0].value),
                        "source": filename,
                    }
        return None

    def _extract_regex(self, code: str, filename: str) -> List[Dict[str, str]]:
        extracted = []
        for pat in self.JS_PATTERNS:
            for match in re.finditer(pat, code, re.IGNORECASE):
                extracted.append({
                    "method": "ANY",
                    "path": match.group(1),
                    "source": filename,
                })
        return extracted

    def _looks_like_python(self, code: str) -> bool:
        score = 0
        if re.search(r"\bdef [a-zA-Z_]", code):
            score += 2
        if re.search(r"\bimport [a-zA-Z_]", code):
            score += 1
        if re.search(r"\bclass [a-zA-Z_]", code):
            score += 1
        return score >= 2

    def _normalize_path(self, path: str) -> str:
        path = path.strip()
        if not path.startswith("/"):
            path = f"/{path}"
        path = re.sub(r"<([^>:]+)(?::[^>]+)?>", r":\1", path)
        path = re.sub(r"\{([^}]+)\}", r":\1", path)
        path = re.sub(r"\s+", "", path)
        return path