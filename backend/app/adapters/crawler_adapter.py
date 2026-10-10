# from abc import abstractmethod
# import logging
# from collections import deque
# from html.parser import HTMLParser
# from urllib.parse import urljoin, urlparse, urlunparse
# from app.adapters.base import ToolAdapter, ToolResult, NormalizedFinding
# import json
# import urllib.parse
# from html.parser import HTMLParser
# from typing import List, Dict, Any, Set
# import requests
# from app.adapters.base import ToolAdapter, ToolResult, NormalizedFinding
# from urllib.parse import urlparse

# class _FormAndLinkParser(HTMLParser):
#     def __init__(self, base_url: str):
#         super().__init__()
#         self.base_url = base_url
#         self.links: Set[str] = set()
#         self.forms: List[Dict[str, Any]] = []
#         self._current_form: Dict[str, Any] = {}

#     def handle_starttag(self, tag: str, attrs: List[tuple]):
#         attr_dict = dict(attrs)
#         if tag == "a" and "href" in attr_dict:
#             href = attr_dict["href"].strip()
#             joined = urllib.parse.urljoin(self.base_url, href)
#             if joined.startswith(self.base_url):
#                 self.links.add(joined)

#         elif tag == "form":
#             action = attr_dict.get("action", "")
#             method = attr_dict.get("method", "GET").upper()
#             self._current_form = {
#                 "action": urllib.parse.urljoin(self.base_url, action),
#                 "method": method,
#                 "inputs": [],
#             }

#         elif tag in ("input", "textarea", "select") and self._current_form:
#             inp_name = attr_dict.get("name")
#             inp_type = attr_dict.get("type", "text")
#             if inp_name:
#                 self._current_form["inputs"].append({"name": inp_name, "type": inp_type})

#     def handle_endtag(self, tag: str):
#         if tag == "form" and self._current_form:
#             self.forms.append(self._current_form)
#             self._current_form = {}


# class CrawlerAdapter(ToolAdapter):
#     name = "crawler"

#     def build_command(self, target: str, params: dict) -> list[str]:
#         # Pure-Python runner stub; parameters passed via JSON to _execute_local override or run()
#         return ["python", "-c", "import sys; print(sys.argv[1])", json.dumps({"target": target, **params})]

#     def run(self, target: str, params: dict, scope_check_fn=None) -> ToolResult:
#         if scope_check_fn:
#             scope_check_fn(target)

#         max_depth = params.get("max_depth", 2)
#         discovered_urls: Set[str] = {target}
#         visited: Set[str] = set()
#         to_visit = [target]
#         all_forms = []

#         for _ in range(max_depth):
#             if not to_visit:
#                 break
#             current_url = to_visit.pop(0)
#             if current_url in visited:
#                 continue

#             try:
#                 resp = requests.get(current_url, timeout=5, headers={"User-Agent": "PentestAI-Bot/1.0"})
#                 visited.add(current_url)
#                 if "text/html" in resp.headers.get("Content-Type", ""):
#                     parser = _FormAndLinkParser(target)
#                     parser.feed(resp.text)
#                     for link in parser.links:
#                         if link not in visited:
#                             discovered_urls.add(link)
#                             to_visit.append(link)
#                     all_forms.extend(parser.forms)
#             except Exception:
#                 continue

#         payload = {
#             "target": target,
#             "discovered_urls": list(discovered_urls),
#             "forms": all_forms,
#         }
#         return self.parse(json.dumps(payload))

#     @abstractmethod
#     def parse(self, raw_output: str) -> ToolResult:
#         result = ToolResult(raw_output=raw_output)
#         try:
#             data = json.loads(raw_output)
#         except Exception:
#             return result

#         target = data.get("target", "")
#         parsed_target = urllib.parse.urlparse(target)
#         host = parsed_target.hostname or target
#         port = parsed_target.port or (443 if parsed_target.scheme == "https" else 80)

#         result.hosts.append({"ip_address": host, "target": target})

#         for url in data.get("discovered_urls", []):
#             result.findings.append(
#                 NormalizedFinding(
#                     host=host,
#                     port=port,
#                     vuln_type="discovered_endpoint",
#                     parameter=url,
#                     severity="info",
#                     description=f"Crawled route: {url}",
#                     evidence=url,
#                     service_name="http",
#                 )
#             )

#         for form in data.get("forms", []):
#             action = form.get("action", "")
#             method = form.get("method", "GET")
#             inputs = [i.get("name") for i in form.get("inputs", [])]
#             result.findings.append(
#                 NormalizedFinding(
#                     host=host,
#                     port=port,
#                     vuln_type="html_form",
#                     parameter=",".join(filter(None, inputs)),
#                     severity="info",
#                     description=f"Discovered HTML Form ({method}) submitting to {action}",
#                     evidence=json.dumps(form),
#                     service_name="http",
#                 )
#             )

#         return result
# logger = logging.getLogger(__name__)

# SENSITIVE_PATH_HINTS = (
#     "admin", "debug", "backup", "internal", "dev", "console",
#     "swagger", "graphql", "staging", "test", "healthz", "actuator",
# )
# IGNORED_EXTENSIONS = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".woff", ".woff2", ".ico")


# class _LinkExtractor(HTMLParser):
#     def __init__(self, base_url: str):
#         super().__init__()
#         self.base_url = base_url
#         self.links = set()
#         self.form_actions = set()
#         self.script_srcs = set()

#     def _norm(self, url):
#         parsed = urlparse(urljoin(self.base_url, url))
#         if parsed.scheme not in ("http", "https"):
#             return None
#         path = parsed.path.rstrip("/") or "/"
#         return urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))

#     def handle_starttag(self, tag, attrs):
#         attrs = dict(attrs)
#         if tag == "a" and attrs.get("href"):
#             norm = self._norm(attrs["href"])
#             if norm:
#                 self.links.add(norm)
#         if tag == "form" and attrs.get("action"):
#             norm = self._norm(attrs["action"])
#             if norm:
#                 self.form_actions.add(norm)
#         if tag == "script" and attrs.get("src"):
#             norm = self._norm(attrs["src"])
#             if norm:
#                 self.script_srcs.add(norm)


# class CrawlerAdapter(ToolAdapter):
#     """Headless web crawler for dynamic route discovery.

#     Uses a lightweight httpx crawler by default so it runs anywhere.
#     If the `playwright` package is installed (and the caller opts in via
#     js_render=True), pages are rendered in headless Chromium so links built
#     by client-side JavaScript are discovered too.
#     """

#     name = "crawler"

#     def build_command(self, target: str, params: dict) -> list[str]:
#         return ["crawler", target]

#     def parse(self, raw_output: str) -> ToolResult:
#         return ToolResult(raw_output=raw_output)

#     def run(self, target: str, params: dict, scope_check_fn=None) -> ToolResult:
#         if scope_check_fn:
#             scope_check_fn(target)

#         if not target.startswith(("http://", "https://")):
#             target = f"http://{target}"

#         max_pages = int(params.get("max_pages", 25))
#         js_render = bool(params.get("js_render", False))

#         discovered = self._crawl(target, max_pages=max_pages, js_render=js_render)

#         findings = []
#         sections = []
#         sections.append(f"=== CRAWL REPORT: {target} ===")
#         sections.append(f"Engine: {'playwright (headless chromium)' if discovered.get('used_playwright') else 'httpx (lightweight)'}")
#         sections.append(f"Pages visited: {len(discovered['visited'])}")
#         sections.append("")

#         sections.append("DISCOVERED ROUTES:")
#         for url in sorted(discovered["routes"]):
#             sections.append(f"  {url}")

#         if discovered["form_actions"]:
#             sections.append("\nDISCOVERED FORM ACTIONS (candidates for injection testing):")
#             for action in sorted(discovered["form_actions"]):
#                 sections.append(f"  {action}")

#         if discovered["api_hints"]:
#             sections.append("\nAPI / SCRIPT HINTS:")
#             for hint in sorted(discovered["api_hints"]):
#                 sections.append(f"  {hint}")

#         sensitive = [r for r in discovered["routes"] if any(h in r.lower() for h in SENSITIVE_PATH_HINTS)]
#         if sensitive:
#             sections.append("\nSENSITIVE PATHS (worth probing):")
#             for path in sorted(sensitive):
#                 sections.append(f"  {path}")
#                 findings.append(NormalizedFinding(
#                     host=target,
#                     vuln_type="crawled_sensitive_route",
#                     severity="medium" if path.lower().endswith((".env", "swagger", "graphql")) else "low",
#                     parameter=urlparse(path).path,
#                     description=f"Crawler discovered potentially sensitive route: {path}",
#                     evidence=f"URL: {path}",
#                 ))

#         if discovered["errors"]:
#             sections.append("\nERRORS:")
#             for err in discovered["errors"][:20]:
#                 sections.append(f"  {err}")

#         return ToolResult(raw_output="\n".join(sections), findings=findings)

#     def _crawl(self, start_url: str, max_pages: int = 25, js_render: bool = False) -> dict:
#         start_netloc = urlparse(start_url).netloc

#         if js_render:
#             try:
#                 return self._crawl_playwright(start_url, max_pages=max_pages)
#             except Exception as e:
#                 logger.warning(f"Playwright crawl failed, falling back to httpx: {e}")
#                 return self._crawl_httpx(start_url, max_pages=max_pages)
#         return self._crawl_httpx(start_url, max_pages=max_pages)

#     def _crawl_httpx(self, start_url: str, max_pages: int = 25) -> dict:
#         import httpx

#         start_netloc = urlparse(start_url).netloc
#         visited = set()
#         queue = deque([start_url])
#         routes = set()
#         form_actions = set()
#         api_hints = set()
#         errors = []

#         unsafe = httpx.Client(
#             timeout=10, follow_redirects=True, verify=False,
#             headers={"User-Agent": "PentestAI-Crawler/0.1"},
#         )
#         try:
#             pages = 0
#             while queue and pages < max_pages:
#                 url = queue.popleft()
#                 norm = url.rstrip("/")
#                 if norm in visited:
#                     continue
#                 visited.add(norm)
#                 routes.add(norm)
#                 pages += 1

#                 try:
#                     resp = unsafe.get(url)
#                     if resp.status_code != 200:
#                         continue
#                 except httpx.RequestError as e:
#                     errors.append(f"{url}: {e}")
#                     continue

#                 parser = _LinkExtractor(url)
#                 try:
#                     parser.feed(resp.text)
#                 except Exception:
#                     continue

#                 for link in parser.links:
#                     routes.add(link)
#                     parsed = urlparse(link)
#                     if parsed.netloc == start_netloc:
#                         queue.append(link)

#                 for action in parser.form_actions:
#                     form_actions.add(action)

#                 for script in parser.script_srcs:
#                     api_hints.add(script)

#                 # Cheap JS hint scan: endpoint-looking strings inside scripts/data
#                 for match in _extract_api_hints(resp.text):
#                     api_hints.add(match)
#         finally:
#             unsafe.close()

#         return {
#             "used_playwright": False,
#             "visited": sorted(visited),
#             "routes": sorted(routes),
#             "form_actions": sorted(form_actions),
#             "api_hints": sorted(api_hints),
#             "errors": errors,
#         }

#     def _crawl_playwright(self, start_url: str, max_pages: int = 25) -> dict:
#         from playwright.sync_api import sync_playwright

#         start_netloc = urlparse(start_url).netloc
#         visited = set()
#         queue = deque([start_url])
#         routes = set()
#         form_actions = set()
#         api_hints = set()
#         errors = []

#         with sync_playwright() as p:
#             browser = p.chromium.launch(headless=True)
#             page = browser.new_page()
#             page.set_default_timeout(15000)

#             pages = 0
#             while queue and pages < max_pages:
#                 url = queue.popleft()
#                 norm = url.rstrip("/")
#                 if norm in visited:
#                     continue
#                 visited.add(norm)
#                 routes.add(norm)
#                 pages += 1

#                 try:
#                     page.goto(url, wait_until="domcontentloaded")
#                 except Exception as e:
#                     errors.append(f"{url}: {e}")
#                     continue

#                 try:
#                     links = page.eval_on_selector_all("a", "els => els.map(e => e.href)")
#                     forms = page.eval_on_selector_all("form", "els => els.map(e => e.action)")
#                     scripts = page.eval_on_selector_all("script[src]", "els => els.map(e => e.src)")
#                 except Exception:
#                     links = forms = scripts = []

#                 for link in links:
#                     routes.add(link.rstrip("/"))
#                     parsed = urlparse(link)
#                     if parsed.netloc == start_netloc:
#                         queue.append(link)

#                 for action in forms:
#                     form_actions.add(action)

#                 for src in scripts:
#                     api_hints.add(src)

#             browser.close()

#         return {
#             "used_playwright": True,
#             "visited": sorted(visited),
#             "routes": sorted(routes),
#             "form_actions": sorted(form_actions),
#             "api_hints": sorted(api_hints),
#             "errors": errors,
#         }


# def _extract_api_hints(html: str, limit: int = 30) -> list:
#     """Cheap regex scan for endpoint-shaped strings referenced by client JS."""
#     import re

#     hints = []
#     patterns = [
#         r'["\']/(?:api|v\d+|rest|graphql)[/"\'][^"\'\\s]*',
#         r'fetch\(["\']([^"\']+)["\']',
#         r'axios\.(?:get|post|put|delete)\(["\']([^"\']+)["\']',
#     ]
#     for pattern in patterns:
#         for match in re.findall(pattern, html, re.IGNORECASE):
#             candidate = match.lstrip("\"'").lstrip("/")
#             if not candidate.startswith(tuple(IGNORED_EXTENSIONS)) and len(hints) < limit:
#                 hints.append(f"/{candidate}")
#     return hints

import json
import logging
import re
from collections import deque
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse, urlunparse

from app.adapters.base import NormalizedFinding, ToolAdapter, ToolResult

logger = logging.getLogger(__name__)

SENSITIVE_PATH_HINTS = (
    "admin", "debug", "backup", "internal", "dev", "console",
    "swagger", "graphql", "staging", "test", "healthz", "actuator",
    ".env", ".git"
)

IGNORED_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".css",
    ".woff", ".woff2", ".ico", ".pdf", ".zip"
)


class _PageParser(HTMLParser):
    """Extracts links, form actions, input parameters, and script sources."""

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links: Set[str] = set()
        self.form_actions: Set[str] = set()
        self.forms: List[Dict[str, Any]] = []
        self.script_srcs: Set[str] = set()
        self._current_form: Optional[Dict[str, Any]] = None

    def _normalize(self, url: str) -> Optional[str]:
        if not url:
            return None
        joined = urljoin(self.base_url, url.strip())
        parsed = urlparse(joined)
        if parsed.scheme not in ("http", "https"):
            return None
        path = parsed.path.rstrip("/") or "/"
        return urlunparse((parsed.scheme, parsed.netloc, path, parsed.params, parsed.query, ""))

    def handle_starttag(self, tag: str, attrs: List[tuple]):
        attr_dict = dict(attrs)

        if tag == "a" and "href" in attr_dict:
            norm = self._normalize(attr_dict["href"])
            if norm and not norm.lower().endswith(IGNORED_EXTENSIONS):
                self.links.add(norm)

        elif tag == "form":
            action = self._normalize(attr_dict.get("action", self.base_url)) or self.base_url
            method = attr_dict.get("method", "GET").upper()
            self.form_actions.add(action)
            self._current_form = {
                "action": action,
                "method": method,
                "inputs": [],
            }

        elif tag in ("input", "textarea", "select") and self._current_form is not None:
            name = attr_dict.get("name")
            inp_type = attr_dict.get("type", "text")
            if name:
                self._current_form["inputs"].append({"name": name, "type": inp_type})

        elif tag == "script" and "src" in attr_dict:
            norm = self._normalize(attr_dict["src"])
            if norm:
                self.script_srcs.add(norm)

    def handle_endtag(self, tag: str):
        if tag == "form" and self._current_form:
            self.forms.append(self._current_form)
            self._current_form = None


def _extract_api_hints(html_text: str, limit: int = 30) -> List[str]:
    """Lightweight regex scan for client-side API routes and fetch/axios calls."""
    hints = set()
    patterns = [
        r'["\']/(?:api|v\d+|rest|graphql)/[^"\'\s>]*["\']',
        r'fetch\(["\']([^"\']+)["\']',
        r'axios\.(?:get|post|put|delete|patch)\(["\']([^"\']+)["\']',
    ]
    for pattern in patterns:
        for match in re.findall(pattern, html_text, re.IGNORECASE):
            candidate = match.strip("\"'").lstrip("/")
            if not candidate.lower().endswith(IGNORED_EXTENSIONS) and len(hints) < limit:
                hints.add(f"/{candidate}")
    return sorted(hints)


class CrawlerAdapter(ToolAdapter):
    """
    Pure-Python In-Memory Web Crawler with optional headless browser rendering.
    Maps internal links, routes, form parameters, and JavaScript API endpoints.
    """

    name = "crawler"

    def build_command(self, target: str, params: dict) -> list[str]:
        # Native execution runs in-process inside run()
        return ["crawler", target]

    def parse(self, raw_output: str) -> ToolResult:
        result = ToolResult(raw_output=raw_output)
        try:
            data = json.loads(raw_output)
        except Exception:
            return result

        target = data.get("target", "")
        parsed = urlparse(target)
        host = parsed.hostname or target
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        result.hosts.append({"ip_address": host, "target": target})
        result.services.append({
            "host": host,
            "port": port,
            "protocol": "tcp",
            "service_name": parsed.scheme or "http",
            "version": "",
        })

        for route in data.get("routes", []):
            is_sensitive = any(h in route.lower() for h in SENSITIVE_PATH_HINTS)
            result.findings.append(
                NormalizedFinding(
                    host=host,
                    port=port,
                    vuln_type="sensitive_route" if is_sensitive else "crawled_route",
                    parameter=urlparse(route).path,
                    severity="medium" if any(h in route.lower() for h in (".env", "swagger", "graphql")) else ("low" if is_sensitive else "info"),
                    description=f"{'Sensitive route' if is_sensitive else 'Route'} discovered: {route}",
                    evidence=f"URL: {route}",
                    service_name=parsed.scheme or "http",
                )
            )

        for form in data.get("forms", []):
            action = form.get("action", "")
            method = form.get("method", "GET")
            inputs = [f"{i.get('name')} ({i.get('type')})" for i in form.get("inputs", [])]
            param_str = ", ".join(inputs) if inputs else "no_inputs"

            result.findings.append(
                NormalizedFinding(
                    host=host,
                    port=port,
                    vuln_type="html_form",
                    parameter=param_str,
                    severity="info",
                    description=f"HTML Form ({method}) on action '{action}'",
                    evidence=json.dumps(form),
                    service_name=parsed.scheme or "http",
                )
            )

        return result

    def run(self, target: str, params: dict, scope_check_fn=None) -> ToolResult:
        if scope_check_fn:
            scope_check_fn(target)

        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"

        max_pages = int(params.get("max_pages", 25))
        js_render = bool(params.get("js_render", False))

        discovered = self._crawl(target, max_pages=max_pages, js_render=js_render)

        # Produce normalized JSON structure for parse()
        payload = {
            "target": target,
            "engine": "playwright" if discovered.get("used_playwright") else "requests",
            "visited": discovered.get("visited", []),
            "routes": discovered.get("routes", []),
            "forms": discovered.get("forms", []),
            "api_hints": discovered.get("api_hints", []),
            "errors": discovered.get("errors", []),
        }

        result = self.parse(json.dumps(payload))
        result.exit_code = 0 if not discovered.get("errors") else 1
        return result

    def _crawl(self, start_url: str, max_pages: int = 25, js_render: bool = False) -> dict:
        if js_render:
            try:
                return self._crawl_playwright(start_url, max_pages=max_pages)
            except Exception as e:
                logger.warning(f"Playwright unavailable or failed ({e}); falling back to HTTP client.")
                return self._crawl_http(start_url, max_pages=max_pages)
        return self._crawl_http(start_url, max_pages=max_pages)

    def _crawl_http(self, start_url: str, max_pages: int = 25) -> dict:
        import requests

        start_netloc = urlparse(start_url).netloc
        visited: Set[str] = set()
        queue = deque([start_url])
        routes: Set[str] = set()
        form_actions: Set[str] = set()
        all_forms: List[Dict[str, Any]] = []
        api_hints: Set[str] = set()
        errors: List[str] = []

        session = requests.Session()
        try:
            from app.core.safe_policy import scanner_headers
            session.headers.update(scanner_headers("crawler"))
        except Exception:
            session.headers.update({"User-Agent": "PentestAI-Crawler/1.0"})

        pages = 0
        while queue and pages < max_pages:
            url = queue.popleft()
            norm = url.rstrip("/")
            if norm in visited:
                continue
            visited.add(norm)
            routes.add(norm)
            pages += 1

            try:
                resp = session.get(url, timeout=8, verify=False, allow_redirects=True)
                content_type = resp.headers.get("Content-Type", "")
                if "text/html" not in content_type and "application/xhtml" not in content_type:
                    continue
            except Exception as e:
                errors.append(f"{url}: {str(e)}")
                continue

            parser = _PageParser(url)
            try:
                parser.feed(resp.text)
            except Exception:
                continue

            for link in parser.links:
                routes.add(link)
                if urlparse(link).netloc == start_netloc and link.rstrip("/") not in visited:
                    queue.append(link)

            form_actions.update(parser.form_actions)
            all_forms.extend(parser.forms)

            for hint in _extract_api_hints(resp.text):
                api_hints.add(hint)

        return {
            "used_playwright": False,
            "visited": sorted(visited),
            "routes": sorted(routes),
            "form_actions": sorted(form_actions),
            "forms": all_forms,
            "api_hints": sorted(api_hints),
            "errors": errors,
        }

    def _crawl_playwright(self, start_url: str, max_pages: int = 25) -> dict:
        from playwright.sync_api import sync_playwright

        start_netloc = urlparse(start_url).netloc
        visited: Set[str] = set()
        queue = deque([start_url])
        routes: Set[str] = set()
        form_actions: Set[str] = set()
        all_forms: List[Dict[str, Any]] = []
        api_hints: Set[str] = set()
        errors: List[str] = []

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.set_default_timeout(10000)

            pages = 0
            while queue and pages < max_pages:
                url = queue.popleft()
                norm = url.rstrip("/")
                if norm in visited:
                    continue
                visited.add(norm)
                routes.add(norm)
                pages += 1

                try:
                    page.goto(url, wait_until="domcontentloaded")
                    content = page.content()
                except Exception as e:
                    errors.append(f"{url}: {str(e)}")
                    continue

                parser = _PageParser(url)
                try:
                    parser.feed(content)
                except Exception:
                    pass

                for link in parser.links:
                    routes.add(link)
                    if urlparse(link).netloc == start_netloc and link.rstrip("/") not in visited:
                        queue.append(link)

                form_actions.update(parser.form_actions)
                all_forms.extend(parser.forms)

                for hint in _extract_api_hints(content):
                    api_hints.add(hint)

            browser.close()

        return {
            "used_playwright": True,
            "visited": sorted(visited),
            "routes": sorted(routes),
            "form_actions": sorted(form_actions),
            "forms": all_forms,
            "api_hints": sorted(api_hints),
            "errors": errors,
        }