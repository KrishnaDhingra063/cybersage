import logging
from typing import Dict, Type, Optional, Callable, Any

from app.adapters.base import ToolAdapter, ToolResult
from app.adapters.nmap_adapter import NmapAdapter
from app.adapters.crawler_adapter import CrawlerAdapter
from app.adapters.shadow_api_adapter import ShadowApiAdapter
from app.adapters.nuclei_adapter import NucleiAdapter
from app.adapters.zap_adapter import ZapAdapter
from app.adapters.nikto_adapter import NiktoAdapter
from app.adapters.web_vuln_adapter import WebVulnAdapter
from app.adapters.sqlmap_adapter import SqlmapAdapter
from app.adapters.metasploit_adapter import MetasploitAdapter
from app.adapters.hashcat_adapter import HashcatAdapter

logger = logging.getLogger(__name__)

# Tools strictly requiring human authorization before execution
HIGH_RISK_TOOLS = {"sqlmap", "metasploit", "hashcat"}

# Canonical adapter registry mapping (including common aliases)
ADAPTER_REGISTRY: Dict[str, Type[ToolAdapter]] = {
    "nmap": NmapAdapter,
    "crawler": CrawlerAdapter,
    "shadow_api": ShadowApiAdapter,
    "nuclei": NucleiAdapter,
    "zap": ZapAdapter,
    "owasp_zap": ZapAdapter,
    "nikto": NiktoAdapter,
    "web_vuln": WebVulnAdapter,
    "web_vuln_check": WebVulnAdapter,
    "sqlmap": SqlmapAdapter,
    "metasploit": MetasploitAdapter,
    "hashcat": HashcatAdapter,
}


def get_adapter(tool_name: str, **kwargs) -> ToolAdapter:
    """
    Instantiates and returns the adapter associated with the given tool name.
    Passes custom initialization parameters (such as zap_api_url or api_key).
    """
    normalized_name = tool_name.lower().strip()
    adapter_cls = ADAPTER_REGISTRY.get(normalized_name)
    if not adapter_cls:
        raise ValueError(
            f"Tool '{tool_name}' is not registered. Available tools: {list(ADAPTER_REGISTRY.keys())}"
        )

    # Inject specific runtime parameters for ZAP if passed
    if adapter_cls is ZapAdapter:
        zap_url = kwargs.get("zap_api_url", "http://localhost:8080")
        api_key = kwargs.get("api_key", "")
        return ZapAdapter(zap_api_url=zap_url, api_key=api_key)

    return adapter_cls()


def execute_tool(
    tool_name: str,
    target: str,
    params: Optional[Dict[str, Any]] = None,
    scope_check_fn: Optional[Callable[[str], None]] = None,
    is_approved: bool = False,
) -> ToolResult:
    """
    Unified entrypoint for orchestrators and Celery tasks:
    1. Validates high-risk tool approval requirements.
    2. Retrieves the registered adapter (supporting zap and web_vuln configurations).
    3. Runs execution with scope enforcement and returns a normalized ToolResult.
    """
    normalized_name = tool_name.lower().strip()
    params = params or {}

    # Approval Gate Enforcement
    if normalized_name in HIGH_RISK_TOOLS and not is_approved:
        logger.warning(f"Execution blocked: '{normalized_name}' requires explicit operator approval.")
        return ToolResult(
            raw_output=f"APPROVAL_REQUIRED: Tool '{normalized_name}' is classified as HIGH_RISK and requires operator approval.",
            exit_code=403,
        )

    try:
        # Extract potential Zap connection overrides from params
        zap_api_url = params.get("zap_api_url", "http://localhost:8080")
        zap_api_key = params.get("zap_api_key", "")

        adapter = get_adapter(
            normalized_name,
            zap_api_url=zap_api_url,
            api_key=zap_api_key
        )
        return adapter.run(target, params, scope_check_fn=scope_check_fn)
    except Exception as exc:
        logger.exception(f"Failed to execute adapter for '{normalized_name}'")
        return ToolResult(
            raw_output=f"ADAPTER_DISPATCH_ERROR: {str(exc)}",
            exit_code=-1,
        )