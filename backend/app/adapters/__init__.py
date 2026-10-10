from app.adapters.nmap_adapter import NmapAdapter
from app.adapters.zap_adapter import ZapAdapter
from app.adapters.nuclei_adapter import NucleiAdapter
from app.adapters.metasploit_adapter import MetasploitAdapter
from app.adapters.sqlmap_adapter import SqlmapAdapter
from app.adapters.hashcat_adapter import HashcatAdapter
from app.adapters.web_vuln_adapter import WebVulnAdapter
from app.adapters.crawler_adapter import CrawlerAdapter
from app.adapters.shadow_api_adapter import ShadowApiAdapter
# New analyst stack — additive, no break
from app.adapters.dns_adapter import DnsAdapter
from app.adapters.subdomain_adapter import SubdomainAdapter
from app.adapters.shodan_adapter import ShodanAdapter
from app.adapters.masscan_adapter import MasscanAdapter
from app.adapters.whatweb_adapter import WhatWebAdapter
from app.adapters.dirsearch_adapter import DirsearchAdapter
from app.adapters.repeater_adapter import RepeaterAdapter
from app.adapters.loot_adapter import LootAdapter
from app.adapters.cloud_adapter import CloudAdapter
from app.adapters.nikto_adapter import NiktoAdapter

ADAPTERS = {
    "nmap": NmapAdapter,
    "zap": ZapAdapter,
    "nuclei": NucleiAdapter,
    "metasploit": MetasploitAdapter,
    "sqlmap": SqlmapAdapter,
    "hashcat": HashcatAdapter,
    "web_vuln_check": WebVulnAdapter,
    "crawler": CrawlerAdapter,
    "shadow_api": ShadowApiAdapter,
    # New recon / web / post-exploit
    "dns_enum": DnsAdapter,
    "subdomain": SubdomainAdapter,
    "shodan": ShodanAdapter,
    "masscan": MasscanAdapter,
    "whatweb": WhatWebAdapter,
    "dirsearch": DirsearchAdapter,
    "repeater": RepeaterAdapter,
    "loot": LootAdapter,
    "cloud_enum": CloudAdapter,
    "nikto": NiktoAdapter,
    # Aliases for orchestrator prompt compatibility
    "subdomain_enum": SubdomainAdapter,
    "cloud": CloudAdapter,
}


def get_adapter(tool_name: str, **kwargs):
    adapter_class = ADAPTERS.get(tool_name)
    if not adapter_class:
        raise ValueError(f"Unknown tool: {tool_name}. Available: {list(ADAPTERS.keys())}")
    return adapter_class(**kwargs)
