import xml.etree.ElementTree as ET
import re
from typing import List, Dict, Any
from app.adapters.base import ToolAdapter, ToolResult, NormalizedFinding
from app.security_guard import sanitize_target


class NmapAdapter(ToolAdapter):
    """
    Hardened Adapter for Nmap network and service exploration with NSE vulnerability integration.
    Streams XML output directly from stdout (-oX -).
    """
    name = "nmap"

    # Block disruptive arguments, output redirects, and file-injection flags
    DISALLOWED_ARGS = {
        "-oN", "-oX", "-oS", "-oG", "--stylesheet", 
        "--interactive", "--script-updatedb", "--resume",
        "-iL", "-iR", "--datadir", "--append-output"
    }

    def build_command(self, target: str, params: dict) -> list[str]:
        # 1. Strict Target Validation & Command Injection Prevention
        safe_target = sanitize_target(target)

        scan_type = params.get("scan_type", "-sT -sV")
        ports = params.get("ports", "")
        timing = params.get("timing", "-T4")
        extra_args = params.get("extra_args", [])

        # Enterprise safety features #1 + #4: strict timing set, ceiling at
        # NMAP_MAX_TIMING, and exploit/dos/intrusive/brute NSE stripped.
        from app.core.safe_policy import clamp_nmap_timing, strip_denied_nmap_scripts
        if timing not in {"-T0", "-T1", "-T2", "-T3", "-T4", "-T5"}:
            timing = "-T4"
        timing = clamp_nmap_timing(timing)

        # Handle extra_args whether provided as list or space-delimited string
        if isinstance(extra_args, str):
            extra_args = extra_args.split()
        extra_args = list(extra_args) if extra_args else []

        flat = " ".join([scan_type] + extra_args)

        # Bypass host discovery ping (essential for VMs that block ICMP echo)
        if "-Pn" not in flat and "-sn" not in flat:
            extra_args.append("-Pn")

        # Host timeout ceiling to prevent network hanging
        if "--host-timeout" not in flat:
            extra_args.extend(["--host-timeout", "45s"])

        # Fast top ports selection if no specific port range is defined
        if not ports and "--top-ports" not in flat and "-p" not in flat:
            extra_args.extend(["--top-ports", "100"])

        # Enable safe vulnerability scripts to capture real CVEs
        if "--script" not in flat:
            extra_args.extend(["--script", "vuln and not dos"])

        # Split scan_type parts (e.g., "-sT -sV")
        scan_parts = scan_type.split() if isinstance(scan_type, str) and " " in scan_type else [scan_type]
        cmd = ["nmap"] + scan_parts + [timing, "-oX", "-"]

        # 2. Port argument parameter sanitization (allow numbers, dashes, commas only)
        if ports:
            clean_ports = str(ports).strip()
            if not re.match(r"^[0-9,\-]+$", clean_ports):
                raise ValueError(f"Security Alert: Invalid port format '{clean_ports}' detected.")
            cmd.extend(["-p", clean_ports])

        # Filter out disallowed arguments from extra_args
        try:
            extra_args = strip_denied_nmap_scripts(list(extra_args))
        except Exception:
            pass
        for arg in extra_args:
            if not any(arg.startswith(banned) for banned in self.DISALLOWED_ARGS):
                cmd.append(arg)

        # Append strictly validated target
        cmd.append(safe_target)
        return cmd

    def parse(self, raw_output: str) -> ToolResult:
        result = ToolResult(raw_output=raw_output)

        try:
            root = ET.fromstring(raw_output)
        except ET.ParseError:
            try:
                extracted = self._extract_xml(raw_output)
                root = ET.fromstring(extracted)
            except Exception:
                return result

        for host_elem in root.findall(".//host"):
            status_elem = host_elem.find("status")
            if status_elem is not None and status_elem.get("state") != "up":
                continue

            # 1. Resolve IP (IPv4 or IPv6 fallback)
            ip = ""
            for addr in host_elem.findall("address"):
                if addr.get("addrtype") in ("ipv4", "ipv6"):
                    ip = addr.get("addr", "")
                    break

            if not ip:
                continue

            # 2. Hostname
            hostname = ""
            hostnames = host_elem.find("hostnames")
            if hostnames is not None:
                hn = hostnames.find("hostname")
                if hn is not None:
                    hostname = hn.get("name", "")

            # 3. OS Detection Guess
            os_guess = ""
            os_elem = host_elem.find(".//os/osmatch")
            if os_elem is not None:
                os_guess = os_elem.get("name", "")

            result.hosts.append({
                "ip_address": ip,
                "hostname": hostname,
                "os_guess": os_guess,
            })

            # 4. Port & Service Parsing
            ports_elem = host_elem.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    state_elem = port_elem.find("state")
                    state = state_elem.get("state", "") if state_elem is not None else ""
                    if state != "open":
                        continue

                    port_id = int(port_elem.get("portid", 0))
                    protocol = port_elem.get("protocol", "tcp")

                    service_elem = port_elem.find("service")
                    service_name = ""
                    version = ""
                    if service_elem is not None:
                        service_name = service_elem.get("name", "")
                        product = service_elem.get("product", "")
                        ver = service_elem.get("version", "")
                        version = f"{product} {ver}".strip()

                    result.services.append({
                        "host": ip,
                        "port": port_id,
                        "protocol": protocol,
                        "service_name": service_name,
                        "version": version,
                    })

                    # Base open port finding
                    result.findings.append(NormalizedFinding(
                        host=ip,
                        port=port_id,
                        vuln_type="open_port",
                        severity="info",
                        description=f"Open port {port_id}/{protocol} running {service_name} {version}".strip(),
                        evidence=f"Service: {service_name} | Product: {version}",
                        service_name=service_name,
                        version=version,
                    ))

                    # Extract Port-level NSE Vulnerability Scripts
                    for script_elem in port_elem.findall("script"):
                        self._extract_script_finding(result, script_elem, ip, port_id, service_name, version)

            # 5. Extract Host-level NSE Scripts
            hostscript_elem = host_elem.find("hostscript")
            if hostscript_elem is not None:
                for script_elem in hostscript_elem.findall("script"):
                    self._extract_script_finding(result, script_elem, ip, 0, "host", "")

        return result

    def _extract_script_finding(
        self,
        result: ToolResult,
        script_elem: ET.Element,
        ip: str,
        port_id: int,
        service_name: str,
        version: str
    ):
        script_id = script_elem.get("id", "")
        script_output = script_elem.get("output", "")

        cve_matches = re.findall(r"CVE-\d{4}-\d{4,7}", script_output, re.IGNORECASE)
        cvss_match = re.search(r"\b([0-9]\.[0-9]|10\.0)\b", script_output)
        cvss_score = float(cvss_match.group(1)) if cvss_match else 0.0

        if cvss_score >= 7.0 or cve_matches or "VULNERABLE" in script_output.upper():
            severity = "high"
        elif cvss_score >= 4.0:
            severity = "medium"
        else:
            severity = "info"

        result.findings.append(NormalizedFinding(
            host=ip,
            port=port_id,
            vuln_type="script_vulnerability" if severity != "info" else "script_output",
            parameter=cve_matches[0] if cve_matches else script_id,
            severity=severity,
            description=f"Nmap NSE script '{script_id}' triggered on {ip}:{port_id}",
            evidence=script_output.strip()[:1000],
            cvss_score=cvss_score,
            service_name=service_name,
            version=version,
        ))

    def _extract_xml(self, text: str) -> str:
        start = text.find("<?xml")
        if start == -1:
            start = text.find("<nmaprun")
        end = text.rfind("</nmaprun>")
        if start != -1 and end != -1:
            return text[start : end + len("</nmaprun>")]
        return text