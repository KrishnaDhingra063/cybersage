import hashlib
import re
import urllib.parse
from typing import Any, Dict, Optional
from uuid import UUID

from sqlalchemy.orm import Session

from app.models.models import Finding, utcnow


class FingerprintGenerator:
    """
    Generates deterministic, canonical SHA-256 fingerprints 
    for vulnerability findings to prevent duplicate database records.
    """

    @classmethod
    def canonicalize_host(cls, host: str) -> str:
        """Normalizes hostnames and IP addresses to lowercase stripped strings."""
        if not host:
            return ""
        host = host.strip().lower()
        if "://" in host:
            parsed = urllib.parse.urlparse(host)
            return (parsed.hostname or host).lower()
        return host.split("/")[0]

    @classmethod
    def canonicalize_port(cls, port: Optional[int]) -> str:
        """Ensures a valid string integer port representation."""
        if not port or port < 0:
            return "0"
        return str(int(port))

    @classmethod
    def canonicalize_vuln_type(cls, vuln_type: str) -> str:
        """
        Normalizes tool-specific vulnerability identifiers into canonical categories.
        Strips tool prefixes like 'nuclei_', 'zap_', 'nikto_'.
        """
        if not vuln_type:
            return "unknown"
        
        v = vuln_type.strip().lower()
        v = re.sub(r"^(nuclei_|zap_|nikto_|msf_)", "", v)
        
        if any(term in v for term in ["sql_injection", "sqli"]):
            return "sqli"
        if any(term in v for term in ["cross_site_scripting", "xss"]):
            return "xss"
        if any(term in v for term in ["missing_security_header", "missing_header", "header_missing"]):
            return "missing_security_header"
        if any(term in v for term in ["directory_listing", "directory_indexing"]):
            return "directory_listing"
        if any(term in v for term in ["sensitive_file", "sensitive_path", "exposure"]):
            return "sensitive_exposure"
        
        return v

    @classmethod
    def canonicalize_parameter(cls, parameter: str) -> str:
        """
        Normalizes paths and parameters so variable formatting doesn't break deduplication.
        e.g., '/api/v1/users/' and '/api/v1/users' produce the identical canonical parameter.
        """
        if not parameter:
            return ""
        
        param = parameter.strip().lower()
        if "://" in param:
            parsed = urllib.parse.urlparse(param)
            param = parsed.path
        
        param = re.sub(r"/+", "/", param).rstrip("/")
        return param or "/"

    @classmethod
    def generate(cls, host: str, port: int, vuln_type: str, parameter: str) -> str:
        """
        Computes the SHA-256 digest of the canonical string:
        canonical_host|canonical_port|canonical_vuln_type|canonical_parameter
        """
        c_host = cls.canonicalize_host(host)
        c_port = cls.canonicalize_port(port)
        c_vuln = cls.canonicalize_vuln_type(vuln_type)
        c_param = cls.canonicalize_parameter(parameter)

        key_material = f"{c_host}|{c_port}|{c_vuln}|{c_param}".encode("utf-8")
        return hashlib.sha256(key_material).hexdigest()


# =====================================================================
# Functional Exports Expected by scans.py, decision_loop.py & tests
# =====================================================================

def compute_fingerprint(
    host: str,
    port: int,
    vuln_type: str,
    parameter: str = ""
) -> str:
    """
    Convenience wrapper around FingerprintGenerator.generate.
    """
    return FingerprintGenerator.generate(
        host=host,
        port=port,
        vuln_type=vuln_type,
        parameter=parameter,
    )


def upsert_finding(
    db: Session,
    engagement_id: Any,
    finding_data: Optional[Dict[str, Any]] = None,
    host: str = "",
    port: int = 0,
    vuln_type: str = "",
    parameter: str = "",
    **kwargs: Any,
) -> Finding:
    """
    Deduplicates and upserts a vulnerability finding.

    Accepts parameters either via a dictionary (finding_data) or as direct kwargs.
    If a finding with the same fingerprint exists under the engagement, it updates
    last_seen, increments occurrences, and preserves the most detailed evidence.
    Otherwise, creates a new Finding entry.
    """
    data: Dict[str, Any] = {}
    if finding_data:
        data.update(finding_data)
    data.update(kwargs)

    # Resolve core values with fallback priorities
    target_host = host or data.get("host") or data.get("target") or ""
    target_port = port if port else data.get("port", 0)
    target_vuln = vuln_type or data.get("vuln_type") or data.get("title") or "unknown"
    target_param = parameter or data.get("parameter") or data.get("path") or ""

    # Generate canonical fingerprint if not already provided
    fingerprint = data.get("fingerprint")
    if not fingerprint:
        fingerprint = compute_fingerprint(
            host=target_host,
            port=target_port,
            vuln_type=target_vuln,
            parameter=target_param,
        )

    # Check for existing duplicate finding within this engagement
    existing_finding = (
        db.query(Finding)
        .filter(
            Finding.engagement_id == engagement_id,
            Finding.fingerprint == fingerprint,
        )
        .first()
    )

    now = utcnow()

    if existing_finding:
        existing_finding.last_seen = now
        existing_finding.occurrences = (existing_finding.occurrences or 1) + 1

        # Optionally update cvss_score and severity if newly observed score is higher
        new_cvss = float(data.get("cvss_score", 0.0) or 0.0)
        if new_cvss > (existing_finding.cvss_score or 0.0):
            existing_finding.cvss_score = new_cvss
            if data.get("severity"):
                existing_finding.severity = data["severity"]

        if data.get("evidence") and not existing_finding.evidence:
            existing_finding.evidence = data["evidence"]

        db.commit()
        db.refresh(existing_finding)
        return existing_finding

    # Create new Finding instance
    new_finding = Finding(
        engagement_id=engagement_id,
        host_id=data.get("host_id"),
        service_id=data.get("service_id"),
        source_tool=data.get("source_tool", "orchestrator"),
        vuln_type=target_vuln,
        parameter=target_param,
        severity=data.get("severity", "info"),
        description=data.get("description", ""),
        evidence=data.get("evidence", ""),
        cvss_score=float(data.get("cvss_score", 0.0) or 0.0),
        fingerprint=fingerprint,
        occurrences=1,
        status=data.get("status", "open"),
        first_seen=now,
        last_seen=now,
    )

    db.add(new_finding)
    db.commit()
    db.refresh(new_finding)
    return new_finding
