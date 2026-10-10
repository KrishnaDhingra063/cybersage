import fnmatch
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse
from sqlalchemy.orm import Session  # type: ignore
from app.models.models import ScopeAuthorization, Engagement


class ScopeViolation(Exception):
    pass


class ApprovalRequired(Exception):
    """Raised when a decision tries to skip approval for a high-risk tool."""
    pass


HIGH_RISK_TOOLS = {"metasploit", "sqlmap", "hashcat"}


class AutonomyLevels:
    """How much the AI is permitted to do without human sign-off."""
    SUGGEST_ONLY = "suggest_only"   # AI only proposes; nothing auto-runs
    HUMAN_GATED = "human_gated"     # default: recon auto, everything else approved
    AUTONOMOUS = "autonomous"       # auto-run within scope (never bypasses HIGH_RISK_TOOLS)


def is_target_in_scope(db: Session, engagement_id: str, target: str) -> bool:
    auth = (
        db.query(ScopeAuthorization)
        .filter(
            ScopeAuthorization.engagement_id == engagement_id,
            ScopeAuthorization.approved == True,
        )
        .first()
    )

    if not auth:
        raise ScopeViolation(f"No approved scope authorization for engagement {engagement_id}")

    # Check authorized execution window (normalize naive SQLite datetimes to UTC)
    now = datetime.now(timezone.utc)
    _start = auth.allowed_window_start
    _end = auth.allowed_window_end
    try:
        if _start is not None and _start.tzinfo is None:
            _start = _start.replace(tzinfo=timezone.utc)
        if _end is not None and _end.tzinfo is None:
            _end = _end.replace(tzinfo=timezone.utc)
    except Exception:
        pass
    if not (_start <= now <= _end):
        raise ScopeViolation(
            f"Current time {now.isoformat()} is outside allowed window "
            f"[{auth.allowed_window_start} — {auth.allowed_window_end}]"
        )

    # 1b. Cryptographic scope pin (enterprise safety feature #3): the HMAC
    # signature committed at approval time must still match the row. Any
    # DB-level tampering with targets/window breaks the pin -> block.
    try:
        from app.core.safe_policy import verify_scope_signature, sign_scope
        if getattr(auth, "signature", ""):
            if not verify_scope_signature(auth):
                raise ScopeViolation(
                    "Scope authorization signature INVALID — the approved target "
                    "list may have been tampered with. Have a Lead re-approve the scope."
                )
        else:
            # Legacy row from before pinning: self-heal by signing now.
            try:
                sign_scope(auth)
                db.commit()
            except Exception:
                try:
                    db.rollback()
                except Exception:
                    pass
    except ScopeViolation:
        raise
    except Exception:
        pass

    parsed_target = _parse_target(target)

    # 1. Verify target falls inside allowed rules
    in_allowed = False
    for allowed in (auth.allowed_targets or []):
        if _target_matches_range(parsed_target, allowed):
            in_allowed = True
            break

    if not in_allowed:
        raise ScopeViolation(f"Target '{target}' ({parsed_target}) is not in allowed targets: {auth.allowed_targets}")

    # 2. Verify target does not hit exclusions
    for excluded in (auth.excluded_targets or []):
        if _target_matches_range(parsed_target, excluded):
            raise ScopeViolation(f"Target '{target}' ({parsed_target}) is in excluded list: {auth.excluded_targets}")

    # 3. Check active engagement status
    engagement = db.query(Engagement).filter(Engagement.id == engagement_id).first()
    if engagement and engagement.status != "active":
        raise ScopeViolation(f"Engagement is not active (status={engagement.status})")

    return True


def _parse_target(target: str) -> str:
    """
    Cleans URLs, paths, and ports to isolate bare IP or domain.
    Examples:
      - 'https://api.target.com:8443/v1' -> 'api.target.com'
      - 'http://192.168.1.50:8080'       -> '192.168.1.50'
      - '10.0.0.1'                      -> '10.0.0.1'
    """
    if not target:
        raise ScopeViolation("Target string cannot be empty.")
    
    target = target.strip()

    # Extract hostname from URLs
    if "://" in target:
        parsed = urlparse(target)
        if parsed.hostname:
            return parsed.hostname.lower()

    # Strip port if host:port (avoiding IPv6 collision)
    if ":" in target and not target.count(":") > 1:
        target = target.split(":")[0]

    target = target.strip("/").lower()

    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        return target


def _target_matches_range(target: str, cidr_or_domain: str) -> bool:
    """Evaluates IP/CIDR ranges, exact domain matches, and domain wildcards.

    A rule of "*" (or "0.0.0.0/0" for IPs) means GLOBAL — every target is
    authorized. Global scopes still need Lead approval + valid time window +
    active engagement; only the target allowlist is opened up.
    """
    cidr_or_domain = cidr_or_domain.strip().lower()

    # Global wildcard — any target authorized (exclusions still apply)
    if cidr_or_domain in ("*", "0.0.0.0/0", "internet"):
        return True

    # IP / CIDR check
    try:
        network = ipaddress.ip_network(cidr_or_domain, strict=False)
        try:
            return ipaddress.ip_address(target) in network
        except ValueError:
            return False
    except ValueError:
        pass

    # Exact string match
    if target == cidr_or_domain:
        return True

    # Wildcard domain check (*.example.com)
    if cidr_or_domain.startswith("*."):
        root_domain = cidr_or_domain[2:]
        if target == root_domain or target.endswith("." + root_domain):
            return True

    return fnmatch.fnmatch(target, cidr_or_domain)


def check_recon_auto_approved(action_type: str, risk_level: str) -> bool:
    from app.core.config import get_settings
    settings = get_settings()

    if action_type == "scan" and risk_level == "low" and settings.AUTO_APPROVE_RECON:
        return True
    if action_type in ("exploit_attempt", "credential_test") and settings.REQUIRE_APPROVAL_EXPLOIT:
        return False
    return False


def enforce_high_risk_approval(tool_name: str, requires_approval: bool) -> None:
    if tool_name in HIGH_RISK_TOOLS and not requires_approval:
        raise ApprovalRequired(
            f"'{tool_name}' always requires human approval — "
            f"this cannot be bypassed by the decision object."
        )   