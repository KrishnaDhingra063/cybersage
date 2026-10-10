"""Central enterprise safety doctrine — single source of truth for guardrails.

Implements (and enforces in code):
 1. Non-destructive exploit whitelisting  — only safe CHECKS run, never payloads
 2. Throttling                            — nmap timing / masscan rate ceilings
 4. Scope-signature helpers               — HMAC pinning for authorizations
 7. Zero-exfiltration proofs              — secret redaction for logs & evidence
 8. Scanner identity                      — official calling-card headers

Top-level imports are stdlib-only so adapters can import this with zero
circular-import risk. Settings are read lazily inside functions.
"""

import hashlib
import hmac
import os
import re

# ---------------------------------------------------------------------------
# 1. Non-destructive exploit whitelisting
# ---------------------------------------------------------------------------

# NSE categories that can damage targets or lock accounts. Anything matching
# these is stripped from nmap --script arguments (detection-only stays).
NMAP_DENIED_SCRIPT_CATS = {"exploit", "dos", "intrusive", "brute"}

# sqlmap params that exfiltrate data or execute OS commands. build_command()
# never honors these; passing them raises instead of silently ignoring.
SQLMAP_DENIED_PARAMS = {
    "dump", "dump_all", "dump-all", "dump_table", "dump-table",
    "os_shell", "os-shell", "os_cmd", "os-cmd", "os_pwn", "os-pwn",
    "sql_shell", "sql-shell", "sql_query", "sql-query",
    "file_read", "file-read", "file_write", "file-write", "file_dest",
    "reg_read", "reg_add", "reg_del", "priv_esc", "uac_bypass",
}

# sqlmap --technique letters: B(oolean) E(rror) U(nion) S(tacked) T(ime) Q(uery).
# Stacked queries can write on misconfigured DBs — disallowed by default.
SQLMAP_ALLOWED_TECHNIQUES = set("BEUTQ")

_TIMING_ORDER = ["-T0", "-T1", "-T2", "-T3", "-T4", "-T5"]


def _get_setting(name: str, default):
    try:
        from app.core.config import get_settings
        return getattr(get_settings(), name, default)
    except Exception:
        return os.getenv(name, default)


def clamp_nmap_timing(timing: str) -> str:
    """Cap nmap timing template at NMAP_MAX_TIMING (default -T4)."""
    ceiling = str(_get_setting("NMAP_MAX_TIMING", "-T4"))
    try:
        if _TIMING_ORDER.index(timing) > _TIMING_ORDER.index(ceiling):
            return ceiling
    except ValueError:
        return "-T4"
    return timing


def strip_denied_nmap_scripts(extra_args: list) -> list:
    """Remove exploit/dos/intrusive/brute NSE selections from extra_args.

    Handles both `--script=X` and `--script X` forms. If a --script flag is
    left with no safe categories, the flag itself is dropped too.
    """
    cleaned: list = []
    skip_next = False
    for arg in extra_args:
        if skip_next:
            skip_next = False
            if _is_denied_script_value(str(arg)):
                continue
            cleaned.append(arg)
            continue
        if arg == "--script":
            # Peek handled on next iteration; keep flag tentatively.
            cleaned.append(arg)
            skip_next = True
            continue
        if isinstance(arg, str) and arg.startswith("--script="):
            value = arg.split("=", 1)[1]
            kept = _keep_safe_scripts(value)
            if kept:
                cleaned.append(f"--script={kept}")
            # else: drop the whole flag
            continue
        cleaned.append(arg)
    # Drop a trailing bare "--script" whose value was stripped.
    if cleaned and cleaned[-1] == "--script":
        cleaned.pop()
    # Drop "--script" flag whose next token was consumed as denied value:
    # (handled above by skipping) — also collapse "--script" left dangling
    # before another flag.
    final: list = []
    i = 0
    while i < len(cleaned):
        if cleaned[i] == "--script" and (i + 1 >= len(cleaned) or str(cleaned[i + 1]).startswith("-")):
            i += 1
            continue
        final.append(cleaned[i])
        i += 1
    return final


def _is_denied_script_value(value: str) -> bool:
    cats = {c.strip().lower() for c in value.split(",") if c.strip()}
    return bool(cats & NMAP_DENIED_SCRIPT_CATS)


def _keep_safe_scripts(value: str) -> str:
    kept = [c.strip() for c in value.split(",")
            if c.strip() and c.strip().lower() not in NMAP_DENIED_SCRIPT_CATS]
    return ",".join(kept)


def validate_sqlmap_params(params: dict) -> dict:
    """Enforce detection-only sqlmap usage. Raises ValueError on violations."""
    params = dict(params or {})
    denied = {k for k in params if str(k).lower().replace("-", "_") in
              {d.replace("-", "_") for d in SQLMAP_DENIED_PARAMS}}
    if denied:
        raise ValueError(
            f"Refused non-destructive policy violation: sqlmap exfiltration/execution "
            f"params are never allowed: {sorted(denied)}"
        )
    # Coerce level/risk to sane ints (detection depth, still non-destructive).
    try:
        level = int(params.get("level", 1))
    except (TypeError, ValueError):
        level = 1
    try:
        risk = int(params.get("risk", 1))
    except (TypeError, ValueError):
        risk = 1
    params["level"] = min(max(level, 1), 5)
    params["risk"] = min(max(risk, 1), 3)
    technique = params.get("technique")
    if technique:
        letters = {c.upper() for c in str(technique) if c.strip().upper() in "BEUSTQ"}
        letters -= {"S"}  # stacked queries stay off under safe-checks policy
        if not letters or not letters <= SQLMAP_ALLOWED_TECHNIQUES:
            raise ValueError(
                f"Refused sqlmap technique '{technique}': allowed letters are "
                f"{sorted(SQLMAP_ALLOWED_TECHNIQUES - {'S'})} (stacked queries disabled)"
            )
        params["technique"] = "".join(sorted(letters))
    return params


def clamp_masscan_rate(rate) -> int:
    """Cap masscan packet rate at MASSCAN_MAX_RATE (default 1000 pps)."""
    try:
        ceiling = int(_get_setting("MASSCAN_MAX_RATE", 1000))
    except (TypeError, ValueError):
        ceiling = 1000
    try:
        rate = int(rate)
    except (TypeError, ValueError):
        return min(1000, ceiling)
    return min(max(rate, 1), ceiling)


# ---------------------------------------------------------------------------
# 7/10. Zero-exfiltration proofs + in-memory-only secrets
# ---------------------------------------------------------------------------

_SECRET_PATTERNS = [
    # (name, regex) — matched value is masked, type + shape are kept
    ("aws_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws_secret", re.compile(r"(?i)(aws_secret_access_key\s*[:=]\s*)([A-Za-z0-9/+=]{20,})")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----[\s\S]{0,200}?-----END (?:RSA )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("bearer", re.compile(r"(?i)(Bearer\s+)([A-Za-z0-9\-_.]{20,})")),
    ("password", re.compile(r"(?i)((?:password|passwd|pwd|secret|api[_-]?key|token|auth|sess(?:ion)?(?:id)?|cookie)\s*[:=]\s*['\"]?)([^'\"\s;]{3,})")),
]

# Param keys whose VALUES must never hit logs/audit in cleartext.
SECRET_PARAM_KEYS = {
    "cookie", "cookies", "data", "body", "password", "passwd", "pwd",
    "secret", "token", "api_key", "apikey", "authorization", "auth",
    "rpc_pass", "rpc_user", "session", "sessionid", "set_cookie",
}


def _mask_value(value: str) -> str:
    value = str(value)
    if len(value) <= 6:
        return "***redacted***"
    return f"{value[:4]}***redacted***{value[-2:]}"


def redact_secrets(text: str) -> str:
    """Mask secret VALUES but keep finding types (proof without exfiltration)."""
    if not text:
        return text
    out = str(text)
    out = _SECRET_PATTERNS[0][1].sub(lambda m: _mask_value(m.group(0)), out)
    # Patterns with a (prefix)(secret) shape: keep prefix, mask secret.
    for _name, rx in _SECRET_PATTERNS[1:]:
        if _name in ("aws_secret", "bearer", "password"):
            out = rx.sub(lambda m: m.group(1) + _mask_value(m.group(2)), out)
        elif _name == "private_key":
            out = rx.sub("-----BEGIN PRIVATE KEY-----***redacted***-----END PRIVATE KEY-----", out)
        else:  # jwt
            out = rx.sub(lambda m: _mask_value(m.group(0)), out)
    return out


def redact_params(params: dict) -> dict:
    """Return a log-safe copy of tool params with secret values masked."""
    if not isinstance(params, dict):
        return params
    clean = {}
    for k, v in params.items():
        if str(k).lower() in SECRET_PARAM_KEYS:
            clean[k] = "***redacted***"
        elif isinstance(v, dict):
            clean[k] = redact_params(v)
        elif isinstance(v, str):
            clean[k] = redact_secrets(v)
        else:
            clean[k] = v
    return clean


# ---------------------------------------------------------------------------
# 8. Dedicated egress identity (official calling card)
# ---------------------------------------------------------------------------

def scanner_user_agent(tool: str) -> str:
    return f"PentestAI/{tool}"


def scanner_headers(tool: str, extra: dict | None = None) -> dict:
    """Identification headers stamped on every Python-driven probe request.

    Static egress IPs themselves are operational (SOC allowlist runbook in
    README); these headers are the in-traffic calling card.
    """
    identity = str(_get_setting("SCANNER_IDENTITY", "PentestAI-Authorized-Scan"))
    headers = {
        "User-Agent": scanner_user_agent(tool),
        "X-PentestAI-Authorized-Scan": identity,
    }
    if extra:
        for k, v in extra.items():
            headers.setdefault(k, v)
    return headers


# ---------------------------------------------------------------------------
# 3. Cryptographic scope pinning (HMAC-SHA256 over the authorization row)
# ---------------------------------------------------------------------------

def _signing_key() -> bytes:
    try:
        from app.core.config import get_settings
        secret = get_settings().JWT_SECRET or ""
    except Exception:
        secret = os.getenv("JWT_SECRET", "")
    return (secret or "change-me-in-production").encode()


def scope_signature(engagement_id: str, allowed, excluded, window_start, window_end) -> str:
    canonical = "|".join([
        str(engagement_id),
        ",".join(sorted(str(t) for t in (allowed or []))),
        ",".join(sorted(str(t) for t in (excluded or []))),
        str(window_start),
        str(window_end),
    ])
    return hmac.new(_signing_key(), canonical.encode(), hashlib.sha256).hexdigest()


def sign_scope(scope) -> str:
    """Compute + attach the HMAC pin for a ScopeAuthorization row (no commit)."""
    sig = scope_signature(
        scope.engagement_id, scope.allowed_targets, scope.excluded_targets,
        scope.allowed_window_start, scope.allowed_window_end,
    )
    scope.signature = sig
    return sig


def verify_scope_signature(scope) -> bool:
    stored = getattr(scope, "signature", "") or ""
    if not stored:
        return False
    expected = scope_signature(
        scope.engagement_id, scope.allowed_targets, scope.excluded_targets,
        scope.allowed_window_start, scope.allowed_window_end,
    )
    return hmac.compare_digest(stored, expected)
