"""Immutable audit trail — the black-box flight recorder.

Every dispatched scan command is appended to a per-day JSONL ledger with:
  * IST timestamps (Asia/Kolkata, UTC+5:30)
  * SHA-256 hash chain (each entry commits to the previous entry's hash,
    so tampering with any line invalidates every line after it)
  * secret redaction (proof of WHAT ran, never the credentials)

Append-only by design: this module only ever opens the ledger in append
mode and never edits or deletes. Verification helper included.

Never raises — audit must never break a scan.
"""

import hashlib
import json
import logging
import os
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

_IST = timezone(timedelta(hours=5, minutes=30))
_CHAIN_CACHE: dict[str, str] = {}


def _ledger_dir() -> str:
    try:
        from app.core.config import get_settings
        d = getattr(get_settings(), "AUDIT_TRAIL_DIR", "./audit_trail") or "./audit_trail"
    except Exception:
        d = os.getenv("AUDIT_TRAIL_DIR", "./audit_trail")
    try:
        os.makedirs(d, exist_ok=True)
    except Exception:
        pass
    return d


def _ledger_path() -> str:
    day = datetime.now(_IST).strftime("%Y-%m-%d")
    return os.path.join(_ledger_dir(), f"audit-{day}.jsonl")


def _tail_hash(path: str) -> str:
    """Last entry hash in the ledger (GENESIS for a fresh file)."""
    cached = _CHAIN_CACHE.get(path)
    if cached:
        return cached
    prev = "GENESIS"
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    prev = json.loads(line).get("entry_hash", prev)
                except Exception:
                    continue
    except FileNotFoundError:
        pass
    except Exception as exc:
        logger.debug(f"audit chain tail unreadable: {exc}")
    _CHAIN_CACHE[path] = prev
    return prev


def log_audit_event(engagement_id: str = "", operator: str = "",
                    command: str = "", target: str = "", **extra) -> str:
    """Append one hash-chained entry. Returns the entry hash ('' on failure)."""
    try:
        from app.core.safe_policy import redact_secrets, redact_params
        command = redact_secrets(command or "")
        target = redact_secrets(target or "")
        extra = redact_params(extra or {})
    except Exception:
        pass
    try:
        path = _ledger_path()
        prev = _tail_hash(path)
        entry = {
            "ts_ist": datetime.now(_IST).isoformat(),
            "engagement_id": str(engagement_id or ""),
            "operator": str(operator or ""),
            "command": str(command or "")[:2000],
            "target": str(target or "")[:500],
            "prev_hash": prev,
        }
        if extra:
            entry["extra"] = extra
        payload = json.dumps(entry, sort_keys=True, ensure_ascii=False)
        entry_hash = hashlib.sha256((prev + payload).encode("utf-8")).hexdigest()
        entry["entry_hash"] = entry_hash
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        _CHAIN_CACHE[path] = entry_hash
        return entry_hash
    except Exception as exc:
        logger.debug(f"audit trail write bypassed: {exc}")
        return ""


def verify_chain(path: str = "") -> tuple[bool, str]:
    """Verify the hash chain of a ledger file. Returns (ok, message)."""
    path = path or _ledger_path()
    prev = "GENESIS"
    count = 0
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                entry_hash = obj.pop("entry_hash", "")
                payload = json.dumps(obj, sort_keys=True, ensure_ascii=False)
                expected = hashlib.sha256((prev + payload).encode("utf-8")).hexdigest()
                if not hmac_compare(expected, entry_hash) or obj.get("prev_hash") != prev:
                    return False, f"Chain broken at line {lineno} of {path}"
                prev = entry_hash
                count += 1
        return True, f"Chain valid: {count} entries in {path}"
    except FileNotFoundError:
        return True, f"No ledger yet at {path}"
    except Exception as exc:
        return False, f"Verification failed: {exc}"


def hmac_compare(a: str, b: str) -> bool:
    import hmac as _hmac
    try:
        return _hmac.compare_digest(str(a), str(b))
    except Exception:
        return a == b
