"""Encrypted backup export (founder only via admin API).

Encrypts a JSON snapshot of core tables with Fernet. Key resolution:
BACKUP_KEY env (Fernet key) -> derived from JWT_SECRET -> raises if neither.
"""
import base64
import hashlib
import json
import os
from datetime import datetime, timezone


def _fernet():
    from cryptography.fernet import Fernet

    key = os.getenv("BACKUP_KEY", "").strip()
    if key:
        return Fernet(key.encode() if isinstance(key, str) else key)
    jwt_secret = os.getenv("JWT_SECRET", "")
    # also try settings (backend/.env loaded via config)
    if not jwt_secret:
        try:
            from app.core.config import get_settings
            jwt_secret = get_settings().JWT_SECRET or ""
        except Exception:
            jwt_secret = ""
    if not jwt_secret:
        raise RuntimeError("No BACKUP_KEY or JWT_SECRET configured for backup encryption")
    digest = hashlib.sha256(jwt_secret.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def build_snapshot(db) -> dict:
    from app.models.models import User, Engagement, Finding, Host

    def ser(rows, fields):
        out = []
        for r in rows:
            d = {}
            for f in fields:
                try:
                    v = getattr(r, f, None)
                    d[f] = str(v) if v is not None and not isinstance(v, (str, int, float, bool)) else v
                except Exception:
                    d[f] = None
            out.append(d)
        return out

    return {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "users": ser(db.query(User).all(), ["id", "username", "email", "role", "is_founder", "is_active", "created_at"]),
        "engagements": ser(db.query(Engagement).all(), ["id", "name", "client_name", "status", "test_type", "created_at"]),
        "hosts": ser(db.query(Host).limit(1000).all(), ["id", "engagement_id", "ip_address", "hostname", "status"]),
        "findings": ser(db.query(Finding).limit(2000).all(), ["id", "engagement_id", "vuln_type", "severity", "status", "cvss_score"]),
    }


def encrypt_snapshot(snapshot: dict) -> bytes:
    return _fernet().encrypt(json.dumps(snapshot).encode())


def decrypt_snapshot(blob: bytes) -> dict:
    return json.loads(_fernet().decrypt(blob).decode())
