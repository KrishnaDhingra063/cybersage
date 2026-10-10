"""Stdlib-only TOTP (RFC 6238) helper — no extra dependency.

Primary path uses this module so local dev works without pyotp.
If pyotp is installed (docker image), callers may use it interchangeably.
"""
import base64
import hashlib
import hmac
import secrets
import struct
import time


def random_base32(length: int = 20) -> str:
    raw = secrets.token_bytes(length)
    return base64.b32encode(raw).decode("utf-8").rstrip("=")


def _pad(secret: str) -> bytes:
    s = secret.strip().replace(" ", "").upper()
    pad = "=" * (-len(s) % 8)
    return base64.b32decode(s + pad)


def generate(secret: str, for_time: float | None = None, interval: int = 30, digits: int = 6) -> str:
    key = _pad(secret)
    counter = int((for_time if for_time is not None else time.time()) // interval)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def verify(secret: str, code: str, window: int = 1, interval: int = 30) -> bool:
    if not secret or not code:
        return False
    c = code.strip()
    if not c.isdigit():
        return False
    now = time.time()
    for drift in range(-window, window + 1):
        if hmac.compare_digest(generate(secret, now + drift * interval, interval), c):
            return True
    return False


def otpauth_url(secret: str, account: str, issuer: str = "PentestAI") -> str:
    return f"otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&digits=6&period=30"
