import re
from typing import Tuple

# High-risk token & credential patterns
PATTERNS = {
    "AWS_KEY": r"(?i)\b(AKIA[0-9A-Z]{16})\b",
    "PRIVATE_KEY": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "JWT_TOKEN": r"\beyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\b",
    "GENERIC_SECRET": r"(?i)(?:api_key|access_token|client_secret|auth_token|secret_key|db_password)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-.~!@#$%^&*]{8,})['\"]?",
    "BASIC_AUTH_HEADER": r"(?i)Authorization:\s*Basic\s+[a-zA-Z0-9+/=]+",
    "BEARER_AUTH_HEADER": r"(?i)Authorization:\s*Bearer\s+[a-zA-Z0-9_\-\.]+",
}

def sanitize_tool_output(raw_text: str) -> Tuple[str, int]:
    """
    Scans stdout/stderr from active tools and redacts high-risk credentials,
    cryptographic keys, and session tokens before LLM context ingestion.
    """
    if not raw_text:
        return "", 0

    sanitized = raw_text
    total_redactions = 0

    # 1. Strip Full Private Key Blocks
    if re.search(PATTERNS["PRIVATE_KEY"], sanitized):
        sanitized, count = re.subn(PATTERNS["PRIVATE_KEY"], "[REDACTED_RSA_PRIVATE_KEY]", sanitized)
        total_redactions += count

    # 2. Strip Specific Known Tokens
    for token_type, pattern in PATTERNS.items():
        if token_type == "PRIVATE_KEY":
            continue
        matches = re.findall(pattern, sanitized)
        if matches:
            sanitized, count = re.subn(pattern, f"[REDACTED_{token_type}]", sanitized)
            total_redactions += count

    return sanitized, total_redactions