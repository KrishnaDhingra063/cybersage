import re
import ipaddress

HOSTNAME_REGEX = re.compile(
    r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"
)
DANGEROUS_CHARS = [";", "&", "|", "`", "$", "(", ")", "<", ">", "\n", "\r", "\\", "\t"]

def sanitize_target(target: str) -> str:
    """Blocks Command Injection and enforces strict IP/Domain format."""
    cleaned = target.strip().replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

    for char in DANGEROUS_CHARS:
        if char in cleaned:
            raise ValueError(f"Security Alert: Malicious character '{char}' detected in target.")

    try:
        ipaddress.ip_address(cleaned)
        return cleaned
    except ValueError:
        pass

    if HOSTNAME_REGEX.match(cleaned) and len(cleaned) <= 253:
        return cleaned

    raise ValueError(f"Security Alert: Target '{cleaned}' is not a valid hostname or IP address.")