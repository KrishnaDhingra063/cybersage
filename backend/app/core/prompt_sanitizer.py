import html
import re

# Maximum allowed character limit for untrusted external payloads
MAX_DATA_LEN = 2000

def sanitize_untrusted_content(raw_data: str) -> str:
    """
    Cleans and bounds untrusted network data (banners, headers, page bodies)
    to prevent delimiter escapes and prompt injection attacks.
    """
    if not raw_data:
        return ""

    text = str(raw_data).strip()

    # 1. Truncate arbitrarily long responses (e.g., massive HTML bodies)
    if len(text) > MAX_DATA_LEN:
        text = text[:MAX_DATA_LEN] + "\n...[TRUNCATED_FOR_SECURITY]"

    # 2. Escape XML/HTML delimiters to avoid closing containment tags
    text = html.escape(text, quote=True)

    # 3. Neutralize common prompt jailbreak phrases / escape sequences
    jailbreak_patterns = [
        r"ignore\s+(previous|all)\s+instructions",
        r"system\s+override",
        r"new\s+role:",
        r"<\|im_start\|>",
        r"<\|im_end\|>",
        r"\[INST\]",
        r"\[/INST\]"
    ]
    for pattern in jailbreak_patterns:
        text = re.sub(pattern, "[FILTERED_INJECTION_PATTERN]", text, flags=re.IGNORECASE)

    return text


def wrap_untrusted_context(telemetry_type: str, raw_data: str) -> str:
    """
    Wraps sanitized telemetry in strict structural delimiters for the LLM prompt.
    """
    sanitized = sanitize_untrusted_content(raw_data)
    return (
        f'<{telemetry_type} source="untrusted_network_target">\n'
        f'{sanitized}\n'
        f'</{telemetry_type}>\n'
    )