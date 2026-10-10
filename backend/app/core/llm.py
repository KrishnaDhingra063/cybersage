"""
llm_router.py
--------------
Free-tier + BYOK (Bring-Your-Own-Key) LLM routing layer with automatic
503 high-demand retry and multi-model fallback.
"""

import os
import time
import json
import logging
from dataclasses import dataclass
from typing import Optional, Callable
import httpx
from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 1. Key encryption for stored BYOK keys
# ---------------------------------------------------------------------------

def _fernet() -> Fernet:
    key = os.environ.get("APP_ENCRYPTION_KEY")
    if not key:
        raise RuntimeError("APP_ENCRYPTION_KEY is not set.")
    return Fernet(key)

def encrypt_key(raw_key: str) -> str:
    return _fernet().encrypt(raw_key.encode()).decode()

def decrypt_key(token: str) -> str:
    return _fernet().decrypt(token.encode()).decode()


# ---------------------------------------------------------------------------
# 2. Free-tier rate limiter
# ---------------------------------------------------------------------------

_free_tier_hits: dict[str, list[float]] = {}
FREE_TIER_LIMIT = 20         # requests
FREE_TIER_WINDOW_SEC = 3600  # per hour, per user

def check_free_tier_quota(user_id: str) -> bool:
    now = time.time()
    hits = [t for t in _free_tier_hits.get(user_id, []) if t > now - FREE_TIER_WINDOW_SEC]
    if len(hits) >= FREE_TIER_LIMIT:
        _free_tier_hits[user_id] = hits
        return False
    hits.append(now)
    _free_tier_hits[user_id] = hits
    return True


# ---------------------------------------------------------------------------
# 3. Provider registry & Helpers
# ---------------------------------------------------------------------------

@dataclass
class Provider:
    id: str
    display_name: str
    tier: str
    build_request: Callable[[str, str, str], tuple]
    parse_response: Callable[[httpx.Response], str]
    key_env_var: Optional[str] = None


def _get_raw_gemini_key() -> str:
    """Read GEMINI_API_KEY directly from env or backend/.env file."""
    key = os.environ.get("GEMINI_API_KEY", "")
    if key and len(key) > 10:
        return key.strip()

    current_dir = os.path.dirname(os.path.abspath(__file__))
    candidate_paths = [
        os.path.join(current_dir, "..", "..", ".env"),
        os.path.join(current_dir, "..", ".env"),
        os.path.join(os.getcwd(), ".env"),
        os.path.join(os.getcwd(), "backend", ".env"),
    ]

    for p in candidate_paths:
        if os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("GEMINI_API_KEY="):
                            val = line.split("=", 1)[1].strip().strip('"').strip("'")
                            if val:
                                return val
            except Exception:
                pass
    return ""


def _gemini_request(system, prompt, key, model_id="gemini-3.6-flash"):
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_id}:generateContent?key={key}"
    payload = {
        "contents": [
            {
                "role": "user",
                "parts": [{"text": f"System Instructions:\n{system}\n\nUser Message:\n{prompt}"}]
            }
        ],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 2048
        },
    }
    return "POST", url, {}, payload

def _gemini_parse(res: httpx.Response) -> str:
    j = res.json()
    chunks = []
    for cand in j.get("candidates", []) or []:
        content = (cand or {}).get("content", {}) or {}
        for part in content.get("parts", []) or []:
            t = (part or {}).get("text")
            if t:
                chunks.append(t)
    if chunks:
        return "".join(chunks)
    try:
        return j["candidates"][0]["content"]["parts"][0]["text"]
    except Exception:
        return ""

def _anthropic_request(system, prompt, key, model_id="claude-3-5-sonnet-20241022"):
    url = "https://api.anthropic.com/v1/messages"
    headers = {"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"}
    payload = {"model": model_id, "system": system, "messages": [{"role": "user", "content": prompt}], "max_tokens": 2048}
    return "POST", url, headers, payload

def _anthropic_parse(res: httpx.Response) -> str:
    return res.json()["content"][0]["text"]

def _openai_request(system, prompt, key, model_id="gpt-4o"):
    url = "https://api.openai.com/v1/chat/completions"
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    payload = {"model": model_id, "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}], "max_tokens": 2048}
    return "POST", url, headers, payload

def _openai_parse(res: httpx.Response) -> str:
    return res.json()["choices"][0]["message"]["content"]


PROVIDERS: dict[str, Provider] = {
    "gemini-flash": Provider("gemini-flash", "Gemini Flash (Free)", "free",
                             _gemini_request, _gemini_parse, key_env_var="GEMINI_API_KEY"),
    "claude-sonnet": Provider("claude-sonnet", "Claude Sonnet (BYOK)", "byok",
                              _anthropic_request, _anthropic_parse),
    "gpt-4o": Provider("gpt-4o", "GPT-4o (BYOK)", "byok",
                        _openai_request, _openai_parse),
}


# ---------------------------------------------------------------------------
# 4. Router Core
# ---------------------------------------------------------------------------

class LLM:
    def __init__(self):
        from app.core.config import get_settings
        self.settings = get_settings()

    def complete(self, system: str, prompt: str, max_tokens: int = 2048) -> str:
        provider = (getattr(self.settings, "LLM_PROVIDER", "") or "gemini").lower()
        gemini_key = _get_raw_gemini_key() or getattr(self.settings, "GEMINI_API_KEY", "")

        # 1. Primary path: Gemini with auto-retry and multi-endpoint fallback
        if "gemini" in provider or gemini_key:
            if not gemini_key:
                print("\n[DEBUG LLM] Failed: GEMINI_API_KEY is missing from env and backend/.env\n")
                return json.dumps({
                    "message": "GEMINI_API_KEY is not configured in backend/.env file.",
                    "actions": []
                })

            # Try primary active model, then alternative endpoints if 503 spike occurs
            models_to_try = ["gemini-3.6-flash", "gemini-flash"]
            payload = {
                "contents": [
                    {
                        "role": "user",
                        "parts": [
                            {"text": f"You are an AI security assistant.\nSystem Instructions:\n{system}\n\nTask:\n{prompt}"}
                        ]
                    }
                ],
                "generationConfig": {
                    "temperature": 0.2,
                    "maxOutputTokens": max_tokens
                },
            }

            last_error_msg = ""
            with httpx.Client(timeout=45.0) as client:
                for model_id in models_to_try:
                    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_id}:generateContent?key={gemini_key}"
                    
                    # 2 attempts per model with a small backoff delay for temporary 503 spikes
                    for attempt in range(2):
                        try:
                            res = client.post(url, json=payload)
                            print(f"[DEBUG LLM] {model_id} (Attempt {attempt+1}) -> HTTP {res.status_code}")

                            if res.status_code == 200:
                                j = res.json()
                                chunks = []
                                for cand in j.get("candidates", []) or []:
                                    content = (cand or {}).get("content", {}) or {}
                                    for part in content.get("parts", []) or []:
                                        t = (part or {}).get("text")
                                        if t:
                                            chunks.append(t)
                                if chunks:
                                    return "".join(chunks)
                                try:
                                    return j["candidates"][0]["content"]["parts"][0]["text"]
                                except Exception:
                                    return "Model executed with empty output."

                            elif res.status_code == 503:
                                last_error_msg = res.text
                                print(f"[DEBUG LLM WARN] {model_id} experienced high demand (503). Waiting 1s...")
                                time.sleep(1.0)
                                continue
                            else:
                                last_error_msg = res.text
                                break
                        except Exception as exc:
                            print(f"[DEBUG LLM EXCEPTION] {model_id}: {exc}")
                            last_error_msg = str(exc)
                            break

            return json.dumps({
                "message": f"Gemini servers are currently experiencing peak traffic (503). Please send the prompt again. ({last_error_msg[:100]})",
                "actions": []
            })

        # 2. Secondary path: OpenAI
        if provider == "openai" and getattr(self.settings, "OPENAI_API_KEY", ""):
            try:
                from openai import OpenAI
                client = OpenAI(api_key=self.settings.OPENAI_API_KEY)
                resp = client.chat.completions.create(
                    model=getattr(self.settings, "OPENAI_MODEL", "gpt-4o-mini") or "gpt-4o-mini",
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": prompt},
                    ],
                    max_tokens=max_tokens,
                )
                return resp.choices[0].message.content or ""
            except Exception as e:
                logger.error(f"OpenAI error: {e}")

        # 3. Secondary path: Anthropic
        if provider == "anthropic" and getattr(self.settings, "ANTHROPIC_API_KEY", ""):
            try:
                import anthropic
                client = anthropic.Anthropic(api_key=self.settings.ANTHROPIC_API_KEY)
                resp = client.messages.create(
                    model=getattr(self.settings, "ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022") or "claude-3-5-sonnet-20241022",
                    system=system,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=max_tokens,
                )
                return resp.content[0].text
            except Exception as e:
                logger.error(f"Anthropic error: {e}")

        return json.dumps({
            "message": "Model execution failed: No active API key found on server.",
            "actions": []
        })


_llm_instance = None

def get_llm() -> LLM:
    global _llm_instance
    if _llm_instance is None:
        _llm_instance = LLM()
    return _llm_instance