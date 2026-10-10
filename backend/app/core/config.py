from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+asyncpg://pentest:pentest@localhost:5432/pentest_platform"
    DATABASE_URL_SYNC: str = "postgresql://pentest:pentest@localhost:5432/pentest_platform"
    REDIS_URL: str = "redis://localhost:6379/0"

    ANTHROPIC_API_KEY: str = ""
    ANTHROPIC_MODEL: str = "claude-sonnet-4-20250514"
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4o-mini"
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-2.0-flash"
    EMBEDDING_MODEL: str = "text-embedding-3-small"

    # LLM provider for the AI reasoning layer.
    # Options: "anthropic" | "openai" | "ollama" | "gemini"
    # "ollama" points at a LOCAL model (air-gapped / self-hosted mode) —
    # no data leaves the network.
    LLM_PROVIDER: str = "gemini"
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3.1"
    GOOGLE_CLIENT_ID: str = ""
    JWT_SECRET: str = "change-me-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_HOURS: int = 12

    # 1-click GitHub PR creation
    GITHUB_TOKEN: str = ""
    GITHUB_REPO: str = ""  # e.g. owner/repo
    GITHUB_BASE_BRANCH: str = "main"

    DOCKER_TOOL_IMAGE: str = "kali-tools:latest"
    # Enterprise sandbox hardening (features #2 + #9). Flags are appended to
    # every `docker run` in adapters/base.py; disable only for debugging.
    DOCKER_HARDENED: bool = True
    DOCKER_ROOTLESS: bool = True
    DOCKER_PIDS_LIMIT: int = 256
    # Throttle ceilings (feature #4) + scanner calling card (feature #8).
    NMAP_MAX_TIMING: str = "-T4"
    MASSCAN_MAX_RATE: int = 1000
    SCANNER_IDENTITY: str = "PentestAI-Authorized-Scan"
    # Flight-recorder ledger directory (feature #5).
    AUDIT_TRAIL_DIR: str = "./audit_trail"
    # Optional explicit Docker endpoint, e.g. tcp://localhost:2375 when the
    # Windows named pipe is flaky. Empty = default pipe/socket.
    DOCKER_HOST: str = ""
    USE_DOCKER: bool = False
    TOOL_TIMEOUT_SECONDS: int = 600

    AUTO_APPROVE_RECON: bool = True
    REQUIRE_APPROVAL_EXPLOIT: bool = True

    class Config:
        env_file = ".env"
        extra = "ignore"


@lru_cache()
def get_settings() -> Settings:
    return Settings()
