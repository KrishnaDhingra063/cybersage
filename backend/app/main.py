from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Depends, Request
from starlette.middleware.base import BaseHTTPMiddleware
from app.api import auth, engagements, findings, fixes, reasoning, reports, scans, agent, users, groups, admin
from app.models.database import engine, Base
from app.core.security import require_auth
from app.models.models import User as AuthUser


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """OWASP baseline headers. Permissive enough for Vite dev (inline scripts/styles)."""

    async def dispatch(self, request: Request, call_next):
        resp = await call_next(request)
        try:
            resp.headers["X-Content-Type-Options"] = "nosniff"
            resp.headers["X-Frame-Options"] = "DENY"
            resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
            resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
            if request.url.path.startswith("/api/"):
                resp.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
        except Exception:
            pass
        return resp


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create tables if they don't exist (Alembic handles migrations in prod)
    Base.metadata.create_all(bind=engine)
    # Ensure user profile columns exist for existing SQLite/Postgres DBs (surgical migration)
    try:
        from sqlalchemy import text, inspect

        insp = inspect(engine)
        if "users" in insp.get_table_names():
            cols = {c["name"] for c in insp.get_columns("users")}
            to_add = []
            if "is_founder" not in cols:
                to_add.append("is_founder BOOLEAN DEFAULT 0")
            if "bio" not in cols:
                to_add.append("bio TEXT DEFAULT ''")
            if "phone_number" not in cols:
                to_add.append("phone_number VARCHAR(20)")
            if "full_name" not in cols:
                to_add.append("full_name VARCHAR(100)")
            if "reset_otp" not in cols:
                to_add.append("reset_otp VARCHAR(10)")
            if "otp_expires_at" not in cols:
                to_add.append("otp_expires_at TIMESTAMP")
            if "totp_secret" not in cols:
                to_add.append("totp_secret TEXT")
            if "totp_enabled" not in cols:
                to_add.append("totp_enabled BOOLEAN DEFAULT 0")
            # Cryptographic scope pin (enterprise safety feature #3)
            try:
                scope_cols = {c["name"] for c in insp.get_columns("scope_authorizations")}
                if "signature" not in scope_cols:
                    with engine.begin() as conn:
                        if engine.dialect.name == "postgresql":
                            conn.execute(text("ALTER TABLE scope_authorizations ADD COLUMN IF NOT EXISTS signature TEXT DEFAULT ''"))
                        else:
                            conn.execute(text("ALTER TABLE scope_authorizations ADD COLUMN signature TEXT DEFAULT ''"))
            except Exception:
                pass
            for col_def in to_add:
                try:
                    with engine.begin() as conn:
                        # Postgres supports IF NOT EXISTS, SQLite ignores but we already checked
                        if engine.dialect.name == "postgresql":
                            conn.execute(text(f"ALTER TABLE users ADD COLUMN IF NOT EXISTS {col_def}"))
                        else:
                            conn.execute(text(f"ALTER TABLE users ADD COLUMN {col_def}"))
                except Exception:
                    pass
    except Exception:
        pass
    yield


app = FastAPI(
    title="AI Pentesting Platform",
    description="AI-orchestrated penetration testing with reasoning transparency and finding deduplication",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS: explicit origins required when allow_credentials=True (wildcard "*" is rejected by browsers)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SecurityHeadersMiddleware)

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(engagements.router)
app.include_router(findings.router)
app.include_router(reasoning.router)
app.include_router(fixes.router)
app.include_router(reports.router)
app.include_router(scans.router)
app.include_router(agent.router)
app.include_router(groups.router)
app.include_router(admin.router)


@app.get("/health")
def health_check():
    return {"status": "healthy"}


@app.get("/api/stats")
def platform_stats(user: AuthUser = Depends(require_auth)):
    from sqlalchemy.orm import Session
    from app.models.database import SessionLocal
    from app.models.models import Engagement, Finding, ReasoningLog, ToolJob

    db = SessionLocal()
    try:
        return {
            "engagements": db.query(Engagement).count(),
            "findings": db.query(Finding).count(),
            "reasoning_entries": db.query(ReasoningLog).count(),
            "tool_jobs": db.query(ToolJob).count(),
        }
    finally:
        db.close()
