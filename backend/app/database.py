import os
import logging
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.engine import Engine

logger = logging.getLogger(__name__)

# Fallback to local SQLite if DATABASE_URL is unspecified
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./pentest.db")

# Detect database engine type
IS_SQLITE = DATABASE_URL.startswith("sqlite")
IS_POSTGRES = DATABASE_URL.startswith("postgresql") or DATABASE_URL.startswith("postgres")

# Configure engine connection properties based on dialect
engine_kwargs = {}
if IS_SQLITE:
    engine_kwargs["connect_args"] = {"check_same_thread": False}
else:
    engine_kwargs.update({
        "pool_size": int(os.getenv("DB_POOL_SIZE", 10)),
        "max_overflow": int(os.getenv("DB_MAX_OVERFLOW", 20)),
        "pool_pre_ping": True,
    })

engine = create_engine(DATABASE_URL, **engine_kwargs)


# Enforce Foreign Keys and WAL Mode on SQLite connections
@event.listens_for(Engine, "connect")
def configure_sqlite_pragmas(dbapi_connection, connection_record):
    if IS_SQLITE:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """FastAPI dependency for yielding database sessions."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Initializes tables and extensions conditionally."""
    if IS_POSTGRES:
        with engine.begin() as conn:
            try:
                from sqlalchemy import text
                conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
                logger.info("pgvector extension confirmed/enabled.")
            except Exception as e:
                logger.warning(f"Could not initialize pgvector extension: {e}")

    # Create tables
    Base.metadata.create_all(bind=engine)