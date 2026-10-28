"""
Database session management and engine configuration.
Supports PostgreSQL with fallback to SQLite for local development/testing.
"""
import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import JSON

from backend.config import settings

logger = logging.getLogger("xdr.database")

Base = declarative_base()


def get_json_type():
    """Returns JSONB if on PostgreSQL, else generic JSON."""
    if "postgres" in settings.DATABASE_URL.lower():
        return JSONB
    return JSON


# Connect with fallback
def create_app_engine():
    db_url = settings.DATABASE_URL
    try:
        if "postgres" in db_url.lower():
            # Test engine connection
            eng = create_engine(
                db_url,
                pool_pre_ping=True,
                pool_size=10,
                max_overflow=20
            )
            with eng.connect():
                pass
            logger.info("Connected to PostgreSQL database.")
            return eng
    except Exception as e:
        logger.warning("Failed to connect to PostgreSQL (%s).", e)
        if not settings.DB_FALLBACK_SQLITE:
            raise

    logger.info("Using SQLite database at %s.", settings.SQLITE_URL)
    return create_engine(
        settings.SQLITE_URL,
        connect_args={"check_same_thread": False}
    )


engine = create_app_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    """FastAPI database dependency yielding a session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
