"""
Application Configuration
Loads settings from environment variables or .env file with safe defaults.
"""
import os
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "Cloud XDR URL Threat Analyzer"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    ENVIRONMENT: str = "production"

    # Database
    DATABASE_URL: str = os.environ.get(
        "DATABASE_URL",
        "postgresql+psycopg2://postgres:postgres@localhost:5432/url_analyzer"
    )
    # Automatic fallback to SQLite if PostgreSQL connection fails in standalone mode
    DB_FALLBACK_SQLITE: bool = True
    SQLITE_URL: str = "sqlite:///./url_analyzer.db"

    # Security
    SECRET_KEY: str = os.environ.get(
        "SECRET_KEY", "change-this-in-production-super-secret-key-at-least-32-chars-long"
    )
    CSRF_SECRET: str = os.environ.get(
        "CSRF_SECRET", "csrf-token-secret-change-in-production-min-32-chars"
    )
    SESSION_COOKIE_NAME: str = "xdr_session"
    CSRF_COOKIE_NAME: str = "xdr_csrf"
    COOKIE_SECURE: bool = os.environ.get("COOKIE_SECURE", "false").lower() in ("1", "true", "yes")
    COOKIE_SAMESITE: str = "lax"
    SESSION_EXPIRE_MINUTES: int = 60 * 24  # 24 hours
    MAX_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_DURATION_MINUTES: int = 15

    # Storage
    STORAGE_DIR: str = os.environ.get("STORAGE_DIR", "./storage")
    SCREENSHOT_DIR: str = os.environ.get("SCREENSHOT_DIR", "./storage/screenshots")
    REPORTS_DIR: str = os.environ.get("REPORTS_DIR", "./storage/reports")

    # Scanner / Sandbox
    ALLOW_PRIVATE: bool = os.environ.get("ALLOW_PRIVATE", "0") == "1"
    ANALYSIS_TIMEOUT_MS: int = 30000
    DETONATION_WAIT_MS: int = 3000
    MAX_WORKERS: int = int(os.environ.get("WORKERS", "4"))
    MAX_BULK_ROWS: int = 500
    MAX_UPLOAD_SIZE_BYTES: int = 5 * 1024 * 1024  # 5 MB

    # Task Queue / Redis
    REDIS_URL: Optional[str] = os.environ.get("REDIS_URL", None)

    # Optional Threat Intelligence & AI
    VT_API_KEY: Optional[str] = os.environ.get("VT_API_KEY", None)
    GSB_API_KEY: Optional[str] = os.environ.get("GSB_API_KEY", None)
    GEMINI_API_KEY: Optional[str] = os.environ.get("GEMINI_API_KEY", None)
    OPENAI_API_KEY: Optional[str] = os.environ.get("OPENAI_API_KEY", None)

    # Initial Bootstrap Admin
    INITIAL_ADMIN_EMAIL: str = os.environ.get("INITIAL_ADMIN_EMAIL", "admin@xdr.local")
    INITIAL_ADMIN_PASSWORD: str = os.environ.get("INITIAL_ADMIN_PASSWORD", "AdminPass123!")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()

# Ensure storage directories exist
os.makedirs(settings.STORAGE_DIR, exist_ok=True)
os.makedirs(settings.SCREENSHOT_DIR, exist_ok=True)
os.makedirs(settings.REPORTS_DIR, exist_ok=True)
