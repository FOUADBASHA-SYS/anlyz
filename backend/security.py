"""
Security, Authentication, RBAC, CSRF, and Rate-Limiting.
"""
import hashlib
import hmac
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Optional, List

import bcrypt
import jwt
from fastapi import Request, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from backend.config import settings
from backend.database import get_db
from backend.models import User, RevokedToken, ApiToken

bearer_scheme = HTTPBearer(auto_error=False)


# ============================================================================
# Password Hashing
# ============================================================================
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False


# ============================================================================
# API Token Hashing
# ============================================================================
def generate_api_token() -> tuple[str, str, str]:
    """Generates (raw_token, token_prefix, token_hash)."""
    raw_secret = secrets.token_hex(32)
    raw_token = f"xdr_{raw_secret}"
    token_prefix = raw_token[:12]
    token_hash = hash_token(raw_token)
    return raw_token, token_prefix, token_hash


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ============================================================================
# JWT Sessions
# ============================================================================
def create_session_token(user_id: str, role: str) -> tuple[str, str, datetime]:
    jti = secrets.token_hex(16)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=settings.SESSION_EXPIRE_MINUTES)
    payload = {
        "sub": user_id,
        "role": role,
        "jti": jti,
        "exp": int(expires_at.timestamp()),
        "iat": int(time.time()),
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
    return token, jti, expires_at


def decode_session_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.PyJWTError:
        return None


# ============================================================================
# CSRF Token Management
# ============================================================================
def generate_csrf_token(session_jti: str) -> str:
    mac = hmac.new(
        settings.CSRF_SECRET.encode("utf-8"),
        session_jti.encode("utf-8"),
        hashlib.sha256
    )
    return f"{session_jti}:{mac.hexdigest()[:32]}"


def verify_csrf_token(session_jti: str, csrf_token: str) -> bool:
    if not csrf_token or ":" not in csrf_token:
        return False
    jti, sig = csrf_token.split(":", 1)
    if not hmac.compare_digest(jti, session_jti):
        return False
    expected = generate_csrf_token(jti)
    return hmac.compare_digest(csrf_token, expected)


# ============================================================================
# In-Memory Rate Limiting for Login / IP Requests
# ============================================================================
_login_failures = {}  # ip/email -> [timestamps]


def check_login_rate_limit(key: str) -> bool:
    """Returns True if allowed, False if rate limited."""
    now = time.time()
    cutoff = now - 60  # 1 minute window
    failures = [t for t in _login_failures.get(key, []) if t > cutoff]
    _login_failures[key] = failures
    return len(failures) < 10


def record_login_failure(key: str):
    now = time.time()
    _login_failures.setdefault(key, []).append(now)


# ============================================================================
# Auth Dependencies
# ============================================================================
class CurrentAuth:
    def __init__(self, user: User, is_api_token: bool = False, token_scopes: Optional[List[str]] = None):
        self.user = user
        self.is_api_token = is_api_token
        self.token_scopes = token_scopes or []


def is_dt_expired(dt: Optional[datetime]) -> bool:
    if not dt:
        return False
    now = datetime.now(timezone.utc)
    val = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return val < now


def is_dt_active(dt: Optional[datetime]) -> bool:
    if not dt:
        return True
    now = datetime.now(timezone.utc)
    val = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return val >= now


async def get_current_user_optional(
    request: Request,
    db: Session = Depends(get_db),
    bearer: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> Optional[CurrentAuth]:
    """Extracts user from API token header, Bearer session, or Session Cookie."""
    # 1. Check X-API-Token header
    api_token_val = request.headers.get("X-API-Token")
    if api_token_val:
        thash = hash_token(api_token_val)
        tok = db.query(ApiToken).filter(ApiToken.token_hash == thash, ApiToken.is_active == True).first()
        if tok:
            if is_dt_expired(tok.expires_at):
                return None
            tok.last_used_at = datetime.now(timezone.utc)
            db.commit()
            return CurrentAuth(user=tok.user, is_api_token=True, token_scopes=tok.scopes or [])

    # 2. Check Bearer Authorization or Session Cookie
    raw_token = None
    from_cookie = False
    if bearer and bearer.credentials:
        raw_token = bearer.credentials
    else:
        raw_token = request.cookies.get(settings.SESSION_COOKIE_NAME)
        from_cookie = bool(raw_token)

    if not raw_token:
        return None

    # Check if raw_token is an API token
    if raw_token.startswith("xdr_"):
        thash = hash_token(raw_token)
        tok = db.query(ApiToken).filter(ApiToken.token_hash == thash, ApiToken.is_active == True).first()
        if tok and is_dt_active(tok.expires_at):
            tok.last_used_at = datetime.now(timezone.utc)
            db.commit()
            return CurrentAuth(user=tok.user, is_api_token=True, token_scopes=tok.scopes or [])
        return None

    # Decode JWT
    payload = decode_session_token(raw_token)
    if not payload:
        return None

    jti = payload.get("jti")
    # Verify not revoked
    if jti:
        rev = db.query(RevokedToken).filter(RevokedToken.jti == jti).first()
        if rev:
            return None

    user_id = payload.get("sub")
    if not user_id:
        return None

    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_active or not user.is_approved:
        return None

    # Check lockout
    if user.locked_until and is_dt_active(user.locked_until):
        return None

    # If cookie authenticated and state changing request, enforce CSRF
    if from_cookie and request.method in ("POST", "PUT", "PATCH", "DELETE"):
        csrf_header = request.headers.get("X-CSRF-Token")
        csrf_cookie = request.cookies.get(settings.CSRF_COOKIE_NAME)
        if not csrf_header or not verify_csrf_token(jti, csrf_header):
            # Also check if matching csrf_cookie
            if not csrf_cookie or csrf_cookie != csrf_header:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Invalid or missing CSRF token"
                )

    return CurrentAuth(user=user, is_api_token=False)


async def get_current_user(
    auth: Optional[CurrentAuth] = Depends(get_current_user_optional)
) -> User:
    if not auth or not auth.user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return auth.user


async def get_current_auth(
    auth: Optional[CurrentAuth] = Depends(get_current_user_optional)
) -> CurrentAuth:
    if not auth or not auth.user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return auth


def require_admin(auth: CurrentAuth = Depends(get_current_auth)) -> User:
    if auth.is_api_token:
        if "admin" not in auth.token_scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Administrative token scope required"
            )
    if auth.user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator privilege required"
        )
    return auth.user


def require_analyst_or_admin(auth: CurrentAuth = Depends(get_current_auth)) -> User:
    if auth.user.role not in ("admin", "analyst"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions"
        )
    return auth.user


def require_scope(required_scope: str):
    def checker(auth: CurrentAuth = Depends(get_current_auth)) -> User:
        if auth.is_api_token:
            if required_scope not in auth.token_scopes and "admin" not in auth.token_scopes:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"API token missing required scope: {required_scope}"
                )
        return auth.user
    return checker
