"""
Authentication and Session Router.
Handles login, invitation-based registration, logout, lockout protection, and CSRF tokens.
"""
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from backend.config import settings
from backend.database import get_db
from backend.models import User, Invitation, RevokedToken
from backend.schemas import UserLogin, RegisterWithInvite, UserResponse, InviteResponse
from backend.security import (
    hash_password, verify_password, create_session_token, decode_session_token,
    generate_csrf_token, check_login_rate_limit, record_login_failure,
    get_current_user
)
from backend.services.audit_service import log_audit_event

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


@router.post("/login", response_model=UserResponse)
def login(payload: UserLogin, request: Request, response: Response, db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "unknown"
    rate_key = f"{client_ip}:{payload.email}"

    if not check_login_rate_limit(rate_key):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Please wait 1 minute before retrying."
        )

    user = db.query(User).filter(User.email == payload.email.lower().strip()).first()
    now = datetime.now(timezone.utc)

    # Check lockout
    if user and user.locked_until:
        lock_dt = user.locked_until if user.locked_until.tzinfo else user.locked_until.replace(tzinfo=timezone.utc)
        if lock_dt > now:
            remaining = int((lock_dt - now).total_seconds() // 60) + 1
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Account is temporarily locked due to repeated failed logins. Try again in {remaining} minutes."
            )

    if not user or not verify_password(payload.password, user.hashed_password):
        record_login_failure(rate_key)
        if user:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= settings.MAX_LOGIN_ATTEMPTS:
                user.locked_until = now + timedelta(minutes=settings.LOCKOUT_DURATION_MINUTES)
                user.failed_login_attempts = 0
                log_audit_event(db, "ACCOUNT_LOCKED", "user", user.id, user, request, {"reason": "max_failed_attempts"})
            db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled")

    if not user.is_approved:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is pending administrator approval")

    # Successful login: reset failed attempts
    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()

    token, jti, expires_at = create_session_token(user.id, user.role)
    csrf_token = generate_csrf_token(jti)

    # Set Secure HttpOnly Cookies
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        max_age=settings.SESSION_EXPIRE_MINUTES * 60,
        path="/"
    )
    # Set readable CSRF cookie
    response.set_cookie(
        key=settings.CSRF_COOKIE_NAME,
        value=csrf_token,
        httponly=False,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        max_age=settings.SESSION_EXPIRE_MINUTES * 60,
        path="/"
    )
    # Also expose in header
    response.headers["X-CSRF-Token"] = csrf_token

    log_audit_event(db, "AUTH_LOGIN", "user", user.id, user, request)
    return user


@router.post("/register", response_model=UserResponse)
def register_with_invitation(payload: RegisterWithInvite, request: Request, response: Response, db: Session = Depends(get_db)):
    """User registration strictly restricted to valid invitation tokens."""
    now = datetime.now(timezone.utc)
    invitation = db.query(Invitation).filter(
        Invitation.token == payload.token.strip(),
        Invitation.used_at == None
    ).first()

    if invitation and invitation.expires_at:
        exp_dt = invitation.expires_at if invitation.expires_at.tzinfo else invitation.expires_at.replace(tzinfo=timezone.utc)
        if exp_dt <= now:
            invitation = None

    if not invitation:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired invitation token."
        )

    norm_email = payload.email.lower().strip()
    if invitation.email.lower() != norm_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The invitation was issued to a different email address."
        )

    existing = db.query(User).filter(User.email == norm_email).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email is already registered.")

    new_user = User(
        email=norm_email,
        hashed_password=hash_password(payload.password),
        role=invitation.role,
        is_active=True,
        is_approved=True,
        created_at=now,
    )
    db.add(new_user)
    invitation.used_at = now
    db.commit()
    db.refresh(new_user)

    token, jti, expires_at = create_session_token(new_user.id, new_user.role)
    csrf_token = generate_csrf_token(jti)

    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        max_age=settings.SESSION_EXPIRE_MINUTES * 60,
        path="/"
    )
    response.set_cookie(
        key=settings.CSRF_COOKIE_NAME,
        value=csrf_token,
        httponly=False,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        max_age=settings.SESSION_EXPIRE_MINUTES * 60,
        path="/"
    )
    response.headers["X-CSRF-Token"] = csrf_token

    log_audit_event(db, "USER_REGISTER", "user", new_user.id, new_user, request, {"invitation_id": invitation.id})
    return new_user


@router.post("/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    raw_token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if raw_token:
        payload = decode_session_token(raw_token)
        if payload and payload.get("jti"):
            rev = RevokedToken(
                jti=payload["jti"],
                user_id=payload.get("sub", ""),
                expires_at=datetime.fromtimestamp(payload.get("exp", time.time() + 3600), timezone.utc),
                created_at=datetime.now(timezone.utc),
            )
            db.add(rev)
            db.commit()

    response.delete_cookie(settings.SESSION_COOKIE_NAME, path="/")
    response.delete_cookie(settings.CSRF_COOKIE_NAME, path="/")
    return {"message": "Successfully logged out"}


@router.get("/me", response_model=UserResponse)
def get_me(user: User = Depends(get_current_user)):
    return user


@router.get("/csrf")
def get_csrf(request: Request, response: Response, user: User = Depends(get_current_user)):
    raw_token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    jti = "guest"
    if raw_token:
        payload = decode_session_token(raw_token)
        if payload:
            jti = payload.get("jti", "guest")
    csrf = generate_csrf_token(jti)
    response.set_cookie(
        key=settings.CSRF_COOKIE_NAME,
        value=csrf,
        httponly=False,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        max_age=settings.SESSION_EXPIRE_MINUTES * 60,
        path="/"
    )
    return {"csrf_token": csrf}
