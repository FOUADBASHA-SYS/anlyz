"""
API Token Management Router for programmatic XDR integrations.
"""
from datetime import datetime, timezone, timedelta
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.database import get_db
from backend.models import ApiToken, User
from backend.schemas import TokenCreate, TokenCreateResponse, TokenResponse
from backend.security import get_current_user, generate_api_token
from backend.services.audit_service import log_audit_event

router = APIRouter(prefix="/api/v1/tokens", tags=["API Tokens"])


@router.get("", response_model=List[TokenResponse])
def list_api_tokens(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    tokens = db.query(ApiToken).filter(ApiToken.user_id == user.id, ApiToken.is_active == True).order_by(desc(ApiToken.created_at)).all()
    return tokens


@router.post("", response_model=TokenCreateResponse, status_code=status.HTTP_201_CREATED)
def create_new_api_token(
    payload: TokenCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    raw_token, prefix, thash = generate_api_token()
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=payload.expires_in_days) if payload.expires_in_days else None

    # Enforce least privilege: analyst cannot create 'admin' scope token
    scopes = payload.scopes or ["scans:read", "scans:write"]
    if "admin" in scopes and user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot assign 'admin' scope with analyst role."
        )

    tok = ApiToken(
        user_id=user.id,
        name=payload.name.strip(),
        token_prefix=prefix,
        token_hash=thash,
        scopes=scopes,
        expires_at=expires_at,
        is_active=True,
        created_at=now
    )
    db.add(tok)
    db.commit()
    db.refresh(tok)

    log_audit_event(db, "TOKEN_CREATE", "api_token", tok.id, user, metadata={
        "token_prefix": prefix, "scopes": scopes
    })

    return TokenCreateResponse(
        id=tok.id,
        name=tok.name,
        token=raw_token,  # ONLY DISPLAYED ONCE!
        token_prefix=prefix,
        scopes=tok.scopes,
        expires_at=tok.expires_at,
        created_at=tok.created_at
    )


@router.delete("/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_api_token(
    token_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    tok = db.query(ApiToken).filter(ApiToken.id == token_id, ApiToken.user_id == user.id).first()
    if not tok:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Token not found")
    tok.is_active = False
    db.commit()
    log_audit_event(db, "TOKEN_REVOKE", "api_token", tok.id, user, metadata={"prefix": tok.token_prefix})
    return None
