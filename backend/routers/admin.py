"""
Admin Router: User management, invitation link generation, audit logs, and system status.
Strictly restricted to Admin role.
"""
import secrets
from datetime import datetime, timezone, timedelta
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.database import get_db
from backend.models import User, Invitation, AuditLog, Scan
from backend.schemas import (
    UserResponse, UserRoleUpdate, InviteCreate, InviteResponse, AuditLogResponse
)
from backend.security import require_admin
from backend.services.audit_service import log_audit_event

router = APIRouter(prefix="/api/v1/admin", tags=["Administration"])


# ============================================================================
# Users Management
# ============================================================================
@router.get("/users", response_model=List[UserResponse])
def list_users(
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    return db.query(User).order_by(desc(User.created_at)).offset(offset).limit(limit).all()


@router.patch("/users/{user_id}", response_model=UserResponse)
def update_user(
    user_id: str,
    payload: UserRoleUpdate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    old_role = target.role
    target.role = payload.role
    if payload.is_active is not None:
        target.is_active = payload.is_active
    if payload.is_approved is not None:
        target.is_approved = payload.is_approved

    db.commit()
    db.refresh(target)
    log_audit_event(db, "USER_UPDATE", "user", target.id, admin, metadata={
        "old_role": old_role, "new_role": target.role, "active": target.is_active
    })
    return target


# ============================================================================
# Invitations
# ============================================================================
@router.post("/invitations", response_model=InviteResponse, status_code=status.HTTP_201_CREATED)
def create_invitation(
    payload: InviteCreate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=payload.expires_in_days)

    invite = Invitation(
        token=token,
        email=payload.email.lower().strip(),
        role=payload.role,
        created_by_id=admin.id,
        expires_at=expires,
        created_at=now,
    )
    db.add(invite)
    db.commit()
    db.refresh(invite)

    log_audit_event(db, "INVITE_CREATE", "invitation", invite.id, admin, metadata={
        "email": invite.email, "role": invite.role
    })
    return invite


@router.get("/invitations", response_model=List[InviteResponse])
def list_invitations(
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    return db.query(Invitation).order_by(desc(Invitation.created_at)).limit(50).all()


# ============================================================================
# Audit Log
# ============================================================================
@router.get("/audit-log", response_model=List[AuditLogResponse])
def get_audit_log(
    action: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    q = db.query(AuditLog)
    if action:
        q = q.filter(AuditLog.action == action)
    return q.order_by(desc(AuditLog.created_at)).offset(offset).limit(limit).all()


# ============================================================================
# System Status & Health
# ============================================================================
@router.get("/system-status")
def get_system_status(
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    import sys, platform
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "python_version": sys.version,
        "platform": platform.platform(),
        "database": "connected",
        "total_scans": db.query(Scan).count(),
        "registered_users": db.query(User).count(),
        "scheduler_status": "running",
    }
