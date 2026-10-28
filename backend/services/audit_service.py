"""
Audit logging service for security-sensitive operations.
"""
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from fastapi import Request

from backend.models import AuditLog, User


def log_audit_event(
    db: Session,
    action: str,
    target_type: str,
    target_id: Optional[str] = None,
    actor: Optional[User] = None,
    request: Optional[Request] = None,
    metadata: Optional[Dict[str, Any]] = None,
):
    ip_addr = None
    uagent = None
    if request:
        # Check X-Forwarded-For or client host
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            ip_addr = forwarded.split(",")[0].strip()
        elif request.client:
            ip_addr = request.client.host
        uagent = request.headers.get("User-Agent")

    entry = AuditLog(
        user_id=actor.id if actor else None,
        user_email=actor.email if actor else None,
        action=action,
        target_type=target_type,
        target_id=str(target_id) if target_id else None,
        ip_address=ip_addr,
        user_agent=uagent[:250] if uagent else None,
        extra_metadata=metadata or {},
        created_at=datetime.now(timezone.utc),
    )
    db.add(entry)
    db.commit()
