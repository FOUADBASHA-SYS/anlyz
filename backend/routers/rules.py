"""
Rules Router: Allowlist and Blocklist CRUD operations.
Role-based access: Admin can create and delete; analysts can view.
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.database import get_db
from backend.models import Blocklist, Allowlist, User
from backend.schemas import RuleCreate, RuleResponse
from backend.security import get_current_user, require_admin
from backend.services.rules_service import add_blocklist_rule, add_allowlist_rule
from backend.services.audit_service import log_audit_event

router = APIRouter(prefix="/api/v1/rules", tags=["Allowlist & Blocklist"])


# ============================================================================
# Blocklist
# ============================================================================
@router.get("/blocklist", response_model=List[RuleResponse])
def get_blocklist(
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    return db.query(Blocklist).order_by(desc(Blocklist.created_at)).offset(offset).limit(limit).all()


@router.post("/blocklist", response_model=RuleResponse, status_code=status.HTTP_201_CREATED)
def create_blocklist_entry(
    payload: RuleCreate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    rule = add_blocklist_rule(
        db=db,
        pattern=payload.pattern,
        pattern_type=payload.pattern_type,
        reason=payload.reason,
        creator=admin,
        expires_at=payload.expires_at
    )
    return rule


@router.delete("/blocklist/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_blocklist_entry(
    rule_id: str,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    rule = db.query(Blocklist).filter(Blocklist.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    log_audit_event(db, "BLOCKLIST_DELETE", "blocklist", rule.id, admin, metadata={"pattern": rule.pattern})
    db.delete(rule)
    db.commit()
    return None


# ============================================================================
# Allowlist
# ============================================================================
@router.get("/allowlist", response_model=List[RuleResponse])
def get_allowlist(
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    return db.query(Allowlist).order_by(desc(Allowlist.created_at)).offset(offset).limit(limit).all()


@router.post("/allowlist", response_model=RuleResponse, status_code=status.HTTP_201_CREATED)
def create_allowlist_entry(
    payload: RuleCreate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    rule = add_allowlist_rule(
        db=db,
        pattern=payload.pattern,
        pattern_type=payload.pattern_type,
        reason=payload.reason,
        creator=admin,
        expires_at=payload.expires_at
    )
    return rule


@router.delete("/allowlist/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_allowlist_entry(
    rule_id: str,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    rule = db.query(Allowlist).filter(Allowlist.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    log_audit_event(db, "ALLOWLIST_DELETE", "allowlist", rule.id, admin, metadata={"pattern": rule.pattern})
    db.delete(rule)
    db.commit()
    return None
