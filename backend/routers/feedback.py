"""
Analyst Feedback Router: True Positive / False Positive / Needs Review labeling.
"""
from datetime import datetime, timezone
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.database import get_db
from backend.models import Scan, Finding, AnalystFeedback, User
from backend.schemas import FeedbackCreate, FeedbackResponse
from backend.security import get_current_user
from backend.services.audit_service import log_audit_event

router = APIRouter(prefix="/api/v1/scans", tags=["Analyst Feedback"])


@router.post("/{scan_id}/feedback", response_model=FeedbackResponse, status_code=status.HTTP_201_CREATED)
def submit_feedback(
    scan_id: str,
    payload: FeedbackCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    if payload.finding_id:
        f_exists = db.query(Finding).filter(Finding.id == payload.finding_id, Finding.scan_id == scan_id).first()
        if not f_exists:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not associated with this scan")

    # Check existing feedback by this user on this scan/finding to allow update rather than duplicate
    existing = db.query(AnalystFeedback).filter(
        AnalystFeedback.scan_id == scan_id,
        AnalystFeedback.finding_id == payload.finding_id,
        AnalystFeedback.user_id == user.id
    ).first()

    now = datetime.now(timezone.utc)
    if existing:
        old_verdict = existing.verdict
        existing.verdict = payload.verdict
        existing.notes = payload.notes
        existing.updated_at = now
        db.commit()
        db.refresh(existing)
        log_audit_event(db, "FEEDBACK_UPDATE", "scan", scan_id, user, metadata={
            "old_verdict": old_verdict, "new_verdict": payload.verdict, "finding_id": payload.finding_id
        })
        return existing

    feedback = AnalystFeedback(
        scan_id=scan_id,
        finding_id=payload.finding_id,
        user_id=user.id,
        verdict=payload.verdict,
        notes=payload.notes,
        created_at=now,
        updated_at=now,
    )
    db.add(feedback)
    db.commit()
    db.refresh(feedback)

    log_audit_event(db, "FEEDBACK_CREATE", "scan", scan_id, user, metadata={
        "verdict": payload.verdict, "finding_id": payload.finding_id
    })
    return feedback


@router.get("/{scan_id}/feedback", response_model=List[FeedbackResponse])
def get_scan_feedback(
    scan_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    items = db.query(AnalystFeedback).filter(AnalystFeedback.scan_id == scan_id).order_by(desc(AnalystFeedback.created_at)).all()
    return items
