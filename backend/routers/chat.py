"""
AI Security Assistant Chat Router.
Provides conversational intelligence about scan evidence and triage guidance.
"""
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import Scan, ChatMessage, User
from backend.schemas import ChatRequest, ChatMessageResponse
from backend.security import get_current_user
from backend.services.chat_service import process_chat_message

router = APIRouter(prefix="/api/v1/scans", tags=["AI Security Assistant"])


@router.post("/{scan_id}/chat", response_model=ChatMessageResponse)
def send_chat_message(
    scan_id: str,
    payload: ChatRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    assistant_msg = process_chat_message(db, scan, user, payload.message)
    return assistant_msg


@router.get("/{scan_id}/chat", response_model=List[ChatMessageResponse])
def get_chat_history(
    scan_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    messages = db.query(ChatMessage).filter(ChatMessage.scan_id == scan_id).order_by(ChatMessage.created_at).all()
    return messages
