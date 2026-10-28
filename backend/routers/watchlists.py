"""
Watchlists Router: Target monitoring and recurring schedules.
"""
from typing import List
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.database import get_db
from backend.models import Watchlist, User
from backend.schemas import WatchlistCreate, WatchlistResponse
from backend.security import get_current_user
from backend.services.watchlist_service import create_watchlist_entry
from backend.services.scan_service import execute_scan

router = APIRouter(prefix="/api/v1/watchlists", tags=["Watchlists"])


@router.get("", response_model=List[WatchlistResponse])
def list_watchlists(
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    items = db.query(Watchlist).order_by(desc(Watchlist.created_at)).offset(offset).limit(limit).all()
    return items


@router.post("", response_model=WatchlistResponse, status_code=status.HTTP_201_CREATED)
def create_watchlist(
    payload: WatchlistCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    try:
        item = create_watchlist_entry(
            db=db,
            user=user,
            name=payload.name,
            target=payload.target,
            target_type=payload.target_type,
            interval_minutes=payload.interval_minutes
        )
        return item
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.patch("/{watchlist_id}/toggle", response_model=WatchlistResponse)
def toggle_watchlist(
    watchlist_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    item = db.query(Watchlist).filter(Watchlist.id == watchlist_id).first()
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Watchlist entry not found")
    item.is_active = not item.is_active
    db.commit()
    db.refresh(item)
    return item


@router.post("/{watchlist_id}/trigger", status_code=status.HTTP_200_OK)
def trigger_watchlist_now(
    watchlist_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    item = db.query(Watchlist).filter(Watchlist.id == watchlist_id).first()
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Watchlist entry not found")
    target_url = item.target
    if item.target_type == "domain":
        target_url = f"https://{item.target}"
    scan = execute_scan(db=db, url=target_url, initiator=user)
    item.last_run_at = datetime.now(timezone.utc)
    db.commit()
    return {"message": "Scan triggered successfully", "scan_id": scan.id}


@router.delete("/{watchlist_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_watchlist(
    watchlist_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    item = db.query(Watchlist).filter(Watchlist.id == watchlist_id).first()
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Watchlist entry not found")
    db.delete(item)
    db.commit()
    return None
