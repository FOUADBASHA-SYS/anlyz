"""
Watchlist and Recurring Scan Scheduler Service.
Schedules and triggers automated background scans for monitored targets.
"""
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Optional
from sqlalchemy.orm import Session

from backend.database import SessionLocal
from backend.models import Watchlist, User
from backend.services.scan_service import execute_scan, normalize_url

_scheduler_running = False
_scheduler_thread: Optional[threading.Thread] = None


def create_watchlist_entry(db: Session, user: User, name: str, target: str, target_type: str = "url", interval_minutes: int = 1440) -> Watchlist:
    target_clean = target.strip()
    if target_type == "url":
        target_clean = normalize_url(target_clean)

    entry = Watchlist(
        name=name.strip(),
        target=target_clean,
        target_type=target_type,
        interval_minutes=interval_minutes,
        last_run_at=None,
        next_run_at=datetime.now(timezone.utc),  # Trigger right away or at scheduled time
        is_active=True,
        created_by_id=user.id,
        created_at=datetime.now(timezone.utc),
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


def run_due_watchlist_scans():
    """Checks for due watchlists and executes automated scans."""
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        due = db.query(Watchlist).filter(
            Watchlist.is_active == True,
            Watchlist.next_run_at <= now
        ).all()

        for item in due:
            try:
                target_url = item.target
                if item.target_type == "domain":
                    target_url = f"https://{item.target}"
                user = db.query(User).filter(User.id == item.created_by_id).first()
                execute_scan(db, target_url, initiator=user, is_bulk=False)
                item.last_run_at = now
                item.next_run_at = now + timedelta(minutes=item.interval_minutes)
                db.commit()
            except Exception as e:
                # Still reschedule to prevent infinite loop
                item.last_run_at = now
                item.next_run_at = now + timedelta(minutes=max(15, item.interval_minutes))
                db.commit()
    finally:
        db.close()


def _scheduler_loop():
    global _scheduler_running
    while _scheduler_running:
        try:
            run_due_watchlist_scans()
        except Exception:
            pass
        time.sleep(30)  # Check every 30 seconds


def start_scheduler():
    global _scheduler_running, _scheduler_thread
    if not _scheduler_running:
        _scheduler_running = True
        _scheduler_thread = threading.Thread(target=_scheduler_loop, daemon=True)
        _scheduler_thread.start()


def stop_scheduler():
    global _scheduler_running
    _scheduler_running = False
