"""
Bulk Scan Service: CSV processing, batch job tracking, and asynchronous worker queue.
"""
import csv
import io
import threading
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple
from concurrent.futures import ThreadPoolExecutor
from sqlalchemy.orm import Session

from backend.config import settings
from backend.database import SessionLocal
from backend.models import BulkJob, User
from backend.services.scan_service import execute_scan, normalize_url

bulk_executor = ThreadPoolExecutor(max_workers=settings.MAX_WORKERS)


def parse_and_validate_csv(csv_content: bytes) -> Tuple[List[str], List[Dict[str, Any]]]:
    """
    Parses CSV content, extracts URL column, validates rows.
    Returns (valid_urls, errors_list).
    """
    if len(csv_content) > settings.MAX_UPLOAD_SIZE_BYTES:
        raise ValueError(f"File size exceeds maximum allowed limit of {settings.MAX_UPLOAD_SIZE_BYTES // (1024*1024)} MB")

    try:
        text = csv_content.decode("utf-8-sig")
    except UnicodeDecodeError:
        try:
            text = csv_content.decode("latin-1")
        except Exception:
            raise ValueError("CSV encoding could not be decoded. Please use UTF-8.")

    reader = csv.reader(io.StringIO(text))
    rows = list(reader)
    if not rows:
        raise ValueError("Uploaded CSV file is empty.")

    # Detect header
    first_row = [c.strip().lower() for c in rows[0]]
    url_col_idx = 0
    start_row = 0
    if any(h in first_row for h in ("url", "urls", "target", "link", "domain", "address")):
        for idx, h in enumerate(first_row):
            if h in ("url", "urls", "target", "link", "domain", "address"):
                url_col_idx = idx
                break
        start_row = 1

    valid_urls = []
    errors = []

    data_rows = rows[start_row:]
    if len(data_rows) > settings.MAX_BULK_ROWS:
        raise ValueError(f"CSV contains {len(data_rows)} rows. Maximum allowed per batch is {settings.MAX_BULK_ROWS}.")

    for line_num, row in enumerate(data_rows, start=start_row + 1):
        if not row:
            continue
        if url_col_idx >= len(row):
            errors.append({"line": line_num, "error": "Missing column for URL"})
            continue
        raw_val = row[url_col_idx].strip()
        if not raw_val:
            continue
        try:
            norm = normalize_url(raw_val)
            valid_urls.append(norm)
        except Exception as ex:
            errors.append({"line": line_num, "url": raw_val, "error": str(ex)})

    return valid_urls, errors


def start_bulk_scan_job(db: Session, user: User, filename: str, valid_urls: List[str], initial_errors: List[Dict[str, Any]]) -> BulkJob:
    job = BulkJob(
        user_id=user.id,
        filename=filename,
        total_urls=len(valid_urls),
        processed_urls=0,
        successful_urls=0,
        failed_urls=0,
        status="processing" if valid_urls else "completed",
        errors=initial_errors,
        created_at=datetime.now(timezone.utc),
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    if valid_urls:
        bulk_executor.submit(_process_bulk_batch, job.id, user.id, valid_urls)

    return job


def _process_bulk_batch(job_id: str, user_id: str, urls: List[str]):
    """Background task running the bulk batch."""
    db = SessionLocal()
    try:
        job = db.query(BulkJob).filter(BulkJob.id == job_id).first()
        user = db.query(User).filter(User.id == user_id).first()
        if not job:
            return

        for url in urls:
            try:
                execute_scan(db, url, initiator=user, is_bulk=True, batch_id=job.id)
                job.successful_urls += 1
            except Exception as e:
                job.failed_urls += 1
                curr_errors = list(job.errors or [])
                curr_errors.append({"url": url, "error": str(e)[:300]})
                job.errors = curr_errors

            job.processed_urls += 1
            db.commit()

        job.status = "completed"
        job.finished_at = datetime.now(timezone.utc)
        db.commit()
    except Exception as exc:
        if job:
            job.status = "failed"
            job.finished_at = datetime.now(timezone.utc)
            curr_errors = list(job.errors or [])
            curr_errors.append({"general_error": str(exc)[:300]})
            job.errors = curr_errors
            db.commit()
    finally:
        db.close()
