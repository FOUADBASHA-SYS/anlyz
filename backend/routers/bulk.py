"""
Bulk Scan Router: CSV upload, batch job status, and history.
"""
from typing import List
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.database import get_db
from backend.models import BulkJob, User
from backend.schemas import BulkJobResponse
from backend.security import get_current_user
from backend.services.bulk_service import parse_and_validate_csv, start_bulk_scan_job

router = APIRouter(prefix="/api/v1/bulk", tags=["Bulk Scanning"])


@router.post("/upload", response_model=BulkJobResponse, status_code=status.HTTP_202_ACCEPTED)
async def upload_bulk_csv(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    if not file.filename.lower().endswith((".csv", ".txt")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only CSV or plaintext URL files are supported."
        )

    content = await file.read()
    try:
        valid_urls, initial_errors = parse_and_validate_csv(content)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    job = start_bulk_scan_job(
        db=db,
        user=user,
        filename=file.filename,
        valid_urls=valid_urls,
        initial_errors=initial_errors
    )
    return job


@router.get("/jobs", response_model=List[BulkJobResponse])
def list_bulk_jobs(
    limit: int = 20,
    offset: int = 0,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    jobs = db.query(BulkJob).order_by(desc(BulkJob.created_at)).offset(offset).limit(limit).all()
    return jobs


@router.get("/jobs/{job_id}", response_model=BulkJobResponse)
def get_bulk_job(
    job_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    job = db.query(BulkJob).filter(BulkJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Bulk job not found")
    return job
