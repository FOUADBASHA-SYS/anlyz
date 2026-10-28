"""
Scans Router: Submission, history, search/filter, detail, rescan,
comparison, screenshot serving, and report export.
"""
import os
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_

from backend.config import settings
from backend.database import get_db
from backend.models import Scan, User
from backend.schemas import (
    ScanCreate, ScanResponse, ScanDetailResponse, ScanCompareResponse
)
from backend.security import get_current_user, require_scope, get_current_user_optional, CurrentAuth
from backend.services.scan_service import execute_scan, compare_scans
from backend.services.report_service import build_scan_json_export, generate_scan_pdf_report
from analyzer import UnsafeURL

router = APIRouter(tags=["Scans"])


# ============================================================================
# API v1 Scans
# ============================================================================
@router.post("/api/v1/scans", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def create_scan(
    payload: ScanCreate,
    db: Session = Depends(get_db),
    auth: Optional[CurrentAuth] = Depends(get_current_user_optional)
):
    user = auth.user if auth else None
    try:
        scan = execute_scan(
            db=db,
            url=payload.url,
            initiator=user,
            allow_private=payload.allow_private or settings.ALLOW_PRIVATE
        )
        return scan
    except UnsafeURL as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/api/v1/scans", response_model=List[ScanResponse])
def list_scans(
    q: Optional[str] = Query(None, description="Search query by URL or domain"),
    threat_level: Optional[str] = Query(None, pattern="^(Low|Medium|High|Critical)$"),
    status: Optional[str] = Query(None),
    min_score: Optional[int] = Query(None, ge=0, le=100),
    max_score: Optional[int] = Query(None, ge=0, le=100),
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    query = db.query(Scan)

    # Server-side auth: analysts & admins see system scans; guests see none
    if q:
        term = f"%{q.strip().lower()}%"
        query = query.filter(or_(Scan.url.ilike(term), Scan.normalized_domain.ilike(term)))
    if threat_level:
        query = query.filter(Scan.threat_level == threat_level)
    if status:
        query = query.filter(Scan.status == status)
    if min_score is not None:
        query = query.filter(Scan.threat_score >= min_score)
    if max_score is not None:
        query = query.filter(Scan.threat_score <= max_score)

    scans = query.order_by(desc(Scan.created_at)).offset(offset).limit(limit).all()
    return scans


@router.get("/api/v1/scans/{scan_id}", response_model=ScanDetailResponse)
def get_scan_detail(
    scan_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan


@router.get("/api/v1/scans/{scan_id}/screenshot.png")
def get_scan_screenshot(scan_id: str, db: Session = Depends(get_db)):
    filename = f"{scan_id}.png"
    filepath = os.path.join(settings.SCREENSHOT_DIR, filename)
    if os.path.exists(filepath):
        return FileResponse(filepath, media_type="image/png")
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Screenshot not available")


@router.post("/api/v1/scans/{scan_id}/rescan", response_model=ScanResponse)
def rescan_target(
    scan_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target scan not found")
    new_scan = execute_scan(db=db, url=scan.url, initiator=user)
    return new_scan


@router.get("/api/v1/scans/compare/{base_id}/{comp_id}", response_model=ScanCompareResponse)
def compare_two_scans(
    base_id: str,
    comp_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    base_scan = db.query(Scan).filter(Scan.id == base_id).first()
    comp_scan = db.query(Scan).filter(Scan.id == comp_id).first()
    if not base_scan or not comp_scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="One or both scans not found")
    return compare_scans(base_scan, comp_scan)


@router.get("/api/v1/scans/{scan_id}/export/json")
def export_scan_json(
    scan_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    data = build_scan_json_export(scan)
    return Response(
        content=json_dumps_safe(data),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="xdr_scan_{scan.id}.json"'}
    )


@router.get("/api/v1/scans/{scan_id}/export/pdf")
def export_scan_pdf(
    scan_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    pdf_bytes = generate_scan_pdf_report(scan)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="xdr_scan_{scan.id}.pdf"'}
    )


def json_dumps_safe(obj):
    import json
    return json.dumps(obj, indent=2, default=str)


# ============================================================================
# Backward Compatibility Endpoints for existing frontend/tests
# ============================================================================
@router.post("/api/analyze")
def legacy_analyze(
    payload: dict,
    db: Session = Depends(get_db),
    auth: Optional[CurrentAuth] = Depends(get_current_user_optional)
):
    url = (payload.get("url") or "").strip()
    user = auth.user if auth else None
    try:
        scan = execute_scan(db=db, url=url, initiator=user, allow_private=settings.ALLOW_PRIVATE)
        return {"id": scan.id}
    except UnsafeURL as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/api/jobs/{job_id}")
def legacy_job_status(job_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == job_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown job")
    
    findings_list = [
        {
            "id": f.finding_id,
            "group": f.group,
            "category": f.category,
            "severity": f.severity,
            "confidence": f.confidence,
            "title": f.title,
            "detail": f.detail,
            "evidence": f.evidence or []
        }
        for f in scan.findings
    ]
    
    report = {
        "url": scan.url,
        "final_url": (scan.evidence or {}).get("final_url", scan.url),
        "threat_score": scan.threat_score,
        "threat_level": scan.threat_level,
        "hygiene_score": scan.hygiene_score,
        "hygiene_level": scan.hygiene_level,
        "summary": scan.summary,
        "findings": findings_list,
        "evidence": scan.evidence or {},
        "llm_payload": {
            "url": scan.url,
            "threat_score": scan.threat_score,
            "hygiene_score": scan.hygiene_score,
            "findings": findings_list
        },
        "has_screenshot": scan.screenshot_path is not None,
    }
    return {
        "id": scan.id,
        "url": scan.url,
        "status": scan.status,
        "report": report,
        "error": scan.error,
        "created": scan.created_at.timestamp() if scan.created_at else 0
    }


@router.get("/api/jobs/{job_id}/screenshot.png")
def legacy_job_screenshot(job_id: str, db: Session = Depends(get_db)):
    return get_scan_screenshot(job_id, db)
