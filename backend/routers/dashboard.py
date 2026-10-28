"""
Dashboard Router: Aggregated metrics, telemetry, and distribution data.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import User
from backend.schemas import DashboardStats
from backend.security import get_current_user
from backend.services.dashboard_service import get_dashboard_statistics

router = APIRouter(prefix="/api/v1/dashboard", tags=["Dashboard"])


@router.get("/stats", response_model=DashboardStats)
def get_stats(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    return get_dashboard_statistics(db)
