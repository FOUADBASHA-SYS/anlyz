"""
Dashboard Service: Real database-backed metrics, risk distribution,
severity aggregation, and suspicious domain telemetry.
"""
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from backend.models import Scan, Finding, Blocklist, Allowlist, Watchlist
from backend.schemas import DashboardStats, TopDomainItem, ScanResponse


def get_dashboard_statistics(db: Session) -> DashboardStats:
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = now - timedelta(days=7)

    total_scans = db.query(Scan).count()
    scans_today = db.query(Scan).filter(Scan.created_at >= today_start).count()
    scans_this_week = db.query(Scan).filter(Scan.created_at >= week_start).count()

    # Risk Level Distribution
    risk_counts = {
        "Low": db.query(Scan).filter(Scan.threat_level == "Low").count(),
        "Medium": db.query(Scan).filter(Scan.threat_level == "Medium").count(),
        "High": db.query(Scan).filter(Scan.threat_level == "High").count(),
        "Critical": db.query(Scan).filter(Scan.threat_level == "Critical").count(),
    }

    # Severity Distribution from Findings
    sev_counts = {
        "critical": db.query(Finding).filter(Finding.severity == "critical").count(),
        "high": db.query(Finding).filter(Finding.severity == "high").count(),
        "medium": db.query(Finding).filter(Finding.severity == "medium").count(),
        "low": db.query(Finding).filter(Finding.severity == "low").count(),
        "info": db.query(Finding).filter(Finding.severity == "info").count(),
    }

    # Top Suspicious / Malicious Domains (threat_score >= 40)
    top_domains_query = (
        db.query(
            Scan.normalized_domain,
            func.count(Scan.id).label("cnt"),
            func.max(Scan.threat_score).label("max_score")
        )
        .filter(Scan.threat_score >= 40)
        .group_by(Scan.normalized_domain)
        .order_by(desc("cnt"), desc("max_score"))
        .limit(8)
        .all()
    )

    top_domains = [
        TopDomainItem(domain=row[0], count=row[1], max_threat_score=row[2])
        for row in top_domains_query
    ]

    # Recent Scans
    recent_records = (
        db.query(Scan)
        .order_by(desc(Scan.created_at))
        .limit(10)
        .all()
    )
    recent_scans = [ScanResponse.model_validate(s) for s in recent_records]

    active_watchlists = db.query(Watchlist).filter(Watchlist.is_active == True).count()
    blocked_count = db.query(Blocklist).filter(Blocklist.is_active == True).count()
    allowlist_count = db.query(Allowlist).filter(Allowlist.is_active == True).count()

    return DashboardStats(
        total_scans=total_scans,
        scans_today=scans_today,
        scans_this_week=scans_this_week,
        risk_distribution=risk_counts,
        severity_distribution=sev_counts,
        top_suspicious_domains=top_domains,
        recent_scans=recent_scans,
        active_watchlists=active_watchlists,
        blocked_count=blocked_count,
        allowlist_count=allowlist_count,
        worker_status="active",
    )
