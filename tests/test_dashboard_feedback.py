"""
Dashboard Statistics and Analyst Feedback Tests.
"""
from backend.services.dashboard_service import get_dashboard_statistics
from backend.models import Scan, Finding, AnalystFeedback


def test_dashboard_statistics_calculation(db_session, analyst_user):
    scan_low = Scan(url="https://safe1.com", normalized_domain="safe1.com", status="done", threat_score=5, threat_level="Low", hygiene_score=5, hygiene_level="Good")
    scan_crit = Scan(url="https://danger1.com", normalized_domain="danger1.com", status="done", threat_score=95, threat_level="Critical", hygiene_score=60, hygiene_level="Poor")
    db_session.add_all([scan_low, scan_crit])
    db_session.commit()

    f_crit = Finding(scan_id=scan_crit.id, finding_id="script.miner", group="threat", category="script", severity="critical", confidence=1.0, title="Coin miner")
    db_session.add(f_crit)
    db_session.commit()

    stats = get_dashboard_statistics(db_session)
    assert stats.total_scans >= 2
    assert stats.risk_distribution["Low"] >= 1
    assert stats.risk_distribution["Critical"] >= 1
    assert stats.severity_distribution["critical"] >= 1
    assert any(d.domain == "danger1.com" for d in stats.top_suspicious_domains)


def test_analyst_feedback_submission(client, analyst_auth_headers, db_session):
    scan = Scan(url="https://feedback-test.com", normalized_domain="feedback-test.com", status="done", threat_score=80, threat_level="Critical", hygiene_score=20, hygiene_level="Fair")
    db_session.add(scan)
    db_session.commit()

    # Submit True Positive
    res = client.post(f"/api/v1/scans/{scan.id}/feedback", json={
        "verdict": "true_positive",
        "notes": "Verified credential phishing lure"
    }, headers=analyst_auth_headers)
    assert res.status_code == 201
    assert res.json()["verdict"] == "true_positive"

    # Updating existing feedback
    res_update = client.post(f"/api/v1/scans/{scan.id}/feedback", json={
        "verdict": "needs_review",
        "notes": "Re-evaluating kit fingerprint"
    }, headers=analyst_auth_headers)
    assert res_update.status_code == 201
    assert res_update.json()["verdict"] == "needs_review"

    # Check in DB
    feedbacks = db_session.query(AnalystFeedback).filter(AnalystFeedback.scan_id == scan.id).all()
    assert len(feedbacks) == 1
    assert feedbacks[0].verdict == "needs_review"
