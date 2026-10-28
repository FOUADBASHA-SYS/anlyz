"""
Scan Execution, Differential Comparison, and Report Export Tests.
"""
from backend.services.scan_service import execute_scan, compare_scans
from backend.services.report_service import build_scan_json_export, generate_scan_pdf_report
from backend.models import Scan, Finding


def test_scan_execution_and_persistence(db_session, analyst_user):
    scan = execute_scan(
        db=db_session,
        url="https://example.com",
        initiator=analyst_user,
        allow_private=True
    )
    assert scan.id is not None
    assert scan.status in ("done", "queued", "detonating")
    assert scan.normalized_domain == "example.com"
    assert scan.threat_score >= 0
    assert scan.threat_level in ("Low", "Medium", "High", "Critical")

    # Verify in DB
    saved = db_session.query(Scan).filter(Scan.id == scan.id).first()
    assert saved is not None
    assert saved.initiator.id == analyst_user.id


def test_scan_comparison_diff_logic(db_session):
    scan_1 = Scan(
        id="base_scan_101",
        url="https://site.test",
        normalized_domain="site.test",
        status="done",
        threat_score=20,
        threat_level="Medium",
        hygiene_score=10,
        hygiene_level="Good",
        summary="Base scan",
    )
    scan_2 = Scan(
        id="comp_scan_102",
        url="https://site.test",
        normalized_domain="site.test",
        status="done",
        threat_score=60,
        threat_level="High",
        hygiene_score=25,
        hygiene_level="Fair",
        summary="Follow up scan",
    )
    db_session.add_all([scan_1, scan_2])
    db_session.commit()

    # Add findings:
    # f1: unchanged
    # f2: resolved
    # f3: new
    f1_a = Finding(scan_id=scan_1.id, finding_id="script.eval", group="threat", category="script", severity="medium", confidence=0.7, title="Eval usage")
    f2 = Finding(scan_id=scan_1.id, finding_id="url.phish_words", group="threat", category="url", severity="low", confidence=0.5, title="Phish words")
    f1_b = Finding(scan_id=scan_2.id, finding_id="script.eval", group="threat", category="script", severity="medium", confidence=0.7, title="Eval usage")
    f3 = Finding(scan_id=scan_2.id, finding_id="download.executable", group="threat", category="download", severity="critical", confidence=1.0, title="Executable download")

    db_session.add_all([f1_a, f2, f1_b, f3])
    db_session.commit()

    db_session.refresh(scan_1)
    db_session.refresh(scan_2)

    diff = compare_scans(scan_1, scan_2)
    assert diff["threat_score_delta"] == 40
    assert diff["hygiene_score_delta"] == 15
    assert len(diff["new_findings"]) == 1
    assert diff["new_findings"][0]["finding_id"] == "download.executable"
    assert len(diff["resolved_findings"]) == 1
    assert diff["resolved_findings"][0]["finding_id"] == "url.phish_words"
    assert len(diff["unchanged_findings"]) == 1
    assert diff["unchanged_findings"][0]["finding_id"] == "script.eval"


def test_report_json_export(db_session, analyst_user):
    scan = execute_scan(db=db_session, url="https://export-test.com", initiator=analyst_user, allow_private=True)
    report_dict = build_scan_json_export(scan)
    assert report_dict["scan_id"] == scan.id
    assert report_dict["submitted_url"] == "https://export-test.com"
    assert "verdict" in report_dict
    assert "threat_score" in report_dict["verdict"]


def test_report_pdf_generation(db_session, analyst_user):
    scan = execute_scan(db=db_session, url="https://pdf-test.com", initiator=analyst_user, allow_private=True)
    pdf_bytes = generate_scan_pdf_report(scan)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 100
    assert pdf_bytes.startswith(b"%PDF")
