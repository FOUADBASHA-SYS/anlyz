"""
Scan Service: URL detonation, SSRF validation, policy enforcement,
persistence, comparison, and rescan.
"""
import os
import uuid
from datetime import datetime, timezone
from typing import Optional, Tuple, Dict, Any, List
from urllib.parse import urlparse
from sqlalchemy.orm import Session

from backend.config import settings
from backend.models import Scan, Finding, User
from backend.services.rules_service import check_target_policy
from backend.services.audit_service import log_audit_event
from analyzer import HostGuard, UnsafeURL, base_domain
import pipeline
import checks
import scoring


def normalize_url(raw_url: str) -> str:
    url = (raw_url or "").strip()
    if not url:
        raise ValueError("URL cannot be empty")
    if "://" not in url:
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError(f"Invalid URL scheme: {parsed.scheme}. Only HTTP and HTTPS are permitted.")
    if not parsed.hostname:
        raise ValueError("URL must have a valid hostname")
    return url


def execute_scan(
    db: Session,
    url: str,
    initiator: Optional[User] = None,
    allow_private: Optional[bool] = None,
    is_bulk: bool = False,
    batch_id: Optional[str] = None
) -> Scan:
    """Executes full URL threat analysis pipeline and persists in database."""
    url = normalize_url(url)
    parsed = urlparse(url)
    host = parsed.hostname or ""
    domain = base_domain(host)

    if allow_private is None:
        allow_private = settings.ALLOW_PRIVATE

    # SSRF Gate Check
    HostGuard(allow_private).validate_url(url)

    # Create Initial Scan Record
    scan_id = uuid.uuid4().hex[:12]
    scan = Scan(
        id=scan_id,
        url=url,
        normalized_domain=domain,
        status="queued",
        threat_score=0,
        threat_level="Low",
        hygiene_score=0,
        hygiene_level="Good",
        summary="Scan queued for analysis...",
        initiated_by_id=initiator.id if initiator else None,
        is_bulk=is_bulk,
        batch_id=batch_id,
        created_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # 1. Policy Precedence Check (Blocklist vs Allowlist)
    policy_status, policy_reason = check_target_policy(url, domain, db)

    if policy_status == "blocked":
        scan.status = "done"
        scan.threat_score = 100
        scan.threat_level = "Critical"
        scan.hygiene_score = 50
        scan.hygiene_level = "Poor"
        scan.summary = f"Blocked by enterprise security policy: {policy_reason}"
        scan.finished_at = datetime.now(timezone.utc)
        
        block_finding = Finding(
            scan_id=scan.id,
            finding_id="policy.blocklist_match",
            group="threat",
            category="policy",
            severity="critical",
            confidence=1.0,
            title="Target matches active enterprise blocklist",
            detail=policy_reason,
            evidence=[url, domain],
            created_at=datetime.now(timezone.utc)
        )
        db.add(block_finding)
        db.commit()
        db.refresh(scan)
        return scan

    # 2. Detonation Stage
    try:
        scan.status = "detonating"
        db.commit()

        # Detonate URL
        try:
            report, screenshot_bytes = pipeline.analyze_url(url, allow_private=allow_private)
        except Exception as detonate_err:
            # Fallback to passive check if browser detonation is unavailable
            report, screenshot_bytes = _run_passive_fallback(url, str(detonate_err))

        # Check if URL was allowlisted to add context finding
        if policy_status == "allowlisted":
            report["findings"].insert(0, {
                "id": "policy.allowlist_match",
                "group": "hygiene",
                "category": "policy",
                "severity": "info",
                "confidence": 1.0,
                "title": "Target is on the enterprise allowlist",
                "detail": policy_reason,
                "evidence": [domain]
            })

        # Save Screenshot if available
        shot_path = None
        if screenshot_bytes:
            filename = f"{scan.id}.png"
            full_path = os.path.join(settings.SCREENSHOT_DIR, filename)
            with open(full_path, "wb") as f:
                f.write(screenshot_bytes)
            shot_path = f"/api/v1/scans/{scan.id}/screenshot.png"

        # Update Scan Details
        scan.status = "done"
        scan.threat_score = report.get("threat_score", 0)
        scan.threat_level = report.get("threat_level", "Low")
        scan.hygiene_score = report.get("hygiene_score", 0)
        scan.hygiene_level = report.get("hygiene_level", "Good")
        scan.summary = report.get("summary", "")
        scan.evidence = report.get("evidence", {})
        scan.screenshot_path = shot_path
        scan.finished_at = datetime.now(timezone.utc)

        # Persist Findings
        for f in report.get("findings", []):
            finding_obj = Finding(
                scan_id=scan.id,
                finding_id=f.get("id", "generic.finding"),
                group=f.get("group", "threat"),
                category=f.get("category", "url"),
                severity=f.get("severity", "info"),
                confidence=float(f.get("confidence", 0.8)),
                title=f.get("title", ""),
                detail=f.get("detail", ""),
                evidence=f.get("evidence", []),
                created_at=datetime.now(timezone.utc),
            )
            db.add(finding_obj)

        db.commit()
        db.refresh(scan)
        return scan

    except Exception as e:
        scan.status = "error"
        scan.error = str(e)[:400]
        scan.finished_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(scan)
        return scan


def _run_passive_fallback(url: str, reason: str) -> Tuple[Dict[str, Any], Optional[bytes]]:
    """Safe passive inspection when Chromium browser engine is unavailable."""
    ev = {
        "input_url": url, "final_url": url, "title": "Passive Analysis Only",
        "status": 200, "error": f"Browser sandbox unavailable ({reason}); ran passive heuristics.",
        "headers": {}, "server_ip": None, "tls": None,
        "redirect_chain": [{"url": url, "status": 200}], "navigations": [url],
        "requests": [{"url": url, "method": "GET", "type": "document", "host": urlparse(url).hostname or "", "base_domain": base_domain(urlparse(url).hostname or "")}],
        "blocked_requests": [], "scripts": [], "inline_scripts": [],
        "downloads": [], "popups": [], "dialogs": [], "console": [], "page_errors": [],
        "cookies": [], "forms": [], "iframes": [], "meta_refresh": [],
        "password_fields": 0, "visible_text": "", "elapsed_s": 0.1,
    }
    findings = checks.run_all(ev)
    threat = scoring.group_score(findings, "threat")
    hygiene = scoring.group_score(findings, "hygiene")
    report = {
        "url": url,
        "final_url": url,
        "threat_score": threat,
        "threat_level": scoring.threat_level(threat),
        "hygiene_score": hygiene,
        "hygiene_level": scoring.hygiene_level(hygiene),
        "summary": scoring.build_summary(url, threat, hygiene, findings) + " (Evaluated via passive threat heuristics)",
        "findings": findings,
        "evidence": pipeline._public_evidence(ev),
        "llm_payload": scoring.llm_payload(url, threat, hygiene, findings),
        "has_screenshot": False,
    }
    return report, None


def compare_scans(base_scan: Scan, comp_scan: Scan) -> Dict[str, Any]:
    """Compares two scans of the same URL or domain and produces a detailed diff."""
    base_findings = {f.finding_id: f for f in base_scan.findings}
    comp_findings = {f.finding_id: f for f in comp_scan.findings}

    new_ids = set(comp_findings.keys()) - set(base_findings.keys())
    resolved_ids = set(base_findings.keys()) - set(comp_findings.keys())
    unchanged_ids = set(base_findings.keys()) & set(comp_findings.keys())

    def serialize_finding(f):
        return {
            "finding_id": f.finding_id,
            "title": f.title,
            "severity": f.severity,
            "group": f.group,
            "detail": f.detail
        }

    base_ev = base_scan.evidence or {}
    comp_ev = comp_scan.evidence or {}
    base_chain = [c.get("url") for c in base_ev.get("redirect_chain", [])]
    comp_chain = [c.get("url") for c in comp_ev.get("redirect_chain", [])]

    return {
        "base_scan": base_scan,
        "compare_scan": comp_scan,
        "threat_score_delta": comp_scan.threat_score - base_scan.threat_score,
        "hygiene_score_delta": comp_scan.hygiene_score - base_scan.hygiene_score,
        "new_findings": [serialize_finding(comp_findings[fid]) for fid in sorted(new_ids)],
        "resolved_findings": [serialize_finding(base_findings[fid]) for fid in sorted(resolved_ids)],
        "unchanged_findings": [serialize_finding(comp_findings[fid]) for fid in sorted(unchanged_ids)],
        "redirect_chain_changed": base_chain != comp_chain,
    }
