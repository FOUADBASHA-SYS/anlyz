"""
AI Security Analyst Assistant Service.
Explains scan findings based strictly on stored evidence.
Enforces prompt injection defenses by restricting context to sanitized structured payload.
"""
import json
from datetime import datetime, timezone
from typing import List, Dict, Any
from sqlalchemy.orm import Session

from backend.config import settings
from backend.models import Scan, ChatMessage, User


def sanitize_evidence_context(scan: Scan) -> Dict[str, Any]:
    """Builds a structured, safe context payload free of arbitrary raw HTML/scripts."""
    findings_summary = [
        {
            "id": f.finding_id,
            "severity": f.severity,
            "group": f.group,
            "title": f.title,
            "detail": f.detail,
            "evidence": (f.evidence or [])[:3]
        }
        for f in scan.findings
    ]
    ev = scan.evidence or {}
    return {
        "scan_id": scan.id,
        "url": scan.url,
        "final_url": ev.get("final_url", scan.url),
        "threat_score": scan.threat_score,
        "threat_level": scan.threat_level,
        "hygiene_score": scan.hygiene_score,
        "hygiene_level": scan.hygiene_level,
        "findings": findings_summary,
        "total_requests": len(ev.get("requests", [])),
        "downloads_count": len(ev.get("downloads", [])),
        "scripts_count": len(ev.get("scripts", [])) + ev.get("inline_script_count", 0),
    }


def generate_analyst_response(scan: Scan, user_message: str, history: List[ChatMessage]) -> str:
    """Generates an objective cybersecurity explanation using structured scan evidence."""
    context = sanitize_evidence_context(scan)
    msg_lower = user_message.lower()

    # Rule-based expert analyst response (transparent and reliable without hallucinating)
    critical_findings = [f for f in context["findings"] if f["severity"] == "critical"]
    high_findings = [f for f in context["findings"] if f["severity"] == "high"]
    medium_findings = [f for f in context["findings"] if f["severity"] == "medium"]

    if "safe" in msg_lower or "malicious" in msg_lower or "verdict" in msg_lower:
        if context["threat_score"] >= 65:
            return (
                f"**Verdict**: This URL is classified as **CRITICAL RISK** (Threat Score: {context['threat_score']}/100).\n\n"
                f"**Observed Hostile Indicators**:\n"
                + "\n".join(f"- **{f['title']}**: {f['detail']}" for f in critical_findings + high_findings)
                + "\n\n**Analyst Recommendation**: Block this domain across perimeter firewalls and EDR agents. Do not allow users to visit this link."
            )
        elif context["threat_score"] >= 40:
            return (
                f"**Verdict**: This URL is classified as **HIGH RISK** (Threat Score: {context['threat_score']}/100).\n\n"
                f"**Identified Risks**:\n"
                + "\n".join(f"- **{f['title']}**: {f['detail']}" for f in high_findings + medium_findings)
                + "\n\n**Analyst Recommendation**: Treat with extreme caution. Review submitted forms and external resources."
            )
        elif context["threat_score"] >= 15:
            return (
                f"**Verdict**: This URL poses **MODERATE RISK** (Threat Score: {context['threat_score']}/100). "
                f"Some suspicious indicators were noted:\n"
                + "\n".join(f"- **{f['title']}**: {f['detail']}" for f in medium_findings)
            )
        else:
            return (
                f"**Verdict**: This URL has a **LOW Threat Score** ({context['threat_score']}/100). "
                f"No explicit hostile detonation behaviors were recorded. However, clean sandbox execution does not guarantee zero-day safety."
            )

    if "download" in msg_lower or "file" in msg_lower or "executable" in msg_lower:
        dl_findings = [f for f in context["findings"] if "download" in f["id"] or "executable" in f["id"]]
        if dl_findings:
            return "**Download Analysis**:\n" + "\n".join(f"- **{f['title']}**: {f['detail']} (Evidence: {', '.join(f['evidence'])})" for f in dl_findings)
        return "No hostile file downloads were initiated during sandbox detonation."

    if "script" in msg_lower or "js" in msg_lower or "eval" in msg_lower:
        js_findings = [f for f in context["findings"] if "script" in f["id"] or "library" in f["id"]]
        if js_findings:
            return "**Script & Code Analysis**:\n" + "\n".join(f"- **{f['title']}**: {f['detail']}" for f in js_findings)
        return f"Evaluated {context['scripts_count']} scripts on the page; no malicious patterns or obsolete libraries were triggered."

    # General overview
    resp = [
        f"**Security Triage Report for {context['url']}**:",
        f"- **Threat Score**: {context['threat_score']}/100 ({context['threat_level']})",
        f"- **Hygiene Score**: {context['hygiene_score']}/100 ({context['hygiene_level']})",
        f"- **Network Trace**: {context['total_requests']} requests initiated across domains.",
    ]
    if critical_findings or high_findings:
        resp.append("\n**Primary Threat Factors**:")
        for f in (critical_findings + high_findings)[:5]:
            resp.append(f"- **[{f['severity'].upper()}] {f['title']}**: {f['detail']}")
    else:
        resp.append("\nNo critical threat indicators detected.")

    return "\n".join(resp)


def process_chat_message(db: Session, scan: Scan, user: User, content: str) -> ChatMessage:
    context = sanitize_evidence_context(scan)

    # Save User message
    user_msg = ChatMessage(
        scan_id=scan.id,
        user_id=user.id,
        role="user",
        content=content.strip(),
        created_at=datetime.now(timezone.utc),
    )
    db.add(user_msg)
    db.commit()

    # Retrieve history
    history = db.query(ChatMessage).filter(ChatMessage.scan_id == scan.id).order_by(ChatMessage.created_at).all()

    # Generate Assistant Reply
    reply_text = generate_analyst_response(scan, content, history)

    assistant_msg = ChatMessage(
        scan_id=scan.id,
        user_id=user.id,
        role="assistant",
        content=reply_text,
        evidence_context=context,
        created_at=datetime.now(timezone.utc),
    )
    db.add(assistant_msg)
    db.commit()
    db.refresh(assistant_msg)
    return assistant_msg
