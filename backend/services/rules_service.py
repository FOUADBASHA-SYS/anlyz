"""
Rules service for Allowlist and Blocklist management with strict precedence.
Precedence: Blocklist always overrides Allowlist.
"""
from datetime import datetime, timezone
from typing import Optional, Tuple
from urllib.parse import urlparse
from sqlalchemy.orm import Session

from backend.models import Blocklist, Allowlist, User
from backend.services.audit_service import log_audit_event


def normalize_pattern(pattern: str, pattern_type: str = "domain") -> str:
    """Safely normalizes domain or URL patterns for robust matching."""
    pattern = pattern.strip()
    if pattern_type == "domain":
        # Remove any protocol, port, or path
        if "://" in pattern:
            parsed = urlparse(pattern)
            pattern = parsed.hostname or pattern
        else:
            pattern = pattern.split("/")[0].split(":")[0]
        return pattern.lower().strip(".")
    elif pattern_type == "url":
        if "://" not in pattern:
            pattern = "https://" + pattern
        parsed = urlparse(pattern)
        scheme = parsed.scheme.lower()
        netloc = (parsed.hostname or "").lower()
        if parsed.port and parsed.port not in (80, 443):
            netloc += f":{parsed.port}"
        path = parsed.path or "/"
        return f"{scheme}://{netloc}{path}"
    return pattern.strip().lower()


def is_rule_active(rule) -> bool:
    if not rule.is_active:
        return False
    if rule.expires_at and rule.expires_at < datetime.now(timezone.utc):
        return False
    return True


def check_target_policy(url: str, domain: str, db: Session) -> Tuple[str, Optional[str]]:
    """
    Evaluates policy for a URL / domain.
    Precedence:
      1. BLOCKLIST matches -> status='blocked', reason=...
      2. ALLOWLIST matches -> status='allowlisted', reason=...
      3. Neither -> status='neutral', reason=None
    """
    domain_norm = domain.lower().strip(".")
    url_norm = url.lower().strip()

    # 1. Check Blocklist
    active_blocks = db.query(Blocklist).filter(Blocklist.is_active == True).all()
    for b in active_blocks:
        if not is_rule_active(b):
            continue
        p = b.pattern.lower().strip(".")
        if b.pattern_type == "domain":
            if domain_norm == p or domain_norm.endswith("." + p):
                return "blocked", f"Domain matched blocklist rule: {b.pattern} (Reason: {b.reason})"
        elif b.pattern_type == "url":
            if url_norm.startswith(b.pattern.lower()):
                return "blocked", f"URL matched blocklist rule: {b.pattern} (Reason: {b.reason})"

    # 2. Check Allowlist
    active_allows = db.query(Allowlist).filter(Allowlist.is_active == True).all()
    for a in active_allows:
        if not is_rule_active(a):
            continue
        p = a.pattern.lower().strip(".")
        if a.pattern_type == "domain":
            if domain_norm == p or domain_norm.endswith("." + p):
                return "allowlisted", f"Domain matched allowlist rule: {a.pattern} (Reason: {a.reason})"
        elif a.pattern_type == "url":
            if url_norm.startswith(a.pattern.lower()):
                return "allowlisted", f"URL matched allowlist rule: {a.pattern} (Reason: {a.reason})"

    return "neutral", None


def add_blocklist_rule(db: Session, pattern: str, pattern_type: str, reason: str, creator: User, expires_at: Optional[datetime] = None) -> Blocklist:
    norm = normalize_pattern(pattern, pattern_type)
    existing = db.query(Blocklist).filter(Blocklist.pattern == norm).first()
    if existing:
        existing.reason = reason
        existing.expires_at = expires_at
        existing.is_active = True
        db.commit()
        log_audit_event(db, "BLOCKLIST_UPDATE", "blocklist", existing.id, creator, metadata={"pattern": norm, "reason": reason})
        return existing

    rule = Blocklist(
        pattern=norm,
        pattern_type=pattern_type,
        reason=reason,
        created_by_id=creator.id,
        expires_at=expires_at,
        is_active=True,
        created_at=datetime.now(timezone.utc)
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    log_audit_event(db, "BLOCKLIST_CREATE", "blocklist", rule.id, creator, metadata={"pattern": norm, "reason": reason})
    return rule


def add_allowlist_rule(db: Session, pattern: str, pattern_type: str, reason: str, creator: User, expires_at: Optional[datetime] = None) -> Allowlist:
    norm = normalize_pattern(pattern, pattern_type)
    existing = db.query(Allowlist).filter(Allowlist.pattern == norm).first()
    if existing:
        existing.reason = reason
        existing.expires_at = expires_at
        existing.is_active = True
        db.commit()
        log_audit_event(db, "ALLOWLIST_UPDATE", "allowlist", existing.id, creator, metadata={"pattern": norm, "reason": reason})
        return existing

    rule = Allowlist(
        pattern=norm,
        pattern_type=pattern_type,
        reason=reason,
        created_by_id=creator.id,
        expires_at=expires_at,
        is_active=True,
        created_at=datetime.now(timezone.utc)
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    log_audit_event(db, "ALLOWLIST_CREATE", "allowlist", rule.id, creator, metadata={"pattern": norm, "reason": reason})
    return rule
