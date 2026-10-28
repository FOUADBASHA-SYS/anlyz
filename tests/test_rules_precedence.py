"""
Allowlist and Blocklist Precedence Tests.
Validates that Blocklist strictly overrides Allowlist in conflicts.
"""
from backend.services.rules_service import (
    add_blocklist_rule, add_allowlist_rule, check_target_policy, normalize_pattern
)


def test_rule_pattern_normalization():
    assert normalize_pattern("https://evil.com/path?q=1", "domain") == "evil.com"
    assert normalize_pattern("Sub.Evil.COM:8080", "domain") == "sub.evil.com"
    assert normalize_pattern("https://trusted.corp/login", "url") == "https://trusted.corp/login"


def test_blocklist_matches_subdomains(db_session, admin_user):
    add_blocklist_rule(
        db=db_session,
        pattern="bad-domain.com",
        pattern_type="domain",
        reason="Known C2 server",
        creator=admin_user
    )

    status, reason = check_target_policy("https://sub.bad-domain.com/login", "sub.bad-domain.com", db_session)
    assert status == "blocked"
    assert "bad-domain.com" in reason


def test_allowlist_matches_clean_domain(db_session, admin_user):
    add_allowlist_rule(
        db=db_session,
        pattern="corp-portal.local",
        pattern_type="domain",
        reason="Internal enterprise service",
        creator=admin_user
    )

    status, reason = check_target_policy("https://corp-portal.local", "corp-portal.local", db_session)
    assert status == "allowlisted"
    assert "corp-portal.local" in reason


def test_strict_precedence_blocklist_overrides_allowlist(db_session, admin_user):
    # Target is in both allowlist and blocklist
    add_allowlist_rule(
        db=db_session,
        pattern="conflict-domain.com",
        pattern_type="domain",
        reason="Claimed partner domain",
        creator=admin_user
    )
    add_blocklist_rule(
        db=db_session,
        pattern="conflict-domain.com",
        pattern_type="domain",
        reason="Identified malicious phishing kit",
        creator=admin_user
    )

    # When evaluated, blocklist must win
    status, reason = check_target_policy("https://conflict-domain.com/pay", "conflict-domain.com", db_session)
    assert status == "blocked"
    assert "blocklist" in reason.lower()
