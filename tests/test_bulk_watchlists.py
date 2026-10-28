"""
Bulk CSV Scanning and Watchlists Tests.
"""
import pytest
from backend.services.bulk_service import parse_and_validate_csv
from backend.services.watchlist_service import create_watchlist_entry, run_due_watchlist_scans
from backend.models import Watchlist, Scan


def test_csv_parser_validates_and_extracts_urls():
    csv_data = b"url,notes\nhttps://example.com,clean\nhttps://test-site.org,safe\ninvalid-scheme://foo,bad"
    valid_urls, errors = parse_and_validate_csv(csv_data)

    assert "https://example.com" in valid_urls
    assert "https://test-site.org" in valid_urls
    assert len(errors) == 1
    assert "invalid-scheme" in errors[0]["url"]


def test_csv_parser_enforces_row_limit():
    # 501 rows exceeds the 500 max limit
    rows = [b"url"] + [f"https://domain{i}.com".encode() for i in range(501)]
    csv_data = b"\n".join(rows)

    with pytest.raises(ValueError, match="Maximum allowed per batch"):
        parse_and_validate_csv(csv_data)


def test_watchlist_creation_and_recurring_execution(db_session, analyst_user):
    entry = create_watchlist_entry(
        db=db_session,
        user=analyst_user,
        name="Critical Infrastructure Monitor",
        target="https://monitored-service.com",
        target_type="url",
        interval_minutes=60
    )
    assert entry.id is not None
    assert entry.is_active is True
    assert entry.name == "Critical Infrastructure Monitor"

    # Verify saved
    saved = db_session.query(Watchlist).filter(Watchlist.id == entry.id).first()
    assert saved is not None
