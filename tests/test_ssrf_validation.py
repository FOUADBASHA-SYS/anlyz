"""
SSRF Protection and URL Normalization Tests.
Verifies loopback, private, link-local, cloud metadata, and illegal schemes are blocked.
"""
import pytest
from analyzer import HostGuard, UnsafeURL, base_domain
from backend.services.scan_service import normalize_url


def test_ssrf_blocks_private_and_internal_destinations():
    guard = HostGuard(allow_private=False)
    blocked_targets = [
        "http://127.0.0.1/",
        "http://127.0.0.2:8080/admin",
        "http://localhost:5000",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/",
        "http://192.168.0.1/router",
        "http://172.16.0.5/",
        "http://[::1]/",
        "file:///etc/passwd",
        "ftp://internal.vault/",
        "javascript:alert(1)"
    ]

    for target in blocked_targets:
        with pytest.raises(UnsafeURL, match=r"(private/internal|Only http:// and https://)"):
            guard.validate_url(target)


def test_ssrf_allows_public_targets():
    guard = HostGuard(allow_private=False)
    # Valid public URL should pass validation
    url = guard.validate_url("https://example.com")
    assert url == "https://example.com"


def test_url_normalization():
    assert normalize_url("example.com") == "https://example.com"
    assert normalize_url("http://shop.co.uk/item?id=1") == "http://shop.co.uk/item?id=1"

    with pytest.raises(ValueError):
        normalize_url("   ")

    with pytest.raises(ValueError):
        normalize_url("ftp://ftp.example.com")


def test_base_domain_extractor():
    assert base_domain("sub.example.com") == "example.com"
    assert base_domain("deep.nested.sub.domain.co.uk") == "domain.co.uk"
    assert base_domain("127.0.0.1") == "127.0.0.1"
    assert base_domain("GOOGLE.COM") == "google.com"
