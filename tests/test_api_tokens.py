"""
API Token Management and Scoped Authorization Tests.
"""
from backend.models import ApiToken
from backend.security import hash_token


def test_api_token_creation_and_hashing(client, analyst_auth_headers, db_session):
    res = client.post("/api/v1/tokens", json={
        "name": "Integration SOAR Token",
        "scopes": ["scans:read", "scans:write"],
        "expires_in_days": 30
    }, headers=analyst_auth_headers)
    assert res.status_code == 201
    data = res.json()
    assert "token" in data
    raw_token = data["token"]
    assert raw_token.startswith("xdr_")

    # Verify token is hashed in DB, never stored in plaintext
    token_obj = db_session.query(ApiToken).filter(ApiToken.id == data["id"]).first()
    assert token_obj is not None
    assert token_obj.token_hash == hash_token(raw_token)
    assert raw_token not in token_obj.token_hash


def test_api_token_authenticates_requests(client, analyst_auth_headers):
    # 1. Create token
    create_res = client.post("/api/v1/tokens", json={
        "name": "Automated Scanner Token",
        "scopes": ["scans:read", "scans:write"],
    }, headers=analyst_auth_headers)
    raw_token = create_res.json()["token"]

    # 2. Use X-API-Token to call /api/v1/scans
    scans_res = client.get("/api/v1/scans", headers={"X-API-Token": raw_token})
    assert scans_res.status_code == 200
    assert isinstance(scans_res.json(), list)


def test_api_token_revocation(client, analyst_auth_headers):
    create_res = client.post("/api/v1/tokens", json={
        "name": "Temporary Token",
        "scopes": ["scans:read"],
    }, headers=analyst_auth_headers)
    token_id = create_res.json()["id"]
    raw_token = create_res.json()["token"]

    # Revoke
    rev_res = client.delete(f"/api/v1/tokens/{token_id}", headers=analyst_auth_headers)
    assert rev_res.status_code == 204

    # Using revoked token now fails
    fail_res = client.get("/api/v1/scans", headers={"X-API-Token": raw_token})
    assert fail_res.status_code == 401
