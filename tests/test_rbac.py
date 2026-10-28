"""
Role-Based Access Control (RBAC) tests.
Ensures analysts cannot perform administrative actions and least privilege is strictly enforced.
"""

def test_unauthenticated_request_rejected(client):
    res = client.get("/api/v1/admin/users")
    assert res.status_code == 401


def test_analyst_cannot_access_admin_user_directory(client, analyst_auth_headers):
    res = client.get("/api/v1/admin/users", headers=analyst_auth_headers)
    assert res.status_code == 403
    assert "Administrator privilege required" in res.json()["detail"]


def test_analyst_cannot_issue_invitation(client, analyst_auth_headers):
    res = client.post("/api/v1/admin/invitations", json={
        "email": "test@corp.local",
        "role": "analyst",
        "expires_in_days": 7
    }, headers=analyst_auth_headers)
    assert res.status_code == 403


def test_analyst_cannot_modify_blocklist(client, analyst_auth_headers):
    res = client.post("/api/v1/rules/blocklist", json={
        "pattern": "malicious-test.com",
        "pattern_type": "domain",
        "reason": "Test block"
    }, headers=analyst_auth_headers)
    assert res.status_code == 403


def test_admin_can_access_admin_console(client, admin_auth_headers):
    res = client.get("/api/v1/admin/users", headers=admin_auth_headers)
    assert res.status_code == 200
    assert isinstance(res.json(), list)


def test_admin_can_issue_invitation(client, admin_auth_headers):
    res = client.post("/api/v1/admin/invitations", json={
        "email": "newanalyst@corp.local",
        "role": "analyst",
        "expires_in_days": 7
    }, headers=admin_auth_headers)
    assert res.status_code == 201
    assert res.json()["email"] == "newanalyst@corp.local"
    assert "token" in res.json()
