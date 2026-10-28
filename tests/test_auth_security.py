"""
Automated tests for Accounts and Security.
Tests: Login, Lockout, Invitation Registration, Logout, and CSRF protection.
"""
from datetime import datetime, timezone, timedelta
from backend.models import User, Invitation
from backend.config import settings


def test_login_success(client, admin_user):
    res = client.post("/api/v1/auth/login", json={
        "email": admin_user.email,
        "password": "AdminPass123!"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["email"] == admin_user.email
    assert data["role"] == "admin"
    assert settings.SESSION_COOKIE_NAME in res.cookies
    assert "X-CSRF-Token" in res.headers


def test_login_invalid_password(client, admin_user):
    res = client.post("/api/v1/auth/login", json={
        "email": admin_user.email,
        "password": "WrongPassword123!"
    })
    assert res.status_code == 401
    assert "Invalid email or password" in res.json()["detail"]


def test_account_lockout_after_repeated_failures(client, db_session):
    test_user = User(
        email="lockout_test@xdr.local",
        hashed_password="hashed_pass_placeholder",
        role="analyst",
        is_active=True,
        is_approved=True,
        failed_login_attempts=0
    )
    db_session.add(test_user)
    db_session.commit()

    # Trigger failed attempts
    for _ in range(settings.MAX_LOGIN_ATTEMPTS):
        client.post("/api/v1/auth/login", json={
            "email": "lockout_test@xdr.local",
            "password": "WrongPassword!"
        })

    db_session.refresh(test_user)
    assert test_user.locked_until is not None

    # Next attempt should return 403 Account Locked
    res = client.post("/api/v1/auth/login", json={
        "email": "lockout_test@xdr.local",
        "password": "AnyPassword!"
    })
    assert res.status_code == 403
    assert "locked" in res.json()["detail"].lower()


def test_registration_requires_valid_invitation(client, db_session):
    # 1. Attempt register with bogus token -> 400
    res = client.post("/api/v1/auth/register", json={
        "token": "non_existent_token_123",
        "email": "newuser@xdr.local",
        "password": "StrongPassword2026!"
    })
    assert res.status_code == 400
    assert "Invalid or expired invitation" in res.json()["detail"]

    # 2. Issue valid invitation
    invite = Invitation(
        token="valid_test_token_abc",
        email="invited@xdr.local",
        role="analyst",
        expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        created_at=datetime.now(timezone.utc)
    )
    db_session.add(invite)
    db_session.commit()

    # 3. Register with matching email and token -> 200
    reg_res = client.post("/api/v1/auth/register", json={
        "token": "valid_test_token_abc",
        "email": "invited@xdr.local",
        "password": "StrongPassword2026!"
    })
    assert reg_res.status_code == 200
    assert reg_res.json()["email"] == "invited@xdr.local"

    # 4. Token cannot be reused
    reuse_res = client.post("/api/v1/auth/register", json={
        "token": "valid_test_token_abc",
        "email": "invited@xdr.local",
        "password": "StrongPassword2026!"
    })
    assert reuse_res.status_code == 400


def test_logout(client, admin_auth_headers):
    res = client.post("/api/v1/auth/logout", headers=admin_auth_headers)
    assert res.status_code == 200
    assert "logged out" in res.json()["message"].lower()
