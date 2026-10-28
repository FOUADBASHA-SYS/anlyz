"""
Pytest configuration and shared fixtures.
Creates isolated test database and FastAPI TestClient.
"""
import os
import sys
sys.path.insert(0, os.path.abspath("."))
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Force SQLite for test isolation
os.environ["DATABASE_URL"] = "sqlite:///./test_url_analyzer.db"
os.environ["ALLOW_PRIVATE"] = "1"

from backend.database import Base, get_db
from backend.main import app
from backend.models import User, Invitation
from backend.security import hash_password, create_session_token, generate_csrf_token

TEST_DB_URL = "sqlite:///./test_url_analyzer.db"
test_engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)
    if os.path.exists("./test_url_analyzer.db"):
        try:
            os.remove("./test_url_analyzer.db")
        except Exception:
            pass


@pytest.fixture
def db_session():
    connection = test_engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def admin_user(db_session):
    user = db_session.query(User).filter(User.email == "admin_fixture@xdr.local").first()
    if not user:
        user = User(
            email="admin_fixture@xdr.local",
            hashed_password=hash_password("AdminPass123!"),
            role="admin",
            is_active=True,
            is_approved=True,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)
    return user


@pytest.fixture
def analyst_user(db_session):
    user = db_session.query(User).filter(User.email == "analyst_fixture@xdr.local").first()
    if not user:
        user = User(
            email="analyst_fixture@xdr.local",
            hashed_password=hash_password("AnalystPass123!"),
            role="analyst",
            is_active=True,
            is_approved=True,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)
    return user


@pytest.fixture
def admin_auth_headers(admin_user):
    token, jti, _ = create_session_token(admin_user.id, "admin")
    csrf = generate_csrf_token(jti)
    return {
        "Authorization": f"Bearer {token}",
        "X-CSRF-Token": csrf,
    }


@pytest.fixture
def analyst_auth_headers(analyst_user):
    token, jti, _ = create_session_token(analyst_user.id, "analyst")
    csrf = generate_csrf_token(jti)
    return {
        "Authorization": f"Bearer {token}",
        "X-CSRF-Token": csrf,
    }
