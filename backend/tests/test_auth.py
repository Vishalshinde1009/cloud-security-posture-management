import uuid
from datetime import timedelta
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.database.session import get_db, Base
from app.models.auth import User, Role, Permission
from app.models.audit import AuditLog
from app.core.security import (
    get_password_hash,
    verify_password,
    validate_password_strength,
    create_access_token,
    decode_access_token,
)

from sqlalchemy.pool import StaticPool

# Test in-memory database setup with StaticPool so all connections share the schema
test_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)


@event.listens_for(test_engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()

TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="function")
def db_session():
    """Provides a fresh isolated in-memory test database."""
    Base.metadata.create_all(bind=test_engine)
    session = TestingSessionLocal()
    
    # Create standard roles & permissions
    p_read = Permission(id=uuid.uuid4(), name="findings:read", description="Read findings")
    p_scan = Permission(id=uuid.uuid4(), name="scans:create", description="Run scans")
    p_admin = Permission(id=uuid.uuid4(), name="users:manage", description="Manage users")
    session.add_all([p_read, p_scan, p_admin])
    session.flush()

    r_admin = Role(id=uuid.uuid4(), name="ADMIN", description="Admin role")
    r_admin.permissions.extend([p_read, p_scan, p_admin])

    r_analyst = Role(id=uuid.uuid4(), name="SECURITY_ANALYST", description="Analyst role")
    r_analyst.permissions.extend([p_read, p_scan])

    r_viewer = Role(id=uuid.uuid4(), name="VIEWER", description="Viewer role")
    r_viewer.permissions.append(p_read)

    session.add_all([r_admin, r_analyst, r_viewer])
    session.flush()

    # Create active test users
    admin_user = User(
        id=uuid.uuid4(),
        username="sec_admin",
        email="admin@test-cspm.local",
        password_hash=get_password_hash("AdminP@ssw0rd123!"),
        is_active=True,
    )
    admin_user.roles.append(r_admin)

    analyst_user = User(
        id=uuid.uuid4(),
        username="sec_analyst",
        email="analyst@test-cspm.local",
        password_hash=get_password_hash("AnalystP@ssw0rd123!"),
        is_active=True,
    )
    analyst_user.roles.append(r_analyst)

    viewer_user = User(
        id=uuid.uuid4(),
        username="sec_viewer",
        email="viewer@test-cspm.local",
        password_hash=get_password_hash("ViewerP@ssw0rd123!"),
        is_active=True,
    )
    viewer_user.roles.append(r_viewer)

    inactive_user = User(
        id=uuid.uuid4(),
        username="inactive_guy",
        email="inactive@test-cspm.local",
        password_hash=get_password_hash("InactiveP@ssw0rd123!"),
        is_active=False,
    )
    inactive_user.roles.append(r_viewer)

    session.add_all([admin_user, analyst_user, viewer_user, inactive_user])
    session.commit()

    yield session

    session.close()
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture(scope="function")
def client(db_session):
    """Overrides get_db with test in-memory database."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


# ------------------------------------------------------------------------------
# 1. Password Security & Strength Tests
# ------------------------------------------------------------------------------

def test_password_hashing_and_verification():
    raw_pass = "SecureStrongP@ss99!"
    hashed = get_password_hash(raw_pass)
    assert hashed != raw_pass
    assert hashed.startswith("$2b$")
    assert verify_password(raw_pass, hashed) is True
    assert verify_password("WrongPassword123!", hashed) is False


def test_password_strength_validation():
    # Weak passwords
    assert validate_password_strength("short")[0] is False
    assert validate_password_strength("alllowercase123!")[0] is False
    assert validate_password_strength("ALLUPPERCASE123!")[0] is False
    assert validate_password_strength("NoDigitsOrSymbols")[0] is False
    assert validate_password_strength("a" * 75)[0] is False  # exceeds 72 bytes

    # Strong password
    is_valid, err = validate_password_strength("ValidP@ssw0rd2026")
    assert is_valid is True
    assert err is None


# ------------------------------------------------------------------------------
# 2. Login Endpoint Tests
# ------------------------------------------------------------------------------

def test_login_success_with_username(client, db_session):
    resp = client.post(
        "/api/auth/login",
        json={"username_or_email": "sec_admin", "password": "AdminP@ssw0rd123!"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert "user" in data
    assert data["user"]["username"] == "sec_admin"
    assert data["user"]["roles"] == ["ADMIN"]
    assert "password" not in data["user"]
    assert "password_hash" not in data["user"]

    # Verify audit log recorded
    log = db_session.query(AuditLog).filter(AuditLog.action == "LOGIN_SUCCESS").first()
    assert log is not None
    assert log.result == "SUCCESS"


def test_login_success_with_email(client):
    resp = client.post(
        "/api/auth/login",
        json={"username_or_email": "analyst@test-cspm.local", "password": "AnalystP@ssw0rd123!"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["user"]["username"] == "sec_analyst"
    assert "SECURITY_ANALYST" in data["user"]["roles"]


def test_login_invalid_password(client, db_session):
    resp = client.post(
        "/api/auth/login",
        json={"username_or_email": "sec_admin", "password": "IncorrectPassword!"},
    )
    assert resp.status_code == 401
    assert "Invalid email/username or password" in resp.json()["detail"]

    # Verify audit log failure
    log = db_session.query(AuditLog).filter(AuditLog.action == "LOGIN_FAILURE").first()
    assert log is not None
    assert log.result == "FAILURE"
    # Verify password was NEVER logged
    assert "IncorrectPassword!" not in str(log.metadata_json)


def test_login_nonexistent_user(client, db_session):
    resp = client.post(
        "/api/auth/login",
        json={"username_or_email": "does_not_exist@fake.local", "password": "RandomPassword123!"},
    )
    assert resp.status_code == 401
    assert "Invalid email/username or password" in resp.json()["detail"]


def test_login_inactive_user(client):
    resp = client.post(
        "/api/auth/login",
        json={"username_or_email": "inactive_guy", "password": "InactiveP@ssw0rd123!"},
    )
    assert resp.status_code == 401
    assert "disabled" in resp.json()["detail"].lower()


# ------------------------------------------------------------------------------
# 3. JWT Lifecycle & Token Verification Tests
# ------------------------------------------------------------------------------

def test_jwt_claims_and_decoding():
    token = create_access_token(
        subject="test-user-id",
        claims={"roles": ["ADMIN"], "username": "admin_test"},
        expires_delta=timedelta(minutes=15),
    )
    payload = decode_access_token(token)
    assert payload is not None
    assert payload["sub"] == "test-user-id"
    assert payload["roles"] == ["ADMIN"]
    assert "exp" in payload


def test_jwt_expiration(client):
    # Create expired token (-5 minutes in the past)
    expired_token = create_access_token(
        subject=str(uuid.uuid4()),
        expires_delta=timedelta(minutes=-5),
    )
    resp = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert resp.status_code == 401
    assert "Could not validate authentication credentials" in resp.json()["detail"]


def test_tampered_jwt_signature(client):
    valid_token = create_access_token(subject="valid-sub")
    tampered_token = valid_token[:-4] + "abcd"
    resp = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {tampered_token}"},
    )
    assert resp.status_code == 401


def test_missing_token_on_protected_route(client):
    resp = client.get("/api/auth/me")
    assert resp.status_code == 401


# ------------------------------------------------------------------------------
# 4. User Profile & Logout Tests
# ------------------------------------------------------------------------------

def test_get_me_profile_and_permissions(client):
    # Login as admin to obtain token
    login_resp = client.post(
        "/api/auth/login",
        json={"username_or_email": "sec_admin", "password": "AdminP@ssw0rd123!"},
    )
    token = login_resp.json()["access_token"]

    resp = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["username"] == "sec_admin"
    assert data["roles"] == ["ADMIN"]
    assert "findings:read" in data["permissions"]
    assert "users:manage" in data["permissions"]
    assert "password_hash" not in data


def test_logout_and_audit(client, db_session):
    login_resp = client.post(
        "/api/auth/login",
        json={"username_or_email": "sec_admin", "password": "AdminP@ssw0rd123!"},
    )
    token = login_resp.json()["access_token"]

    logout_resp = client.post(
        "/api/auth/logout",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert logout_resp.status_code == 200
    assert "Successfully logged out" in logout_resp.json()["message"]

    log = db_session.query(AuditLog).filter(AuditLog.action == "LOGOUT").first()
    assert log is not None
    assert log.result == "SUCCESS"


# ------------------------------------------------------------------------------
# 5. Role-Based Access Control (RBAC) Tests
# ------------------------------------------------------------------------------

def test_admin_role_authorization(client):
    # ADMIN accessing /admin-only -> 200 OK
    login_resp = client.post(
        "/api/auth/login",
        json={"username_or_email": "sec_admin", "password": "AdminP@ssw0rd123!"},
    )
    token = login_resp.json()["access_token"]

    resp = client.get(
        "/api/auth/admin-only",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert "ADMIN authorization successful" in resp.json()["detail"]


def test_analyst_forbidden_on_admin_endpoint(client, db_session):
    # SECURITY_ANALYST accessing /admin-only -> 403 Forbidden
    login_resp = client.post(
        "/api/auth/login",
        json={"username_or_email": "sec_analyst", "password": "AnalystP@ssw0rd123!"},
    )
    token = login_resp.json()["access_token"]

    resp = client.get(
        "/api/auth/admin-only",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403
    assert "Access forbidden" in resp.json()["detail"]

    # Verify ACCESS_DENIED audit log
    denied_log = db_session.query(AuditLog).filter(AuditLog.action == "ACCESS_DENIED").first()
    assert denied_log is not None
    assert denied_log.result == "DENIED"


def test_viewer_forbidden_on_analyst_endpoint(client):
    # VIEWER accessing /analyst-only -> 403 Forbidden
    login_resp = client.post(
        "/api/auth/login",
        json={"username_or_email": "sec_viewer", "password": "ViewerP@ssw0rd123!"},
    )
    token = login_resp.json()["access_token"]

    resp = client.get(
        "/api/auth/analyst-only",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403
    assert "Access forbidden" in resp.json()["detail"]


def test_analyst_allowed_on_analyst_endpoint(client):
    # SECURITY_ANALYST accessing /analyst-only -> 200 OK
    login_resp = client.post(
        "/api/auth/login",
        json={"username_or_email": "sec_analyst", "password": "AnalystP@ssw0rd123!"},
    )
    token = login_resp.json()["access_token"]

    resp = client.get(
        "/api/auth/analyst-only",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200


# ------------------------------------------------------------------------------
# 5. User Registration Endpoint Tests
# ------------------------------------------------------------------------------

def test_registration_success(client, db_session):
    resp = client.post(
        "/api/auth/register",
        json={
            "username": "new_sec_user",
            "email": "new_user@cspm.local",
            "password": "Secur3P@ssw0rd!",
            "password_confirm": "Secur3P@ssw0rd!",
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["message"] == "Account successfully registered. You can now log in."
    assert data["username"] == "new_sec_user"
    assert data["email"] == "new_user@cspm.local"
    assert data["roles"] == ["VIEWER"]

    # Verify user exists in database and password is encrypted with bcrypt
    created_user = db_session.query(User).filter(User.username == "new_sec_user").first()
    assert created_user is not None
    assert created_user.email == "new_user@cspm.local"
    assert created_user.is_active is True
    assert created_user.password_hash.startswith("$2b$") or created_user.password_hash.startswith("$2a$")
    assert "Secur3P@ssw0rd!" not in created_user.password_hash

    # Verify audit log recorded
    log = db_session.query(AuditLog).filter(
        AuditLog.action == "USER_REGISTER",
        AuditLog.user_id == created_user.id
    ).first()
    assert log is not None
    assert log.result == "SUCCESS"
    assert "Secur3P@ssw0rd!" not in str(log.metadata_json)


def test_registration_duplicate_username(client):
    # First registration
    client.post(
        "/api/auth/register",
        json={
            "username": "dup_username_user",
            "email": "user1@cspm.local",
            "password": "Password123!",
            "password_confirm": "Password123!",
        },
    )
    # Second attempt with same username
    resp = client.post(
        "/api/auth/register",
        json={
            "username": "dup_username_user",
            "email": "user2@cspm.local",
            "password": "Password123!",
            "password_confirm": "Password123!",
        },
    )
    assert resp.status_code == 400
    assert "Username is already registered" in resp.json()["detail"]


def test_registration_duplicate_email(client):
    # First registration
    client.post(
        "/api/auth/register",
        json={
            "username": "unique_user1",
            "email": "shared_email@cspm.local",
            "password": "Password123!",
            "password_confirm": "Password123!",
        },
    )
    # Second attempt with same email
    resp = client.post(
        "/api/auth/register",
        json={
            "username": "unique_user2",
            "email": "shared_email@cspm.local",
            "password": "Password123!",
            "password_confirm": "Password123!",
        },
    )
    assert resp.status_code == 400
    assert "Email address is already registered" in resp.json()["detail"]


def test_registration_invalid_email(client):
    resp = client.post(
        "/api/auth/register",
        json={
            "username": "bad_email_user",
            "email": "not-an-email",
            "password": "Password123!",
            "password_confirm": "Password123!",
        },
    )
    assert resp.status_code in (400, 422)


def test_registration_weak_password_no_number_or_special(client):
    resp = client.post(
        "/api/auth/register",
        json={
            "username": "weak_pwd_user",
            "email": "weak_pwd@cspm.local",
            "password": "PasswordOnly",
            "password_confirm": "PasswordOnly",
        },
    )
    assert resp.status_code == 400
    assert "digit or special symbol" in resp.json()["detail"]


def test_registration_password_mismatch(client):
    resp = client.post(
        "/api/auth/register",
        json={
            "username": "mismatch_user",
            "email": "mismatch@cspm.local",
            "password": "Password123!",
            "password_confirm": "DifferentPassword123!",
        },
    )
    assert resp.status_code == 400
    assert "do not match" in resp.json()["detail"]


def test_registration_followed_by_login_and_access(client):
    # 1. Register new user
    reg_resp = client.post(
        "/api/auth/register",
        json={
            "username": "active_viewer",
            "email": "active_viewer@cspm.local",
            "password": "GoodPassword123!",
            "password_confirm": "GoodPassword123!",
        },
    )
    assert reg_resp.status_code == 201

    # 2. Log in with new credentials
    login_resp = client.post(
        "/api/auth/login",
        json={
            "username_or_email": "active_viewer",
            "password": "GoodPassword123!",
        },
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]
    assert token is not None

    # 3. Access /auth/me
    me_resp = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert me_resp.status_code == 200
    me_data = me_resp.json()
    assert me_data["username"] == "active_viewer"
    assert me_data["roles"] == ["VIEWER"]

    # 4. Attempt accessing ADMIN-only endpoint (must be forbidden)
    admin_resp = client.get(
        "/api/auth/admin-only",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert admin_resp.status_code == 403

