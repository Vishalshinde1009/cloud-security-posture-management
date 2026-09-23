"""
Cross-Account AWS STS AssumeRole with External ID Test Suite
============================================================
Verifies:
1. External ID auto-generation for AWS cloud accounts to prevent Confused Deputy attacks.
2. Trust policy snippet generation with sts:ExternalId condition.
3. IAM Role ARN syntax validation and account ID matching.
4. PATCH /api/cloud-accounts/{id} for updating Role ARN with tenant isolation.
5. AWSClientFactory passing ExternalId to STS assume_role.
6. Target account verification in test_sts_connection.
7. End-to-end test-connection endpoint behavior for assumed roles.
"""

import uuid
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database.session import get_db, Base
from app.database.seed import seed_database
from app.models.auth import User, Role, Permission
from app.models.cloud import CloudAccount
from app.core.security import get_password_hash, create_access_token
from app.scanner.providers.aws.client_factory import AWSClientFactory

# Shared in-memory SQLite database
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
    """Provides a fresh seeded in-memory database session."""
    Base.metadata.create_all(bind=test_engine)
    session = TestingSessionLocal()
    seed_database(db=session)

    # Ensure SECURITY_ANALYST has cloud_accounts:manage
    analyst_role = session.query(Role).filter(Role.name == "SECURITY_ANALYST").first()
    p_manage_acc = session.query(Permission).filter(Permission.name == "cloud_accounts:manage").first()
    if p_manage_acc and p_manage_acc not in analyst_role.permissions:
        analyst_role.permissions.append(p_manage_acc)
        session.commit()

    yield session

    session.close()
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture(scope="function")
def client(db_session):
    """FastAPI TestClient with get_db dependency overridden."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def auth_header_for_user(user: User) -> dict:
    roles = [r.name for r in user.roles]
    token = create_access_token(subject=str(user.id), claims={"roles": roles})
    return {"Authorization": f"Bearer {token}"}


def create_test_user(db, username: str, email: str, role_name: str) -> User:
    role = db.query(Role).filter(Role.name == role_name).first()
    user = User(
        id=uuid.uuid4(),
        username=username,
        email=email,
        password_hash=get_password_hash("ComplexSecurePass123!"),
        is_active=True,
    )
    if role:
        user.roles.append(role)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


# =============================================================================
# 1. External ID Auto-Generation & Trust Policy Snippet Tests
# =============================================================================

def test_external_id_auto_generation_on_create(client, db_session):
    """Registering an AWS account automatically generates an External ID and trust policy snippet."""
    analyst = create_test_user(db_session, "analyst_ext", "analyst_ext@example.com", "SECURITY_ANALYST")
    headers = auth_header_for_user(analyst)

    payload = {
        "name": "Production Account",
        "provider": "AWS",
        "account_identifier": "123456789012",
        "default_region": "us-east-1",
        "credential_mode": "ENVIRONMENT",
    }
    resp = client.post("/api/cloud-accounts", json=payload, headers=headers)
    assert resp.status_code == 201
    data = resp.json()

    # External ID must be generated
    assert data["external_id"] is not None
    assert data["external_id"].startswith("cspm-ext-")
    assert len(data["external_id"]) >= 20

    # Trust policy snippet must be returned
    assert data["trust_policy_snippet"] is not None
    assert "sts:AssumeRole" in data["trust_policy_snippet"]
    assert data["external_id"] in data["trust_policy_snippet"]


def test_mock_account_does_not_require_external_id(client, db_session):
    """MOCK provider accounts do not auto-generate an external_id."""
    analyst = create_test_user(db_session, "analyst_mock", "analyst_mock@example.com", "SECURITY_ANALYST")
    headers = auth_header_for_user(analyst)

    payload = {
        "name": "Simulated Lab",
        "provider": "MOCK",
        "account_identifier": "mock-tenant-100",
        "default_region": "us-east-1",
        "credential_mode": "MOCK",
    }
    resp = client.post("/api/cloud-accounts", json=payload, headers=headers)
    assert resp.status_code == 201
    data = resp.json()
    assert data["external_id"] is None
    assert data["trust_policy_snippet"] is None


# =============================================================================
# 2. Role ARN Syntax & Account ID Cross-Check Validation Tests
# =============================================================================

def test_role_arn_valid_format_accepted(client, db_session):
    """A valid IAM Role ARN matching the account identifier is accepted."""
    analyst = create_test_user(db_session, "analyst_arn_ok", "arn_ok@example.com", "SECURITY_ANALYST")
    headers = auth_header_for_user(analyst)

    payload = {
        "name": "Audited Client AWS",
        "provider": "AWS",
        "account_identifier": "123456789012",
        "default_region": "us-east-1",
        "credential_mode": "ROLE",
        "role_arn": "arn:aws:iam::123456789012:role/CSPM-ReadOnly-Scanner",
    }
    resp = client.post("/api/cloud-accounts", json=payload, headers=headers)
    assert resp.status_code == 201
    data = resp.json()
    assert data["role_arn"] == "arn:aws:iam::123456789012:role/CSPM-ReadOnly-Scanner"
    assert data["credential_mode"] == "ROLE"


def test_role_arn_invalid_syntax_rejected(client, db_session):
    """An invalid IAM Role ARN format is rejected with HTTP 400."""
    analyst = create_test_user(db_session, "analyst_arn_bad", "arn_bad@example.com", "SECURITY_ANALYST")
    headers = auth_header_for_user(analyst)

    payload = {
        "name": "Bad ARN Account",
        "provider": "AWS",
        "account_identifier": "123456789012",
        "default_region": "us-east-1",
        "role_arn": "invalid-role-arn-format",
    }
    resp = client.post("/api/cloud-accounts", json=payload, headers=headers)
    assert resp.status_code == 400
    assert "Invalid AWS IAM Role ARN format" in resp.json()["detail"]


def test_role_arn_account_mismatch_rejected(client, db_session):
    """A Role ARN containing a different account ID than account_identifier is rejected."""
    analyst = create_test_user(db_session, "analyst_arn_mismatch", "arn_mis@example.com", "SECURITY_ANALYST")
    headers = auth_header_for_user(analyst)

    payload = {
        "name": "Mismatch Account",
        "provider": "AWS",
        "account_identifier": "111111111111",
        "default_region": "us-east-1",
        "role_arn": "arn:aws:iam::222222222222:role/CSPM-Role",
    }
    resp = client.post("/api/cloud-accounts", json=payload, headers=headers)
    assert resp.status_code == 400
    assert "does not match target account identifier" in resp.json()["detail"]


# =============================================================================
# 3. PATCH /api/cloud-accounts/{id} & Tenant Isolation Tests
# =============================================================================

def test_patch_cloud_account_role_arn_lifecycle(client, db_session):
    """User can create an account first, obtain external_id, then patch role_arn."""
    analyst = create_test_user(db_session, "analyst_patch", "analyst_patch@example.com", "SECURITY_ANALYST")
    headers = auth_header_for_user(analyst)

    # Step 1: Create account with ENVIRONMENT mode
    create_resp = client.post("/api/cloud-accounts", json={
        "name": "Staged Account",
        "provider": "AWS",
        "account_identifier": "333333333333",
        "default_region": "eu-central-1",
    }, headers=headers)
    assert create_resp.status_code == 201
    account_id = create_resp.json()["id"]
    ext_id = create_resp.json()["external_id"]
    assert ext_id is not None

    # Step 2: Patch account with Role ARN
    patch_resp = client.patch(f"/api/cloud-accounts/{account_id}", json={
        "role_arn": "arn:aws:iam::333333333333:role/CustomerAuditRole"
    }, headers=headers)
    assert patch_resp.status_code == 200
    patch_data = patch_resp.json()
    assert patch_data["role_arn"] == "arn:aws:iam::333333333333:role/CustomerAuditRole"
    assert patch_data["credential_mode"] == "ROLE"
    assert patch_data["external_id"] == ext_id

    # Step 3: Clear Role ARN back to ENVIRONMENT mode
    clear_resp = client.patch(f"/api/cloud-accounts/{account_id}", json={
        "role_arn": ""
    }, headers=headers)
    assert clear_resp.status_code == 200
    assert clear_resp.json()["role_arn"] is None
    assert clear_resp.json()["credential_mode"] == "ENVIRONMENT"


def test_patch_cloud_account_tenant_isolation(client, db_session):
    """User B cannot PATCH User A's cloud account (returns 404)."""
    user_a = create_test_user(db_session, "tenant_a_user", "tenant_a@example.com", "SECURITY_ANALYST")
    user_b = create_test_user(db_session, "tenant_b_user", "tenant_b@example.com", "SECURITY_ANALYST")

    headers_a = auth_header_for_user(user_a)
    headers_b = auth_header_for_user(user_b)

    # User A creates account
    resp_a = client.post("/api/cloud-accounts", json={
        "name": "Tenant A Secret Cloud",
        "provider": "AWS",
        "account_identifier": "444444444444",
        "default_region": "us-east-1",
    }, headers=headers_a)
    account_id = resp_a.json()["id"]

    # User B attempts to patch User A's account
    resp_b = client.patch(f"/api/cloud-accounts/{account_id}", json={
        "role_arn": "arn:aws:iam::444444444444:role/HijackedRole"
    }, headers=headers_b)
    assert resp_b.status_code == 404


# =============================================================================
# 4. AWSClientFactory AssumeRole with External ID & Identity Verification
# =============================================================================

def test_aws_client_factory_passes_external_id_to_assume_role():
    """AWSClientFactory passes ExternalId to STS assume_role call."""
    mock_sts_client = MagicMock()
    mock_sts_client.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "ASIA_TEST_KEY",
            "SecretAccessKey": "test_secret_key",
            "SessionToken": "test_session_token",
        }
    }

    mock_session = MagicMock()
    mock_session.client.return_value = mock_sts_client

    with patch("boto3.Session", return_value=mock_session):
        factory = AWSClientFactory(
            region_name="us-east-1",
            role_arn="arn:aws:iam::123456789012:role/CSPMRole",
            external_id="cspm-ext-unique-token-xyz",
            target_account_id="123456789012",
        )

        mock_sts_client.assume_role.assert_called_once_with(
            RoleArn="arn:aws:iam::123456789012:role/CSPMRole",
            RoleSessionName="CSPM-123456789012",
            DurationSeconds=3600,
            ExternalId="cspm-ext-unique-token-xyz",
        )


def test_aws_client_factory_verifies_target_account_id_match():
    """test_sts_connection verifies that caller identity Account matches target_account_id."""
    mock_sts_client = MagicMock()
    mock_sts_client.get_caller_identity.return_value = {
        "Account": "999999999999",  # Different from target
        "Arn": "arn:aws:sts::999999999999:assumed-role/CSPM/session",
        "UserId": "AROA_TEST:session",
    }

    mock_session = MagicMock()
    mock_session.client.return_value = mock_sts_client

    with patch("boto3.Session", return_value=mock_session):
        factory = AWSClientFactory(
            region_name="us-east-1",
            target_account_id="123456789012",
        )

        with pytest.raises(ValueError) as exc_info:
            factory.test_sts_connection()

        assert "Account ID mismatch" in str(exc_info.value)
        assert "999999999999" in str(exc_info.value)
        assert "123456789012" in str(exc_info.value)


# =============================================================================
# 5. Live Test Connection Endpoint with Assumed Role
# =============================================================================

def test_cloud_account_test_connection_endpoint_success(client, db_session):
    """POST /{id}/test-connection successfully validates assumed role identity."""
    analyst = create_test_user(db_session, "analyst_test_conn", "conn_test@example.com", "SECURITY_ANALYST")
    headers = auth_header_for_user(analyst)

    create_resp = client.post("/api/cloud-accounts", json={
        "name": "Live Assumed Cloud",
        "provider": "AWS",
        "account_identifier": "555555555555",
        "default_region": "us-east-1",
        "role_arn": "arn:aws:iam::555555555555:role/ScannerRole",
    }, headers=headers)
    account_id = create_resp.json()["id"]

    mock_factory = MagicMock()
    mock_factory.test_sts_connection.return_value = {
        "account_id": "555555555555",
        "arn": "arn:aws:sts::555555555555:assumed-role/ScannerRole/CSPM-555555555555",
        "user_id": "AROA_TEST_USER:CSPM-555555555555",
    }

    with patch("app.api.cloud_accounts.AWSClientFactory", return_value=mock_factory):
        test_resp = client.post(f"/api/cloud-accounts/{account_id}/test-connection", headers=headers)
        assert test_resp.status_code == 200
        data = test_resp.json()
        assert data["status"] == "CONNECTED"
        assert data["account_id"] == "555555555555"
        assert "Successfully authenticated to AWS Account 555555555555 via STS" in data["message"]
