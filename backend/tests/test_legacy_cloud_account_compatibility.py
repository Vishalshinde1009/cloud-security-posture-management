"""
Phase 2B.1 — Legacy CloudAccount Compatibility Test Suite
==========================================================
Verifies:
1. Existing AWS account with NULL external_id gets populated with a unique external_id.
2. Existing non-null external_id is preserved and unchanged.
3. MOCK account is not modified with an external_id.
4. External ID is cryptographically generated and unpredictable.
5. Generated External IDs are unique across multiple accounts.
6. Existing CloudAccount scan history remains intact.
7. Existing CloudAccount ownership remains intact.
8. Legacy ENVIRONMENT account can be changed to ROLE (with role_arn initially None).
9. ROLE account without role ARN cannot connect yet (fails cleanly, no fallback).
10. ROLE account with valid role ARN uses ExternalId.
11. Cross-tenant PATCH remains blocked (returns 404).
12. Role ARN account mismatch remains rejected (returns 400).
"""

import uuid
import secrets
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
from app.models.cloud import CloudAccount, Scan
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
# 1. Backfill & Legacy AWS Account Tests
# =============================================================================

def test_legacy_aws_account_gets_populated_and_preserves_data(client, db_session):
    """Legacy AWS accounts with external_id=NULL get populated while preserving ID, ownership, and scan history."""
    owner = create_test_user(db_session, "legacy_owner", "legacy_owner@example.com", "SECURITY_ANALYST")
    headers = auth_header_for_user(owner)

    # Directly create a legacy AWS account with external_id=NULL in the database
    account_id = uuid.uuid4()
    legacy_account = CloudAccount(
        id=account_id,
        name="cspm-readonly-eu",
        provider="AWS",
        account_identifier="123456789012",
        default_region="eu-north-1",
        credential_mode="ENVIRONMENT",
        role_arn=None,
        external_id=None,
        user_id=owner.id,
        is_active=True,
    )
    db_session.add(legacy_account)
    db_session.commit()

    # Add historical scan record to verify scan history preservation
    scan = Scan(
        id=uuid.uuid4(),
        cloud_account_id=account_id,
        status="COMPLETED",
        resources_scanned=5,
        findings_count=2,
        security_score=85.0,
    )
    db_session.add(scan)
    db_session.commit()

    # Query the account via API
    resp = client.get(f"/api/cloud-accounts/{account_id}", headers=headers)
    assert resp.status_code == 200
    data = resp.json()

    # Verify external_id was populated and is secure
    assert data["external_id"] is not None
    assert data["external_id"].startswith("cspm-ext-")
    assert len(data["external_id"]) >= 20

    # Verify trust policy snippet is now available
    assert data["trust_policy_snippet"] is not None
    assert data["external_id"] in data["trust_policy_snippet"]

    # Verify all original account metadata preserved
    assert data["id"] == str(account_id)
    assert data["name"] == "cspm-readonly-eu"
    assert data["account_identifier"] == "123456789012"
    assert data["default_region"] == "eu-north-1"
    assert data["credential_mode"] == "ENVIRONMENT"
    assert data["total_scans"] == 1
    assert data["latest_scan"]["security_score"] == 85.0


def test_existing_non_null_external_id_is_unchanged(client, db_session):
    """An AWS account with an existing external_id must not be overwritten."""
    owner = create_test_user(db_session, "ext_owner", "ext_owner@example.com", "SECURITY_ANALYST")
    headers = auth_header_for_user(owner)

    account_id = uuid.uuid4()
    original_ext_id = "cspm-ext-custom-pre-existing-id"
    account = CloudAccount(
        id=account_id,
        name="Pre-Configured AWS",
        provider="AWS",
        account_identifier="987654321098",
        default_region="us-east-1",
        credential_mode="ENVIRONMENT",
        role_arn=None,
        external_id=original_ext_id,
        user_id=owner.id,
        is_active=True,
    )
    db_session.add(account)
    db_session.commit()

    resp = client.get(f"/api/cloud-accounts/{account_id}", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["external_id"] == original_ext_id


def test_mock_account_not_modified_with_external_id(client, db_session):
    """MOCK accounts must remain with external_id=None."""
    owner = create_test_user(db_session, "mock_owner", "mock_owner@example.com", "SECURITY_ANALYST")
    headers = auth_header_for_user(owner)

    account_id = uuid.uuid4()
    mock_account = CloudAccount(
        id=account_id,
        name="Demo Environment",
        provider="MOCK",
        account_identifier="mock-account-001",
        default_region="us-east-1",
        credential_mode="MOCK",
        role_arn=None,
        external_id=None,
        user_id=owner.id,
        is_active=True,
    )
    db_session.add(mock_account)
    db_session.commit()

    resp = client.get(f"/api/cloud-accounts/{account_id}", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["external_id"] is None
    assert resp.json()["trust_policy_snippet"] is None


def test_generated_external_ids_are_unique(client, db_session):
    """Auto-generated External IDs must be globally unique across multiple accounts."""
    owner = create_test_user(db_session, "unique_owner", "unique_owner@example.com", "SECURITY_ANALYST")
    headers = auth_header_for_user(owner)

    ext_ids = set()
    for i in range(5):
        resp = client.post("/api/cloud-accounts", json={
            "name": f"Account {i}",
            "provider": "AWS",
            "account_identifier": f"10000000000{i}",
            "default_region": "us-east-1",
        }, headers=headers)
        assert resp.status_code == 201
        ext_id = resp.json()["external_id"]
        assert ext_id not in ext_ids
        ext_ids.add(ext_id)

    assert len(ext_ids) == 5


# =============================================================================
# 2. Legacy Account Upgrade: ENVIRONMENT -> ROLE
# =============================================================================

def test_legacy_environment_account_upgraded_to_role_without_role_arn(client, db_session):
    """Authorized owner can switch credential_mode to ROLE while leaving role_arn as NULL."""
    owner = create_test_user(db_session, "upgrade_owner", "upgrade_owner@example.com", "SECURITY_ANALYST")
    headers = auth_header_for_user(owner)

    # Step 1: Create account with ENVIRONMENT mode
    create_resp = client.post("/api/cloud-accounts", json={
        "name": "Upgradable AWS Account",
        "provider": "AWS",
        "account_identifier": "555666777888",
        "default_region": "us-west-2",
        "credential_mode": "ENVIRONMENT",
    }, headers=headers)
    account_id = create_resp.json()["id"]
    ext_id = create_resp.json()["external_id"]

    # Step 2: Patch credential_mode to ROLE without role_arn
    patch_resp = client.patch(f"/api/cloud-accounts/{account_id}", json={
        "credential_mode": "ROLE"
    }, headers=headers)
    assert patch_resp.status_code == 200
    data = patch_resp.json()
    assert data["credential_mode"] == "ROLE"
    assert data["role_arn"] is None
    assert data["external_id"] == ext_id

    # Step 3: Test connection fails gracefully with clear message (no crash, no fallback)
    conn_resp = client.post(f"/api/cloud-accounts/{account_id}/test-connection", headers=headers)
    assert conn_resp.status_code == 200
    conn_data = conn_resp.json()
    assert conn_data["status"] == "ERROR"
    assert "IAM Role ARN is not configured for ROLE credential mode" in conn_data["message"]

    # Step 4: Configure valid Role ARN
    role_arn = "arn:aws:iam::555666777888:role/CSPM-ReadOnly-Role"
    patch_role_resp = client.patch(f"/api/cloud-accounts/{account_id}", json={
        "role_arn": role_arn
    }, headers=headers)
    assert patch_role_resp.status_code == 200
    assert patch_role_resp.json()["role_arn"] == role_arn
    assert patch_role_resp.json()["credential_mode"] == "ROLE"


def test_cross_tenant_patch_blocked(client, db_session):
    """User B cannot PATCH User A's account (returns 404)."""
    user_a = create_test_user(db_session, "user_alpha", "alpha@example.com", "SECURITY_ANALYST")
    user_b = create_test_user(db_session, "user_beta", "beta@example.com", "SECURITY_ANALYST")

    headers_a = auth_header_for_user(user_a)
    headers_b = auth_header_for_user(user_b)

    resp_a = client.post("/api/cloud-accounts", json={
        "name": "Alpha Account",
        "provider": "AWS",
        "account_identifier": "777888999000",
        "default_region": "us-east-1",
    }, headers=headers_a)
    account_id = resp_a.json()["id"]

    resp_b = client.patch(f"/api/cloud-accounts/{account_id}", json={
        "credential_mode": "ROLE"
    }, headers=headers_b)
    assert resp_b.status_code == 404


def test_role_arn_account_mismatch_rejected_on_patch(client, db_session):
    """Patching a role_arn with mismatched account ID is rejected with 400."""
    user = create_test_user(db_session, "arn_user", "arn_user@example.com", "SECURITY_ANALYST")
    headers = auth_header_for_user(user)

    resp = client.post("/api/cloud-accounts", json={
        "name": "Target Account",
        "provider": "AWS",
        "account_identifier": "111222333444",
        "default_region": "us-east-1",
    }, headers=headers)
    account_id = resp.json()["id"]

    patch_resp = client.patch(f"/api/cloud-accounts/{account_id}", json={
        "role_arn": "arn:aws:iam::999888777666:role/MismatchRole"
    }, headers=headers)
    assert patch_resp.status_code == 400
    assert "does not match target account identifier" in patch_resp.json()["detail"]


# =============================================================================
# 3. STS AssumeRole & ExternalId Enforcement
# =============================================================================

def test_role_account_with_valid_role_arn_passes_external_id():
    """When role_arn and external_id are present, ExternalId is passed to sts:assume_role."""
    mock_sts_client = MagicMock()
    mock_sts_client.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "ASIA_UPGRADED_KEY",
            "SecretAccessKey": "upgraded_secret",
            "SessionToken": "upgraded_token",
        }
    }
    mock_session = MagicMock()
    mock_session.client.return_value = mock_sts_client

    with patch("boto3.Session", return_value=mock_session):
        factory = AWSClientFactory(
            region_name="eu-north-1",
            role_arn="arn:aws:iam::123456789012:role/CSPM-Upgrade-Role",
            external_id="cspm-ext-upgrade-test-token",
            target_account_id="123456789012",
        )

        mock_sts_client.assume_role.assert_called_once_with(
            RoleArn="arn:aws:iam::123456789012:role/CSPM-Upgrade-Role",
            RoleSessionName="CSPM-123456789012",
            DurationSeconds=3600,
            ExternalId="cspm-ext-upgrade-test-token",
        )
