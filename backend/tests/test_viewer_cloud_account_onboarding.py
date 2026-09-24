"""
Public User / VIEWER Cloud Account Onboarding Test Suite
=========================================================
Verifies:
1. Newly registered users (VIEWER role) can create their own CloudAccount.
2. External ID auto-generation and trust policy snippet generation for AWS accounts.
3. VIEWER can retrieve their own cloud account (list and detail).
4. VIEWER cannot see or access other users' cloud accounts (HTTP 404 / filtered list).
5. VIEWER can update (PATCH) their own cloud account (Role ARN / credential_mode).
6. VIEWER cannot update another user's cloud account (HTTP 404).
7. VIEWER can test connection on their own cloud account.
8. VIEWER cannot test connection on another user's cloud account (HTTP 404).
9. VIEWER can run a scan on their own cloud account (HTTP 201).
10. VIEWER cannot run a scan on another user's cloud account (HTTP 404).
11. ADMIN retains global oversight across all accounts, scans, and connections.
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
from app.models.auth import User, Role
from app.models.cloud import CloudAccount
from app.core.security import get_password_hash, create_access_token
from app.scanner.providers.base import DiscoveredResource
from app.scanner.providers.aws.provider import AWSProvider
from app.scanner.providers.aws.client_factory import AWSClientFactory
from app.scanner.providers.aws.read_only_guard import (
    AWS_READ_ONLY,
    assert_read_only_operation,
    AWSReadOnlyViolationError,
)


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
    """Provides a clean seeded database session."""
    Base.metadata.create_all(bind=test_engine)
    session = TestingSessionLocal()
    seed_database(db=session)
    yield session
    session.close()
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture(scope="function")
def client(db_session):
    """FastAPI TestClient with get_db overridden."""
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
    token = create_access_token(subject=str(user.id), claims={"roles": roles, "username": user.username})
    return {"Authorization": f"Bearer {token}"}


def create_test_user(db, username: str, email: str, role_name: str) -> User:
    role = db.query(Role).filter(Role.name == role_name).first()
    user = User(
        id=uuid.uuid4(),
        username=username,
        email=email,
        password_hash=get_password_hash("ValidPass12345!"),
        is_active=True,
    )
    if role:
        user.roles.append(role)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


# =============================================================================
# 1. Cloud Account Creation for VIEWER & External ID Auto-Generation
# =============================================================================

def test_viewer_can_create_aws_cloud_account_with_external_id(client, db_session):
    """Scenario 1: Authenticated VIEWER creates an AWS cloud account; External ID and trust policy auto-generated."""
    viewer = create_test_user(db_session, "onboarding_viewer_1", "viewer1@onboard.com", "VIEWER")
    headers = auth_header_for_user(viewer)

    payload = {
        "name": "My Production AWS",
        "provider": "AWS",
        "account_identifier": "123456789012",
        "default_region": "eu-north-1",
        "credential_mode": "ENVIRONMENT",
    }
    resp = client.post("/api/cloud-accounts", json=payload, headers=headers)
    assert resp.status_code == 201
    data = resp.json()

    assert data["name"] == "My Production AWS"
    assert data["provider"] == "AWS"
    assert data["account_identifier"] == "123456789012"
    assert data["default_region"] == "eu-north-1"
    assert data["credential_mode"] == "ENVIRONMENT"

    # External ID generated
    assert data["external_id"] is not None
    assert data["external_id"].startswith("cspm-ext-")
    assert len(data["external_id"]) >= 20

    # Trust policy snippet generated
    assert data["trust_policy_snippet"] is not None
    assert "sts:AssumeRole" in data["trust_policy_snippet"]
    assert data["external_id"] in data["trust_policy_snippet"]

    # Database verification: user_id assigned to viewer
    acc_db = db_session.query(CloudAccount).filter(CloudAccount.id == uuid.UUID(data["id"])).first()
    assert acc_db is not None
    assert acc_db.user_id == viewer.id


def test_viewer_can_list_and_get_own_cloud_account(client, db_session):
    """Scenario 2: VIEWER can list and retrieve detail of their own cloud account."""
    viewer = create_test_user(db_session, "onboarding_viewer_2", "viewer2@onboard.com", "VIEWER")
    headers = auth_header_for_user(viewer)

    # Create account
    create_res = client.post(
        "/api/cloud-accounts",
        json={
            "name": "Viewer 2 Account",
            "provider": "AWS",
            "account_identifier": "222333444555",
            "default_region": "us-east-1",
            "credential_mode": "ENVIRONMENT",
        },
        headers=headers,
    )
    assert create_res.status_code == 201
    acc_id = create_res.json()["id"]

    # List accounts -> contains acc_id
    list_res = client.get("/api/cloud-accounts", headers=headers)
    assert list_res.status_code == 200
    accounts = list_res.json()
    assert any(a["id"] == acc_id for a in accounts)

    # Get account by ID -> 200 OK
    detail_res = client.get(f"/api/cloud-accounts/{acc_id}", headers=headers)
    assert detail_res.status_code == 200
    assert detail_res.json()["id"] == acc_id
    assert detail_res.json()["name"] == "Viewer 2 Account"


# =============================================================================
# 2. Multi-Tenant Isolation & IDOR Protection across Viewers
# =============================================================================

def test_viewer_cannot_see_other_users_cloud_accounts(client, db_session):
    """Scenario 3: VIEWER cannot see another user's cloud account in list or via direct ID (HTTP 404)."""
    user_a = create_test_user(db_session, "user_a", "usera@test.com", "VIEWER")
    user_b = create_test_user(db_session, "user_b", "userb@test.com", "VIEWER")

    headers_a = auth_header_for_user(user_a)
    headers_b = auth_header_for_user(user_b)

    # User A creates an account
    res_a = client.post(
        "/api/cloud-accounts",
        json={
            "name": "User A Private AWS",
            "provider": "AWS",
            "account_identifier": "111122223333",
            "default_region": "us-east-1",
            "credential_mode": "ENVIRONMENT",
        },
        headers=headers_a,
    )
    assert res_a.status_code == 201
    acc_a_id = res_a.json()["id"]

    # User B lists cloud accounts -> User A's account must NOT appear
    list_b = client.get("/api/cloud-accounts", headers=headers_b)
    assert list_b.status_code == 200
    b_acc_ids = [a["id"] for a in list_b.json()]
    assert acc_a_id not in b_acc_ids

    # User B attempts direct GET /api/cloud-accounts/{acc_a_id} -> 404 Not Found
    get_b = client.get(f"/api/cloud-accounts/{acc_a_id}", headers=headers_b)
    assert get_b.status_code == 404


def test_viewer_can_update_own_account_with_role_arn(client, db_session):
    """Scenario 4: VIEWER can update (PATCH) their own cloud account with IAM Role ARN."""
    viewer = create_test_user(db_session, "viewer_role_updater", "updater@test.com", "VIEWER")
    headers = auth_header_for_user(viewer)

    create_res = client.post(
        "/api/cloud-accounts",
        json={
            "name": "Updatable AWS Account",
            "provider": "AWS",
            "account_identifier": "333444555666",
            "default_region": "us-west-2",
            "credential_mode": "ENVIRONMENT",
        },
        headers=headers,
    )
    acc_id = create_res.json()["id"]

    # PATCH account to configure Cross-Account Role ARN
    role_arn = "arn:aws:iam::333444555666:role/CSPM-ReadOnly-Role"
    patch_res = client.patch(
        f"/api/cloud-accounts/{acc_id}",
        json={"role_arn": role_arn, "credential_mode": "ROLE"},
        headers=headers,
    )
    assert patch_res.status_code == 200
    data = patch_res.json()
    assert data["role_arn"] == role_arn
    assert data["credential_mode"] == "ROLE"


def test_viewer_cannot_update_other_users_cloud_account(client, db_session):
    """Scenario 5: VIEWER cannot PATCH another user's cloud account (HTTP 404 IDOR prevention)."""
    user_a = create_test_user(db_session, "victim_user", "victim@test.com", "VIEWER")
    attacker = create_test_user(db_session, "attacker_user", "attacker@test.com", "VIEWER")

    headers_a = auth_header_for_user(user_a)
    headers_att = auth_header_for_user(attacker)

    res_a = client.post(
        "/api/cloud-accounts",
        json={
            "name": "Victim AWS Account",
            "provider": "AWS",
            "account_identifier": "444555666777",
            "default_region": "us-east-1",
            "credential_mode": "ENVIRONMENT",
        },
        headers=headers_a,
    )
    acc_a_id = res_a.json()["id"]

    # Attacker attempts to change Victim's role_arn
    evil_patch = client.patch(
        f"/api/cloud-accounts/{acc_a_id}",
        json={"role_arn": "arn:aws:iam::444555666777:role/HackedRole"},
        headers=headers_att,
    )
    assert evil_patch.status_code == 404


# =============================================================================
# 3. Connection Testing & Scan Execution Permissions & Isolation
# =============================================================================

def test_viewer_can_test_connection_on_own_account(client, db_session):
    """Scenario 6: VIEWER can test connection on their own cloud account."""
    viewer = create_test_user(db_session, "test_conn_viewer", "testconn@test.com", "VIEWER")
    headers = auth_header_for_user(viewer)

    # Create MOCK provider account for deterministic test-connection
    create_res = client.post(
        "/api/cloud-accounts",
        json={
            "name": "Viewer Mock Environment",
            "provider": "MOCK",
            "account_identifier": "mock-viewer-conn-01",
            "default_region": "us-east-1",
            "credential_mode": "MOCK",
        },
        headers=headers,
    )
    acc_id = create_res.json()["id"]

    # Test connection on own account -> 200 OK
    test_res = client.post(f"/api/cloud-accounts/{acc_id}/test-connection", headers=headers)
    assert test_res.status_code == 200
    assert test_res.json()["status"] == "CONNECTED"


def test_viewer_cannot_test_connection_on_other_users_account(client, db_session):
    """Scenario 7: VIEWER cannot test connection on another user's cloud account (HTTP 404)."""
    user_a = create_test_user(db_session, "conn_user_a", "conna@test.com", "VIEWER")
    user_b = create_test_user(db_session, "conn_user_b", "connb@test.com", "VIEWER")

    headers_a = auth_header_for_user(user_a)
    headers_b = auth_header_for_user(user_b)

    create_res = client.post(
        "/api/cloud-accounts",
        json={
            "name": "User A Mock Target",
            "provider": "MOCK",
            "account_identifier": "mock-conn-a",
            "default_region": "us-east-1",
            "credential_mode": "MOCK",
        },
        headers=headers_a,
    )
    acc_a_id = create_res.json()["id"]

    # User B attempts test-connection on User A's account -> 404
    test_b = client.post(f"/api/cloud-accounts/{acc_a_id}/test-connection", headers=headers_b)
    assert test_b.status_code == 404


def test_viewer_can_run_scan_on_own_account(client, db_session):
    """Scenario 8: VIEWER can trigger a scan on their own cloud account (HTTP 201)."""
    viewer = create_test_user(db_session, "scan_viewer_owner", "scanviewer@test.com", "VIEWER")
    headers = auth_header_for_user(viewer)

    create_res = client.post(
        "/api/cloud-accounts",
        json={
            "name": "Viewer Target for Scan",
            "provider": "MOCK",
            "account_identifier": "mock-scan-target-01",
            "default_region": "us-east-1",
            "credential_mode": "MOCK",
        },
        headers=headers,
    )
    acc_id = create_res.json()["id"]

    # Trigger scan
    scan_res = client.post("/api/scans", json={"account_id": acc_id}, headers=headers)
    assert scan_res.status_code == 201
    scan_data = scan_res.json()
    assert scan_data["cloud_account_id"] == acc_id
    assert scan_data["status"] == "COMPLETED"
    assert scan_data["resources_scanned"] > 0


def test_viewer_cannot_run_scan_on_other_users_account(client, db_session):
    """Scenario 9: VIEWER cannot trigger a scan on another user's cloud account (HTTP 404)."""
    user_a = create_test_user(db_session, "scan_owner_a", "scana@test.com", "VIEWER")
    user_b = create_test_user(db_session, "scan_attacker_b", "scanb@test.com", "VIEWER")

    headers_a = auth_header_for_user(user_a)
    headers_b = auth_header_for_user(user_b)

    create_res = client.post(
        "/api/cloud-accounts",
        json={
            "name": "Owner A Target",
            "provider": "MOCK",
            "account_identifier": "mock-target-a",
            "default_region": "us-east-1",
            "credential_mode": "MOCK",
        },
        headers=headers_a,
    )
    acc_a_id = create_res.json()["id"]

    # User B attempts to scan User A's account -> 404 Not Found
    res_b = client.post("/api/scans", json={"account_id": acc_a_id}, headers=headers_b)
    assert res_b.status_code == 404


def test_viewer_can_trigger_scan_on_own_account_with_real_aws_role(client, db_session):
    """Scenario 9b: VIEWER can trigger a scan on their own AWS account configured with IAM Role ARN & External ID (HTTP 201)."""
    viewer = create_test_user(db_session, "aws_role_scanner", "rolescanner@test.com", "VIEWER")
    headers = auth_header_for_user(viewer)

    # Create AWS account
    create_res = client.post(
        "/api/cloud-accounts",
        json={
            "name": "Viewer AWS Role Target",
            "provider": "AWS",
            "account_identifier": "123456789012",
            "default_region": "eu-north-1",
            "credential_mode": "ENVIRONMENT",
        },
        headers=headers,
    )
    assert create_res.status_code == 201
    acc_id = create_res.json()["id"]

    # Configure ROLE mode with role ARN
    role_arn = "arn:aws:iam::123456789012:role/CSPMViewerReadOnlyRole"
    patch_res = client.patch(
        f"/api/cloud-accounts/{acc_id}",
        json={"role_arn": role_arn, "credential_mode": "ROLE"},
        headers=headers,
    )
    assert patch_res.status_code == 200

    # Mock AWSProvider.discover_resources to return simulated AWS discovered resources
    mock_resource = DiscoveredResource(
        provider="AWS",
        account_id="123456789012",
        service="S3",
        resource_type="aws_s3_bucket",
        resource_id="arn:aws:s3:::viewer-secure-bucket",
        resource_name="viewer-secure-bucket",
        region="eu-north-1",
        configuration={
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            },
        },
    )

    with patch.object(AWSClientFactory, "_initialize_session", return_value=None), \
         patch.object(AWSProvider, "discover_resources", return_value=[mock_resource]):
        scan_res = client.post("/api/scans", json={"account_id": acc_id}, headers=headers)
        assert scan_res.status_code == 201
        scan_data = scan_res.json()
        assert scan_data["cloud_account_id"] == acc_id
        assert scan_data["status"] == "COMPLETED"
        assert scan_data["resources_scanned"] == 1


def test_unauthenticated_user_cannot_trigger_scan(client, db_session):
    """Scenario 9c: Unauthenticated request to POST /api/scans returns HTTP 401 Unauthorized."""
    res = client.post("/api/scans", json={"account_id": str(uuid.uuid4())})
    assert res.status_code == 401


def test_read_only_guard_still_blocks_mutating_actions():
    """Scenario 9d: Read-only guard enforces AWS_READ_ONLY=True and blocks mutating operations."""
    assert AWS_READ_ONLY is True

    # Mutating operations must raise AWSReadOnlyViolationError
    for op in ["delete_bucket", "create_bucket", "terminate_instances", "create_user", "delete_security_group", "put_bucket_policy"]:
        with pytest.raises(AWSReadOnlyViolationError):
            assert_read_only_operation(op)

    # Read-only operations must pass without raising
    for op in ["describe_instances", "list_buckets", "get_caller_identity", "get_bucket_encryption", "describe_security_groups"]:
        assert_read_only_operation(op)



# =============================================================================
# 4. Admin Global Oversight
# =============================================================================

def test_admin_retains_global_visibility_and_management(client, db_session):
    """Scenario 10: ADMIN retains global access to view, test, and scan across all tenants."""
    admin_user = db_session.query(User).join(User.roles).filter(Role.name == "ADMIN").first()
    assert admin_user is not None
    headers_admin = auth_header_for_user(admin_user)

    viewer = create_test_user(db_session, "tenant_viewer_x", "viewerx@test.com", "VIEWER")
    headers_viewer = auth_header_for_user(viewer)

    create_res = client.post(
        "/api/cloud-accounts",
        json={
            "name": "Viewer Registered Cloud",
            "provider": "MOCK",
            "account_identifier": "mock-tenant-x",
            "default_region": "us-east-1",
            "credential_mode": "MOCK",
        },
        headers=headers_viewer,
    )
    acc_id = create_res.json()["id"]

    # Admin lists accounts -> sees Viewer's account
    admin_list = client.get("/api/cloud-accounts", headers=headers_admin)
    assert admin_list.status_code == 200
    assert any(a["id"] == acc_id for a in admin_list.json())

    # Admin views account detail -> 200 OK
    admin_detail = client.get(f"/api/cloud-accounts/{acc_id}", headers=headers_admin)
    assert admin_detail.status_code == 200

    # Admin tests connection on viewer's account -> 200 OK
    admin_test = client.post(f"/api/cloud-accounts/{acc_id}/test-connection", headers=headers_admin)
    assert admin_test.status_code == 200

    # Admin triggers scan on viewer's account -> 201 Created
    admin_scan = client.post("/api/scans", json={"account_id": acc_id}, headers=headers_admin)
    assert admin_scan.status_code == 201
    assert admin_scan.json()["status"] == "COMPLETED"


# =============================================================================
# 5. Reports Onboarding & Tenant Isolation
# =============================================================================

def test_viewer_can_generate_and_download_report_for_own_completed_scan(client, db_session):
    """Scenario 11: VIEWER can generate and download a PDF report for their own completed scan."""
    viewer = create_test_user(db_session, "rep_viewer_own", "repviewer@test.com", "VIEWER")
    headers = auth_header_for_user(viewer)

    # 1. Create account
    acc_res = client.post(
        "/api/cloud-accounts",
        json={
            "name": "Viewer Report Target",
            "provider": "MOCK",
            "account_identifier": "mock-rep-target-01",
            "default_region": "us-east-1",
            "credential_mode": "MOCK",
        },
        headers=headers,
    )
    acc_id = acc_res.json()["id"]

    # 2. Trigger scan
    scan_res = client.post("/api/scans", json={"account_id": acc_id}, headers=headers)
    assert scan_res.status_code == 201
    assert scan_res.json()["status"] == "COMPLETED"

    # 3. Generate Report
    gen_res = client.post(
        "/api/reports",
        json={
            "account_id": acc_id,
            "report_type": "EXECUTIVE",
            "title": "My Executive Assessment",
        },
        headers=headers,
    )
    assert gen_res.status_code == 201
    rep_data = gen_res.json()
    rep_id = rep_data["id"]
    assert rep_data["report_type"] == "EXECUTIVE"
    assert rep_data["format"] == "PDF"

    # 4. List reports -> contains rep_id
    list_res = client.get("/api/reports", headers=headers)
    assert list_res.status_code == 200
    assert rep_id in [r["id"] for r in list_res.json()["items"]]

    # 5. Download report -> 200 OK
    dl_res = client.get(f"/api/reports/{rep_id}/download", headers=headers)
    assert dl_res.status_code == 200
    assert dl_res.headers["content-type"] == "application/pdf"
    assert len(dl_res.content) > 1000


def test_viewer_cannot_generate_report_for_other_users_account(client, db_session):
    """Scenario 12: VIEWER cannot generate a report targeting another user's cloud account (HTTP 404)."""
    user_a = create_test_user(db_session, "victim_rep_owner", "victim_rep@test.com", "VIEWER")
    attacker = create_test_user(db_session, "attacker_rep_user", "attacker_rep@test.com", "VIEWER")

    headers_a = auth_header_for_user(user_a)
    headers_att = auth_header_for_user(attacker)

    # User A creates account and runs scan
    acc_a = client.post(
        "/api/cloud-accounts",
        json={
            "name": "User A Private Cloud",
            "provider": "MOCK",
            "account_identifier": "mock-victim-cloud",
            "default_region": "us-east-1",
            "credential_mode": "MOCK",
        },
        headers=headers_a,
    ).json()["id"]

    client.post("/api/scans", json={"account_id": acc_a}, headers=headers_a)

    # Attacker tries to generate report for User A's account -> 404
    evil_gen = client.post(
        "/api/reports",
        json={"account_id": acc_a, "report_type": "EXECUTIVE"},
        headers=headers_att,
    )
    assert evil_gen.status_code == 404


def test_viewer_cannot_access_or_download_other_users_report(client, db_session):
    """Scenario 13: VIEWER cannot view metadata or download another user's report (HTTP 404)."""
    user_a = create_test_user(db_session, "legit_user_a", "legita@test.com", "VIEWER")
    user_b = create_test_user(db_session, "snooping_user_b", "snoopb@test.com", "VIEWER")

    headers_a = auth_header_for_user(user_a)
    headers_b = auth_header_for_user(user_b)

    # User A creates account, scans, and generates report
    acc_a = client.post(
        "/api/cloud-accounts",
        json={
            "name": "Legit Account",
            "provider": "MOCK",
            "account_identifier": "mock-legit-01",
            "default_region": "us-east-1",
            "credential_mode": "MOCK",
        },
        headers=headers_a,
    ).json()["id"]

    client.post("/api/scans", json={"account_id": acc_a}, headers=headers_a)
    rep_a = client.post(
        "/api/reports",
        json={"account_id": acc_a, "report_type": "EXECUTIVE"},
        headers=headers_a,
    ).json()["id"]

    # User B lists reports -> User A's report must NOT be included
    list_b = client.get("/api/reports", headers=headers_b)
    assert list_b.status_code == 200
    assert rep_a not in [r["id"] for r in list_b.json()["items"]]

    # User B attempts direct GET metadata -> 404
    assert client.get(f"/api/reports/{rep_a}", headers=headers_b).status_code == 404

    # User B attempts direct download -> 404
    assert client.get(f"/api/reports/{rep_a}/download", headers=headers_b).status_code == 404


def test_admin_retains_global_report_access(client, db_session):
    """Scenario 14: ADMIN retains global access to view and download reports across all tenants."""
    admin_user = db_session.query(User).join(User.roles).filter(Role.name == "ADMIN").first()
    viewer = create_test_user(db_session, "tenant_rep_viewer", "tenant_rep@test.com", "VIEWER")

    headers_admin = auth_header_for_user(admin_user)
    headers_viewer = auth_header_for_user(viewer)

    # Viewer creates account, scans, and generates report
    acc_id = client.post(
        "/api/cloud-accounts",
        json={
            "name": "Viewer Multi Cloud",
            "provider": "MOCK",
            "account_identifier": "mock-multi-rep",
            "default_region": "us-east-1",
            "credential_mode": "MOCK",
        },
        headers=headers_viewer,
    ).json()["id"]

    client.post("/api/scans", json={"account_id": acc_id}, headers=headers_viewer)
    rep_id = client.post(
        "/api/reports",
        json={"account_id": acc_id, "report_type": "EXECUTIVE"},
        headers=headers_viewer,
    ).json()["id"]

    # Admin lists reports -> sees Viewer's report
    list_admin = client.get("/api/reports", headers=headers_admin)
    assert list_admin.status_code == 200
    assert rep_id in [r["id"] for r in list_admin.json()["items"]]

    # Admin gets report metadata -> 200 OK
    assert client.get(f"/api/reports/{rep_id}", headers=headers_admin).status_code == 200

    # Admin downloads report -> 200 OK
    assert client.get(f"/api/reports/{rep_id}/download", headers=headers_admin).status_code == 200


# =============================================================================
# 6. Audit Log RBAC Preservation
# =============================================================================

def test_audit_log_rbac_viewer_restricted_admin_allowed(client, db_session):
    """Scenario 15: Audit logs allow VIEWER tenant-scoped access (200 OK); Admin gets global 200 OK."""
    admin_user = db_session.query(User).join(User.roles).filter(Role.name == "ADMIN").first()
    viewer = create_test_user(db_session, "audit_probe_viewer", "probe@test.com", "VIEWER")

    headers_admin = auth_header_for_user(admin_user)
    headers_viewer = auth_header_for_user(viewer)

    # Viewer receives 200 OK scoped to own tenant activity
    res_v = client.get("/api/audit-logs", headers=headers_viewer)
    assert res_v.status_code == 200
    assert "items" in res_v.json()
    assert "total" in res_v.json()

    # Admin receives 200 OK with global access
    res_a = client.get("/api/audit-logs", headers=headers_admin)
    assert res_a.status_code == 200
    assert "items" in res_a.json()
    assert "total" in res_a.json()


# =============================================================================
# 7. Explicit Cloud Account RBAC & Tenant Isolation Tests
# =============================================================================

def test_viewer_cloud_account_rbac_and_tenant_isolation(client, db_session):
    """
    Verifies:
    - Unauthenticated GET /api/cloud-accounts -> 401
    - Publicly registered user (VIEWER) can GET /api/cloud-accounts -> 200 (not 403)
    - VIEWER sees only their own cloud accounts (not another tenant's)
    - VIEWER accessing another user's cloud account detail -> 404
    - ADMIN retains global access
    - SECURITY_ANALYST retains access
    """
    # 1. Unauthenticated request -> 401
    unauth_res = client.get("/api/cloud-accounts")
    assert unauth_res.status_code == 401

    # 2. Public registration -> user gets VIEWER role with read:accounts
    reg_res = client.post(
        "/api/auth/register",
        json={
            "username": "fresh_registered_viewer",
            "email": "fresh_viewer@test.com",
            "password": "SecurePassword123!",
            "password_confirm": "SecurePassword123!",
        },
    )
    assert reg_res.status_code == 201

    # Login as fresh viewer
    login_res = client.post(
        "/api/auth/login",
        json={
            "username_or_email": "fresh_registered_viewer",
            "password": "SecurePassword123!",
        },
    )
    assert login_res.status_code == 200
    fresh_token = login_res.json()["access_token"]
    fresh_headers = {"Authorization": f"Bearer {fresh_token}"}

    # Fresh viewer can immediately list cloud accounts -> 200 OK (not 403)
    fresh_list_res = client.get("/api/cloud-accounts", headers=fresh_headers)
    assert fresh_list_res.status_code == 200
    assert isinstance(fresh_list_res.json(), list)

    # 3. Create cloud account for fresh viewer
    create_res1 = client.post(
        "/api/cloud-accounts",
        json={
            "name": "Fresh Viewer Account",
            "provider": "AWS",
            "account_identifier": "111122223333",
            "default_region": "us-east-1",
            "credential_mode": "ENVIRONMENT",
        },
        headers=fresh_headers,
    )
    assert create_res1.status_code == 201
    acc1_id = create_res1.json()["id"]

    # Create another viewer user and their account
    viewer2 = create_test_user(db_session, "tenant2_viewer", "t2_viewer@test.com", "VIEWER")
    headers_viewer2 = auth_header_for_user(viewer2)

    create_res2 = client.post(
        "/api/cloud-accounts",
        json={
            "name": "Tenant 2 Account",
            "provider": "AWS",
            "account_identifier": "444455556666",
            "default_region": "us-west-2",
            "credential_mode": "ENVIRONMENT",
        },
        headers=headers_viewer2,
    )
    assert create_res2.status_code == 201
    acc2_id = create_res2.json()["id"]

    # 4. Fresh viewer lists accounts -> sees acc1, but NOT acc2
    v1_accounts = client.get("/api/cloud-accounts", headers=fresh_headers).json()
    v1_account_ids = [a["id"] for a in v1_accounts]
    assert acc1_id in v1_account_ids
    assert acc2_id not in v1_account_ids

    # 5. Fresh viewer tries to access acc2 detail -> 404 Not Found (tenant isolated)
    assert client.get(f"/api/cloud-accounts/{acc2_id}", headers=fresh_headers).status_code == 404

    # 6. Admin user -> sees both accounts
    admin_user = db_session.query(User).join(User.roles).filter(Role.name == "ADMIN").first()
    headers_admin = auth_header_for_user(admin_user)
    admin_accounts = client.get("/api/cloud-accounts", headers=headers_admin).json()
    admin_account_ids = [a["id"] for a in admin_accounts]
    assert acc1_id in admin_account_ids
    assert acc2_id in admin_account_ids

    # 7. Security Analyst -> has access to list cloud accounts
    analyst_user = create_test_user(db_session, "analyst_rbac_user", "analyst_rbac@test.com", "SECURITY_ANALYST")
    headers_analyst = auth_header_for_user(analyst_user)
    analyst_res = client.get("/api/cloud-accounts", headers=headers_analyst)
    assert analyst_res.status_code == 200


def test_strict_tenant_isolation_unowned_accounts_admin_only(client, db_session):
    """
    Verifies strict tenant isolation for unowned/legacy accounts (user_id IS NULL):
    - Unauthenticated GET /api/cloud-accounts -> 401
    - Unowned account created with user_id=None
    - VIEWER cannot list unowned accounts (hidden from list)
    - VIEWER cannot retrieve unowned account GET /api/cloud-accounts/{unowned_id} -> 404
    - VIEWER cannot update unowned account PATCH /api/cloud-accounts/{unowned_id} -> 404
    - VIEWER cannot delete unowned account DELETE /api/cloud-accounts/{unowned_id} -> 404
    - VIEWER cannot test connection on unowned account -> 404
    - VIEWER cannot trigger scan on unowned account -> 404
    - VIEWER can list and access their own owned account
    - ADMIN can list and retrieve all accounts including unowned accounts (user_id IS NULL)
    """
    # Create unowned account (legacy/system account with user_id=None)
    unowned_acc = CloudAccount(
        id=uuid.uuid4(),
        name="Legacy Unowned Account",
        provider="AWS",
        account_identifier="000011112222",
        default_region="us-east-1",
        credential_mode="ENVIRONMENT",
        role_arn=None,
        external_id="cspm-ext-unowned-01",
        user_id=None,
        is_active=True,
    )
    db_session.add(unowned_acc)
    db_session.commit()

    # Create VIEWER user and an owned account
    viewer = create_test_user(db_session, "strict_viewer_user", "strict_viewer@test.com", "VIEWER")
    viewer_headers = auth_header_for_user(viewer)

    create_res = client.post(
        "/api/cloud-accounts",
        json={
            "name": "Viewer Owned Account",
            "provider": "AWS",
            "account_identifier": "999988887777",
            "default_region": "us-east-1",
            "credential_mode": "ENVIRONMENT",
        },
        headers=viewer_headers,
    )
    assert create_res.status_code == 201
    viewer_acc_id = create_res.json()["id"]

    # 1. Unauthenticated request -> 401
    assert client.get("/api/cloud-accounts").status_code == 401
    assert client.get(f"/api/cloud-accounts/{unowned_acc.id}").status_code == 401

    # 2. VIEWER listing -> sees ONLY their owned account, unowned is HIDDEN
    viewer_list_res = client.get("/api/cloud-accounts", headers=viewer_headers)
    assert viewer_list_res.status_code == 200
    listed_ids = [a["id"] for a in viewer_list_res.json()]
    assert viewer_acc_id in listed_ids
    assert str(unowned_acc.id) not in listed_ids

    # 3. VIEWER retrieving unowned account -> 404 Not Found
    get_unowned_res = client.get(f"/api/cloud-accounts/{unowned_acc.id}", headers=viewer_headers)
    assert get_unowned_res.status_code == 404

    # 4. VIEWER updating unowned account -> 404 Not Found
    patch_res = client.patch(
        f"/api/cloud-accounts/{unowned_acc.id}",
        json={"name": "Hacked Unowned Account"},
        headers=viewer_headers,
    )
    assert patch_res.status_code == 404

    # 5. VIEWER deleting unowned account -> 404 Not Found
    delete_res = client.delete(f"/api/cloud-accounts/{unowned_acc.id}", headers=viewer_headers)
    assert delete_res.status_code == 404

    # 6. VIEWER testing connection on unowned account -> 404 Not Found
    test_conn_res = client.post(
        f"/api/cloud-accounts/{unowned_acc.id}/test-connection",
        headers=viewer_headers,
    )
    assert test_conn_res.status_code == 404

    # 7. VIEWER triggering scan on unowned account -> 404 Not Found
    scan_res = client.post(
        "/api/scans",
        json={"account_id": str(unowned_acc.id)},
        headers=viewer_headers,
    )
    assert scan_res.status_code == 404

    # 8. VIEWER can access their own account
    get_owned_res = client.get(f"/api/cloud-accounts/{viewer_acc_id}", headers=viewer_headers)
    assert get_owned_res.status_code == 200
    assert get_owned_res.json()["id"] == viewer_acc_id

    # 9. ADMIN can list and retrieve all accounts, including unowned accounts
    admin_user = db_session.query(User).join(User.roles).filter(Role.name == "ADMIN").first()
    admin_headers = auth_header_for_user(admin_user)

    admin_list_res = client.get("/api/cloud-accounts", headers=admin_headers)
    assert admin_list_res.status_code == 200
    admin_listed_ids = [a["id"] for a in admin_list_res.json()]
    assert str(unowned_acc.id) in admin_listed_ids
    assert viewer_acc_id in admin_listed_ids

    admin_get_unowned = client.get(f"/api/cloud-accounts/{unowned_acc.id}", headers=admin_headers)
    assert admin_get_unowned.status_code == 200
    assert admin_get_unowned.json()["id"] == str(unowned_acc.id)
