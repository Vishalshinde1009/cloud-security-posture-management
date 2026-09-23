"""
Cloud Account Safe Deletion Test Suite
======================================
Verifies:
1. Owner can safely delete their own CloudAccount.
2. VIEWER role can delete their own CloudAccount.
3. Unauthenticated request to delete is rejected with HTTP 401.
4. Normal user cannot delete another user's CloudAccount (HTTP 404 / IDOR protection).
5. Administrator can delete cloud accounts according to RBAC.
6. Dependent CSPM data (Scans, Resources, Findings, Reports) are atomically cleaned up.
7. Deleting one duplicate account (same AWS account ID) does NOT affect the other account.
8. Deletion creates an audit event (CLOUD_ACCOUNT_DELETED) with non-sensitive metadata.
9. Deletion NEVER calls AWS mutation APIs or STS AssumeRole (pure CSPM local database cleanup).
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
from app.models.cloud import CloudAccount, Scan, Resource
from app.models.finding import Finding, SecurityRule
from app.models.report import Report
from app.models.audit import AuditLog
from app.core.security import get_password_hash, create_access_token


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
    """Provides a clean seeded database session with foreign keys enforced."""
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
# 1. Owner & VIEWER Deletion Permissions
# =============================================================================

def test_owner_viewer_can_delete_own_cloud_account(client, db_session):
    """Viewer can delete their own CloudAccount."""
    viewer = create_test_user(db_session, "del_viewer_1", "viewer1@del.com", "VIEWER")
    headers = auth_header_for_user(viewer)

    # Register account
    acc = CloudAccount(
        name="Viewer Target To Delete",
        provider="AWS",
        account_identifier="181137999524",
        default_region="us-east-1",
        credential_mode="ROLE",
        role_arn="arn:aws:iam::181137999524:role/OldRole",
        user_id=viewer.id,
        is_active=True,
    )
    db_session.add(acc)
    db_session.commit()
    acc_id = acc.id

    # Delete
    resp = client.delete(f"/api/cloud-accounts/{acc_id}", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "SUCCESS"
    assert data["account_id"] == str(acc_id)

    # Confirm removed from database
    db_session.expire_all()
    deleted = db_session.query(CloudAccount).filter(CloudAccount.id == acc_id).first()
    assert deleted is None


def test_unauthenticated_delete_rejected(client, db_session):
    """Unauthenticated request to DELETE /api/cloud-accounts/{id} returns 401."""
    viewer = create_test_user(db_session, "del_viewer_2", "viewer2@del.com", "VIEWER")
    acc = CloudAccount(
        name="Target Unauth",
        provider="AWS",
        account_identifier="181137999524",
        default_region="us-east-1",
        user_id=viewer.id,
        is_active=True,
    )
    db_session.add(acc)
    db_session.commit()

    resp = client.delete(f"/api/cloud-accounts/{acc.id}")
    assert resp.status_code == 401


def test_cross_tenant_delete_rejected_with_404(client, db_session):
    """Normal user cannot delete another tenant's CloudAccount (returns 404)."""
    user_a = create_test_user(db_session, "user_a_owner", "usera@del.com", "VIEWER")
    user_b = create_test_user(db_session, "user_b_attacker", "userb@del.com", "VIEWER")
    headers_b = auth_header_for_user(user_b)

    acc_a = CloudAccount(
        name="User A Account",
        provider="AWS",
        account_identifier="181137999524",
        default_region="eu-north-1",
        user_id=user_a.id,
        is_active=True,
    )
    db_session.add(acc_a)
    db_session.commit()

    # User B attempts to delete User A's account
    resp = client.delete(f"/api/cloud-accounts/{acc_a.id}", headers=headers_b)
    assert resp.status_code == 404

    # Confirm Account A is still safely in database
    db_session.expire_all()
    check = db_session.query(CloudAccount).filter(CloudAccount.id == acc_a.id).first()
    assert check is not None


def test_admin_can_delete_any_account(client, db_session):
    """Admin can delete accounts across tenants per existing RBAC."""
    admin = create_test_user(db_session, "admin_deleter", "admin@del.com", "ADMIN")
    user = create_test_user(db_session, "target_user", "target@del.com", "VIEWER")
    admin_headers = auth_header_for_user(admin)

    acc = CloudAccount(
        name="User Account Deleted By Admin",
        provider="AWS",
        account_identifier="181137999524",
        default_region="eu-north-1",
        user_id=user.id,
        is_active=True,
    )
    db_session.add(acc)
    db_session.commit()
    acc_id = acc.id

    resp = client.delete(f"/api/cloud-accounts/{acc_id}", headers=admin_headers)
    assert resp.status_code == 200

    deleted = db_session.query(CloudAccount).filter(CloudAccount.id == acc_id).first()
    assert deleted is None


# =============================================================================
# 2. Atomic Database Cleanup (Dependent CSPM Records)
# =============================================================================

def test_dependent_cspm_data_cleaned_atomically(client, db_session):
    """Deleting a CloudAccount cleans up its dependent scans, findings, reports, and resources."""
    user = create_test_user(db_session, "cascade_user", "cascade@del.com", "VIEWER")
    headers = auth_header_for_user(user)

    rule = db_session.query(SecurityRule).first()

    # 1. Create CloudAccount
    acc = CloudAccount(
        name="Account With Deep Data",
        provider="AWS",
        account_identifier="181137999524",
        default_region="eu-north-1",
        user_id=user.id,
        is_active=True,
    )
    db_session.add(acc)
    db_session.commit()

    # 2. Create Scan
    scan = Scan(
        cloud_account_id=acc.id,
        status="COMPLETED",
        resources_scanned=5,
        findings_count=1,
    )
    db_session.add(scan)
    db_session.commit()

    # 3. Create Resource
    res = Resource(
        cloud_account_id=acc.id,
        scan_id=scan.id,
        service="S3",
        resource_type="AWS::S3::Bucket",
        resource_id="cascade-test-bucket",
    )
    db_session.add(res)
    db_session.commit()

    # 4. Create Finding
    finding = Finding(
        rule_id=rule.id,
        scan_id=scan.id,
        cloud_account_id=acc.id,
        resource_id=res.id,
        finding_identifier="finding-cascade-test-01",
        title="Test Cascade S3 Bucket Public",
        description="Bucket allows public read access",
        remediation="Enable S3 block public access",
        severity="HIGH",
        risk_score=7.5,
    )
    db_session.add(finding)
    db_session.commit()

    # 5. Create Report
    report = Report(
        scan_id=scan.id,
        generated_by=user.id,
        report_type="EXECUTIVE",
        status="COMPLETED",
    )
    db_session.add(report)
    db_session.commit()

    scan_id = scan.id
    res_id = res.id
    finding_id = finding.id
    report_id = report.id

    # Execute DELETE
    resp = client.delete(f"/api/cloud-accounts/{acc.id}", headers=headers)
    assert resp.status_code == 200

    # Verify all dependent CSPM data was safely removed
    db_session.expire_all()
    assert db_session.query(CloudAccount).filter(CloudAccount.id == acc.id).first() is None
    assert db_session.query(Scan).filter(Scan.id == scan_id).first() is None
    assert db_session.query(Resource).filter(Resource.id == res_id).first() is None
    assert db_session.query(Finding).filter(Finding.id == finding_id).first() is None
    assert db_session.query(Report).filter(Report.id == report_id).first() is None


# =============================================================================
# 3. Duplicate Account Independence
# =============================================================================

def test_deleting_duplicate_account_preserves_other_duplicate(client, db_session):
    """
    Scenario: User has duplicate AWS registrations (e.g. 181137999524 in us-east-1 and eu-north-1).
    Deleting the old us-east-1 duplicate must leave the eu-north-1 account completely intact!
    """
    user = create_test_user(db_session, "dup_user", "dup@del.com", "VIEWER")
    headers = auth_header_for_user(user)

    # 1. Old registration (us-east-1)
    acc_old = CloudAccount(
        name="Vishal AWS Account",
        provider="AWS",
        account_identifier="181137999524",
        default_region="us-east-1",
        credential_mode="ROLE",
        role_arn="arn:aws:iam::181137999524:role/OldBrokenRole",
        user_id=user.id,
        is_active=True,
    )
    # 2. Working registration (eu-north-1)
    acc_working = CloudAccount(
        name="Vishal AWS Account",
        provider="AWS",
        account_identifier="181137999524",
        default_region="eu-north-1",
        credential_mode="ROLE",
        role_arn="arn:aws:iam::181137999524:role/WorkingRole",
        user_id=user.id,
        is_active=True,
    )
    db_session.add_all([acc_old, acc_working])
    db_session.commit()

    old_id = acc_old.id
    working_id = acc_working.id

    # Delete the old us-east-1 duplicate
    resp = client.delete(f"/api/cloud-accounts/{old_id}", headers=headers)
    assert resp.status_code == 200

    db_session.expire_all()
    # Old is deleted
    assert db_session.query(CloudAccount).filter(CloudAccount.id == old_id).first() is None

    # Working account is completely intact
    retained = db_session.query(CloudAccount).filter(CloudAccount.id == working_id).first()
    assert retained is not None
    assert retained.default_region == "eu-north-1"
    assert retained.account_identifier == "181137999524"
    assert retained.role_arn == "arn:aws:iam::181137999524:role/WorkingRole"


# =============================================================================
# 4. Audit Logging & AWS Safety
# =============================================================================

def test_audit_event_created_on_account_deletion(client, db_session):
    """Verified that an audit event CLOUD_ACCOUNT_DELETED is recorded with non-sensitive metadata."""
    user = create_test_user(db_session, "audit_user", "audit@del.com", "VIEWER")
    headers = auth_header_for_user(user)

    acc = CloudAccount(
        name="Audited Account Deletion",
        provider="AWS",
        account_identifier="181137999524",
        default_region="eu-north-1",
        credential_mode="ROLE",
        user_id=user.id,
        is_active=True,
    )
    db_session.add(acc)
    db_session.commit()
    acc_id = acc.id

    resp = client.delete(f"/api/cloud-accounts/{acc_id}", headers=headers)
    assert resp.status_code == 200

    # Verify audit record
    audit = db_session.query(AuditLog).filter(
        AuditLog.action == "CLOUD_ACCOUNT_DELETED",
        AuditLog.resource_id == str(acc_id),
    ).first()

    assert audit is not None
    assert audit.user_id == user.id
    assert audit.result == "SUCCESS"
    assert audit.metadata_json["name"] == "Audited Account Deletion"
    assert audit.metadata_json["account_identifier"] == "181137999524"
    assert audit.metadata_json["default_region"] == "eu-north-1"
    # Ensure no secret tokens or keys are present
    assert "secret" not in audit.metadata_json
    assert "token" not in audit.metadata_json


@patch("botocore.client.BaseClient._make_api_call")
def test_no_aws_mutation_performed_during_deletion(mock_boto, client, db_session):
    """
    Strict AWS Safety Guarantee:
    Deleting a CloudAccount is purely a local CSPM database operation.
    Zero calls may be made to STS AssumeRole, IAM DeleteRole, S3 DeleteBucket, etc.
    """
    user = create_test_user(db_session, "safety_user", "safety@del.com", "VIEWER")
    headers = auth_header_for_user(user)

    acc = CloudAccount(
        name="Safe AWS Target",
        provider="AWS",
        account_identifier="181137999524",
        default_region="eu-north-1",
        credential_mode="ROLE",
        role_arn="arn:aws:iam::181137999524:role/CSPMViewerReadOnlyRole",
        user_id=user.id,
        is_active=True,
    )
    db_session.add(acc)
    db_session.commit()

    resp = client.delete(f"/api/cloud-accounts/{acc.id}", headers=headers)
    assert resp.status_code == 200

    # Ensure boto3 was never invoked
    mock_boto.assert_not_called()
