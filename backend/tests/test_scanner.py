import uuid
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database.session import get_db, Base
from app.models.auth import User, Role, Permission
from app.models.cloud import Resource
from app.models.audit import AuditLog
from app.core.security import get_password_hash, create_access_token
from app.scanner.providers.mock.provider import MockProvider
from app.scanner.engine.scanner import ScannerEngine
from app.services.scan_service import ScanService

# Isolated in-memory SQLite database with StaticPool so all connections share the same memory DB
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
    """Provides an isolated database session with standard roles and seeded users."""
    Base.metadata.create_all(bind=test_engine)
    session = TestingSessionLocal()

    # Permissions
    p_scans = Permission(id=uuid.uuid4(), name="run:scans", description="Run scans")
    p_read_scans = Permission(id=uuid.uuid4(), name="read:scans", description="Read scans")
    session.add_all([p_scans, p_read_scans])
    session.flush()

    # Roles
    r_admin = Role(id=uuid.uuid4(), name="ADMIN", description="Admin role")
    r_admin.permissions.extend([p_scans, p_read_scans])

    r_analyst = Role(id=uuid.uuid4(), name="SECURITY_ANALYST", description="Analyst role")
    r_analyst.permissions.extend([p_scans, p_read_scans])

    r_viewer = Role(id=uuid.uuid4(), name="VIEWER", description="Viewer role")
    r_viewer.permissions.append(p_read_scans)

    session.add_all([r_admin, r_analyst, r_viewer])
    session.flush()

    # Users
    admin_user = User(
        id=uuid.uuid4(),
        username="admin_scanner",
        email="admin@scan-cspm.local",
        password_hash=get_password_hash("AdminP@ss12345!"),
        is_active=True,
    )
    admin_user.roles.append(r_admin)

    analyst_user = User(
        id=uuid.uuid4(),
        username="analyst_scanner",
        email="analyst@scan-cspm.local",
        password_hash=get_password_hash("AnalystP@ss12345!"),
        is_active=True,
    )
    analyst_user.roles.append(r_analyst)

    viewer_user = User(
        id=uuid.uuid4(),
        username="viewer_scanner",
        email="viewer@scan-cspm.local",
        password_hash=get_password_hash("ViewerP@ss12345!"),
        is_active=True,
    )
    viewer_user.roles.append(r_viewer)

    session.add_all([admin_user, analyst_user, viewer_user])
    session.commit()

    yield session

    session.close()
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def client(db_session):
    """FastAPI TestClient overriding the get_db dependency."""
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
def tokens(db_session):
    """Generates valid JWT bearer tokens for each user persona."""
    admin = db_session.query(User).filter(User.username == "admin_scanner").first()
    analyst = db_session.query(User).filter(User.username == "analyst_scanner").first()
    viewer = db_session.query(User).filter(User.username == "viewer_scanner").first()

    return {
        "admin": create_access_token(subject=str(admin.id), claims={"roles": ["ADMIN"]}),
        "analyst": create_access_token(subject=str(analyst.id), claims={"roles": ["SECURITY_ANALYST"]}),
        "viewer": create_access_token(subject=str(viewer.id), claims={"roles": ["VIEWER"]}),
        "admin_user": admin,
        "analyst_user": analyst,
        "viewer_user": viewer,
    }


# ==============================================================================
# UNIT & INTEGRATION TESTS
# ==============================================================================

def test_mock_provider_discovery():
    """Verify MockProvider discovers multi-service resources with realistic AWS config schemas."""
    provider = MockProvider(account_id="mock-account-001", default_region="us-east-1")
    assert provider.get_provider_name() == "MOCK"

    resources = provider.discover_resources()
    assert len(resources) >= 15

    services = set(r.service for r in resources)
    assert services == {"S3", "IAM", "EC2", "VPC", "CloudTrail", "RDS"}

    # Verify provider is strictly MOCK
    for r in resources:
        assert r.provider == "MOCK"
        assert isinstance(r.configuration, dict)
        assert isinstance(r.tags, dict)

    # Verify S3 configuration presence
    s3_buckets = [r for r in resources if r.service == "S3"]
    assert len(s3_buckets) >= 3
    bucket_names = [b.resource_name for b in s3_buckets]
    assert "public-test-bucket" in bucket_names
    assert "secure-production-bucket" in bucket_names

    # Verify S3 config contains real Boto3-shaped parameters
    pub_bucket = next(b for b in s3_buckets if b.resource_name == "public-test-bucket")
    assert "PublicAccessBlockConfiguration" in pub_bucket.configuration
    assert pub_bucket.configuration["PublicAccessBlockConfiguration"]["BlockPublicAcls"] is False


def test_scanner_engine_discovery_pipeline():
    """Verify ScannerEngine runs discovery pipeline and applies baseline security status checks."""
    provider = MockProvider()
    engine = ScannerEngine(provider=provider)

    discovered = engine.run_discovery_pipeline()
    assert len(discovered) > 0

    statuses = set(r.security_status for r in discovered)
    assert "SECURE" in statuses
    assert "AT_RISK" in statuses

    # Public bucket should be identified as AT_RISK
    pub_bucket = next(r for r in discovered if r.resource_name == "public-test-bucket")
    assert pub_bucket.security_status == "AT_RISK"

    # Production secure bucket should be SECURE
    sec_bucket = next(r for r in discovered if r.resource_name == "secure-production-bucket")
    assert sec_bucket.security_status == "SECURE"


def test_scan_service_trigger_and_persistence(db_session, tokens):
    """Verify ScanService creates scan, transitions state, and persists Resource records."""
    admin = tokens["admin_user"]
    scan = ScanService.trigger_scan(db=db_session, user=admin)

    assert scan.status == "COMPLETED"
    assert scan.resources_scanned >= 15
    assert scan.security_score is not None
    assert 0.0 <= scan.security_score <= 100.0
    assert scan.completed_at is not None
    assert scan.duration >= 0.0

    # Verify Resources are stored in DB
    db_resources = db_session.query(Resource).filter(Resource.cloud_account_id == scan.cloud_account_id).all()
    assert len(db_resources) == scan.resources_scanned

    # Verify Audit Log entry was created
    audit = db_session.query(AuditLog).filter(
        AuditLog.resource_id == str(scan.id),
        AuditLog.action == "SCAN_TRIGGERED"
    ).first()
    assert audit is not None
    assert audit.result == "SUCCESS"
    assert audit.user_id == admin.id


def test_scan_history_preservation(db_session, tokens):
    """Verify multiple scans create separate historical records and do not overwrite previous scans."""
    admin = tokens["admin_user"]

    scan_1 = ScanService.trigger_scan(db=db_session, user=admin)
    scan_2 = ScanService.trigger_scan(db=db_session, user=admin)

    assert scan_1.id != scan_2.id

    scans, total = ScanService.get_scans(db=db_session)
    assert total >= 2
    scan_ids = [s.id for s in scans]
    assert scan_1.id in scan_ids
    assert scan_2.id in scan_ids


def test_scan_service_failure_isolation(db_session, tokens):
    """Verify unexpected discovery errors safely transition scan to FAILED without crashing."""
    admin = tokens["admin_user"]

    with patch.object(ScannerEngine, "run_discovery_pipeline", side_effect=RuntimeError("Simulated AWS Timeout")):
        scan = ScanService.trigger_scan(db=db_session, user=admin)

        assert scan.status == "FAILED"
        assert "Simulated AWS Timeout" in scan.error_message

        # Audit log should capture failure
        audit = db_session.query(AuditLog).filter(
            AuditLog.resource_id == str(scan.id),
            AuditLog.result == "FAILURE"
        ).first()
        assert audit is not None


def test_api_trigger_scan_rbac_enforcement(client, tokens):
    """Verify RBAC and authorization on POST /api/scans: unauthenticated rejected (401); authenticated users receive 201."""
    # Unauthenticated -> 401 Unauthorized
    res_anon = client.post("/api/scans", json={})
    assert res_anon.status_code == 401

    # VIEWER -> 201 Created on accessible account
    res_viewer = client.post(
        "/api/scans",
        json={},
        headers={"Authorization": f"Bearer {tokens['viewer']}"},
    )
    assert res_viewer.status_code == 201
    assert res_viewer.json()["status"] == "COMPLETED"

    # ANALYST -> 201 Created
    res_analyst = client.post(
        "/api/scans",
        json={},
        headers={"Authorization": f"Bearer {tokens['analyst']}"},
    )
    assert res_analyst.status_code == 201
    analyst_scan = res_analyst.json()
    assert analyst_scan["status"] == "COMPLETED"
    assert analyst_scan["resources_scanned"] >= 15

    # ADMIN -> 201 Created
    res_admin = client.post(
        "/api/scans",
        json={},
        headers={"Authorization": f"Bearer {tokens['admin']}"},
    )
    assert res_admin.status_code == 201
    assert res_admin.json()["status"] == "COMPLETED"


def test_api_list_scans_and_get_by_id(client, tokens, db_session):
    """Verify GET /api/scans and GET /api/scans/{id} endpoints."""
    # Trigger a scan first
    ScanService.trigger_scan(db=db_session, user=tokens["admin_user"])

    # List scans
    res = client.get(
        "/api/scans?page=1&limit=10",
        headers={"Authorization": f"Bearer {tokens['viewer']}"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["total"] >= 1
    assert len(data["items"]) >= 1

    first_scan_id = data["items"][0]["id"]

    # Get scan by ID
    res_detail = client.get(
        f"/api/scans/{first_scan_id}",
        headers={"Authorization": f"Bearer {tokens['viewer']}"},
    )
    assert res_detail.status_code == 200
    assert res_detail.json()["id"] == first_scan_id

    # Non-existent scan ID -> 404
    fake_id = str(uuid.uuid4())
    res_404 = client.get(
        f"/api/scans/{fake_id}",
        headers={"Authorization": f"Bearer {tokens['viewer']}"},
    )
    assert res_404.status_code == 404


def test_api_list_resources_and_filters(client, tokens, db_session):
    """Verify GET /api/resources with service, status, and search filters."""
    # Trigger scan to populate resources
    ScanService.trigger_scan(db=db_session, user=tokens["admin_user"])

    # Unfiltered
    res_all = client.get(
        "/api/resources",
        headers={"Authorization": f"Bearer {tokens['viewer']}"},
    )
    assert res_all.status_code == 200
    assert res_all.json()["total"] >= 15

    # Filter by Service: S3
    res_s3 = client.get(
        "/api/resources?service=S3",
        headers={"Authorization": f"Bearer {tokens['viewer']}"},
    )
    assert res_s3.status_code == 200
    s3_items = res_s3.json()["items"]
    assert len(s3_items) >= 3
    for item in s3_items:
        assert item["service"] == "S3"

    # Filter by Security Status: AT_RISK
    res_risk = client.get(
        "/api/resources?security_status=AT_RISK",
        headers={"Authorization": f"Bearer {tokens['viewer']}"},
    )
    assert res_risk.status_code == 200
    risk_items = res_risk.json()["items"]
    assert len(risk_items) > 0
    for item in risk_items:
        assert item["security_status"] == "AT_RISK"

    # Search filter
    res_search = client.get(
        "/api/resources?search=public-test-bucket",
        headers={"Authorization": f"Bearer {tokens['viewer']}"},
    )
    assert res_search.status_code == 200
    assert res_search.json()["total"] >= 1


def test_api_get_resource_detail(client, tokens, db_session):
    """Verify GET /api/resources/{id} returns raw configuration JSON and metadata."""
    ScanService.trigger_scan(db=db_session, user=tokens["admin_user"])

    # Get first resource ID
    res_list = client.get(
        "/api/resources?limit=1",
        headers={"Authorization": f"Bearer {tokens['viewer']}"},
    )
    resource_id = res_list.json()["items"][0]["id"]

    # Get resource detail
    res_detail = client.get(
        f"/api/resources/{resource_id}",
        headers={"Authorization": f"Bearer {tokens['viewer']}"},
    )
    assert res_detail.status_code == 200
    item = res_detail.json()
    assert item["id"] == resource_id
    assert "configuration" in item
    assert isinstance(item["configuration"], dict)
    assert "tags" in item


def test_mock_mode_safe_labeling(client, tokens, db_session):
    """Verify all discovered assets carry provider='MOCK' provenance and safe metadata."""
    ScanService.trigger_scan(db=db_session, user=tokens["admin_user"])

    res = client.get(
        "/api/resources",
        headers={"Authorization": f"Bearer {tokens['viewer']}"},
    )
    assert res.status_code == 200
    items = res.json()["items"]
    for item in items:
        assert item["provider"] == "MOCK"


def test_aws_inventory_scoped_by_account_id(client, tokens, db_session):
    """Verifies that filtering by AWS cloud_account_id returns only AWS assets and strictly excludes mock assets."""
    from app.models.cloud import CloudAccount, Scan, Resource

    # 1. Create a mock account with resources
    mock_account = CloudAccount(
        name="Demo Environment",
        provider="MOCK",
        account_identifier="mock-12345",
        default_region="us-east-1",
        credential_mode="MOCK",
        is_active=True,
    )
    db_session.add(mock_account)
    db_session.flush()

    mock_scan = Scan(
        cloud_account_id=mock_account.id,
        status="COMPLETED",
        resources_scanned=1,
    )
    db_session.add(mock_scan)
    db_session.flush()

    mock_res = Resource(
        cloud_account_id=mock_account.id,
        scan_id=mock_scan.id,
        resource_id="arn:aws:s3:::mock-bucket-alpha",
        resource_name="mock-bucket-alpha",
        service="S3",
        resource_type="s3_bucket",
        region="us-east-1",
        provider="MOCK",
        security_status="PASSING",
        configuration={"mock": True},
    )
    db_session.add(mock_res)

    # 2. Create a real AWS account with resources
    aws_account = CloudAccount(
        name="Audit Target",
        provider="AWS",
        account_identifier="123456789012",
        default_region="eu-north-1",
        credential_mode="ENVIRONMENT",
        is_active=True,
    )
    db_session.add(aws_account)
    db_session.flush()

    aws_scan = Scan(
        cloud_account_id=aws_account.id,
        status="COMPLETED",
        resources_scanned=1,
    )
    db_session.add(aws_scan)
    db_session.flush()

    aws_res = Resource(
        cloud_account_id=aws_account.id,
        scan_id=aws_scan.id,
        resource_id="arn:aws:s3:::real-production-audit-bucket",
        resource_name="real-production-audit-bucket",
        service="S3",
        resource_type="s3_bucket",
        region="eu-north-1",
        provider="AWS",
        security_status="AT_RISK",
        configuration={"BucketName": "real-production-audit-bucket"},
    )
    db_session.add(aws_res)
    db_session.commit()

    # Query resources for AWS account via account_id
    res_aws = client.get(
        f"/api/resources?account_id={aws_account.id}",
        headers={"Authorization": f"Bearer {tokens['viewer']}"},
    )
    assert res_aws.status_code == 200
    data_aws = res_aws.json()
    assert data_aws["total"] == 1
    assert data_aws["items"][0]["resource_name"] == "real-production-audit-bucket"
    assert data_aws["items"][0]["provider"] == "AWS"
    assert data_aws["items"][0]["region"] == "eu-north-1"

    # Query resources for AWS account via cloud_account_id alias
    res_aws_alias = client.get(
        f"/api/resources?cloud_account_id={aws_account.id}",
        headers={"Authorization": f"Bearer {tokens['viewer']}"},
    )
    assert res_aws_alias.status_code == 200
    assert res_aws_alias.json()["total"] == 1
    assert res_aws_alias.json()["items"][0]["resource_name"] == "real-production-audit-bucket"

    # Query resources for Mock account
    res_mock = client.get(
        f"/api/resources?account_id={mock_account.id}",
        headers={"Authorization": f"Bearer {tokens['viewer']}"},
    )
    assert res_mock.status_code == 200
    data_mock = res_mock.json()
    assert data_mock["total"] == 1
    assert data_mock["items"][0]["resource_name"] == "mock-bucket-alpha"
    assert data_mock["items"][0]["provider"] == "MOCK"


def test_cross_account_and_scan_isolation(client, tokens, db_session):
    """Verifies that resources strictly map to their respective scan_id and cloud_account_id without leaking."""
    from app.models.cloud import CloudAccount, Scan, Resource

    acc = CloudAccount(
        name="Target Isolation Acc",
        provider="AWS",
        account_identifier="111222333444",
        default_region="eu-north-1",
        credential_mode="ENVIRONMENT",
        is_active=True,
    )
    db_session.add(acc)
    db_session.flush()

    scan1 = Scan(cloud_account_id=acc.id, status="COMPLETED")
    scan2 = Scan(cloud_account_id=acc.id, status="COMPLETED")
    db_session.add_all([scan1, scan2])
    db_session.flush()

    res1 = Resource(
        cloud_account_id=acc.id,
        scan_id=scan1.id,
        resource_id="arn:aws:iam::111222333444:user/Alice",
        resource_name="Alice",
        service="IAM",
        resource_type="iam_user",
        region="global",
        provider="AWS",
        security_status="PASSING",
        configuration={},
    )
    res2 = Resource(
        cloud_account_id=acc.id,
        scan_id=scan2.id,
        resource_id="arn:aws:iam::111222333444:user/Bob",
        resource_name="Bob",
        service="IAM",
        resource_type="iam_user",
        region="global",
        provider="AWS",
        security_status="PASSING",
        configuration={},
    )
    db_session.add_all([res1, res2])
    db_session.commit()

    # Query by scan1
    r_scan1 = client.get(
        f"/api/resources?scan_id={scan1.id}",
        headers={"Authorization": f"Bearer {tokens['viewer']}"},
    )
    assert r_scan1.status_code == 200
    items1 = r_scan1.json()["items"]
    assert len(items1) == 1
    assert items1[0]["resource_name"] == "Alice"

    # Query by scan2
    r_scan2 = client.get(
        f"/api/resources?scan_id={scan2.id}",
        headers={"Authorization": f"Bearer {tokens['viewer']}"},
    )
    assert r_scan2.status_code == 200
    items2 = r_scan2.json()["items"]
    assert len(items2) == 1
    assert items2[0]["resource_name"] == "Bob"


def test_mode_aware_default_resource_resolution(client, tokens, db_session):
    """Verifies that when account_id is omitted and CSPM_MODE is aws, active AWS account resources are chosen over mock."""
    from app.models.cloud import CloudAccount, Scan, Resource
    from app.core.config import settings

    mock_acc = CloudAccount(
        name="Demo AWS Environment",
        provider="MOCK",
        account_identifier="mock-sim",
        default_region="us-east-1",
        credential_mode="MOCK",
        is_active=True,
    )
    aws_acc = CloudAccount(
        name="Audit Target",
        provider="AWS",
        account_identifier="999888777666",
        default_region="eu-north-1",
        credential_mode="ENVIRONMENT",
        is_active=True,
    )
    db_session.add_all([mock_acc, aws_acc])
    db_session.flush()

    s_mock = Scan(cloud_account_id=mock_acc.id, status="COMPLETED")
    s_aws = Scan(cloud_account_id=aws_acc.id, status="COMPLETED")
    db_session.add_all([s_mock, s_aws])
    db_session.flush()

    r_mock = Resource(
        cloud_account_id=mock_acc.id,
        scan_id=s_mock.id,
        resource_id="arn:aws:s3:::simulated-stale-bucket",
        resource_name="simulated-stale-bucket",
        service="S3",
        resource_type="s3_bucket",
        region="us-east-1",
        provider="MOCK",
        security_status="PASSING",
        configuration={},
    )
    r_aws = Resource(
        cloud_account_id=aws_acc.id,
        scan_id=s_aws.id,
        resource_id="arn:aws:s3:::live-aws-active-bucket",
        resource_name="live-aws-active-bucket",
        service="S3",
        resource_type="s3_bucket",
        region="eu-north-1",
        provider="AWS",
        security_status="PASSING",
        configuration={},
    )
    db_session.add_all([r_mock, r_aws])
    db_session.commit()

    with patch.object(settings, "CSPM_MODE", "aws"):
        res = client.get(
            "/api/resources",
            headers={"Authorization": f"Bearer {tokens['viewer']}"},
        )
        assert res.status_code == 200
        items = res.json()["items"]
        assert len(items) == 1
        assert items[0]["resource_name"] == "live-aws-active-bucket"
        assert items[0]["provider"] == "AWS"
