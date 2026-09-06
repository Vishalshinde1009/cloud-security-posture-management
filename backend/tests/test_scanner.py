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
    """Verify RBAC on POST /api/scans: VIEWER receives 403; ANALYST and ADMIN receive 201."""
    # VIEWER -> 403 Forbidden
    res_viewer = client.post(
        "/api/scans",
        json={},
        headers={"Authorization": f"Bearer {tokens['viewer']}"},
    )
    assert res_viewer.status_code == 403
    assert "Access forbidden" in res_viewer.json()["detail"]

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
