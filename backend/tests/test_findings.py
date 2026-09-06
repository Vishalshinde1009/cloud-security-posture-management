import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database.session import get_db, Base
from app.models.auth import User, Role, Permission
from app.models.cloud import CloudAccount, Scan, Resource
from app.models.finding import SecurityRule, Finding
from app.core.security import get_password_hash, create_access_token
from app.services.scan_service import ScanService
from app.services.finding_service import FindingService
from app.scanner.rules.registry import default_registry

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
    """Isolated in-memory database session."""
    Base.metadata.create_all(bind=test_engine)
    session = TestingSessionLocal()

    # Permissions
    p_scans = Permission(id=uuid.uuid4(), name="run:scans", description="Run scans")
    p_read_scans = Permission(id=uuid.uuid4(), name="read:scans", description="Read scans")
    p_read_find = Permission(id=uuid.uuid4(), name="read:findings", description="Read findings")
    session.add_all([p_scans, p_read_scans, p_read_find])
    session.flush()

    # Roles
    r_admin = Role(id=uuid.uuid4(), name="ADMIN", description="Admin role")
    r_admin.permissions.extend([p_scans, p_read_scans, p_read_find])

    r_analyst = Role(id=uuid.uuid4(), name="SECURITY_ANALYST", description="Analyst role")
    r_analyst.permissions.extend([p_scans, p_read_scans, p_read_find])

    r_viewer = Role(id=uuid.uuid4(), name="VIEWER", description="Viewer role")
    r_viewer.permissions.extend([p_read_scans, p_read_find])

    session.add_all([r_admin, r_analyst, r_viewer])
    session.flush()

    # Users
    admin_user = User(
        id=uuid.uuid4(),
        username="admin_findings",
        email="admin@findings-cspm.local",
        password_hash=get_password_hash("AdminPass12345!"),
        is_active=True,
    )
    admin_user.roles.append(r_admin)

    viewer_user = User(
        id=uuid.uuid4(),
        username="viewer_findings",
        email="viewer@findings-cspm.local",
        password_hash=get_password_hash("ViewerPass12345!"),
        is_active=True,
    )
    viewer_user.roles.append(r_viewer)

    session.add_all([admin_user, viewer_user])
    session.commit()

    yield session

    session.close()
    Base.metadata.drop_all(bind=test_engine)


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
def tokens(db_session):
    admin = db_session.query(User).filter(User.username == "admin_findings").first()
    viewer = db_session.query(User).filter(User.username == "viewer_findings").first()

    return {
        "admin": create_access_token(subject=str(admin.id), claims={"roles": ["ADMIN"]}),
        "viewer": create_access_token(subject=str(viewer.id), claims={"roles": ["VIEWER"]}),
        "admin_user": admin,
        "viewer_user": viewer,
    }


# ==============================================================================
# INTEGRATION TESTS
# ==============================================================================

def test_scan_pipeline_generates_evidence_backed_findings(db_session, tokens):
    """Verify executing a mock scan triggers the rule engine and produces concrete findings."""
    admin = tokens["admin_user"]
    scan = ScanService.trigger_scan(db=db_session, user=admin)

    assert scan.status == "COMPLETED"
    assert scan.findings_count > 0
    assert scan.critical_count > 0
    assert scan.high_count > 0

    # Verify findings are in the database
    findings = db_session.query(Finding).filter(Finding.scan_id == scan.id).all()
    assert len(findings) == scan.findings_count

    # Verify S3-001 finding on public-test-bucket
    s3_findings = [f for f in findings if f.rule.rule_id == "S3-001"]
    assert len(s3_findings) >= 1
    f_s3 = s3_findings[0]
    assert f_s3.severity == "CRITICAL"
    assert "PublicAccessBlockConfiguration" in f_s3.evidence
    assert f_s3.evidence["PublicAccessBlockConfiguration"]["BlockPublicAcls"] is False

    # Verify NET-001 finding on unrestricted-ssh-sg
    ssh_findings = [f for f in findings if f.rule.rule_id == "NET-001"]
    assert len(ssh_findings) >= 1
    f_ssh = ssh_findings[0]
    assert f_ssh.evidence["Source"] == "0.0.0.0/0"
    assert f_ssh.evidence["FromPort"] == 22

    # Verify clean resources have no false findings (e.g. secure-production-bucket)
    clean_bucket = db_session.query(Resource).filter(Resource.resource_name == "secure-production-bucket").first()
    assert clean_bucket is not None
    bucket_findings = db_session.query(Finding).filter(Finding.resource_id == clean_bucket.id).all()
    assert len(bucket_findings) == 0
    assert clean_bucket.security_status == "SECURE"


def test_finding_deduplication_across_consecutive_scans(db_session, tokens):
    """Verify repeated scans update existing open findings rather than creating duplicates."""
    admin = tokens["admin_user"]

    # Scan 1
    scan_1 = ScanService.trigger_scan(db=db_session, user=admin)
    initial_findings_count = db_session.query(Finding).count()
    assert initial_findings_count > 0

    first_finding = db_session.query(Finding).first()
    first_id = first_finding.id
    first_first_detected = first_finding.first_detected
    first_last_detected = first_finding.last_detected

    # Scan 2 (same mock environment)
    scan_2 = ScanService.trigger_scan(db=db_session, user=admin)
    second_findings_count = db_session.query(Finding).count()

    # Zero new rows created! Deduplication succeeded
    assert second_findings_count == initial_findings_count

    # Verify last_detected was updated and first_detected was preserved
    reloaded = db_session.query(Finding).filter(Finding.id == first_id).first()
    assert reloaded.first_detected == first_first_detected
    assert reloaded.scan_id == scan_2.id
    assert reloaded.status == "OPEN"


def test_finding_drift_resolution(db_session, tokens):
    """Verify that when a misconfiguration is resolved, the finding status transitions to RESOLVED."""
    admin = tokens["admin_user"]

    # Initial scan creates open findings
    ScanService.trigger_scan(db=db_session, user=admin)

    # Grab an open finding
    finding = db_session.query(Finding).filter(Finding.status == "OPEN").first()
    assert finding is not None
    assert finding.resolved_at is None

    # Simulate drift resolution via FindingService
    account = db_session.query(CloudAccount).first()
    scan = db_session.query(Scan).first()

    # Run persistence with empty candidates for this resource (simulating clean state)
    FindingService.persist_finding_candidates(
        db=db_session,
        scan=scan,
        account=account,
        candidates=[],
        scanned_resource_ids={finding.resource.resource_id},
    )

    reloaded = db_session.query(Finding).filter(Finding.id == finding.id).first()
    assert reloaded.status == "RESOLVED"
    assert reloaded.resolved_at is not None


def test_resource_security_status_transitions(db_session, tokens):
    """Verify resource security status reflects finding severity: CRITICAL > AT_RISK > SECURE."""
    admin = tokens["admin_user"]
    ScanService.trigger_scan(db=db_session, user=admin)

    # Public bucket has CRITICAL finding (S3-001) -> CRITICAL
    pub_bucket = db_session.query(Resource).filter(Resource.resource_name == "public-test-bucket").first()
    assert pub_bucket.security_status == "CRITICAL"

    # Unencrypted bucket has HIGH finding (S3-002) and MEDIUM (S3-004) -> AT_RISK
    unenc_bucket = db_session.query(Resource).filter(Resource.resource_name == "unencrypted-storage-bucket").first()
    assert unenc_bucket.security_status == "AT_RISK"

    # Secure production bucket has no findings -> SECURE
    sec_bucket = db_session.query(Resource).filter(Resource.resource_name == "secure-production-bucket").first()
    assert sec_bucket.security_status == "SECURE"


def test_api_list_findings_and_filters(client, tokens, db_session):
    """Verify GET /api/findings with severity, status, service, and search filters."""
    ScanService.trigger_scan(db=db_session, user=tokens["admin_user"])

    # List all
    res_all = client.get("/api/findings", headers={"Authorization": f"Bearer {tokens['viewer']}"})
    assert res_all.status_code == 200
    data = res_all.json()
    assert data["total"] > 0
    assert len(data["items"]) > 0

    # Filter by Severity: CRITICAL
    res_crit = client.get("/api/findings?severity=CRITICAL", headers={"Authorization": f"Bearer {tokens['viewer']}"})
    assert res_crit.status_code == 200
    for item in res_crit.json()["items"]:
        assert item["severity"] == "CRITICAL"

    # Filter by Service: S3
    res_s3 = client.get("/api/findings?service=S3", headers={"Authorization": f"Bearer {tokens['viewer']}"})
    assert res_s3.status_code == 200
    for item in res_s3.json()["items"]:
        assert item["service"] == "S3"

    # Filter by Status: OPEN
    res_open = client.get("/api/findings?status=OPEN", headers={"Authorization": f"Bearer {tokens['viewer']}"})
    assert res_open.status_code == 200
    for item in res_open.json()["items"]:
        assert item["status"] == "OPEN"

    # Search filter
    res_search = client.get("/api/findings?search=SSH", headers={"Authorization": f"Bearer {tokens['viewer']}"})
    assert res_search.status_code == 200
    assert res_search.json()["total"] >= 1


def test_api_get_finding_detail(client, tokens, db_session):
    """Verify GET /api/findings/{id} returns raw configuration evidence and remediation."""
    ScanService.trigger_scan(db=db_session, user=tokens["admin_user"])

    # Get first finding ID
    res_list = client.get("/api/findings?limit=1", headers={"Authorization": f"Bearer {tokens['viewer']}"})
    finding_id = res_list.json()["items"][0]["id"]

    # Get detail
    res_detail = client.get(f"/api/findings/{finding_id}", headers={"Authorization": f"Bearer {tokens['viewer']}"})
    assert res_detail.status_code == 200
    detail = res_detail.json()
    assert detail["id"] == finding_id
    assert "evidence" in detail
    assert isinstance(detail["evidence"], dict)
    assert len(detail["evidence"]) > 0
    assert "remediation" in detail

    # Non-existent ID -> 404
    fake_id = str(uuid.uuid4())
    res_404 = client.get(f"/api/findings/{fake_id}", headers={"Authorization": f"Bearer {tokens['viewer']}"})
    assert res_404.status_code == 404


def test_api_rules_catalog_and_detail(client, tokens, db_session):
    """Verify GET /api/rules returns 26 rules and GET /api/rules/{id} returns specific rule."""
    res = client.get("/api/rules", headers={"Authorization": f"Bearer {tokens['viewer']}"})
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 26
    assert len(data["items"]) == 26

    # Filter by service: RDS
    res_rds = client.get("/api/rules?service=RDS", headers={"Authorization": f"Bearer {tokens['viewer']}"})
    assert res_rds.status_code == 200
    assert res_rds.json()["total"] == 3

    # Get specific rule by rule_id: S3-001
    res_rule = client.get("/api/rules/S3-001", headers={"Authorization": f"Bearer {tokens['viewer']}"})
    assert res_rule.status_code == 200
    rule_data = res_rule.json()
    assert rule_data["rule_id"] == "S3-001"
    assert rule_data["service"] == "S3"
    assert rule_data["severity"] == "CRITICAL"
    assert len(rule_data["references"]) > 0

    # Non-existent rule -> 404
    res_404 = client.get("/api/rules/NONEXISTENT-999", headers={"Authorization": f"Bearer {tokens['viewer']}"})
    assert res_404.status_code == 404
