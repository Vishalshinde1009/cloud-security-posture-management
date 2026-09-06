"""
Unit and integration tests for Phase 6 Explainable Risk Scoring & Security Posture Engine:
- Individual factor evaluators (Severity, Exposure, Criticality, Exploitability, Sensitivity, Weakness)
- Deterministic formula and weighted rounding
- Risk level & priority boundary tests (39/40, 69/70, 89/90, 99/100)
- Factor explanation consistency
- Determinism guarantees (identical inputs produce identical scores)
- Posture scoring formula and posture rating boundaries
- Historical scan comparison (score drift, new, resolved, persistent findings)
- Findings API risk filtering
- Dashboard stats API
"""

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
from app.scanner.risk.evaluators import (
    evaluate_severity,
    evaluate_exposure,
    evaluate_asset_criticality,
    evaluate_exploitability,
    evaluate_data_sensitivity,
    evaluate_config_weakness,
)
from app.scanner.risk.service import (
    RiskScoringService,
    WEIGHT_SEVERITY,
    WEIGHT_EXPOSURE,
    WEIGHT_ASSET_CRITICALITY,
    WEIGHT_EXPLOITABILITY,
    WEIGHT_DATA_SENSITIVITY,
    WEIGHT_CONFIG_WEAKNESS,
)
from app.services.scan_service import ScanService
from app.services.finding_service import FindingService

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
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    session = TestingSessionLocal()

    p_scans = Permission(id=uuid.uuid4(), name="run:scans", description="Run scans")
    p_read_scans = Permission(id=uuid.uuid4(), name="read:scans", description="Read scans")
    p_read_find = Permission(id=uuid.uuid4(), name="read:findings", description="Read findings")
    session.add_all([p_scans, p_read_scans, p_read_find])
    session.flush()

    r_admin = Role(id=uuid.uuid4(), name="ADMIN", description="Admin role")
    r_admin.permissions.extend([p_scans, p_read_scans, p_read_find])

    r_analyst = Role(id=uuid.uuid4(), name="SECURITY_ANALYST", description="Analyst role")
    r_analyst.permissions.extend([p_scans, p_read_scans, p_read_find])

    r_viewer = Role(id=uuid.uuid4(), name="VIEWER", description="Viewer role")
    r_viewer.permissions.extend([p_read_scans, p_read_find])

    session.add_all([r_admin, r_analyst, r_viewer])
    session.flush()

    u_analyst = User(
        id=uuid.uuid4(),
        username="sec_analyst",
        email="analyst@soc.corp",
        password_hash=get_password_hash("AnalystPassword123!"),
        is_active=True,
    )
    u_analyst.roles.append(r_analyst)
    session.add(u_analyst)
    session.commit()

    yield session
    session.close()
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture(scope="function")
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


# =========================================================================
# 1. Unit Tests: Individual Risk Factor Evaluators
# =========================================================================


def test_severity_evaluator():
    assert evaluate_severity("CRITICAL") == 100
    assert evaluate_severity("HIGH") == 80
    assert evaluate_severity("MEDIUM") == 55
    assert evaluate_severity("LOW") == 25
    assert evaluate_severity("INFO") == 0


def test_exposure_evaluator():
    # Internet-wide 0.0.0.0/0
    score, reason = evaluate_exposure("AWS::EC2::SecurityGroup", {}, {"cidr": "0.0.0.0/0"}, "NET-001")
    assert score == 100
    assert "0.0.0.0/0" in reason

    # S3 public bucket
    score, reason = evaluate_exposure("AWS::S3::Bucket", {}, {}, "S3-001")
    assert score == 100

    # Public IP assigned
    score, reason = evaluate_exposure("AWS::EC2::Instance", {"public_ip": "54.210.10.2"}, {}, "EC2-001")
    assert score == 90

    # Internal IAM (no external network ingress)
    score, reason = evaluate_exposure("AWS::IAM::User", {}, {}, "IAM-001")
    assert score == 10


def test_asset_criticality_evaluator():
    # Root Account
    score, reason = evaluate_asset_criticality("AWS::IAM::User", "root", {}, {}, "IAM-005")
    assert score == 100
    assert "Root account" in reason

    # Production Database
    score, reason = evaluate_asset_criticality(
        "AWS::RDS::DBInstance",
        "orders-prod-db",
        {"environment": "production"},
        {},
        "RDS-001",
    )
    assert score == 100

    # Production compute
    score, reason = evaluate_asset_criticality(
        "AWS::EC2::Instance",
        "web-prod-01",
        {"env": "prod"},
        {},
        "EC2-002",
    )
    assert score == 80

    # Dev / Staging
    score, reason = evaluate_asset_criticality(
        "AWS::S3::Bucket",
        "dev-reports",
        {"env": "dev"},
        {},
        "S3-002",
    )
    assert score == 60

    # Test / Sandbox
    score, reason = evaluate_asset_criticality(
        "AWS::EC2::Instance",
        "test-runner-01",
        {"env": "test"},
        {},
        "EC2-002",
    )
    assert score == 30

    # Unclassified
    score, reason = evaluate_asset_criticality("AWS::S3::Bucket", "my-bucket", {}, {}, "S3-003")
    assert score == 50


def test_exploitability_evaluator():
    # Direct internet SSH / RDP
    score, reason = evaluate_exploitability("AWS::EC2::SecurityGroup", {}, {}, "NET-001", "CRITICAL")
    assert score == 95

    # Wildcard admin policy
    score, reason = evaluate_exploitability("AWS::IAM::Policy", {}, {}, "IAM-002", "CRITICAL")
    assert score == 90

    # Public S3 data exposure
    score, reason = evaluate_exploitability("AWS::S3::Bucket", {}, {}, "S3-001", "CRITICAL")
    assert score == 85

    # Internal config weakness
    score, reason = evaluate_exploitability("AWS::IAM::User", {}, {}, "IAM-003", "MEDIUM")
    assert score == 50

    # Low impact logging
    score, reason = evaluate_exploitability("AWS::S3::Bucket", {}, {}, "S3-004", "LOW")
    assert score == 30


def test_data_sensitivity_evaluator():
    # Confirmed sensitive DB
    score, reason = evaluate_data_sensitivity("AWS::RDS::DBInstance", "customer-orders-db", {}, {})
    assert score == 90

    # Sensitive S3 bucket
    score, reason = evaluate_data_sensitivity("AWS::S3::Bucket", "customer-data-backup", {}, {})
    assert score == 90

    # IAM credentials
    score, reason = evaluate_data_sensitivity("AWS::IAM::User", "app-user", {}, {})
    assert score == 70

    # Non-data networking infrastructure
    score, reason = evaluate_data_sensitivity("AWS::EC2::SecurityGroup", "web-sg", {}, {})
    assert score == 20


def test_configuration_weakness_evaluator():
    # Public DB with encryption disabled (compounded)
    score, reason = evaluate_config_weakness("RDS-001", {}, "CRITICAL", {"storage_encrypted": False})
    assert score == 95

    # Unrestricted SSH
    score, reason = evaluate_config_weakness("NET-001", {}, "CRITICAL", {})
    assert score == 90

    # Missing encryption
    score, reason = evaluate_config_weakness("S3-002", {}, "HIGH", {})
    assert score == 75

    # Missing versioning
    score, reason = evaluate_config_weakness("S3-003", {}, "MEDIUM", {})
    assert score == 50

    # Missing logging
    score, reason = evaluate_config_weakness("S3-004", {}, "LOW", {})
    assert score == 30


# =========================================================================
# 2. Unit Tests: Risk Score Calculation, Weights, and Boundaries
# =========================================================================


def test_risk_scoring_formula_and_weights():
    # Validate mathematical weight distribution
    total_weights = (
        WEIGHT_SEVERITY
        + WEIGHT_EXPOSURE
        + WEIGHT_ASSET_CRITICALITY
        + WEIGHT_EXPLOITABILITY
        + WEIGHT_DATA_SENSITIVITY
        + WEIGHT_CONFIG_WEAKNESS
    )
    assert round(total_weights, 4) == 1.0000

    # Critical exposed database workload
    calc = RiskScoringService.calculate_finding_risk(
        severity="CRITICAL",
        resource_type="AWS::RDS::DBInstance",
        resource_name="orders-prod-db",
        tags={"env": "prod"},
        configuration={"publicly_accessible": True, "storage_encrypted": False},
        evidence={"cidr": "0.0.0.0/0"},
        rule_id="RDS-001",
        title="RDS Database Instance Is Publicly Accessible",
    )

    # Expected:
    # sev=100 (40), exp=100 (20), crit=100 (15), expl=85 (8.5), sens=90 (9.0), weak=95 (4.75)
    # 40 + 20 + 15 + 8.5 + 9.0 + 4.75 = 97.25 -> 97
    assert calc["risk_score"] == 97
    assert calc["risk_level"] == "CRITICAL"
    assert calc["risk_priority"] == "IMMEDIATE"
    assert "97/100" in calc["risk_explanation"]
    assert calc["risk_factors"]["severity"] == 100
    assert calc["risk_factors"]["exposure"] == 100


def test_risk_level_boundaries():
    assert RiskScoringService.map_risk_level(100) == "CRITICAL"
    assert RiskScoringService.map_risk_level(90) == "CRITICAL"
    assert RiskScoringService.map_risk_level(89) == "HIGH"
    assert RiskScoringService.map_risk_level(70) == "HIGH"
    assert RiskScoringService.map_risk_level(69) == "MEDIUM"
    assert RiskScoringService.map_risk_level(40) == "MEDIUM"
    assert RiskScoringService.map_risk_level(39) == "LOW"
    assert RiskScoringService.map_risk_level(1) == "LOW"
    assert RiskScoringService.map_risk_level(0) == "INFO"


def test_risk_priority_boundaries():
    assert RiskScoringService.map_risk_priority(100) == "IMMEDIATE"
    assert RiskScoringService.map_risk_priority(90) == "IMMEDIATE"
    assert RiskScoringService.map_risk_priority(89) == "HIGH"
    assert RiskScoringService.map_risk_priority(70) == "HIGH"
    assert RiskScoringService.map_risk_priority(69) == "MEDIUM"
    assert RiskScoringService.map_risk_priority(40) == "MEDIUM"
    assert RiskScoringService.map_risk_priority(39) == "LOW"
    assert RiskScoringService.map_risk_priority(0) == "LOW"


def test_deterministic_scoring_guarantee():
    """Confirms identical finding inputs produce strictly identical risk scores across 50 iterations."""
    first_res = RiskScoringService.calculate_finding_risk(
        severity="HIGH",
        resource_type="AWS::EC2::Instance",
        resource_name="web-prod",
        tags={"env": "prod"},
        configuration={"public_ip": "54.2.1.3"},
        evidence={"exposed_ports": [22]},
        rule_id="EC2-002",
        title="EC2 Instance Ingress Allows Unrestricted SSH",
    )

    for _ in range(50):
        iter_res = RiskScoringService.calculate_finding_risk(
            severity="HIGH",
            resource_type="AWS::EC2::Instance",
            resource_name="web-prod",
            tags={"env": "prod"},
            configuration={"public_ip": "54.2.1.3"},
            evidence={"exposed_ports": [22]},
            rule_id="EC2-002",
            title="EC2 Instance Ingress Allows Unrestricted SSH",
        )
        assert iter_res["risk_score"] == first_res["risk_score"]
        assert iter_res["risk_level"] == first_res["risk_level"]
        assert iter_res["risk_priority"] == first_res["risk_priority"]
        assert iter_res["risk_explanation"] == first_res["risk_explanation"]
        assert iter_res["risk_factors"] == first_res["risk_factors"]


# =========================================================================
# 3. Unit Tests: Posture Score & Posture Ratings
# =========================================================================


def test_posture_score_clean_environment():
    posture = RiskScoringService.calculate_posture_score(total_resources=10, active_findings=[])
    assert posture["security_score"] == 100.0
    assert posture["posture_rating"] == "EXCELLENT"
    assert posture["avg_risk"] == 0.0
    assert posture["max_risk"] == 0


def test_posture_rating_boundaries():
    assert RiskScoringService.map_posture_rating(100.0) == "EXCELLENT"
    assert RiskScoringService.map_posture_rating(90.0) == "EXCELLENT"
    assert RiskScoringService.map_posture_rating(89.9) == "GOOD"
    assert RiskScoringService.map_posture_rating(75.0) == "GOOD"
    assert RiskScoringService.map_posture_rating(74.9) == "MODERATE"
    assert RiskScoringService.map_posture_rating(60.0) == "MODERATE"
    assert RiskScoringService.map_posture_rating(59.9) == "POOR"
    assert RiskScoringService.map_posture_rating(40.0) == "POOR"
    assert RiskScoringService.map_posture_rating(39.9) == "CRITICAL"
    assert RiskScoringService.map_posture_rating(0.0) == "CRITICAL"


# =========================================================================
# 4. Integration Tests: Scan Pipeline, Findings & API
# =========================================================================


def test_scan_pipeline_populates_risk_and_posture(db_session, client):
    """Executes a scan and verifies findings have real risk scores and scan has posture data."""
    user = db_session.query(User).filter(User.username == "sec_analyst").first()
    token = create_access_token(subject=str(user.id), claims={"roles": ["SECURITY_ANALYST"], "username": user.username})

    scan = ScanService.trigger_scan(db=db_session, user=user)

    assert scan.status == "COMPLETED"
    assert scan.security_score is not None
    assert scan.posture_rating in ["EXCELLENT", "GOOD", "MODERATE", "POOR", "CRITICAL"]
    assert "avg_risk" in scan.risk_summary
    assert "max_risk" in scan.risk_summary

    # Inspect findings
    findings = db_session.query(Finding).filter(Finding.scan_id == scan.id).all()
    assert len(findings) > 0

    for f in findings:
        assert 0 <= f.risk_score <= 100
        assert f.risk_level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        assert f.risk_priority in ["IMMEDIATE", "HIGH", "MEDIUM", "LOW"]
        assert len(f.risk_factors) >= 6
        assert f.risk_explanation is not None
        assert f.risk_calculated_at is not None

    # Test GET /api/findings with risk filters
    res = client.get(
        "/api/findings?risk_level=CRITICAL",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    data = res.json()
    for item in data["items"]:
        assert item["risk_level"] == "CRITICAL"
        assert item["risk_score"] >= 90

    # Test GET /api/findings with min_risk_score
    res = client.get(
        "/api/findings?min_risk_score=70",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    for item in res.json()["items"]:
        assert item["risk_score"] >= 70


def test_dashboard_stats_api(db_session, client):
    """Verifies GET /api/dashboard/stats returns real, comprehensive posture analytics."""
    user = db_session.query(User).filter(User.username == "sec_analyst").first()
    token = create_access_token(subject=str(user.id), claims={"roles": ["SECURITY_ANALYST"], "username": user.username})

    # Trigger scan first to seed live data
    ScanService.trigger_scan(db=db_session, user=user)

    res = client.get(
        "/api/dashboard/stats",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    stats = res.json()

    assert "security_score" in stats
    assert "posture_rating" in stats
    assert "severity_distribution" in stats
    assert "priority_distribution" in stats
    assert "score_trend" in stats
    assert "top_findings" in stats
    assert "top_risky_resources" in stats
    assert "comparison" in stats

    assert len(stats["top_findings"]) <= 5
    if stats["top_findings"]:
        assert "risk_score" in stats["top_findings"][0]
        assert "explanation" in stats["top_findings"][0]


def test_historical_scan_comparison(db_session, client):
    """Runs consecutive scans and validates drift / historical progression tracking."""
    user = db_session.query(User).filter(User.username == "sec_analyst").first()
    token = create_access_token(subject=str(user.id), claims={"roles": ["SECURITY_ANALYST"], "username": user.username})

    # Scan 1
    scan1 = ScanService.trigger_scan(db=db_session, user=user)

    # Scan 2
    scan2 = ScanService.trigger_scan(db=db_session, user=user)

    # API call to compare scan2
    res = client.get(
        f"/api/scans/{scan2.id}/comparison",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    comp = res.json()

    assert comp["has_previous_scan"] is True
    assert comp["current_scan_id"] == str(scan2.id)
    assert comp["previous_scan_id"] == str(scan1.id)
    assert comp["score_change"] == round(scan2.security_score - scan1.security_score, 1)
    assert comp["persistent_findings"] >= 0
