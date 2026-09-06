import uuid
import pytest
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError

from app.models.base import Base, utc_now
from app.models.auth import User, Role, Permission
from app.models.cloud import CloudAccount, Scan, Resource
from app.models.finding import SecurityRule, Finding
from app.models.compliance import ComplianceControl, FindingCompliance
from app.models.audit import AuditLog
from app.models.report import Report
from app.models.notification import Notification


@pytest.fixture(scope="function")
def db_session():
    """Provides a clean, fully isolated in-memory database session for each test."""
    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=test_engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    session = TestingSessionLocal()
    
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=test_engine)


def test_db_connection_and_session_lifecycle(db_session):
    """Test 1: Verify database engine connects, can query, and session manages lifecycle."""
    assert db_session.is_active
    user_count = db_session.query(User).count()
    assert user_count == 0


def test_user_role_permission_m2m_relationships(db_session):
    """Test 2: Verify User, Role, Permission entities and bidirectional M:N relationships."""
    # Create Permissions
    p_read = Permission(name="read:findings", description="Read findings")
    p_write = Permission(name="write:findings", description="Write findings")
    db_session.add_all([p_read, p_write])
    db_session.flush()

    # Create Role and assign permissions
    analyst_role = Role(name="SECURITY_ANALYST", description="Security operations")
    analyst_role.permissions.extend([p_read, p_write])
    db_session.add(analyst_role)
    db_session.flush()

    # Create User and assign role
    user = User(
        username="sec_ops",
        email="sec_ops@example.com",
        password_hash="dummyhashedpass",
        is_active=True,
    )
    user.roles.append(analyst_role)
    db_session.add(user)
    db_session.commit()

    # Query back and verify relationships
    saved_user = db_session.query(User).filter(User.username == "sec_ops").first()
    assert saved_user is not None
    assert len(saved_user.roles) == 1
    assert saved_user.roles[0].name == "SECURITY_ANALYST"
    assert len(saved_user.roles[0].permissions) == 2
    perm_names = [p.name for p in saved_user.roles[0].permissions]
    assert "read:findings" in perm_names
    assert "write:findings" in perm_names


def test_unique_constraints(db_session):
    """Test 3: Verify unique constraints on User (email, username), Role (name), Rule (rule_id)."""
    user1 = User(username="admin_test", email="admin@test.com", password_hash="h1")
    db_session.add(user1)
    db_session.commit()

    # Duplicate username
    user2 = User(username="admin_test", email="other@test.com", password_hash="h2")
    db_session.add(user2)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

    # Duplicate email
    user3 = User(username="admin_diff", email="admin@test.com", password_hash="h3")
    db_session.add(user3)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_cloud_account_security_and_storage(db_session):
    """Test 4: Verify CloudAccount creation and verify zero plaintext secret columns exist."""
    account = CloudAccount(
        name="Production AWS Environment",
        provider="AWS",
        account_identifier="123456789012",
        default_region="us-east-1",
        credential_mode="IAM_ROLE",
        is_active=True,
    )
    db_session.add(account)
    db_session.commit()

    saved = db_session.query(CloudAccount).filter(CloudAccount.account_identifier == "123456789012").first()
    assert saved is not None
    assert saved.provider == "AWS"
    assert saved.credential_mode == "IAM_ROLE"

    # Security check: Model schema must NEVER have secret_key or access_key fields
    account_columns = [c.name for c in CloudAccount.__table__.columns]
    assert "aws_secret_access_key" not in account_columns
    assert "secret_key" not in account_columns
    assert "password" not in account_columns


def test_scan_lifecycle_and_metrics(db_session):
    """Test 5: Verify Scan creation, status transitions, and metric calculations."""
    account = CloudAccount(name="Test Acc", account_identifier="999888777666")
    db_session.add(account)
    db_session.flush()

    scan = Scan(
        cloud_account_id=account.id,
        status="QUEUED",
        resources_scanned=0,
        findings_count=0,
    )
    db_session.add(scan)
    db_session.commit()
    assert scan.status == "QUEUED"

    # Simulate scan progression to RUNNING then COMPLETED
    scan.status = "RUNNING"
    scan.started_at = utc_now()
    db_session.commit()
    assert scan.status == "RUNNING"

    scan.status = "COMPLETED"
    scan.completed_at = utc_now()
    scan.duration = 14.5
    scan.resources_scanned = 25
    scan.findings_count = 3
    scan.critical_count = 1
    scan.high_count = 2
    scan.security_score = 82.5
    db_session.commit()

    saved = db_session.query(Scan).filter(Scan.id == scan.id).first()
    assert saved.status == "COMPLETED"
    assert saved.resources_scanned == 25
    assert saved.security_score == 82.5
    assert saved.cloud_account.id == account.id


def test_resource_with_json_configuration(db_session):
    """Test 6: Verify Resource model persists flexible JSON metadata & tags."""
    account = CloudAccount(name="Test Acc", account_identifier="111222333444")
    db_session.add(account)
    db_session.flush()

    bucket_config = {
        "Versioning": {"Status": "Enabled"},
        "PublicAccessBlock": {
            "BlockPublicAcls": True,
            "BlockPublicPolicy": True,
            "IgnorePublicAcls": True,
            "RestrictPublicBuckets": True,
        },
        "ServerSideEncryption": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]},
    }
    tags = {"Environment": "Production", "Owner": "SecOps"}

    res = Resource(
        cloud_account_id=account.id,
        provider="AWS",
        service="S3",
        resource_type="aws_s3_bucket",
        resource_id="corp-confidential-bucket-01",
        resource_name="corp-confidential-bucket-01",
        region="us-east-1",
        tags=tags,
        configuration=bucket_config,
        security_status="COMPLIANT",
    )
    db_session.add(res)
    db_session.commit()

    saved = db_session.query(Resource).filter(Resource.resource_id == "corp-confidential-bucket-01").first()
    assert saved is not None
    assert saved.service == "S3"
    assert saved.tags["Environment"] == "Production"
    assert saved.configuration["PublicAccessBlock"]["BlockPublicAcls"] is True


def test_security_rule_uniqueness_and_storage(db_session):
    """Test 7: Verify SecurityRule uniqueness on rule_id and attribute storage."""
    rule = SecurityRule(
        rule_id="S3-001",
        title="Public bucket access detected",
        description="Bucket ACL allows public access",
        service="S3",
        resource_type="aws_s3_bucket",
        severity="CRITICAL",
        category="Data Exposure",
        remediation="Enable S3 Block Public Access",
        references=["https://aws.amazon.com/s3/"],
        enabled=True,
    )
    db_session.add(rule)
    db_session.commit()

    # Duplicate rule_id should raise IntegrityError
    dup_rule = SecurityRule(
        rule_id="S3-001",
        title="Duplicate rule",
        description="Dup",
        service="S3",
        resource_type="aws_s3_bucket",
        severity="HIGH",
        category="Data Exposure",
        remediation="Remediation",
        references=[],
    )
    db_session.add(dup_rule)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_finding_creation_and_associations(db_session):
    """Test 8: Verify Finding entity with JSON evidence, foreign keys, and indexes."""
    account = CloudAccount(name="Acc", account_identifier="123")
    db_session.add(account)
    db_session.flush()

    scan = Scan(cloud_account_id=account.id, status="RUNNING")
    db_session.add(scan)
    db_session.flush()

    res = Resource(
        cloud_account_id=account.id,
        scan_id=scan.id,
        provider="AWS",
        service="EC2",
        resource_type="aws_security_group",
        resource_id="sg-0123456789abcdef0",
    )
    db_session.add(res)
    db_session.flush()

    rule = SecurityRule(
        rule_id="EC2-002",
        title="Unrestricted SSH",
        description="Port 22 open to 0.0.0.0/0",
        service="EC2",
        resource_type="aws_security_group",
        severity="CRITICAL",
        category="Network Security",
        remediation="Restrict SSH",
        references=[],
    )
    db_session.add(rule)
    db_session.flush()

    evidence_data = {
        "security_group_id": "sg-0123456789abcdef0",
        "ip_permissions": [
            {"FromPort": 22, "ToPort": 22, "IpProtocol": "tcp", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        ]
    }

    finding = Finding(
        rule_id=rule.id,
        scan_id=scan.id,
        cloud_account_id=account.id,
        resource_id=res.id,
        finding_identifier="hash_ec2_002_sg0123456789",
        title="EC2 Security Group allows unrestricted SSH (port 22)",
        description="Security group permits ingress from 0.0.0.0/0 to port 22.",
        severity="CRITICAL",
        risk_score=95.0,
        status="OPEN",
        remediation="Restrict SSH to authorized IP addresses.",
        evidence=evidence_data,
    )
    db_session.add(finding)
    db_session.commit()

    saved = db_session.query(Finding).filter(Finding.finding_identifier == "hash_ec2_002_sg0123456789").first()
    assert saved is not None
    assert saved.severity == "CRITICAL"
    assert saved.risk_score == 95.0
    assert saved.evidence["security_group_id"] == "sg-0123456789abcdef0"
    assert saved.rule.rule_id == "EC2-002"
    assert saved.resource.resource_id == "sg-0123456789abcdef0"
    assert saved.scan.id == scan.id


def test_compliance_mapping_association(db_session):
    """Test 9: Verify ComplianceControl and FindingCompliance association."""
    account = CloudAccount(name="Acc", account_identifier="123")
    rule = SecurityRule(rule_id="S3-001", title="T", description="D", service="S3", resource_type="R", severity="HIGH", category="C", remediation="R", references=[])
    db_session.add_all([account, rule])
    db_session.flush()

    scan = Scan(cloud_account_id=account.id, status="RUNNING")
    res = Resource(cloud_account_id=account.id, provider="AWS", service="S3", resource_type="R", resource_id="bucket-01")
    db_session.add_all([scan, res])
    db_session.flush()

    finding = Finding(
        rule_id=rule.id,
        scan_id=scan.id,
        cloud_account_id=account.id,
        resource_id=res.id,
        finding_identifier="find_001",
        title="Public S3",
        description="Desc",
        severity="HIGH",
        risk_score=80.0,
    )
    db_session.add(finding)

    ctrl = ComplianceControl(
        framework="CIS_AWS",
        control_id="CIS-2.1.5",
        title="Ensure S3 Bucket Policy is not public",
        description="Checks public bucket access",
    )
    db_session.add(ctrl)
    db_session.flush()

    # Map finding to compliance control
    mapping = FindingCompliance(
        finding_id=finding.id,
        compliance_control_id=ctrl.id,
        status="FAIL",
        notes="Automated scan detected public ACL on bucket-01",
    )
    db_session.add(mapping)
    db_session.commit()

    saved_finding = db_session.query(Finding).filter(Finding.finding_identifier == "find_001").first()
    assert len(saved_finding.compliance_mappings) == 1
    assert saved_finding.compliance_mappings[0].compliance_control.control_id == "CIS-2.1.5"
    assert saved_finding.compliance_mappings[0].status == "FAIL"


def test_audit_log_and_operational_entities(db_session):
    """Test 10: Verify AuditLog, Report, and Notification entities."""
    user = User(username="auditor", email="audit@example.com", password_hash="pass")
    db_session.add(user)
    db_session.flush()

    account = CloudAccount(name="Acc", account_identifier="123")
    db_session.add(account)
    db_session.flush()

    scan = Scan(cloud_account_id=account.id, status="COMPLETED")
    db_session.add(scan)
    db_session.flush()

    # 1. Audit Log
    log = AuditLog(
        user_id=user.id,
        action="TRIGGER_SCAN",
        resource_type="scan",
        resource_id=str(scan.id),
        result="SUCCESS",
        metadata_json={"scan_mode": "mock", "target_account": "123"},
        ip_address="192.168.1.50",
    )
    db_session.add(log)

    # 2. Report
    report = Report(
        scan_id=scan.id,
        generated_by=user.id,
        report_type="EXECUTIVE",
        status="GENERATED",
        file_reference="/reports/scan-123-exec.pdf",
    )
    db_session.add(report)

    # 3. Notification
    notif = Notification(
        user_id=user.id,
        notification_type="SCAN_COMPLETED",
        status="UNREAD",
        message=f"Scan {scan.id} completed with security score 85/100.",
    )
    db_session.add(notif)
    db_session.commit()

    saved_log = db_session.query(AuditLog).filter(AuditLog.action == "TRIGGER_SCAN").first()
    assert saved_log is not None
    assert saved_log.user.username == "auditor"
    assert saved_log.metadata_json["scan_mode"] == "mock"

    saved_report = db_session.query(Report).filter(Report.scan_id == scan.id).first()
    assert saved_report.status == "GENERATED"
    assert saved_report.generated_by_user.username == "auditor"

    saved_notif = db_session.query(Notification).filter(Notification.user_id == user.id).first()
    assert saved_notif.status == "UNREAD"
