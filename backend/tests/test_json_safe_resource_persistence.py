import uuid
from datetime import datetime, date, timezone
from decimal import Decimal
import pytest
from unittest.mock import patch, MagicMock
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.json_utils import to_json_safe
from app.database.session import Base
from app.models.auth import User, Role, Permission
from app.models.cloud import CloudAccount, Scan, Resource
from app.models.finding import Finding, SecurityRule
from app.services.scan_service import ScanService
from app.services.finding_service import FindingService
from app.scanner.providers.base import DiscoveredResource, CloudProvider
from app.scanner.engine.scanner import ScannerEngine


# Isolated in-memory SQLite database
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
def db():
    Base.metadata.create_all(bind=test_engine)
    session = TestingSessionLocal()

    # Create admin role and user
    p_run = Permission(id=uuid.uuid4(), name="run:scans", description="Run scans")
    p_read = Permission(id=uuid.uuid4(), name="read:scans", description="Read scans")
    r_admin = Role(id=uuid.uuid4(), name="ADMIN", description="Admin role")
    r_admin.permissions.extend([p_run, p_read])

    user = User(
        id=uuid.uuid4(),
        username="test_scan_user",
        email="scanuser@example.com",
        password_hash="hash",
        is_active=True,
    )
    user.roles.append(r_admin)

    session.add_all([p_run, p_read, r_admin, user])
    session.commit()

    yield session

    session.close()
    Base.metadata.drop_all(bind=test_engine)


class CustomBotoSdkObject:
    """Simulates an arbitrary boto3/SDK response object."""
    def __init__(self, val: str):
        self.val = val

    def __str__(self):
        return f"SdkObject({self.val})"


# =====================================================================
# 1. Unit Tests for to_json_safe normalization
# =====================================================================

def test_to_json_safe_primitives():
    assert to_json_safe("string") == "string"
    assert to_json_safe(123) == 123
    assert to_json_safe(45.67) == 45.67
    assert to_json_safe(True) is True
    assert to_json_safe(False) is False
    assert to_json_safe(None) is None


def test_to_json_safe_datetime_and_date():
    dt_aware = datetime(2026, 3, 15, 10, 30, 45, tzinfo=timezone.utc)
    dt_naive = datetime(2026, 3, 15, 10, 30, 45)
    d = date(2026, 3, 15)

    assert to_json_safe(dt_aware) == "2026-03-15T10:30:45+00:00"
    assert to_json_safe(dt_naive) == "2026-03-15T10:30:45"
    assert to_json_safe(d) == "2026-03-15"


def test_to_json_safe_nested_structures():
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    today = date(2026, 1, 1)

    complex_aws_data = {
        "BucketName": "prod-data-lake",
        "CreationDate": now,
        "Grants": [
            {
                "Grantee": {"DisplayName": "admin"},
                "Permission": "FULL_CONTROL",
                "AssignedDate": today,
            }
        ],
        "Tags": {
            "Environment": "Production",
            "Owner": "SecOps",
        },
        "Versions": [now, today],
        "CostDecimal": Decimal("49.99"),
        "IntDecimal": Decimal("100.00"),
        "UniqueRegions": {"us-east-1", "us-west-2"},
        "CustomObj": CustomBotoSdkObject("arn:aws:s3:::bucket"),
    }

    normalized = to_json_safe(complex_aws_data)

    assert normalized["CreationDate"] == "2026-01-01T12:00:00+00:00"
    assert normalized["Grants"][0]["AssignedDate"] == "2026-01-01"
    assert normalized["CostDecimal"] == 49.99
    assert normalized["IntDecimal"] == 100
    assert sorted(normalized["UniqueRegions"]) == ["us-east-1", "us-west-2"]
    assert normalized["CustomObj"] == "SdkObject(arn:aws:s3:::bucket)"


# =====================================================================
# 2. Database Persistence Boundary Tests
# =====================================================================

def test_resource_persistence_with_raw_datetimes(db):
    """Verifies that Resource configuration with nested datetimes persists cleanly."""
    user = db.query(User).filter(User.username == "test_scan_user").first()
    account = CloudAccount(
        id=uuid.uuid4(),
        user_id=user.id,
        name="Production-AWS",
        account_identifier="123456789012",
        provider="AWS",
        credential_mode="ROLE",
        role_arn="arn:aws:iam::123456789012:role/CSPMReadOnlyRole",
        external_id="ext-id-12345",
        is_active=True,
    )
    db.add(account)
    db.commit()

    scan = Scan(
        id=uuid.uuid4(),
        cloud_account_id=account.id,
        status="RUNNING",
        started_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    db.commit()

    # Emulate raw boto3 configuration containing datetime objects
    raw_boto_config = {
        "InstanceId": "i-0abcdef1234567890",
        "LaunchTime": datetime(2026, 2, 20, 8, 15, 30, tzinfo=timezone.utc),
        "BlockDeviceMappings": [
            {
                "DeviceName": "/dev/sda1",
                "Ebs": {
                    "AttachTime": datetime(2026, 2, 20, 8, 15, 31, tzinfo=timezone.utc),
                    "VolumeId": "vol-12345678",
                },
            }
        ],
    }
    raw_tags = {
        "Launched": date(2026, 2, 20),
        "Owner": "DevOps",
    }

    # Persist via to_json_safe (matching scan_service behavior)
    res = Resource(
        cloud_account_id=account.id,
        scan_id=scan.id,
        provider="AWS",
        service="ec2",
        resource_type="instance",
        resource_id="i-0abcdef1234567890",
        resource_name="web-server-prod",
        region="us-east-1",
        tags=to_json_safe(raw_tags),
        configuration=to_json_safe(raw_boto_config),
        security_status="SECURE",
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
    )
    db.add(res)
    db.commit()

    # Fetch from DB and verify serialization
    saved_res = db.query(Resource).filter(Resource.resource_id == "i-0abcdef1234567890").first()
    assert saved_res is not None
    assert saved_res.configuration["LaunchTime"] == "2026-02-20T08:15:30+00:00"
    assert saved_res.configuration["BlockDeviceMappings"][0]["Ebs"]["AttachTime"] == "2026-02-20T08:15:31+00:00"
    assert saved_res.tags["Launched"] == "2026-02-20"
    # Verify real datetime columns remain Python datetime objects
    assert isinstance(saved_res.first_seen, datetime)
    assert isinstance(saved_res.last_seen, datetime)


# =====================================================================
# 3. End-to-End Scan Execution with Real Boto3 Datetime Payloads
# =====================================================================

class MockAwsProviderWithBotoDatetimes(CloudProvider):
    """Simulates real AWS SDK responses returning boto3-style datetime fields."""

    def get_provider_name(self) -> str:
        return "AWS"

    def get_account_info(self):
        return {"account_id": "111222333444", "alias": "aws-boto-test"}

    def discover_resources(self):
        return [
            DiscoveredResource(
                provider="AWS",
                account_id="111222333444",
                service="s3",
                resource_type="aws_s3_bucket",
                resource_id="boto-datetime-bucket",
                resource_name="boto-datetime-bucket",
                region="us-east-1",
                tags={"Created": date(2026, 1, 15), "Env": "staging"},
                configuration={
                    "CreationDate": datetime(2026, 1, 15, 14, 0, 0, tzinfo=timezone.utc),
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": False,
                        "BlockPublicPolicy": False,
                        "IgnorePublicAcls": False,
                        "RestrictPublicBuckets": False,
                        "CheckDate": datetime(2026, 3, 1, 9, 30, 0, tzinfo=timezone.utc),
                    },
                    "ServerSideEncryptionConfiguration": None,
                },
            ),
            DiscoveredResource(
                provider="AWS",
                account_id="111222333444",
                service="ec2",
                resource_type="instance",
                resource_id="i-boto999",
                resource_name="boto-instance",
                region="us-east-1",
                tags={"Owner": "cloud-sec"},
                configuration={
                    "LaunchTime": datetime(2026, 2, 1, 10, 0, 0, tzinfo=timezone.utc),
                    "State": {"Name": "running"},
                },
            ),
        ]

    def collect_configuration(self, service: str, resource_type: str, resource_id: str):
        return {}


def test_scan_service_succeeds_with_datetime_payload(db):
    """
    End-to-end test verifying that ScanService.execute_scan persists resources
    and findings without raising 'TypeError: Object of type datetime is not JSON serializable'.
    """
    user = db.query(User).filter(User.username == "test_scan_user").first()
    account = CloudAccount(
        id=uuid.uuid4(),
        user_id=user.id,
        name="Boto-Datetime-Account",
        account_identifier="111222333444",
        provider="AWS",
        credential_mode="ROLE",
        role_arn="arn:aws:iam::111222333444:role/CSPMReadOnlyRole",
        external_id="ext-boto-123",
        is_active=True,
    )
    db.add(account)
    db.commit()

    # Mock AWSProvider and run_discovery_pipeline to return provider with boto3 datetime objects
    mock_provider = MockAwsProviderWithBotoDatetimes()
    with patch("app.services.scan_service.AWSProvider", return_value=mock_provider), \
         patch.object(ScannerEngine, "run_discovery_pipeline", return_value=mock_provider.discover_resources()):
        completed_scan = ScanService.trigger_scan(db=db, account_id=account.id, user=user)

    # Scan should succeed cleanly without serialization crash
    assert completed_scan.status == "COMPLETED"
    assert completed_scan.resources_scanned == 2
    assert completed_scan.error_message is None

    # Check persisted resources
    bucket_res = db.query(Resource).filter(Resource.resource_id == "boto-datetime-bucket").first()
    assert bucket_res is not None
    assert bucket_res.configuration["CreationDate"] == "2026-01-15T14:00:00+00:00"
    assert bucket_res.configuration["PublicAccessBlockConfiguration"]["CheckDate"] == "2026-03-01T09:30:00+00:00"
    assert bucket_res.tags["Created"] == "2026-01-15"

    # Check persisted findings
    findings = db.query(Finding).filter(Finding.cloud_account_id == account.id).all()
    assert len(findings) > 0
    for f in findings:
        assert f.status == "OPEN"
        assert isinstance(f.evidence, dict)
        assert isinstance(f.risk_factors, dict)
        # Verify timestamp columns are real Python datetimes
        assert isinstance(f.first_detected, datetime)
        assert isinstance(f.last_detected, datetime)


# =====================================================================
# 4. Rollback and Safe Error Recovery Tests
# =====================================================================

def test_scan_service_handles_db_error_and_rolls_back_safely(db):
    """
    Verifies that if an unexpected exception occurs during scan execution,
    the session is cleanly rolled back and does not enter PendingRollbackError,
    marking scan.status = 'FAILED' cleanly.
    """
    user = db.query(User).filter(User.username == "test_scan_user").first()
    account = CloudAccount(
        id=uuid.uuid4(),
        user_id=user.id,
        name="Fail-Test-Account",
        account_identifier="999888777666",
        provider="MOCK",
        credential_mode="MOCK",
        is_active=True,
    )
    db.add(account)
    db.commit()

    # Simulate an error during discovery
    with patch.object(ScannerEngine, "run_discovery_pipeline", side_effect=RuntimeError("Simulated AWS SDK Network Timeout")):
        failed_scan = ScanService.trigger_scan(db=db, account_id=account.id, user=user)

    # Re-query scan to verify status updated to FAILED and session is usable
    db.expire_all()
    queried_scan = db.query(Scan).filter(Scan.id == failed_scan.id).first()
    assert queried_scan.status == "FAILED"
    assert "Simulated AWS SDK Network Timeout" in queried_scan.error_message
