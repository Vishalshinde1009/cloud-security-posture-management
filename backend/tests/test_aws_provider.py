"""
Tests for Phase 7: Real AWS Read-Only Provider Integration.
Verifies read-only safety, zero credential storage, STS verification,
multi-service discovery & normalization, resilience, strict mode switching,
and Cloud Account management APIs.
"""

import ast
import re
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch
import pytest
from botocore.exceptions import ClientError, NoCredentialsError
from fastapi.testclient import TestClient

from app.main import app
from app.scanner.providers.aws.read_only_guard import (
    AWS_READ_ONLY,
    assert_read_only_operation,
    AWSReadOnlyViolationError,
    FORBIDDEN_MUTATING_PREFIXES,
)
from app.scanner.providers.aws.client_factory import AWSClientFactory, mask_credential
from app.scanner.providers.aws.provider import AWSProvider
from app.scanner.rules.s3 import S3001PublicAccessRule, S3002MissingEncryptionRule
from app.scanner.rules.iam import IAM001UserWithoutMFARule, IAM003OldAccessKeysRule, IAM005RootAccountSecurityRule
from app.scanner.rules.ec2 import EC2004EbsEncryptionDisabledRule, EC2005PublicInstanceExposureRule
from app.scanner.rules.network import NET001UnrestrictedSSHInboundRule
from app.scanner.rules.cloudtrail import CT001CloudTrailNotEnabledRule
from app.scanner.rules.rds import RDS001PublicAccessibilityRule
from app.services.scan_service import ScanService
from app.models.cloud import CloudAccount, Scan
from app.models.auth import User
from app.core.config import settings

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.database.session import get_db, Base
from app.models.auth import Role, Permission
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
    Base.metadata.create_all(bind=test_engine)
    session = TestingSessionLocal()

    p_manage = Permission(id=uuid.uuid4(), name="cloud_accounts:manage", description="Manage cloud accounts")
    p_read = Permission(id=uuid.uuid4(), name="read:accounts", description="View cloud accounts")
    session.add_all([p_manage, p_read])
    session.flush()

    r_admin = Role(id=uuid.uuid4(), name="ADMIN", description="Administrator")
    r_admin.permissions.extend([p_manage, p_read])

    r_analyst = Role(id=uuid.uuid4(), name="SECURITY_ANALYST", description="Analyst")
    r_analyst.permissions.append(p_read)

    r_viewer = Role(id=uuid.uuid4(), name="VIEWER", description="Viewer")
    r_viewer.permissions.append(p_read)

    session.add_all([r_admin, r_analyst, r_viewer])
    session.flush()

    admin_user = User(
        id=uuid.uuid4(),
        username="admin_aws_tester",
        email="admin@aws-cspm.local",
        password_hash=get_password_hash("AdminPass123!"),
        is_active=True,
    )
    admin_user.roles.append(r_admin)

    analyst_user = User(
        id=uuid.uuid4(),
        username="analyst_aws_tester",
        email="analyst@aws-cspm.local",
        password_hash=get_password_hash("AnalystPass123!"),
        is_active=True,
    )
    analyst_user.roles.append(r_analyst)

    viewer_user = User(
        id=uuid.uuid4(),
        username="viewer_aws_tester",
        email="viewer@aws-cspm.local",
        password_hash=get_password_hash("ViewerPass123!"),
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
def test_user(db_session):
    return db_session.query(User).filter(User.username == "admin_aws_tester").first()


@pytest.fixture
def admin_token(db_session):
    user = db_session.query(User).filter(User.username == "admin_aws_tester").first()
    return create_access_token(
        subject=str(user.id),
        claims={"username": user.username, "roles": ["ADMIN"]}
    )


@pytest.fixture
def analyst_token(db_session):
    user = db_session.query(User).filter(User.username == "analyst_aws_tester").first()
    return create_access_token(
        subject=str(user.id),
        claims={"username": user.username, "roles": ["SECURITY_ANALYST"]}
    )


@pytest.fixture
def viewer_token(db_session):
    user = db_session.query(User).filter(User.username == "viewer_aws_tester").first()
    return create_access_token(
        subject=str(user.id),
        claims={"username": user.username, "roles": ["VIEWER"]}
    )


# =============================================================================
# 1. Read-Only Guard & Static Safety Tests
# =============================================================================

def test_read_only_flag_and_guard_assertions():
    """Verifies that AWS_READ_ONLY is True and mutating calls are blocked."""
    assert AWS_READ_ONLY is True

    # Valid read-only calls must pass
    assert_read_only_operation("list_buckets")
    assert_read_only_operation("describe_instances")
    assert_read_only_operation("get_caller_identity")
    assert_read_only_operation("head_bucket")

    # Forbidden mutating calls must raise AWSReadOnlyViolationError
    for forbidden in ["create_bucket", "put_bucket_policy", "delete_trail", "update_user", "modify_instance_attribute"]:
        with pytest.raises(AWSReadOnlyViolationError):
            assert_read_only_operation(forbidden)


def test_static_analysis_zero_mutating_calls_in_aws_provider():
    """
    Static analysis test parsing AST of AWS provider code to ensure
    zero forbidden mutating calls exist in source code.
    """
    import inspect
    import app.scanner.providers.aws.provider as provider_module
    source = inspect.getsource(provider_module)
    parsed_ast = ast.parse(source)

    for node in ast.walk(parsed_ast):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                attr_name = node.func.attr.lower()
                for forbidden in FORBIDDEN_MUTATING_PREFIXES:
                    assert not attr_name.startswith(forbidden), (
                        f"CRITICAL VIOLATION: Source code in provider.py contains mutating call '{attr_name}'"
                    )


def test_credential_masking_helper():
    """Verifies credential masking for safe diagnostics logging."""
    assert mask_credential(None) == "NONE"
    assert mask_credential("") == "NONE"
    assert mask_credential("short") == "****"
    assert mask_credential("AKIAIOSFODNN7EXAMPLE") == "AKIA****MPLE"


# =============================================================================
# 2. AWS Client Factory & STS Caller Identity
# =============================================================================

def test_sts_connection_verification():
    """Verifies that test_sts_connection calls GetCallerIdentity and parses response."""
    mock_factory = AWSClientFactory(region_name="us-east-1")
    mock_sts = MagicMock()
    mock_sts.get_caller_identity.return_value = {
        "Account": "123456789012",
        "Arn": "arn:aws:iam::123456789012:user/cspm-auditor",
        "UserId": "AIDAEXAMPLEUSERID",
    }

    with patch.object(mock_factory, "get_client", return_value=mock_sts):
        result = mock_factory.test_sts_connection()
        assert result["account_id"] == "123456789012"
        assert result["arn"] == "arn:aws:iam::123456789012:user/cspm-auditor"
        assert result["user_id"] == "AIDAEXAMPLEUSERID"


def test_aws_provider_get_account_info():
    """Verifies get_account_info sets provider and metadata from STS."""
    mock_factory = MagicMock()
    mock_factory.test_sts_connection.return_value = {
        "account_id": "999888777666",
        "arn": "arn:aws:iam::999888777666:role/CSPM-Role",
        "user_id": "AROAEXAMPLEROLE",
    }

    provider = AWSProvider(client_factory=mock_factory, default_region="eu-west-1")
    info = provider.get_account_info()
    assert info["provider"] == "AWS"
    assert info["account_id"] == "999888777666"
    assert info["default_region"] == "eu-west-1"


# =============================================================================
# 3. Multi-Service Resource Discovery & Normalization
# =============================================================================

def test_s3_bucket_discovery_and_normalization():
    """Verifies S3 discovery normalizes configuration and triggers S3 rules."""
    mock_factory = MagicMock()
    mock_s3 = MagicMock()

    mock_s3.list_buckets.return_value = {
        "Buckets": [{"Name": "real-test-bucket-01", "CreationDate": datetime.now(timezone.utc)}]
    }
    mock_s3.get_bucket_location.return_value = {"LocationConstraint": "ap-south-1"}
    # Misconfigured: public access block disabled
    mock_s3.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        }
    }
    mock_s3.get_bucket_encryption.side_effect = ClientError(
        {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError", "Message": "Not found"}},
        "GetBucketEncryption"
    )
    mock_s3.get_bucket_versioning.return_value = {"Status": "Suspended"}
    mock_s3.get_bucket_logging.return_value = {}
    mock_s3.get_bucket_policy.side_effect = ClientError(
        {"Error": {"Code": "NoSuchBucketPolicy", "Message": "Not found"}},
        "GetBucketPolicy"
    )
    mock_s3.get_bucket_tagging.return_value = {"TagSet": [{"Key": "Env", "Value": "Staging"}]}

    mock_factory.get_client.side_effect = lambda svc, **kw: mock_s3 if svc == "s3" else MagicMock()

    provider = AWSProvider(account_id="111222333444", client_factory=mock_factory)
    resources = provider._discover_s3_buckets()

    assert len(resources) == 1
    res = resources[0]
    assert res.provider == "AWS"
    assert res.service == "S3"
    assert res.resource_type == "aws_s3_bucket"
    assert res.resource_id == "real-test-bucket-01"
    assert res.region == "ap-south-1"
    assert res.tags == {"Env": "Staging"}

    # Verify S3 rules match correctly
    s3_001 = S3001PublicAccessRule().evaluate(res)
    assert s3_001.matched is True
    assert "public access controls are disabled" in s3_001.reason

    s3_002 = S3002MissingEncryptionRule().evaluate(res)
    assert s3_002.matched is True


def test_iam_user_and_root_discovery_and_normalization():
    """Verifies IAM discovery and root account security posture normalization."""
    mock_factory = MagicMock()
    mock_iam = MagicMock()

    old_create_date = datetime.now(timezone.utc) - timedelta(days=120)
    mock_iam.list_users.return_value = {
        "Users": [
            {
                "UserName": "insecure-engineer",
                "UserId": "AIDA1234567890",
                "Arn": "arn:aws:iam::111222333444:user/insecure-engineer",
                "CreateDate": old_create_date,
            }
        ]
    }
    # User has no MFA
    mock_iam.list_mfa_devices.return_value = {"MFADevices": []}
    # User has key older than 90 days
    mock_iam.list_access_keys.return_value = {
        "AccessKeyMetadata": [
            {"AccessKeyId": "AKIAOLDTESTKEY", "Status": "Active", "CreateDate": old_create_date}
        ]
    }
    mock_iam.list_attached_user_policies.return_value = {
        "AttachedPolicies": [{"PolicyName": "ReadOnlyAccess", "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}]
    }

    # Root account summary: Root MFA missing and access keys present
    mock_iam.get_account_summary.return_value = {
        "SummaryMap": {
            "AccountMFAEnabled": 0,
            "AccountAccessKeysPresent": 1,
        }
    }

    mock_factory.get_client.return_value = mock_iam

    provider = AWSProvider(account_id="111222333444", client_factory=mock_factory)
    resources = provider._discover_iam_resources()

    assert len(resources) == 2
    user_res = next(r for r in resources if r.resource_type == "aws_iam_user")
    root_res = next(r for r in resources if r.resource_type == "aws_iam_root")

    # Evaluate IAM rules
    assert IAM001UserWithoutMFARule().evaluate(user_res).matched is True
    assert IAM003OldAccessKeysRule().evaluate(user_res).matched is True
    assert IAM005RootAccountSecurityRule().evaluate(root_res).matched is True


def test_ec2_and_security_group_discovery_and_normalization():
    """Verifies EC2 and Security Group discovery normalization."""
    mock_factory = MagicMock()
    mock_ec2 = MagicMock()

    mock_ec2.describe_instances.return_value = {
        "Reservations": [
            {
                "Instances": [
                    {
                        "InstanceId": "i-0realinstance99",
                        "InstanceType": "t3.xlarge",
                        "State": {"Name": "running"},
                        "PublicIpAddress": "54.210.10.20",
                        "PrivateIpAddress": "10.0.1.5",
                        "SubnetId": "subnet-real01",
                        "VpcId": "vpc-real01",
                        "SecurityGroups": [{"GroupId": "sg-open-ssh", "GroupName": "unrestricted-ssh-sg"}],
                        "BlockDeviceMappings": [
                            {"DeviceName": "/dev/xvda", "Ebs": {"VolumeId": "vol-12345", "DeleteOnTermination": True}}
                        ],
                        "MetadataOptions": {"HttpTokens": "optional", "HttpEndpoint": "enabled"},
                        "Tags": [{"Key": "Name", "Value": "prod-app-server"}],
                    }
                ]
            }
        ]
    }
    mock_ec2.describe_volumes.return_value = {
        "Volumes": [{"VolumeId": "vol-12345", "Encrypted": False}]
    }
    mock_ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-open-ssh",
                "GroupName": "unrestricted-ssh-sg",
                "Description": "Insecure SG with world SSH",
                "VpcId": "vpc-real01",
                "IpPermissions": [
                    {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
                ],
                "IpPermissionsEgress": [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
                "Tags": [],
            }
        ]
    }

    mock_factory.get_client.return_value = mock_ec2
    provider = AWSProvider(account_id="111222333444", client_factory=mock_factory)

    ec2_items = provider._discover_ec2_instances()
    sg_items = provider._discover_security_groups()

    assert len(ec2_items) == 1
    assert len(sg_items) == 1

    ec2_res = ec2_items[0]
    assert ec2_res.resource_name == "prod-app-server"
    assert ec2_res.configuration["BlockDeviceMappings"][0]["Ebs"]["Encrypted"] is False
    assert EC2004EbsEncryptionDisabledRule().evaluate(ec2_res).matched is True
    assert EC2005PublicInstanceExposureRule().evaluate(ec2_res).matched is True

    sg_res = sg_items[0]
    assert NET001UnrestrictedSSHInboundRule().evaluate(sg_res).matched is True


def test_cloudtrail_and_rds_discovery():
    """Verifies CloudTrail and RDS normalization and rule evaluation."""
    mock_factory = MagicMock()
    mock_ct = MagicMock()
    mock_rds = MagicMock()

    mock_ct.describe_trails.return_value = {
        "trailList": [
            {
                "Name": "company-audit-trail",
                "S3BucketName": "audit-bucket",
                "IsMultiRegionTrail": True,
                "LogFileValidationEnabled": False,
                "KmsKeyId": None,
            }
        ]
    }
    mock_ct.get_trail_status.return_value = {"IsLogging": False}

    mock_rds.describe_db_instances.return_value = {
        "DBInstances": [
            {
                "DBInstanceIdentifier": "insecure-customer-db",
                "DBInstanceClass": "db.t4g.medium",
                "Engine": "postgres",
                "PubliclyAccessible": True,
                "StorageEncrypted": False,
                "VpcSecurityGroups": [],
                "TagList": [],
            }
        ]
    }

    def client_dispatch(service, **kw):
        if service == "cloudtrail":
            return mock_ct
        if service == "rds":
            return mock_rds
        return MagicMock()

    mock_factory.get_client.side_effect = client_dispatch
    provider = AWSProvider(account_id="111222333444", client_factory=mock_factory)

    ct_items = provider._discover_cloudtrail()
    rds_items = provider._discover_rds_instances()

    assert len(ct_items) == 1
    assert CT001CloudTrailNotEnabledRule().evaluate(ct_items[0]).matched is True

    assert len(rds_items) == 1
    assert RDS001PublicAccessibilityRule().evaluate(rds_items[0]).matched is True


# =============================================================================
# 4. Resilience & Partial Discovery Error Handling
# =============================================================================

def test_partial_discovery_resilience_when_service_access_denied():
    """
    Verifies that if one service (e.g. S3) returns AccessDenied,
    the provider records a warning and continues to discover remaining services.
    """
    mock_factory = MagicMock()
    mock_s3 = MagicMock()
    mock_s3.list_buckets.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "User is not authorized to perform s3:ListAllMyBuckets"}},
        "ListBuckets"
    )

    mock_ec2 = MagicMock()
    mock_ec2.describe_instances.return_value = {"Reservations": []}
    mock_ec2.describe_security_groups.return_value = {"SecurityGroups": []}

    mock_iam = MagicMock()
    mock_iam.list_users.return_value = {"Users": []}
    mock_iam.get_account_summary.return_value = {"SummaryMap": {}}

    mock_ct = MagicMock()
    mock_ct.describe_trails.return_value = {"trailList": []}

    mock_rds = MagicMock()
    mock_rds.describe_db_instances.return_value = {"DBInstances": []}

    def client_dispatch(svc, **kw):
        if svc == "s3":
            return mock_s3
        if svc == "ec2":
            return mock_ec2
        if svc == "iam":
            return mock_iam
        if svc == "cloudtrail":
            return mock_ct
        if svc == "rds":
            return mock_rds
        return MagicMock()

    mock_factory.get_client.side_effect = client_dispatch
    provider = AWSProvider(account_id="111222333444", client_factory=mock_factory)

    resources = provider.discover_resources()
    # S3 failed, but discovery completed safely
    assert len(provider.discovery_warnings) >= 1
    assert "S3 discovery failed" in provider.discovery_warnings[0]


# =============================================================================
# 5. Strict Mode Switching & No Silent Fallback
# =============================================================================

def test_strict_aws_mode_scan_failure_without_silent_fallback(db_session, test_user):
    """
    When account provider is AWS, if AWS credentials fail,
    ScanService MUST mark the scan as FAILED and NOT silently fallback to mock.
    """
    aws_account = CloudAccount(
        name="Strict AWS Target",
        provider="AWS",
        account_identifier="123456789012",
        default_region="us-east-1",
        credential_mode="ENVIRONMENT",
        is_active=True,
    )
    db_session.add(aws_account)
    db_session.commit()
    db_session.refresh(aws_account)

    # Simulate NoCredentialsError when AWSProvider attempts discovery
    with patch("app.services.scan_service.AWSProvider") as mock_aws_cls:
        instance = mock_aws_cls.return_value
        instance.discover_resources.side_effect = NoCredentialsError()

        scan = ScanService.trigger_scan(db=db_session, user=test_user, account_id=aws_account.id)
        assert scan.status == "FAILED"
        assert "Unable to locate credentials" in scan.error_message or "Scanner error" in scan.error_message
        assert scan.resources_scanned == 0


# =============================================================================
# 6. Cloud Account RBAC & Management Authorization Tests
# =============================================================================

def test_1_admin_can_create_cloud_account(client, admin_token):
    """1. ADMIN can create cloud account -> 201/200"""
    unique_acc = f"acc-{uuid.uuid4().hex[:6]}"
    res = client.post(
        "/api/cloud-accounts",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "Production Account",
            "provider": "AWS",
            "account_identifier": unique_acc,
            "default_region": "us-west-2",
            "credential_mode": "IAM_ROLE",
        },
    )
    assert res.status_code == 201
    data = res.json()
    assert data["name"] == "Production Account"
    assert data["account_identifier"] == unique_acc
    assert data["provider"] == "AWS"


def test_2_admin_can_test_connection(client, admin_token, db_session):
    """2. ADMIN can test connection -> allowed (200)"""
    mock_acc = CloudAccount(
        name="Admin Test Target",
        provider="MOCK",
        account_identifier="mock-admin-001",
        default_region="us-east-1",
        credential_mode="MOCK",
        is_active=True,
    )
    db_session.add(mock_acc)
    db_session.commit()
    db_session.refresh(mock_acc)

    res = client.post(
        f"/api/cloud-accounts/{mock_acc.id}/test-connection",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 200
    assert res.json()["status"] == "CONNECTED"


def test_3_security_analyst_can_view_cloud_accounts(client, analyst_token):
    """3. SECURITY_ANALYST can view cloud accounts -> allowed (200)"""
    res = client.get(
        "/api/cloud-accounts",
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert res.status_code == 200
    assert isinstance(res.json(), list)


def test_4_security_analyst_can_create_cloud_account(client, analyst_token):
    """4. SECURITY_ANALYST can create own cloud account -> 201 Created"""
    res = client.post(
        "/api/cloud-accounts",
        headers={"Authorization": f"Bearer {analyst_token}"},
        json={
            "name": "Analyst Attempted Account",
            "provider": "AWS",
            "account_identifier": "111222333444",
            "default_region": "us-east-1",
            "credential_mode": "ENVIRONMENT",
        },
    )
    assert res.status_code == 201
    assert res.json()["account_identifier"] == "111222333444"


def test_5_security_analyst_cannot_test_administrative_connection(client, analyst_token, db_session):
    """5. SECURITY_ANALYST cannot test unowned account connection -> 404 Not Found (IDOR protection)"""
    acc = CloudAccount(
        name="Analyst Target",
        provider="MOCK",
        account_identifier="mock-analyst-001",
        default_region="us-east-1",
        credential_mode="MOCK",
        is_active=True,
    )
    db_session.add(acc)
    db_session.commit()
    db_session.refresh(acc)

    res = client.post(
        f"/api/cloud-accounts/{acc.id}/test-connection",
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert res.status_code == 404
    assert "not found" in res.json().get("detail", "").lower()


def test_6_viewer_can_view_cloud_accounts(client, viewer_token):
    """6. VIEWER can view cloud accounts -> allowed (200)"""
    res = client.get(
        "/api/cloud-accounts",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert res.status_code == 200
    assert isinstance(res.json(), list)


def test_7_viewer_can_create_cloud_account(client, viewer_token):
    """7. VIEWER can create their own cloud account -> 201 Created"""
    res = client.post(
        "/api/cloud-accounts",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={
            "name": "Viewer Attempted Account",
            "provider": "AWS",
            "account_identifier": "555666777888",
            "default_region": "us-east-1",
            "credential_mode": "ENVIRONMENT",
        },
    )
    assert res.status_code == 201
    assert res.json()["account_identifier"] == "555666777888"


def test_8_viewer_cannot_test_connection_on_unowned_account(client, viewer_token, db_session):
    """8. VIEWER cannot test connection on unowned account -> 404 Not Found (IDOR protection)"""
    acc = CloudAccount(
        name="Viewer Target",
        provider="MOCK",
        account_identifier="mock-viewer-001",
        default_region="us-east-1",
        credential_mode="MOCK",
        is_active=True,
    )
    db_session.add(acc)
    db_session.commit()
    db_session.refresh(acc)

    res = client.post(
        f"/api/cloud-accounts/{acc.id}/test-connection",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert res.status_code == 404
    assert "not found" in res.json().get("detail", "").lower()


def test_9_unauthenticated_request_cloud_accounts(client, db_session):
    """9. Unauthenticated request -> 401 Unauthorized"""
    # 9a. List accounts without token
    res_list = client.get("/api/cloud-accounts")
    assert res_list.status_code == 401

    # 9b. Create account without token
    res_post = client.post(
        "/api/cloud-accounts",
        json={
            "name": "Anon Account",
            "provider": "AWS",
            "account_identifier": "999888777666",
            "default_region": "us-east-1",
            "credential_mode": "ENVIRONMENT",
        },
    )
    assert res_post.status_code == 401

    # 9c. Test connection without token
    acc = CloudAccount(
        name="Anon Target",
        provider="MOCK",
        account_identifier="mock-anon-001",
        default_region="us-east-1",
        credential_mode="MOCK",
        is_active=True,
    )
    db_session.add(acc)
    db_session.commit()
    db_session.refresh(acc)

    res_test = client.post(f"/api/cloud-accounts/{acc.id}/test-connection")
    assert res_test.status_code == 401


def test_10_seed_synchronization_grants_admin_cloud_accounts_manage_and_allows_management(client, db_session):
    """
    10. Regression Test:
    Verifies that an ADMIN user whose role previously lacked 'cloud_accounts:manage'
    is updated by seed_database(), resolving the 403 error on POST /api/cloud-accounts.
    """
    from app.database.seed import seed_database
    from app.services.auth_service import AuthService

    # 1. Strip 'cloud_accounts:manage' from the existing ADMIN role to simulate legacy state
    admin_role = db_session.query(Role).filter(Role.name == "ADMIN").first()
    p_manage = db_session.query(Permission).filter(Permission.name == "cloud_accounts:manage").first()
    if p_manage and p_manage in admin_role.permissions:
        admin_role.permissions.remove(p_manage)
    db_session.commit()

    admin_user = User(
        id=uuid.uuid4(),
        username="legacy_admin_tester",
        email="legacy_admin@cspm-security.local",
        password_hash=get_password_hash("AdminPass123!"),
        is_active=True,
    )
    admin_user.roles.append(admin_role)
    db_session.add(admin_user)
    db_session.commit()

    # Pre-seed check: verify admin role is missing cloud_accounts:manage
    admin_perms_before = AuthService.get_user_permissions(admin_user)
    assert "cloud_accounts:manage" not in admin_perms_before

    # 2. Run seed_database to synchronize permissions
    seed_database(db=db_session)
    db_session.refresh(admin_role)
    db_session.refresh(admin_user)

    # Post-seed check: verify ADMIN role now has cloud_accounts:manage
    admin_perms = AuthService.get_user_permissions(admin_user)
    assert "cloud_accounts:manage" in admin_perms

    # Post-seed token: create account must succeed with 201 Created
    post_seed_token = AuthService.create_user_token(admin_user)
    res_after = client.post(
        "/api/cloud-accounts",
        headers={"Authorization": f"Bearer {post_seed_token}"},
        json={
            "name": "Post-Seed Success Account",
            "provider": "MOCK",
            "account_identifier": "mock-post-seed-001",
            "default_region": "us-east-1",
            "credential_mode": "MOCK",
        },
    )
    assert res_after.status_code == 201
    created_acc_id = res_after.json()["id"]

    # Test connection must also succeed with 200 OK
    res_test = client.post(
        f"/api/cloud-accounts/{created_acc_id}/test-connection",
        headers={"Authorization": f"Bearer {post_seed_token}"},
    )
    assert res_test.status_code == 200
    assert res_test.json()["status"] == "CONNECTED"


def test_11_trigger_scan_routes_to_aws_provider_for_aws_account(client, admin_token, db_session):
    """Verifies triggering a scan for an AWS cloud account strictly invokes AWSProvider."""
    from app.models.cloud import CloudAccount
    from app.scanner.providers.aws.provider import AWSProvider
    from app.scanner.providers.mock.provider import MockProvider

    aws_account = CloudAccount(
        name="Real Audit AWS Account",
        provider="AWS",
        account_identifier="123456789012",
        default_region="us-east-1",
        credential_mode="ENVIRONMENT",
        is_active=True,
    )
    db_session.add(aws_account)
    db_session.commit()

    with patch.object(AWSProvider, "discover_resources", return_value=[]) as mock_aws_discover, \
         patch.object(MockProvider, "discover_resources", return_value=[]) as mock_mock_discover:
        res = client.post(
            "/api/scans",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"account_id": str(aws_account.id)},
        )
        assert res.status_code == 201
        data = res.json()
        assert data["account_name"] == "Real Audit AWS Account"
        assert data["account_provider"] == "AWS"
        mock_aws_discover.assert_called_once()
        mock_mock_discover.assert_not_called()


def test_12_trigger_scan_routes_to_mock_provider_for_mock_account(client, admin_token, db_session):
    """Verifies triggering a scan for a MOCK cloud account strictly invokes MockProvider."""
    from app.models.cloud import CloudAccount
    from app.scanner.providers.aws.provider import AWSProvider
    from app.scanner.providers.mock.provider import MockProvider

    mock_account = CloudAccount(
        name="Demo Simulated Target",
        provider="MOCK",
        account_identifier="mock-sim-001",
        default_region="us-east-1",
        credential_mode="MOCK",
        is_active=True,
    )
    db_session.add(mock_account)
    db_session.commit()

    with patch.object(AWSProvider, "discover_resources", return_value=[]) as mock_aws_discover, \
         patch.object(MockProvider, "discover_resources", return_value=[]) as mock_mock_discover:
        res = client.post(
            "/api/scans",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"account_id": str(mock_account.id)},
        )
        assert res.status_code == 201
        data = res.json()
        assert data["account_name"] == "Demo Simulated Target"
        assert data["account_provider"] == "MOCK"
        mock_mock_discover.assert_called_once()
        mock_aws_discover.assert_not_called()


def test_13_trigger_scan_accepts_cloud_account_id_alias(client, admin_token, db_session):
    """Verifies that sending cloud_account_id in the payload resolves identically to account_id."""
    from app.models.cloud import CloudAccount
    from app.scanner.providers.aws.provider import AWSProvider

    aws_account = CloudAccount(
        name="Alias Test AWS Account",
        provider="AWS",
        account_identifier="987654321098",
        default_region="us-east-1",
        credential_mode="ENVIRONMENT",
        is_active=True,
    )
    db_session.add(aws_account)
    db_session.commit()

    with patch.object(AWSProvider, "discover_resources", return_value=[]):
        res = client.post(
            "/api/scans",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"cloud_account_id": str(aws_account.id)},
        )
        assert res.status_code == 201
        data = res.json()
        assert data["account_name"] == "Alias Test AWS Account"
        assert data["account_provider"] == "AWS"


def test_14_admin_get_cloud_accounts_with_float_score_returns_aws_and_mock(client, admin_token, db_session):
    """
    Verifies that authenticated ADMIN can GET /api/cloud-accounts,
    both AWS and MOCK accounts are returned, float security scores (e.g. 63.3) serialize cleanly,
    and no secret credentials leak in the response.
    """
    from app.models.cloud import CloudAccount, Scan

    # 1. Seed Real AWS account with float security score
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
        security_score=63.3,
        findings_count=3,
        resources_scanned=3,
    )
    db_session.add(aws_scan)

    # 2. Seed Mock Demo account
    mock_account = CloudAccount(
        name="Demo AWS Environment (Simulated)",
        provider="MOCK",
        account_identifier="mock-sim-001",
        default_region="us-east-1",
        credential_mode="MOCK",
        is_active=True,
    )
    db_session.add(mock_account)
    db_session.flush()

    mock_scan = Scan(
        cloud_account_id=mock_account.id,
        status="COMPLETED",
        security_score=0.0,
        findings_count=17,
        resources_scanned=20,
    )
    db_session.add(mock_scan)
    db_session.commit()

    # 3. Call GET /api/cloud-accounts with admin token
    res = client.get(
        "/api/cloud-accounts",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 200
    accounts = res.json()
    assert isinstance(accounts, list)
    assert len(accounts) >= 2

    # Check AWS account in response
    aws_match = next((a for a in accounts if a["provider"] == "AWS" and a["name"] == "Audit Target"), None)
    assert aws_match is not None
    assert aws_match["account_identifier"] == "123456789012"
    assert aws_match["default_region"] == "eu-north-1"
    assert aws_match["credential_mode"] == "ENVIRONMENT"
    assert aws_match["is_active"] is True
    assert aws_match["latest_scan"] is not None
    assert aws_match["latest_scan"]["security_score"] == 63.3
    assert aws_match["latest_scan"]["status"] == "COMPLETED"

    # Check MOCK account in response
    mock_match = next((a for a in accounts if a["provider"] == "MOCK" and a["name"] == "Demo AWS Environment (Simulated)"), None)
    assert mock_match is not None
    assert mock_match["credential_mode"] == "MOCK"
    assert mock_match["latest_scan"] is not None
    assert mock_match["latest_scan"]["security_score"] == 0.0

    # 4. Strictly verify zero secret/credential keys exist in response
    forbidden_secret_keys = [
        "secret", "secret_key", "aws_secret_access_key", "password", 
        "token", "session_token", "private_key", "credentials"
    ]
    import json
    response_str = json.dumps(accounts).lower()
    for forbidden in forbidden_secret_keys:
        assert f'"{forbidden}"' not in response_str



