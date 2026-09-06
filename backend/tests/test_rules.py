import pytest
from app.scanner.providers.base import DiscoveredResource
from app.scanner.rules.registry import default_registry

# S3 Rules
from app.scanner.rules.s3 import (
    S3001PublicAccessRule,
    S3002MissingEncryptionRule,
    S3003VersioningDisabledRule,
    S3004LoggingDisabledRule,
    S3005InsecurePolicyRule,
)
# IAM Rules
from app.scanner.rules.iam import (
    IAM001UserWithoutMFARule,
    IAM002OverlyPermissivePolicyRule,
    IAM003OldAccessKeysRule,
    IAM004UnusedCredentialsRule,
    IAM005RootAccountSecurityRule,
)
# EC2 Rules
from app.scanner.rules.ec2 import (
    EC2001UnrestrictedSecurityGroupRule,
    EC2002UnrestrictedSSHRule,
    EC2003UnrestrictedRDPRule,
    EC2004EbsEncryptionDisabledRule,
    EC2005PublicInstanceExposureRule,
)
# Network Rules
from app.scanner.rules.network import (
    NET001UnrestrictedSSHInboundRule,
    NET002UnrestrictedRDPInboundRule,
    NET003UnrestrictedSensitivePortsRule,
    NET004OverlyPermissiveInboundRule,
    NET005OverlyPermissiveOutboundRule,
)
# CloudTrail Rules
from app.scanner.rules.cloudtrail import (
    CT001CloudTrailNotEnabledRule,
    CT002CloudTrailLoggingDisabledRule,
    CT003CloudTrailMultiRegionIssueRule,
)
# RDS Rules
from app.scanner.rules.rds import (
    RDS001PublicAccessibilityRule,
    RDS002StorageEncryptionDisabledRule,
    RDS003WeakNetworkExposureRule,
)


def make_resource(service: str, resource_type: str, resource_id: str = "res-test-01", configuration: dict = None) -> DiscoveredResource:
    return DiscoveredResource(
        provider="MOCK",
        account_id="mock-account-001",
        service=service,
        resource_type=resource_type,
        resource_id=resource_id,
        resource_name=resource_id,
        region="us-east-1",
        tags={},
        configuration=configuration or {},
    )


# ==============================================================================
# S3 RULES (S3-001 through S3-005)
# ==============================================================================

def test_s3_001_public_access():
    rule = S3001PublicAccessRule()
    assert rule.rule_id == "S3-001"
    assert rule.severity == "CRITICAL"

    # Positive: BlockPublicAcls is False
    bad_res = make_resource("S3", "aws_s3_bucket", configuration={
        "PublicAccessBlockConfiguration": {"BlockPublicAcls": False, "IgnorePublicAcls": False}
    })
    res = rule.evaluate(bad_res)
    assert res.matched is True
    assert "PublicAccessBlockConfiguration" in res.evidence
    assert res.severity == "CRITICAL"
    assert len(res.remediation) > 0

    # Negative: Compliant
    good_res = make_resource("S3", "aws_s3_bucket", configuration={
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True
        }
    })
    assert rule.evaluate(good_res).matched is False

    # Missing config
    missing_res = make_resource("S3", "aws_s3_bucket", configuration={})
    assert rule.evaluate(missing_res).matched is True  # Missing PAB is a violation


def test_s3_002_missing_encryption():
    rule = S3002MissingEncryptionRule()
    assert rule.rule_id == "S3-002"
    assert rule.severity == "HIGH"

    # Positive: No encryption
    bad_res = make_resource("S3", "aws_s3_bucket", configuration={"ServerSideEncryptionConfiguration": None})
    res = rule.evaluate(bad_res)
    assert res.matched is True
    assert res.severity == "HIGH"

    # Negative: Encrypted
    good_res = make_resource("S3", "aws_s3_bucket", configuration={
        "ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}
    })
    assert rule.evaluate(good_res).matched is False


def test_s3_003_versioning_disabled():
    rule = S3003VersioningDisabledRule()
    assert rule.rule_id == "S3-003"
    assert rule.severity == "MEDIUM"

    # Positive: Suspended or missing
    bad_res = make_resource("S3", "aws_s3_bucket", configuration={"Versioning": {"Status": "Suspended"}})
    res = rule.evaluate(bad_res)
    assert res.matched is True
    assert res.evidence["Status"] == "Suspended"

    # Negative: Enabled
    good_res = make_resource("S3", "aws_s3_bucket", configuration={"Versioning": {"Status": "Enabled"}})
    assert rule.evaluate(good_res).matched is False


def test_s3_004_logging_disabled():
    rule = S3004LoggingDisabledRule()
    assert rule.rule_id == "S3-004"
    assert rule.severity == "MEDIUM"

    # Positive: No logging
    bad_res = make_resource("S3", "aws_s3_bucket", configuration={"Logging": None})
    res = rule.evaluate(bad_res)
    assert res.matched is True

    # Negative: TargetBucket configured
    good_res = make_resource("S3", "aws_s3_bucket", configuration={"Logging": {"TargetBucket": "central-audit-logs"}})
    assert rule.evaluate(good_res).matched is False


def test_s3_005_insecure_policy():
    rule = S3005InsecurePolicyRule()
    assert rule.rule_id == "S3-005"
    assert rule.severity == "HIGH"

    # Positive: Allow to * without condition
    bad_res = make_resource("S3", "aws_s3_bucket", configuration={
        "Policy": {
            "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]
        }
    })
    res = rule.evaluate(bad_res)
    assert res.matched is True
    assert "Principal" in res.evidence

    # Negative: Secure deny transport
    good_res = make_resource("S3", "aws_s3_bucket", configuration={
        "Policy": {
            "Statement": [{"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]
        }
    })
    assert rule.evaluate(good_res).matched is False

    # Missing policy -> no false positive
    assert rule.evaluate(make_resource("S3", "aws_s3_bucket", configuration={})).matched is False


# ==============================================================================
# IAM RULES (IAM-001 through IAM-005)
# ==============================================================================

def test_iam_001_user_without_mfa():
    rule = IAM001UserWithoutMFARule()
    assert rule.rule_id == "IAM-001"
    assert rule.severity == "HIGH"

    bad_res = make_resource("IAM", "aws_iam_user", configuration={
        "UserName": "developer", "PasswordLastUsed": "2026-09-01T00:00:00Z", "MFADevices": []
    })
    res = rule.evaluate(bad_res)
    assert res.matched is True
    assert res.evidence["MFADevices"] == []

    good_res = make_resource("IAM", "aws_iam_user", configuration={
        "UserName": "admin", "PasswordLastUsed": "2026-09-01T00:00:00Z", "MFADevices": [{"SerialNumber": "arn:mfa:123"}]
    })
    assert rule.evaluate(good_res).matched is False


def test_iam_002_overly_permissive_policy():
    rule = IAM002OverlyPermissivePolicyRule()
    assert rule.rule_id == "IAM-002"
    assert rule.severity == "CRITICAL"

    bad_res = make_resource("IAM", "aws_iam_user", configuration={
        "AttachedPolicies": [{"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}]
    })
    res = rule.evaluate(bad_res)
    assert res.matched is True
    assert res.evidence["OffendingPolicy"] == "AdministratorAccess"

    good_res = make_resource("IAM", "aws_iam_user", configuration={
        "AttachedPolicies": [{"PolicyName": "ReadOnlyAccess", "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}]
    })
    assert rule.evaluate(good_res).matched is False


def test_iam_003_old_access_keys():
    rule = IAM003OldAccessKeysRule()
    assert rule.rule_id == "IAM-003"
    assert rule.severity == "MEDIUM"

    bad_res = make_resource("IAM", "aws_iam_user", configuration={
        "AccessKeys": [{"AccessKeyId": "AKIA123", "Status": "Active", "AgeDays": 120}]
    })
    res = rule.evaluate(bad_res)
    assert res.matched is True
    assert res.evidence["OldAccessKeys"][0]["AgeDays"] == 120

    good_res = make_resource("IAM", "aws_iam_user", configuration={
        "AccessKeys": [{"AccessKeyId": "AKIA123", "Status": "Active", "AgeDays": 30}]
    })
    assert rule.evaluate(good_res).matched is False


def test_iam_004_unused_credentials():
    rule = IAM004UnusedCredentialsRule()
    assert rule.rule_id == "IAM-004"
    assert rule.severity == "MEDIUM"

    bad_res = make_resource("IAM", "aws_iam_user", configuration={
        "AccessKeys": [{"AccessKeyId": "AKIA999", "Status": "Inactive"}]
    })
    res = rule.evaluate(bad_res)
    assert res.matched is True
    assert len(res.evidence["InactiveKeys"]) == 1

    good_res = make_resource("IAM", "aws_iam_user", configuration={
        "AccessKeys": [{"AccessKeyId": "AKIA999", "Status": "Active", "AgeDays": 10}]
    })
    assert rule.evaluate(good_res).matched is False


def test_iam_005_root_account_security():
    rule = IAM005RootAccountSecurityRule()
    assert rule.rule_id == "IAM-005"
    assert rule.severity == "CRITICAL"

    bad_res = make_resource("IAM", "aws_iam_root", configuration={
        "AccountMFAEnabled": False, "RootAccessKeysPresent": True
    })
    res = rule.evaluate(bad_res)
    assert res.matched is True
    assert res.evidence["AccountMFAEnabled"] is False

    good_res = make_resource("IAM", "aws_iam_root", configuration={
        "AccountMFAEnabled": True, "RootAccessKeysPresent": False
    })
    assert rule.evaluate(good_res).matched is False


# ==============================================================================
# EC2 RULES (EC2-001 through EC2-005)
# ==============================================================================

def test_ec2_001_unrestricted_security_group():
    rule = EC2001UnrestrictedSecurityGroupRule()
    assert rule.rule_id == "EC2-001"
    assert rule.severity == "HIGH"

    bad_res = make_resource("EC2", "aws_ec2_instance", configuration={
        "InstanceId": "i-test1", "SecurityGroups": [{"GroupId": "sg-1", "GroupName": "unrestricted-sg"}]
    })
    res = rule.evaluate(bad_res)
    assert res.matched is True

    good_res = make_resource("EC2", "aws_ec2_instance", configuration={
        "InstanceId": "i-test1", "SecurityGroups": [{"GroupId": "sg-2", "GroupName": "internal-sg"}]
    })
    assert rule.evaluate(good_res).matched is False


def test_ec2_002_unrestricted_ssh():
    rule = EC2002UnrestrictedSSHRule()
    assert rule.rule_id == "EC2-002"
    assert rule.severity == "HIGH"

    bad_res = make_resource("EC2", "aws_ec2_instance", configuration={
        "InstanceId": "i-test1",
        "PublicIpAddress": "54.210.1.1",
        "SecurityGroups": [{"GroupId": "sg-ssh", "GroupName": "unrestricted-ssh-sg"}],
    })
    res = rule.evaluate(bad_res)
    assert res.matched is True
    assert res.evidence["Port"] == 22

    good_res = make_resource("EC2", "aws_ec2_instance", configuration={
        "InstanceId": "i-test1",
        "PublicIpAddress": None,
        "SecurityGroups": [{"GroupId": "sg-safe", "GroupName": "web-sg"}],
    })
    assert rule.evaluate(good_res).matched is False


def test_ec2_003_unrestricted_rdp():
    rule = EC2003UnrestrictedRDPRule()
    assert rule.rule_id == "EC2-003"
    assert rule.severity == "HIGH"

    bad_res = make_resource("EC2", "aws_ec2_instance", configuration={
        "InstanceId": "i-win1",
        "SecurityGroups": [{"GroupId": "sg-rdp", "GroupName": "unrestricted-rdp-sg"}],
    })
    res = rule.evaluate(bad_res)
    assert res.matched is True
    assert res.evidence["Port"] == 3389

    good_res = make_resource("EC2", "aws_ec2_instance", configuration={
        "InstanceId": "i-win1",
        "SecurityGroups": [{"GroupId": "sg-safe", "GroupName": "internal-sg"}],
    })
    assert rule.evaluate(good_res).matched is False


def test_ec2_004_ebs_encryption_disabled():
    rule = EC2004EbsEncryptionDisabledRule()
    assert rule.rule_id == "EC2-004"
    assert rule.severity == "HIGH"

    bad_res = make_resource("EC2", "aws_ec2_instance", configuration={
        "InstanceId": "i-test1",
        "BlockDeviceMappings": [{"DeviceName": "/dev/xvda", "Ebs": {"VolumeId": "vol-1", "Encrypted": False}}],
    })
    res = rule.evaluate(bad_res)
    assert res.matched is True
    assert res.evidence["UnencryptedVolumes"][0]["Encrypted"] is False

    good_res = make_resource("EC2", "aws_ec2_instance", configuration={
        "InstanceId": "i-test1",
        "BlockDeviceMappings": [{"DeviceName": "/dev/xvda", "Ebs": {"VolumeId": "vol-1", "Encrypted": True}}],
    })
    assert rule.evaluate(good_res).matched is False


def test_ec2_005_public_instance_exposure():
    rule = EC2005PublicInstanceExposureRule()
    assert rule.rule_id == "EC2-005"
    assert rule.severity == "HIGH"

    # Public IP with legacy IMDSv1
    bad_res = make_resource("EC2", "aws_ec2_instance", configuration={
        "InstanceId": "i-test1",
        "PublicIpAddress": "203.0.113.1",
        "MetadataOptions": {"HttpTokens": "optional"},
    })
    res = rule.evaluate(bad_res)
    assert res.matched is True
    assert res.evidence["PublicIpAddress"] == "203.0.113.1"

    # Public IP but IMDSv2 required
    good_res = make_resource("EC2", "aws_ec2_instance", configuration={
        "InstanceId": "i-test1",
        "PublicIpAddress": "203.0.113.1",
        "MetadataOptions": {"HttpTokens": "required"},
    })
    assert rule.evaluate(good_res).matched is False


# ==============================================================================
# NETWORK RULES (NET-001 through NET-005)
# ==============================================================================

def test_net_001_unrestricted_ssh_inbound():
    rule = NET001UnrestrictedSSHInboundRule()
    assert rule.rule_id == "NET-001"

    bad_res = make_resource("VPC", "aws_security_group", configuration={
        "GroupId": "sg-open",
        "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    })
    res = rule.evaluate(bad_res)
    assert res.matched is True
    assert res.evidence["Source"] == "0.0.0.0/0"

    good_res = make_resource("VPC", "aws_security_group", configuration={
        "GroupId": "sg-corp",
        "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "192.168.1.0/24"}]}],
    })
    assert rule.evaluate(good_res).matched is False


def test_net_002_unrestricted_rdp_inbound():
    rule = NET002UnrestrictedRDPInboundRule()
    assert rule.rule_id == "NET-002"

    bad_res = make_resource("VPC", "aws_security_group", configuration={
        "GroupId": "sg-rdp",
        "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    })
    res = rule.evaluate(bad_res)
    assert res.matched is True

    good_res = make_resource("VPC", "aws_security_group", configuration={
        "GroupId": "sg-rdp",
        "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "IpRanges": [{"CidrIp": "10.0.0.0/16"}]}],
    })
    assert rule.evaluate(good_res).matched is False


def test_net_003_unrestricted_sensitive_ports():
    rule = NET003UnrestrictedSensitivePortsRule()
    assert rule.rule_id == "NET-003"

    bad_res = make_resource("VPC", "aws_security_group", configuration={
        "GroupId": "sg-mysql",
        "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 3306, "ToPort": 3306, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    })
    res = rule.evaluate(bad_res)
    assert res.matched is True
    assert res.evidence["ExposedPort"] == 3306
    assert res.evidence["Service"] == "MySQL"

    good_res = make_resource("VPC", "aws_security_group", configuration={
        "GroupId": "sg-web",
        "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    })
    assert rule.evaluate(good_res).matched is False


def test_net_004_overly_permissive_inbound():
    rule = NET004OverlyPermissiveInboundRule()
    assert rule.rule_id == "NET-004"

    bad_res = make_resource("VPC", "aws_security_group", configuration={
        "GroupId": "sg-wide",
        "IpPermissions": [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    })
    res = rule.evaluate(bad_res)
    assert res.matched is True

    good_res = make_resource("VPC", "aws_security_group", configuration={
        "GroupId": "sg-web",
        "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    })
    assert rule.evaluate(good_res).matched is False


def test_net_005_overly_permissive_outbound():
    rule = NET005OverlyPermissiveOutboundRule()
    assert rule.rule_id == "NET-005"

    bad_res = make_resource("VPC", "aws_security_group", configuration={
        "GroupId": "sg-telnet",
        "IpPermissionsEgress": [{"IpProtocol": "tcp", "FromPort": 23, "ToPort": 23, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    })
    res = rule.evaluate(bad_res)
    assert res.matched is True
    assert res.evidence["Port"] == 23

    good_res = make_resource("VPC", "aws_security_group", configuration={
        "GroupId": "sg-normal",
        "IpPermissionsEgress": [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    })
    assert rule.evaluate(good_res).matched is False


# ==============================================================================
# CLOUDTRAIL RULES (CT-001 through CT-003)
# ==============================================================================

def test_ct_001_trail_not_logging():
    rule = CT001CloudTrailNotEnabledRule()
    assert rule.rule_id == "CT-001"

    bad_res = make_resource("CloudTrail", "aws_cloudtrail_trail", configuration={
        "Name": "trail-1", "Status": {"IsLogging": False}
    })
    res = rule.evaluate(bad_res)
    assert res.matched is True
    assert res.evidence["IsLogging"] is False

    good_res = make_resource("CloudTrail", "aws_cloudtrail_trail", configuration={
        "Name": "trail-1", "Status": {"IsLogging": True}
    })
    assert rule.evaluate(good_res).matched is False


def test_ct_002_log_validation_disabled():
    rule = CT002CloudTrailLoggingDisabledRule()
    assert rule.rule_id == "CT-002"

    bad_res = make_resource("CloudTrail", "aws_cloudtrail_trail", configuration={
        "Name": "trail-1", "LogFileValidationEnabled": False
    })
    res = rule.evaluate(bad_res)
    assert res.matched is True
    assert res.evidence["LogFileValidationEnabled"] is False

    good_res = make_resource("CloudTrail", "aws_cloudtrail_trail", configuration={
        "Name": "trail-1", "LogFileValidationEnabled": True
    })
    assert rule.evaluate(good_res).matched is False


def test_ct_003_multi_region_issue():
    rule = CT003CloudTrailMultiRegionIssueRule()
    assert rule.rule_id == "CT-003"

    bad_res = make_resource("CloudTrail", "aws_cloudtrail_trail", configuration={
        "Name": "trail-1", "IsMultiRegionTrail": False
    })
    res = rule.evaluate(bad_res)
    assert res.matched is True
    assert res.evidence["IsMultiRegionTrail"] is False

    good_res = make_resource("CloudTrail", "aws_cloudtrail_trail", configuration={
        "Name": "trail-1", "IsMultiRegionTrail": True
    })
    assert rule.evaluate(good_res).matched is False


# ==============================================================================
# RDS RULES (RDS-001 through RDS-003)
# ==============================================================================

def test_rds_001_public_accessibility():
    rule = RDS001PublicAccessibilityRule()
    assert rule.rule_id == "RDS-001"
    assert rule.severity == "CRITICAL"

    bad_res = make_resource("RDS", "aws_rds_instance", configuration={
        "DBInstanceIdentifier": "db-1", "PubliclyAccessible": True, "Engine": "postgres"
    })
    res = rule.evaluate(bad_res)
    assert res.matched is True
    assert res.evidence["PubliclyAccessible"] is True

    good_res = make_resource("RDS", "aws_rds_instance", configuration={
        "DBInstanceIdentifier": "db-1", "PubliclyAccessible": False, "Engine": "postgres"
    })
    assert rule.evaluate(good_res).matched is False


def test_rds_002_storage_encryption_disabled():
    rule = RDS002StorageEncryptionDisabledRule()
    assert rule.rule_id == "RDS-002"
    assert rule.severity == "HIGH"

    bad_res = make_resource("RDS", "aws_rds_instance", configuration={
        "DBInstanceIdentifier": "db-1", "StorageEncrypted": False, "Engine": "mysql"
    })
    res = rule.evaluate(bad_res)
    assert res.matched is True
    assert res.evidence["StorageEncrypted"] is False

    good_res = make_resource("RDS", "aws_rds_instance", configuration={
        "DBInstanceIdentifier": "db-1", "StorageEncrypted": True, "Engine": "mysql"
    })
    assert rule.evaluate(good_res).matched is False


def test_rds_003_weak_network_exposure():
    rule = RDS003WeakNetworkExposureRule()
    assert rule.rule_id == "RDS-003"

    bad_res = make_resource("RDS", "aws_rds_instance", configuration={
        "DBInstanceIdentifier": "db-1", "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-open-database"}]
    })
    res = rule.evaluate(bad_res)
    assert res.matched is True

    good_res = make_resource("RDS", "aws_rds_instance", configuration={
        "DBInstanceIdentifier": "db-1", "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-internal-only"}]
    })
    assert rule.evaluate(good_res).matched is False


# ==============================================================================
# REGISTRY TEST
# ==============================================================================

def test_registry_contains_all_26_rules():
    """Verify registry loads exactly 26 rules, with unique rule_ids across all 6 services."""
    rules = default_registry.get_all_rules()
    assert len(rules) == 26

    rule_ids = [r.rule_id for r in rules]
    assert len(set(rule_ids)) == 26  # Uniqueness

    # Verify per-service breakdown
    s3_rules = default_registry.get_rules_for_service("S3")
    assert len(s3_rules) == 5

    iam_rules = default_registry.get_rules_for_service("IAM")
    assert len(iam_rules) == 5

    ec2_rules = default_registry.get_rules_for_service("EC2")
    assert len(ec2_rules) == 5

    vpc_rules = default_registry.get_rules_for_service("VPC")
    assert len(vpc_rules) == 5

    ct_rules = default_registry.get_rules_for_service("CloudTrail")
    assert len(ct_rules) == 3

    rds_rules = default_registry.get_rules_for_service("RDS")
    assert len(rds_rules) == 3
