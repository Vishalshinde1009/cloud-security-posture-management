from typing import Dict, Any, List
from app.scanner.providers.base import CloudProvider, DiscoveredResource


class MockProvider(CloudProvider):
    """
    Deterministic Mock Cloud Provider emitting realistic AWS configuration metadata
    for safe offline testing, continuous integration, and demo evaluation.
    """

    MOCK_ACCOUNT_ID = "mock-account-001"
    MOCK_ACCOUNT_NAME = "Demo AWS Environment"
    MOCK_DEFAULT_REGION = "ap-south-1"

    def __init__(self, account_id: str = None, default_region: str = None):
        self.account_id = account_id or self.MOCK_ACCOUNT_ID
        self.default_region = default_region or self.MOCK_DEFAULT_REGION

    def get_provider_name(self) -> str:
        return "MOCK"

    def get_account_info(self) -> Dict[str, Any]:
        return {
            "account_id": self.account_id,
            "account_name": self.MOCK_ACCOUNT_NAME,
            "default_region": self.default_region,
            "provider": "MOCK",
            "credential_mode": "NONE",
        }

    def discover_resources(self) -> List[DiscoveredResource]:
        """Returns a deterministic catalog of realistic cloud resources across 6 AWS services."""
        resources: List[DiscoveredResource] = []

        # ----------------------------------------------------------------------
        # 1. AWS S3 Storage Buckets
        # ----------------------------------------------------------------------
        resources.append(
            DiscoveredResource(
                provider="MOCK",
                account_id=self.MOCK_ACCOUNT_ID,
                service="S3",
                resource_type="aws_s3_bucket",
                resource_id="secure-production-bucket",
                resource_name="secure-production-bucket",
                region=self.MOCK_DEFAULT_REGION,
                tags={"Environment": "Production", "DataClassification": "Confidential", "Owner": "SecOps"},
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
                    "Versioning": {"Status": "Enabled"},
                    "Logging": {"TargetBucket": "audit-logs-archive", "TargetPrefix": "s3-access/"},
                    "Policy": {
                        "Version": "2012-10-17",
                        "Statement": [{"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]
                    }
                },
                security_status="SECURE",
            )
        )

        resources.append(
            DiscoveredResource(
                provider="MOCK",
                account_id=self.MOCK_ACCOUNT_ID,
                service="S3",
                resource_type="aws_s3_bucket",
                resource_id="public-test-bucket",
                resource_name="public-test-bucket",
                region=self.MOCK_DEFAULT_REGION,
                tags={"Environment": "Testing", "Owner": "DevTeam"},
                configuration={
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": False,
                        "IgnorePublicAcls": False,
                        "BlockPublicPolicy": False,
                        "RestrictPublicBuckets": False,
                    },
                    "ServerSideEncryptionConfiguration": None,
                    "Versioning": {"Status": "Suspended"},
                    "Logging": None,
                    "Policy": {
                        "Version": "2012-10-17",
                        "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::public-test-bucket/*"}]
                    }
                },
                security_status="AT_RISK",
            )
        )

        resources.append(
            DiscoveredResource(
                provider="MOCK",
                account_id=self.MOCK_ACCOUNT_ID,
                service="S3",
                resource_type="aws_s3_bucket",
                resource_id="unencrypted-storage-bucket",
                resource_name="unencrypted-storage-bucket",
                region=self.MOCK_DEFAULT_REGION,
                tags={"Environment": "Staging"},
                configuration={
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": True,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": True,
                    },
                    "ServerSideEncryptionConfiguration": None,
                    "Versioning": {"Status": "Enabled"},
                    "Logging": None,
                    "Policy": None
                },
                security_status="AT_RISK",
            )
        )

        # ----------------------------------------------------------------------
        # 2. AWS IAM Identity & Access Management
        # ----------------------------------------------------------------------
        resources.append(
            DiscoveredResource(
                provider="MOCK",
                account_id=self.MOCK_ACCOUNT_ID,
                service="IAM",
                resource_type="aws_iam_user",
                resource_id="admin-user",
                resource_name="admin-user",
                region="global",
                tags={"Department": "SecurityOps"},
                configuration={
                    "UserName": "admin-user",
                    "UserId": "AIDAJEXAMPLEADMIN",
                    "Arn": "arn:aws:iam::mock-account-001:user/admin-user",
                    "CreateDate": "2026-01-15T10:00:00Z",
                    "PasswordLastUsed": "2026-09-05T08:30:00Z",
                    "MFADevices": [{"SerialNumber": "arn:aws:iam::mock-account-001:mfa/admin-user-token"}],
                    "AccessKeys": [{"AccessKeyId": "AKIAEXAMPLEKEY1", "Status": "Active", "AgeDays": 25}],
                    "AttachedPolicies": [{"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}],
                },
                security_status="SECURE",
            )
        )

        resources.append(
            DiscoveredResource(
                provider="MOCK",
                account_id=self.MOCK_ACCOUNT_ID,
                service="IAM",
                resource_type="aws_iam_user",
                resource_id="analyst-user",
                resource_name="analyst-user",
                region="global",
                tags={"Department": "SecurityOps"},
                configuration={
                    "UserName": "analyst-user",
                    "UserId": "AIDAJEXAMPLEANALYST",
                    "Arn": "arn:aws:iam::mock-account-001:user/analyst-user",
                    "CreateDate": "2026-02-10T12:00:00Z",
                    "PasswordLastUsed": "2026-09-06T09:15:00Z",
                    "MFADevices": [{"SerialNumber": "arn:aws:iam::mock-account-001:mfa/analyst-user-token"}],
                    "AccessKeys": [{"AccessKeyId": "AKIAEXAMPLEKEY2", "Status": "Active", "AgeDays": 45}],
                    "AttachedPolicies": [{"PolicyName": "SecurityAudit", "PolicyArn": "arn:aws:iam::aws:policy/SecurityAudit"}],
                },
                security_status="SECURE",
            )
        )

        resources.append(
            DiscoveredResource(
                provider="MOCK",
                account_id=self.MOCK_ACCOUNT_ID,
                service="IAM",
                resource_type="aws_iam_user",
                resource_id="user-without-mfa",
                resource_name="user-without-mfa",
                region="global",
                tags={"Department": "Engineering"},
                configuration={
                    "UserName": "user-without-mfa",
                    "UserId": "AIDAJEXAMPLENOMFA",
                    "Arn": "arn:aws:iam::mock-account-001:user/user-without-mfa",
                    "CreateDate": "2025-06-01T09:00:00Z",
                    "PasswordLastUsed": "2026-09-01T14:20:00Z",
                    "MFADevices": [],  # Vulnerability: No MFA
                    "AccessKeys": [{"AccessKeyId": "AKIAEXAMPLENOMFA", "Status": "Active", "AgeDays": 210}],  # Vulnerability: Old key > 90 days
                    "AttachedPolicies": [{"PolicyName": "PowerUserAccess", "PolicyArn": "arn:aws:iam::aws:policy/PowerUserAccess"}],
                },
                security_status="AT_RISK",
            )
        )

        resources.append(
            DiscoveredResource(
                provider="MOCK",
                account_id=self.MOCK_ACCOUNT_ID,
                service="IAM",
                resource_type="aws_iam_root",
                resource_id="root-account-config",
                resource_name="Root Account Security Posture",
                region="global",
                tags={},
                configuration={
                    "AccountMFAEnabled": False,  # Vulnerability: Root account MFA missing
                    "RootAccessKeysPresent": True,  # Vulnerability: Active root access keys
                },
                security_status="AT_RISK",
            )
        )

        # ----------------------------------------------------------------------
        # 3. AWS EC2 Compute Instances
        # ----------------------------------------------------------------------
        resources.append(
            DiscoveredResource(
                provider="MOCK",
                account_id=self.MOCK_ACCOUNT_ID,
                service="EC2",
                resource_type="aws_ec2_instance",
                resource_id="i-0123456789abcdef0",
                resource_name="web-server",
                region=self.MOCK_DEFAULT_REGION,
                tags={"Name": "web-server", "Tier": "Frontend", "Environment": "Production"},
                configuration={
                    "InstanceId": "i-0123456789abcdef0",
                    "InstanceType": "t3.medium",
                    "State": {"Name": "running"},
                    "PublicIpAddress": "203.0.113.10",
                    "PrivateIpAddress": "10.0.1.15",
                    "SubnetId": "subnet-01234567",
                    "VpcId": "vpc-01234567",
                    "SecurityGroups": [{"GroupId": "sg-0123456789abcdef0", "GroupName": "web-sg"}],
                    "BlockDeviceMappings": [{
                        "DeviceName": "/dev/xvda",
                        "Ebs": {"VolumeId": "vol-01234567", "Encrypted": True, "DeleteOnTermination": True}
                    }],
                    "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"}  # IMDSv2 enforced
                },
                security_status="SECURE",
            )
        )

        resources.append(
            DiscoveredResource(
                provider="MOCK",
                account_id=self.MOCK_ACCOUNT_ID,
                service="EC2",
                resource_type="aws_ec2_instance",
                resource_id="i-0abcdef1234567890",
                resource_name="internal-server",
                region=self.MOCK_DEFAULT_REGION,
                tags={"Name": "internal-server", "Tier": "Backend", "Environment": "Production"},
                configuration={
                    "InstanceId": "i-0abcdef1234567890",
                    "InstanceType": "m5.large",
                    "State": {"Name": "running"},
                    "PublicIpAddress": None,  # Private instance
                    "PrivateIpAddress": "10.0.2.20",
                    "SubnetId": "subnet-0abcdef1",
                    "VpcId": "vpc-01234567",
                    "SecurityGroups": [{"GroupId": "sg-internal001", "GroupName": "internal-sg"}],
                    "BlockDeviceMappings": [{
                        "DeviceName": "/dev/xvda",
                        "Ebs": {"VolumeId": "vol-0abcdef1", "Encrypted": True, "DeleteOnTermination": True}
                    }],
                    "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"}
                },
                security_status="SECURE",
            )
        )

        resources.append(
            DiscoveredResource(
                provider="MOCK",
                account_id=self.MOCK_ACCOUNT_ID,
                service="EC2",
                resource_type="aws_ec2_instance",
                resource_id="i-0987654321fedcba0",
                resource_name="test-server",
                region=self.MOCK_DEFAULT_REGION,
                tags={"Name": "test-server", "Environment": "Sandbox"},
                configuration={
                    "InstanceId": "i-0987654321fedcba0",
                    "InstanceType": "t2.micro",
                    "State": {"Name": "running"},
                    "PublicIpAddress": "203.0.113.55",
                    "PrivateIpAddress": "10.0.3.40",
                    "SubnetId": "subnet-09876543",
                    "VpcId": "vpc-01234567",
                    "SecurityGroups": [{"GroupId": "sg-0unrestrictedssh", "GroupName": "unrestricted-ssh-sg"}],
                    "BlockDeviceMappings": [{
                        "DeviceName": "/dev/xvda",
                        "Ebs": {"VolumeId": "vol-0unencrypted", "Encrypted": False, "DeleteOnTermination": True}  # Vulnerability: unencrypted EBS
                    }],
                    "MetadataOptions": {"HttpTokens": "optional", "HttpEndpoint": "enabled"}  # Vulnerability: IMDSv1 allowed
                },
                security_status="AT_RISK",
            )
        )

        # ----------------------------------------------------------------------
        # 4. AWS VPC & Security Groups
        # ----------------------------------------------------------------------
        resources.append(
            DiscoveredResource(
                provider="MOCK",
                account_id=self.MOCK_ACCOUNT_ID,
                service="VPC",
                resource_type="aws_security_group",
                resource_id="sg-0123456789abcdef0",
                resource_name="web-sg",
                region=self.MOCK_DEFAULT_REGION,
                tags={"Name": "web-sg"},
                configuration={
                    "GroupId": "sg-0123456789abcdef0",
                    "GroupName": "web-sg",
                    "Description": "Security group for public HTTPS web application",
                    "VpcId": "vpc-01234567",
                    "IpPermissions": [
                        {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                    ],
                    "IpPermissionsEgress": [
                        {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
                    ]
                },
                security_status="SECURE",
            )
        )

        resources.append(
            DiscoveredResource(
                provider="MOCK",
                account_id=self.MOCK_ACCOUNT_ID,
                service="VPC",
                resource_type="aws_security_group",
                resource_id="sg-0unrestrictedssh",
                resource_name="unrestricted-ssh-sg",
                region=self.MOCK_DEFAULT_REGION,
                tags={"Name": "unrestricted-ssh-sg"},
                configuration={
                    "GroupId": "sg-0unrestrictedssh",
                    "GroupName": "unrestricted-ssh-sg",
                    "Description": "Insecure SG allowing open SSH from anywhere",
                    "VpcId": "vpc-01234567",
                    "IpPermissions": [
                        # Vulnerability: SSH open to the whole world
                        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                    ],
                    "IpPermissionsEgress": [
                        {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
                    ]
                },
                security_status="AT_RISK",
            )
        )

        resources.append(
            DiscoveredResource(
                provider="MOCK",
                account_id=self.MOCK_ACCOUNT_ID,
                service="VPC",
                resource_type="aws_security_group",
                resource_id="sg-0databaseopen",
                resource_name="database-sg",
                region=self.MOCK_DEFAULT_REGION,
                tags={"Name": "database-sg"},
                configuration={
                    "GroupId": "sg-0databaseopen",
                    "GroupName": "database-sg",
                    "Description": "Insecure SG exposing database port publicly",
                    "VpcId": "vpc-01234567",
                    "IpPermissions": [
                        # Vulnerability: Sensitive database port 3306 open to 0.0.0.0/0
                        {"IpProtocol": "tcp", "FromPort": 3306, "ToPort": 3306, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                    ],
                    "IpPermissionsEgress": [
                        {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
                    ]
                },
                security_status="AT_RISK",
            )
        )

        # ----------------------------------------------------------------------
        # 5. AWS CloudTrail Audit Trails
        # ----------------------------------------------------------------------
        resources.append(
            DiscoveredResource(
                provider="MOCK",
                account_id=self.MOCK_ACCOUNT_ID,
                service="CloudTrail",
                resource_type="aws_cloudtrail_trail",
                resource_id="organization-trail",
                resource_name="organization-trail",
                region=self.MOCK_DEFAULT_REGION,
                tags={"SecurityClassification": "AuditBaseline"},
                configuration={
                    "Name": "organization-trail",
                    "S3BucketName": "audit-logs-archive",
                    "IsMultiRegionTrail": True,
                    "LogFileValidationEnabled": True,
                    "KmsKeyId": "arn:aws:kms:ap-south-1:mock-account-001:key/audit-key",
                    "Status": {"IsLogging": True, "LatestDeliveryTime": "2026-09-06T14:00:00Z"},
                },
                security_status="SECURE",
            )
        )

        resources.append(
            DiscoveredResource(
                provider="MOCK",
                account_id=self.MOCK_ACCOUNT_ID,
                service="CloudTrail",
                resource_type="aws_cloudtrail_trail",
                resource_id="disabled-trail",
                resource_name="disabled-trail",
                region=self.MOCK_DEFAULT_REGION,
                tags={"Environment": "Development"},
                configuration={
                    "Name": "disabled-trail",
                    "S3BucketName": "temp-dev-logs",
                    "IsMultiRegionTrail": False,  # Vulnerability: Single-region
                    "LogFileValidationEnabled": False,  # Vulnerability: Validation disabled
                    "KmsKeyId": None,
                    "Status": {"IsLogging": False},  # Vulnerability: Trail logging is stopped!
                },
                security_status="AT_RISK",
            )
        )

        # ----------------------------------------------------------------------
        # 6. AWS RDS Relational Database Service
        # ----------------------------------------------------------------------
        resources.append(
            DiscoveredResource(
                provider="MOCK",
                account_id=self.MOCK_ACCOUNT_ID,
                service="RDS",
                resource_type="aws_rds_instance",
                resource_id="production-db",
                resource_name="production-db",
                region=self.MOCK_DEFAULT_REGION,
                tags={"Environment": "Production", "App": "CoreBanking"},
                configuration={
                    "DBInstanceIdentifier": "production-db",
                    "DBInstanceClass": "db.m5.large",
                    "Engine": "postgres",
                    "PubliclyAccessible": False,
                    "StorageEncrypted": True,
                    "KmsKeyId": "arn:aws:kms:ap-south-1:mock-account-001:key/rds-key",
                    "AutoMinorVersionUpgrade": True,
                    "MultiAZ": True,
                    "BackupRetentionPeriod": 30,
                    "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-internal001", "Status": "active"}],
                },
                security_status="SECURE",
            )
        )

        resources.append(
            DiscoveredResource(
                provider="MOCK",
                account_id=self.MOCK_ACCOUNT_ID,
                service="RDS",
                resource_type="aws_rds_instance",
                resource_id="public-test-db",
                resource_name="public-test-db",
                region=self.MOCK_DEFAULT_REGION,
                tags={"Environment": "Testing"},
                configuration={
                    "DBInstanceIdentifier": "public-test-db",
                    "DBInstanceClass": "db.t3.small",
                    "Engine": "mysql",
                    "PubliclyAccessible": True,  # Vulnerability: Publicly accessible database!
                    "StorageEncrypted": False,  # Vulnerability: Storage encryption disabled
                    "KmsKeyId": None,
                    "AutoMinorVersionUpgrade": False,
                    "MultiAZ": False,
                    "BackupRetentionPeriod": 1,
                    "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-0databaseopen", "Status": "active"}],
                },
                security_status="AT_RISK",
            )
        )

        return resources

    def collect_configuration(self, service: str, resource_type: str, resource_id: str) -> Dict[str, Any]:
        """Returns the configuration payload for a discovered resource ID."""
        for r in self.discover_resources():
            if r.resource_id == resource_id:
                return r.configuration
        return {}
