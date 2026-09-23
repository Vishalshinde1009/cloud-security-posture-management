"""
Production-grade Real AWS Read-Only Cloud Provider.
Discovers resources across S3, IAM, EC2, VPC, CloudTrail, and RDS using boto3.
Operates with 100% read-only guarantees and zero credential logging or persistence.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from botocore.exceptions import ClientError, BotoCoreError, NoCredentialsError

from app.scanner.providers.base import CloudProvider, DiscoveredResource
from app.scanner.providers.aws.client_factory import AWSClientFactory
from app.scanner.providers.aws.read_only_guard import (
    AWS_READ_ONLY,
    assert_read_only_operation,
    AWSReadOnlyViolationError,
)

logger = logging.getLogger("cspm.aws.provider")


class AWSProvider(CloudProvider):
    """
    Production-grade AWS Cloud Provider executing read-only discovery scans
    via boto3 across target AWS accounts.
    """

    READ_ONLY: bool = AWS_READ_ONLY

    def __init__(
        self,
        account_id: Optional[str] = None,
        default_region: Optional[str] = "us-east-1",
        client_factory: Optional[AWSClientFactory] = None,
        profile_name: Optional[str] = None,
        role_arn: Optional[str] = None,
        external_id: Optional[str] = None,
    ):
        self.account_id = account_id
        self.default_region = default_region or "us-east-1"
        self.role_arn = role_arn
        self.external_id = external_id
        self.factory = client_factory or AWSClientFactory(
            region_name=self.default_region,
            profile_name=profile_name,
            role_arn=role_arn,
            external_id=external_id,
            target_account_id=account_id,
        )
        self.discovery_warnings: List[str] = []
        self._cached_resources: List[DiscoveredResource] = []

    def get_provider_name(self) -> str:
        return "AWS"

    def get_account_info(self) -> Dict[str, Any]:
        """
        Validates connection and resolves account metadata via sts:GetCallerIdentity.
        Raises an exception if credentials cannot be resolved or authenticated.
        """
        assert_read_only_operation("get_caller_identity")
        try:
            info = self.factory.test_sts_connection()
            if not self.account_id:
                self.account_id = info["account_id"]
            return {
                "account_id": info["account_id"],
                "arn": info["arn"],
                "user_id": info["user_id"],
                "default_region": self.default_region,
                "provider": "AWS",
                "credential_mode": "RESOLVED_CHAIN",
            }
        except (ClientError, BotoCoreError, NoCredentialsError) as e:
            logger.error(f"Failed to authenticate AWS credentials via STS: {e}")
            raise

    def discover_resources(self) -> List[DiscoveredResource]:
        """
        Discovers and normalizes resources across 6 AWS services:
        S3, IAM, EC2, VPC/Security Groups, CloudTrail, and RDS.
        """
        resources: List[DiscoveredResource] = []
        self.discovery_warnings.clear()

        # Resolve real account ID via STS if not known or placeholder
        if not self.account_id or not self.account_id.isdigit():
            try:
                info = self.factory.test_sts_connection()
                if info and info.get("account_id"):
                    self.account_id = info["account_id"]
            except Exception as e:
                logger.debug(f"Could not resolve account_id via STS: {e}")

        # 1. AWS S3 Buckets
        try:
            s3_res = self._discover_s3_buckets()
            resources.extend(s3_res)
            logger.info(f"Discovered {len(s3_res)} S3 bucket(s).")
        except Exception as e:
            msg = f"S3 discovery failed: {e}"
            logger.warning(msg)
            self.discovery_warnings.append(msg)

        # 2. AWS IAM Users & Root Security Posture
        try:
            iam_res = self._discover_iam_resources()
            resources.extend(iam_res)
            logger.info(f"Discovered {len(iam_res)} IAM resource(s).")
        except Exception as e:
            msg = f"IAM discovery failed: {e}"
            logger.warning(msg)
            self.discovery_warnings.append(msg)

        # 3. AWS EC2 Compute Instances
        try:
            ec2_res = self._discover_ec2_instances()
            resources.extend(ec2_res)
            logger.info(f"Discovered {len(ec2_res)} EC2 instance(s).")
        except Exception as e:
            msg = f"EC2 discovery failed: {e}"
            logger.warning(msg)
            self.discovery_warnings.append(msg)

        # 4. AWS VPC Security Groups
        try:
            sg_res = self._discover_security_groups()
            resources.extend(sg_res)
            logger.info(f"Discovered {len(sg_res)} Security Group(s).")
        except Exception as e:
            msg = f"Security Group discovery failed: {e}"
            logger.warning(msg)
            self.discovery_warnings.append(msg)

        # 5. AWS CloudTrail Multi-Region Trails
        try:
            ct_res = self._discover_cloudtrail()
            resources.extend(ct_res)
            logger.info(f"Discovered {len(ct_res)} CloudTrail resource(s).")
        except Exception as e:
            msg = f"CloudTrail discovery failed: {e}"
            logger.warning(msg)
            self.discovery_warnings.append(msg)

        # 6. AWS RDS Database Instances
        try:
            rds_res = self._discover_rds_instances()
            resources.extend(rds_res)
            logger.info(f"Discovered {len(rds_res)} RDS instance(s).")
        except Exception as e:
            msg = f"RDS discovery failed: {e}"
            logger.warning(msg)
            self.discovery_warnings.append(msg)

        # Fail explicitly if all services failed and credentials could not be located
        if len(resources) == 0 and len(self.discovery_warnings) >= 5:
            if any("NoCredentialsError" in w or "Unable to locate credentials" in w for w in self.discovery_warnings):
                raise NoCredentialsError()

        self._cached_resources = resources
        return resources

    def collect_configuration(self, service: str, resource_type: str, resource_id: str) -> Dict[str, Any]:
        """Returns granular configuration payload for a specific discovered asset."""
        for r in self._cached_resources:
            if r.resource_id == resource_id:
                return r.configuration
        return {}

    # =========================================================================
    # Internal Service Discovery Implementations (Strict Read-Only)
    # =========================================================================

    def _discover_s3_buckets(self) -> List[DiscoveredResource]:
        """Discovers S3 buckets and extracts configuration evidence."""
        assert_read_only_operation("list_buckets")
        s3 = self.factory.get_client("s3")
        buckets_res = s3.list_buckets()
        buckets = buckets_res.get("Buckets", [])
        results: List[DiscoveredResource] = []

        for b in buckets:
            b_name = b["Name"]
            b_region = self.default_region

            # Bucket Location
            try:
                assert_read_only_operation("get_bucket_location")
                loc_res = s3.get_bucket_location(Bucket=b_name)
                loc = loc_res.get("LocationConstraint")
                if loc:
                    b_region = loc
            except ClientError as e:
                logger.debug(f"Could not get location for S3 bucket {b_name}: {e}")

            # Public Access Block
            pab_config = None
            try:
                assert_read_only_operation("get_public_access_block")
                pab_res = s3.get_public_access_block(Bucket=b_name)
                pab_config = pab_res.get("PublicAccessBlockConfiguration")
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code")
                if code not in ("NoSuchPublicAccessBlockConfiguration", "AccessDenied"):
                    logger.debug(f"Error reading public access block for {b_name}: {e}")

            # Encryption
            sse_config = None
            try:
                assert_read_only_operation("get_bucket_encryption")
                sse_res = s3.get_bucket_encryption(Bucket=b_name)
                sse_config = sse_res.get("ServerSideEncryptionConfiguration")
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code")
                if code not in ("ServerSideEncryptionConfigurationNotFoundError", "AccessDenied"):
                    logger.debug(f"Error reading encryption for {b_name}: {e}")

            # Versioning
            versioning_config = {"Status": "Suspended"}
            try:
                assert_read_only_operation("get_bucket_versioning")
                v_res = s3.get_bucket_versioning(Bucket=b_name)
                if "Status" in v_res:
                    versioning_config = {"Status": v_res["Status"]}
            except ClientError as e:
                logger.debug(f"Error reading versioning for {b_name}: {e}")

            # Logging
            logging_config = None
            try:
                assert_read_only_operation("get_bucket_logging")
                log_res = s3.get_bucket_logging(Bucket=b_name)
                if "LoggingEnabled" in log_res:
                    logging_config = log_res["LoggingEnabled"]
            except ClientError as e:
                logger.debug(f"Error reading logging for {b_name}: {e}")

            # Bucket Policy
            policy_config = None
            try:
                assert_read_only_operation("get_bucket_policy")
                pol_res = s3.get_bucket_policy(Bucket=b_name)
                policy_raw = pol_res.get("Policy")
                if policy_raw:
                    policy_config = json.loads(policy_raw) if isinstance(policy_raw, str) else policy_raw
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code")
                if code not in ("NoSuchBucketPolicy", "AccessDenied"):
                    logger.debug(f"Error reading bucket policy for {b_name}: {e}")

            # Tags
            tags_dict = {}
            try:
                assert_read_only_operation("get_bucket_tagging")
                t_res = s3.get_bucket_tagging(Bucket=b_name)
                tags_dict = {t["Key"]: t["Value"] for t in t_res.get("TagSet", [])}
            except ClientError:
                pass

            results.append(
                DiscoveredResource(
                    provider="AWS",
                    account_id=self.account_id or "unknown",
                    service="S3",
                    resource_type="aws_s3_bucket",
                    resource_id=b_name,
                    resource_name=b_name,
                    region=b_region,
                    tags=tags_dict,
                    configuration={
                        "PublicAccessBlockConfiguration": pab_config,
                        "ServerSideEncryptionConfiguration": sse_config,
                        "Versioning": versioning_config,
                        "Logging": logging_config,
                        "Policy": policy_config,
                    },
                    security_status="PENDING_ANALYSIS",
                )
            )

        return results

    def _discover_iam_resources(self) -> List[DiscoveredResource]:
        """Discovers IAM users and account root security configuration."""
        assert_read_only_operation("list_users")
        iam = self.factory.get_client("iam", region_name="us-east-1")
        results: List[DiscoveredResource] = []
        now_utc = datetime.now(timezone.utc)

        # 1. IAM Users
        try:
            users_res = iam.list_users()
            for u in users_res.get("Users", []):
                u_name = u["UserName"]

                # MFA Devices
                mfa_devices = []
                try:
                    assert_read_only_operation("list_mfa_devices")
                    mfa_res = iam.list_mfa_devices(UserName=u_name)
                    mfa_devices = mfa_res.get("MFADevices", [])
                except ClientError as e:
                    logger.debug(f"Could not list MFA for {u_name}: {e}")

                # Access Keys
                access_keys = []
                try:
                    assert_read_only_operation("list_access_keys")
                    ak_res = iam.list_access_keys(UserName=u_name)
                    for k in ak_res.get("AccessKeyMetadata", []):
                        create_dt = k.get("CreateDate")
                        age_days = (now_utc - create_dt).days if create_dt else 0
                        access_keys.append({
                            "AccessKeyId": k.get("AccessKeyId"),
                            "Status": k.get("Status"),
                            "AgeDays": age_days,
                        })
                except ClientError as e:
                    logger.debug(f"Could not list access keys for {u_name}: {e}")

                # Attached Policies
                attached_policies = []
                try:
                    assert_read_only_operation("list_attached_user_policies")
                    pol_res = iam.list_attached_user_policies(UserName=u_name)
                    attached_policies = pol_res.get("AttachedPolicies", [])
                except ClientError as e:
                    logger.debug(f"Could not list attached policies for {u_name}: {e}")

                create_date_str = str(u.get("CreateDate")) if u.get("CreateDate") else None
                pwd_last_used_str = str(u.get("PasswordLastUsed")) if u.get("PasswordLastUsed") else None

                results.append(
                    DiscoveredResource(
                        provider="AWS",
                        account_id=self.account_id or "unknown",
                        service="IAM",
                        resource_type="aws_iam_user",
                        resource_id=u_name,
                        resource_name=u_name,
                        region="global",
                        tags={},
                        configuration={
                            "UserName": u_name,
                            "UserId": u.get("UserId"),
                            "Arn": u.get("Arn"),
                            "CreateDate": create_date_str,
                            "PasswordLastUsed": pwd_last_used_str,
                            "MFADevices": mfa_devices,
                            "AccessKeys": access_keys,
                            "AttachedPolicies": attached_policies,
                        },
                        security_status="PENDING_ANALYSIS",
                    )
                )
        except ClientError as e:
            logger.warning(f"IAM list_users failed: {e}")
            self.discovery_warnings.append(f"IAM list_users: {e}")

        # 2. IAM Root Account Security Posture via Account Summary
        try:
            assert_read_only_operation("get_account_summary")
            summary_res = iam.get_account_summary()
            summary = summary_res.get("SummaryMap", {})
            mfa_enabled = bool(summary.get("AccountMFAEnabled", 0) > 0)
            root_keys_present = bool(summary.get("AccountAccessKeysPresent", 0) > 0)

            results.append(
                DiscoveredResource(
                    provider="AWS",
                    account_id=self.account_id or "unknown",
                    service="IAM",
                    resource_type="aws_iam_root",
                    resource_id="root-account-config",
                    resource_name="Root Account Security Posture",
                    region="global",
                    tags={},
                    configuration={
                        "AccountMFAEnabled": mfa_enabled,
                        "RootAccessKeysPresent": root_keys_present,
                    },
                    security_status="PENDING_ANALYSIS",
                )
            )
        except ClientError as e:
            logger.warning(f"IAM get_account_summary failed: {e}")
            self.discovery_warnings.append(f"IAM get_account_summary: {e}")

        return results

    def _discover_ec2_instances(self) -> List[DiscoveredResource]:
        """Discovers EC2 compute instances and verifies EBS encryption."""
        assert_read_only_operation("describe_instances")
        ec2 = self.factory.get_client("ec2")
        results: List[DiscoveredResource] = []

        try:
            resp = ec2.describe_instances()
            for res in resp.get("Reservations", []):
                for inst in res.get("Instances", []):
                    inst_id = inst.get("InstanceId")
                    inst_name = inst_id
                    tags_dict = {}
                    for t in inst.get("Tags", []):
                        tags_dict[t.get("Key")] = t.get("Value")
                        if t.get("Key") == "Name":
                            inst_name = t.get("Value")

                    # Extract security groups
                    sgs = [
                        {"GroupId": sg.get("GroupId"), "GroupName": sg.get("GroupName")}
                        for sg in inst.get("SecurityGroups", [])
                    ]

                    # Normalize Block Device Mappings and enrich EBS volume encryption
                    block_mappings = []
                    vol_ids = []
                    for bdm in inst.get("BlockDeviceMappings", []):
                        ebs_info = bdm.get("Ebs", {})
                        vol_id = ebs_info.get("VolumeId")
                        if vol_id:
                            vol_ids.append(vol_id)
                        block_mappings.append({
                            "DeviceName": bdm.get("DeviceName"),
                            "Ebs": {
                                "VolumeId": vol_id,
                                "DeleteOnTermination": ebs_info.get("DeleteOnTermination", True),
                                "Encrypted": ebs_info.get("Encrypted", False),
                            }
                        })

                    # If encryption flag is not in instance payload, query describe_volumes
                    if vol_ids:
                        try:
                            assert_read_only_operation("describe_volumes")
                            vol_resp = ec2.describe_volumes(VolumeIds=vol_ids)
                            vol_enc_map = {
                                v["VolumeId"]: v.get("Encrypted", False)
                                for v in vol_resp.get("Volumes", [])
                            }
                            for bm in block_mappings:
                                vid = bm["Ebs"]["VolumeId"]
                                if vid in vol_enc_map:
                                    bm["Ebs"]["Encrypted"] = vol_enc_map[vid]
                        except ClientError as e:
                            logger.debug(f"Could not describe volumes for {inst_id}: {e}")

                    # Metadata options for IMDSv2
                    meta_opts = inst.get("MetadataOptions", {
                        "HttpTokens": "optional",
                        "HttpEndpoint": "enabled"
                    })

                    results.append(
                        DiscoveredResource(
                            provider="AWS",
                            account_id=self.account_id or "unknown",
                            service="EC2",
                            resource_type="aws_ec2_instance",
                            resource_id=inst_id,
                            resource_name=inst_name,
                            region=self.default_region,
                            tags=tags_dict,
                            configuration={
                                "InstanceId": inst_id,
                                "InstanceType": inst.get("InstanceType"),
                                "State": inst.get("State", {}),
                                "PublicIpAddress": inst.get("PublicIpAddress"),
                                "PrivateIpAddress": inst.get("PrivateIpAddress"),
                                "SubnetId": inst.get("SubnetId"),
                                "VpcId": inst.get("VpcId"),
                                "SecurityGroups": sgs,
                                "BlockDeviceMappings": block_mappings,
                                "MetadataOptions": {
                                    "HttpTokens": meta_opts.get("HttpTokens", "optional"),
                                    "HttpEndpoint": meta_opts.get("HttpEndpoint", "enabled"),
                                },
                            },
                            security_status="PENDING_ANALYSIS",
                        )
                    )
        except ClientError as e:
            logger.warning(f"EC2 describe_instances failed: {e}")
            self.discovery_warnings.append(f"EC2 describe_instances: {e}")

        return results

    def _discover_security_groups(self) -> List[DiscoveredResource]:
        """Discovers VPC security groups and ingress/egress firewall rules."""
        assert_read_only_operation("describe_security_groups")
        ec2 = self.factory.get_client("ec2")
        results: List[DiscoveredResource] = []

        try:
            resp = ec2.describe_security_groups()
            for sg in resp.get("SecurityGroups", []):
                sg_id = sg.get("GroupId")
                sg_name = sg.get("GroupName")
                tags_dict = {t.get("Key"): t.get("Value") for t in sg.get("Tags", [])}

                results.append(
                    DiscoveredResource(
                        provider="AWS",
                        account_id=self.account_id or "unknown",
                        service="VPC",
                        resource_type="aws_security_group",
                        resource_id=sg_id,
                        resource_name=sg_name,
                        region=self.default_region,
                        tags=tags_dict,
                        configuration={
                            "GroupId": sg_id,
                            "GroupName": sg_name,
                            "Description": sg.get("Description", ""),
                            "VpcId": sg.get("VpcId"),
                            "IpPermissions": sg.get("IpPermissions", []),
                            "IpPermissionsEgress": sg.get("IpPermissionsEgress", []),
                        },
                        security_status="PENDING_ANALYSIS",
                    )
                )
        except ClientError as e:
            logger.warning(f"EC2 describe_security_groups failed: {e}")
            self.discovery_warnings.append(f"EC2 describe_security_groups: {e}")

        return results

    def _discover_cloudtrail(self) -> List[DiscoveredResource]:
        """Discovers CloudTrail trails and logging status."""
        assert_read_only_operation("describe_trails")
        ct = self.factory.get_client("cloudtrail")
        results: List[DiscoveredResource] = []

        try:
            resp = ct.describe_trails()
            for t in resp.get("trailList", []):
                t_name = t.get("Name")

                # Get trail status
                status_dict = {"IsLogging": False}
                try:
                    assert_read_only_operation("get_trail_status")
                    st_resp = ct.get_trail_status(Name=t_name)
                    status_dict = {
                        "IsLogging": st_resp.get("IsLogging", False),
                        "LatestDeliveryTime": str(st_resp.get("LatestDeliveryTime", "")),
                    }
                except ClientError as e:
                    logger.debug(f"Could not get status for trail {t_name}: {e}")

                results.append(
                    DiscoveredResource(
                        provider="AWS",
                        account_id=self.account_id or "unknown",
                        service="CloudTrail",
                        resource_type="aws_cloudtrail_trail",
                        resource_id=t_name,
                        resource_name=t_name,
                        region=self.default_region,
                        tags={},
                        configuration={
                            "Name": t_name,
                            "S3BucketName": t.get("S3BucketName"),
                            "IsMultiRegionTrail": t.get("IsMultiRegionTrail", False),
                            "LogFileValidationEnabled": t.get("LogFileValidationEnabled", False),
                            "KmsKeyId": t.get("KmsKeyId"),
                            "Status": status_dict,
                        },
                        security_status="PENDING_ANALYSIS",
                    )
                )
        except ClientError as e:
            logger.warning(f"CloudTrail describe_trails failed: {e}")
            self.discovery_warnings.append(f"CloudTrail describe_trails: {e}")

        return results

    def _discover_rds_instances(self) -> List[DiscoveredResource]:
        """Discovers Amazon RDS database instances."""
        assert_read_only_operation("describe_db_instances")
        rds = self.factory.get_client("rds")
        results: List[DiscoveredResource] = []

        try:
            resp = rds.describe_db_instances()
            for db in resp.get("DBInstances", []):
                db_id = db.get("DBInstanceIdentifier")
                tags_dict = {t.get("Key"): t.get("Value") for t in db.get("TagList", [])}

                vpc_sgs = [
                    {"VpcSecurityGroupId": sg.get("VpcSecurityGroupId"), "Status": sg.get("Status")}
                    for sg in db.get("VpcSecurityGroups", [])
                ]

                results.append(
                    DiscoveredResource(
                        provider="AWS",
                        account_id=self.account_id or "unknown",
                        service="RDS",
                        resource_type="aws_rds_instance",
                        resource_id=db_id,
                        resource_name=db_id,
                        region=self.default_region,
                        tags=tags_dict,
                        configuration={
                            "DBInstanceIdentifier": db_id,
                            "DBInstanceClass": db.get("DBInstanceClass"),
                            "Engine": db.get("Engine"),
                            "PubliclyAccessible": db.get("PubliclyAccessible", False),
                            "StorageEncrypted": db.get("StorageEncrypted", False),
                            "KmsKeyId": db.get("KmsKeyId"),
                            "AutoMinorVersionUpgrade": db.get("AutoMinorVersionUpgrade", True),
                            "MultiAZ": db.get("MultiAZ", False),
                            "BackupRetentionPeriod": db.get("BackupRetentionPeriod", 1),
                            "VpcSecurityGroups": vpc_sgs,
                        },
                        security_status="PENDING_ANALYSIS",
                    )
                )
        except ClientError as e:
            logger.warning(f"RDS describe_db_instances failed: {e}")
            self.discovery_warnings.append(f"RDS describe_db_instances: {e}")

        return results
