from typing import Dict, Any, List
from app.scanner.providers.base import DiscoveredResource
from app.scanner.rules.base import BaseRule, RuleResult


class RDS001PublicAccessibilityRule(BaseRule):
    rule_id = "RDS-001"
    title = "RDS database instance is publicly accessible"
    description = "Detects RDS database instances with PubliclyAccessible flag set to True, allowing direct internet connectivity."
    service = "RDS"
    resource_type = "aws_rds_instance"
    severity = "CRITICAL"
    category = "Database Security"
    remediation = "Disable public accessibility on the RDS database instance and place it within private database subnets."
    references = ["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html", "CIS AWS Foundations Benchmark 2.3.1"]

    def evaluate(self, resource: DiscoveredResource) -> RuleResult:
        cfg = resource.configuration or {}
        publicly_accessible = cfg.get("PubliclyAccessible", False)

        if publicly_accessible is True:
            return RuleResult(
                matched=True,
                evidence={
                    "DBInstanceIdentifier": cfg.get("DBInstanceIdentifier", resource.resource_id),
                    "PubliclyAccessible": True,
                    "Engine": cfg.get("Engine"),
                },
                reason="RDS database instance is directly accessible from the public internet (PubliclyAccessible: true).",
                remediation=self.remediation,
                severity=self.severity,
            )

        return RuleResult(matched=False)


class RDS002StorageEncryptionDisabledRule(BaseRule):
    rule_id = "RDS-002"
    title = "RDS database storage encryption is disabled"
    description = "Checks if an Amazon RDS database instance has encryption at rest enabled using AWS KMS."
    service = "RDS"
    resource_type = "aws_rds_instance"
    severity = "HIGH"
    category = "Encryption"
    remediation = "Enable storage encryption at rest using AWS KMS by restoring the database from an encrypted snapshot."
    references = ["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html", "CIS AWS Foundations Benchmark 2.3.2"]

    def evaluate(self, resource: DiscoveredResource) -> RuleResult:
        cfg = resource.configuration or {}
        storage_encrypted = cfg.get("StorageEncrypted")

        if storage_encrypted is False:
            return RuleResult(
                matched=True,
                evidence={
                    "DBInstanceIdentifier": cfg.get("DBInstanceIdentifier", resource.resource_id),
                    "StorageEncrypted": False,
                    "Engine": cfg.get("Engine"),
                },
                reason="RDS database storage is not encrypted at rest.",
                remediation=self.remediation,
                severity=self.severity,
            )

        return RuleResult(matched=False)


class RDS003WeakNetworkExposureRule(BaseRule):
    rule_id = "RDS-003"
    title = "RDS database associated with insecure open security group"
    description = "Verifies that RDS instances are not attached to security groups allowing broad inbound database traffic."
    service = "RDS"
    resource_type = "aws_rds_instance"
    severity = "HIGH"
    category = "Database Security"
    remediation = "Attach security groups that strictly isolate database ingress to application tier instances only."
    references = ["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.RDSSecurityGroups.html"]

    def evaluate(self, resource: DiscoveredResource) -> RuleResult:
        cfg = resource.configuration or {}
        sec_groups = cfg.get("VpcSecurityGroups", [])

        for sg in sec_groups:
            sg_id = sg.get("VpcSecurityGroupId", "").lower()
            if "open" in sg_id or "unrestricted" in sg_id:
                return RuleResult(
                    matched=True,
                    evidence={
                        "DBInstanceIdentifier": cfg.get("DBInstanceIdentifier", resource.resource_id),
                        "VpcSecurityGroup": sg,
                    },
                    reason=f"Database is attached to an insecure or publicly open security group '{sg.get('VpcSecurityGroupId')}'.",
                    remediation=self.remediation,
                    severity=self.severity,
                )

        return RuleResult(matched=False)
