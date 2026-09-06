from typing import Dict, Any, List
from app.scanner.providers.base import DiscoveredResource
from app.scanner.rules.base import BaseRule, RuleResult


class S3001PublicAccessRule(BaseRule):
    rule_id = "S3-001"
    title = "S3 bucket allows public access"
    description = "Checks if an S3 bucket has Public Access Block disabled, exposing data to the public internet."
    service = "S3"
    resource_type = "aws_s3_bucket"
    severity = "CRITICAL"
    category = "Data Exposure"
    remediation = "Enable S3 Block Public Access (BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets) on the bucket."
    references = ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html", "CIS AWS Foundations Benchmark 2.1.5"]

    def evaluate(self, resource: DiscoveredResource) -> RuleResult:
        cfg = resource.configuration or {}
        pab = cfg.get("PublicAccessBlockConfiguration")

        # If PublicAccessBlock is missing completely or any of the 4 block controls are False
        if not pab:
            return RuleResult(
                matched=True,
                evidence={"PublicAccessBlockConfiguration": None},
                reason="PublicAccessBlockConfiguration is not configured on the bucket.",
                remediation=self.remediation,
                severity=self.severity,
            )

        disabled_blocks = {k: v for k, v in pab.items() if v is False}
        if disabled_blocks or not pab.get("BlockPublicAcls", False):
            return RuleResult(
                matched=True,
                evidence={"PublicAccessBlockConfiguration": pab, "DisabledControls": list(disabled_blocks.keys())},
                reason=f"Bucket public access controls are disabled: {', '.join(disabled_blocks.keys()) or 'BlockPublicAcls is False'}.",
                remediation=self.remediation,
                severity=self.severity,
            )

        return RuleResult(matched=False)


class S3002MissingEncryptionRule(BaseRule):
    rule_id = "S3-002"
    title = "S3 bucket missing default server-side encryption"
    description = "Checks whether an S3 bucket enforces default server-side encryption using AES-256 or AWS KMS."
    service = "S3"
    resource_type = "aws_s3_bucket"
    severity = "HIGH"
    category = "Encryption"
    remediation = "Configure default server-side encryption on the bucket using SSE-S3 (AES256) or SSE-KMS."
    references = ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html", "CIS AWS Foundations Benchmark 2.1.1"]

    def evaluate(self, resource: DiscoveredResource) -> RuleResult:
        cfg = resource.configuration or {}
        sse = cfg.get("ServerSideEncryptionConfiguration")

        if not sse or not sse.get("Rules"):
            return RuleResult(
                matched=True,
                evidence={"ServerSideEncryptionConfiguration": sse},
                reason="Bucket has no default server-side encryption configured.",
                remediation=self.remediation,
                severity=self.severity,
            )

        return RuleResult(matched=False)


class S3003VersioningDisabledRule(BaseRule):
    rule_id = "S3-003"
    title = "S3 bucket versioning is disabled"
    description = "Verifies that S3 bucket versioning is enabled to protect against accidental deletion and ransomware overwrites."
    service = "S3"
    resource_type = "aws_s3_bucket"
    severity = "MEDIUM"
    category = "Configuration Management"
    remediation = "Enable bucket versioning to preserve, retrieve, and restore every version of every object."
    references = ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html"]

    def evaluate(self, resource: DiscoveredResource) -> RuleResult:
        cfg = resource.configuration or {}
        versioning = cfg.get("Versioning")

        status = versioning.get("Status") if isinstance(versioning, dict) else None
        if status != "Enabled":
            return RuleResult(
                matched=True,
                evidence={"Versioning": versioning, "Status": status or "Disabled"},
                reason=f"Bucket versioning status is '{status or 'Disabled'}' instead of 'Enabled'.",
                remediation=self.remediation,
                severity=self.severity,
            )

        return RuleResult(matched=False)


class S3004LoggingDisabledRule(BaseRule):
    rule_id = "S3-004"
    title = "S3 bucket server access logging not configured"
    description = "Ensures server access logging is enabled on S3 buckets for security auditing and forensic investigation."
    service = "S3"
    resource_type = "aws_s3_bucket"
    severity = "MEDIUM"
    category = "Logging & Monitoring"
    remediation = "Enable server access logging targeting a dedicated centralized log archive bucket."
    references = ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html", "CIS AWS Foundations Benchmark 2.1.3"]

    def evaluate(self, resource: DiscoveredResource) -> RuleResult:
        cfg = resource.configuration or {}
        logging_cfg = cfg.get("Logging")

        if not logging_cfg or not logging_cfg.get("TargetBucket"):
            return RuleResult(
                matched=True,
                evidence={"Logging": logging_cfg},
                reason="Server access logging is not configured for this bucket.",
                remediation=self.remediation,
                severity=self.severity,
            )

        return RuleResult(matched=False)


class S3005InsecurePolicyRule(BaseRule):
    rule_id = "S3-005"
    title = "S3 bucket policy contains insecure permissions or unencrypted transport"
    description = "Detects bucket policies granting public principal access ('*') or missing enforcement of TLS/HTTPS (aws:SecureTransport)."
    service = "S3"
    resource_type = "aws_s3_bucket"
    severity = "HIGH"
    category = "Data Exposure"
    remediation = "Update the bucket policy to restrict Principals and require secure HTTPS transport (aws:SecureTransport: true)."
    references = ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies.html"]

    def evaluate(self, resource: DiscoveredResource) -> RuleResult:
        cfg = resource.configuration or {}
        policy = cfg.get("Policy")

        if not policy or not isinstance(policy, dict):
            # No policy present - do not generate false positive if policy info is absent
            return RuleResult(matched=False)

        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            effect = stmt.get("Effect")
            principal = stmt.get("Principal")

            # Check for Allow with public principal '*'
            if effect == "Allow" and (principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*")):
                # Check if restricted by condition
                condition = stmt.get("Condition")
                if not condition:
                    return RuleResult(
                        matched=True,
                        evidence={"Statement": stmt, "Effect": effect, "Principal": principal},
                        reason="Bucket policy grants unrestricted 'Allow' access to public principal '*'.",
                        remediation=self.remediation,
                        severity=self.severity,
                    )

        return RuleResult(matched=False)
