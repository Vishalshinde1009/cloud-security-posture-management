from typing import Dict, Any, List
from app.scanner.providers.base import DiscoveredResource
from app.scanner.rules.base import BaseRule, RuleResult


class CT001CloudTrailNotEnabledRule(BaseRule):
    rule_id = "CT-001"
    title = "CloudTrail trail is not actively logging"
    description = "Verifies that the CloudTrail audit trail is actively enabled and recording API activity."
    service = "CloudTrail"
    resource_type = "aws_cloudtrail_trail"
    severity = "HIGH"
    category = "Logging & Monitoring"
    remediation = "Start logging on the CloudTrail trail using the AWS Console or via 'aws cloudtrail start-logging'."
    references = ["https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-turning-on-and-off.html", "CIS AWS Foundations Benchmark 3.1"]

    def evaluate(self, resource: DiscoveredResource) -> RuleResult:
        cfg = resource.configuration or {}
        status = cfg.get("Status", {})

        if not status.get("IsLogging", False):
            return RuleResult(
                matched=True,
                evidence={
                    "TrailName": cfg.get("Name", resource.resource_name),
                    "IsLogging": status.get("IsLogging", False),
                },
                reason=f"CloudTrail trail '{cfg.get('Name')}' is not actively recording audit logs.",
                remediation=self.remediation,
                severity=self.severity,
            )

        return RuleResult(matched=False)


class CT002CloudTrailLoggingDisabledRule(BaseRule):
    rule_id = "CT-002"
    title = "CloudTrail log file validation is disabled"
    description = "Checks whether CloudTrail log file validation is enabled to provide cryptographic proof of log integrity and detect tampering."
    service = "CloudTrail"
    resource_type = "aws_cloudtrail_trail"
    severity = "HIGH"
    category = "Logging & Monitoring"
    remediation = "Enable log file validation on the trail to ensure tamper-evident audit logs."
    references = ["https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html", "CIS AWS Foundations Benchmark 3.2"]

    def evaluate(self, resource: DiscoveredResource) -> RuleResult:
        cfg = resource.configuration or {}
        val_enabled = cfg.get("LogFileValidationEnabled", False)

        if not val_enabled:
            return RuleResult(
                matched=True,
                evidence={
                    "TrailName": cfg.get("Name", resource.resource_name),
                    "LogFileValidationEnabled": False,
                },
                reason=f"Log file integrity validation is disabled on trail '{cfg.get('Name')}'.",
                remediation=self.remediation,
                severity=self.severity,
            )

        return RuleResult(matched=False)


class CT003CloudTrailMultiRegionIssueRule(BaseRule):
    rule_id = "CT-003"
    title = "CloudTrail trail is not configured for multi-region logging"
    description = "Ensures CloudTrail captures management events across all AWS regions to avoid blind spots in unmonitored regions."
    service = "CloudTrail"
    resource_type = "aws_cloudtrail_trail"
    severity = "MEDIUM"
    category = "Logging & Monitoring"
    remediation = "Configure the CloudTrail trail to be a multi-region trail ('IsMultiRegionTrail: true')."
    references = ["https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html", "CIS AWS Foundations Benchmark 3.1"]

    def evaluate(self, resource: DiscoveredResource) -> RuleResult:
        cfg = resource.configuration or {}
        multi_region = cfg.get("IsMultiRegionTrail", False)

        if not multi_region:
            return RuleResult(
                matched=True,
                evidence={
                    "TrailName": cfg.get("Name", resource.resource_name),
                    "IsMultiRegionTrail": False,
                },
                reason=f"Trail '{cfg.get('Name')}' is single-region only and does not record activity across all regions.",
                remediation=self.remediation,
                severity=self.severity,
            )

        return RuleResult(matched=False)
