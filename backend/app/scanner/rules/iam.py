from typing import Dict, Any, List
from app.scanner.providers.base import DiscoveredResource
from app.scanner.rules.base import BaseRule, RuleResult


class IAM001UserWithoutMFARule(BaseRule):
    rule_id = "IAM-001"
    title = "IAM user without Multi-Factor Authentication (MFA)"
    description = "Checks if an IAM user account has an active virtual or hardware MFA device enabled."
    service = "IAM"
    resource_type = "aws_iam_user"
    severity = "HIGH"
    category = "Identity & Access"
    remediation = "Enforce virtual or hardware Multi-Factor Authentication (MFA) for the IAM user."
    references = ["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html", "CIS AWS Foundations Benchmark 1.5"]

    def evaluate(self, resource: DiscoveredResource) -> RuleResult:
        cfg = resource.configuration or {}
        # Ignore machine service accounts without console passwords
        if "PasswordLastUsed" not in cfg and "CreateDate" not in cfg:
            return RuleResult(matched=False)

        mfa_devices = cfg.get("MFADevices", [])
        if not mfa_devices or len(mfa_devices) == 0:
            return RuleResult(
                matched=True,
                evidence={"UserName": cfg.get("UserName", resource.resource_name), "MFADevices": []},
                reason="IAM user does not have any active MFA devices registered.",
                remediation=self.remediation,
                severity=self.severity,
            )

        return RuleResult(matched=False)


class IAM002OverlyPermissivePolicyRule(BaseRule):
    rule_id = "IAM-002"
    title = "IAM entity has overly broad administrative permissions"
    description = "Detects IAM entities attached with full administrator access or wildcard action policies ('*:*')."
    service = "IAM"
    resource_type = "aws_iam_user"
    severity = "CRITICAL"
    category = "Identity & Access"
    remediation = "Apply the principle of least privilege: replace AdministratorAccess with job-specific, granular IAM policies."
    references = ["https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege", "CIS AWS Foundations Benchmark 1.16"]

    def evaluate(self, resource: DiscoveredResource) -> RuleResult:
        cfg = resource.configuration or {}
        attached_policies = cfg.get("AttachedPolicies", [])

        for pol in attached_policies:
            pol_name = pol.get("PolicyName", "")
            pol_arn = pol.get("PolicyArn", "")
            if pol_name == "AdministratorAccess" or pol_arn.endswith("/AdministratorAccess"):
                return RuleResult(
                    matched=True,
                    evidence={"AttachedPolicy": pol, "OffendingPolicy": pol_name},
                    reason=f"IAM user is directly attached with full administrative policy '{pol_name}'.",
                    remediation=self.remediation,
                    severity=self.severity,
                )

        return RuleResult(matched=False)


class IAM003OldAccessKeysRule(BaseRule):
    rule_id = "IAM-003"
    title = "IAM access keys not rotated within 90 days"
    description = "Identifies active IAM access keys that have not been rotated within the recommended 90-day threshold."
    service = "IAM"
    resource_type = "aws_iam_user"
    severity = "MEDIUM"
    category = "Credential Security"
    remediation = "Rotate IAM access keys regularly (at least every 90 days) and deactivate obsolete credentials."
    references = ["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html", "CIS AWS Foundations Benchmark 1.14"]

    def evaluate(self, resource: DiscoveredResource) -> RuleResult:
        cfg = resource.configuration or {}
        access_keys = cfg.get("AccessKeys", [])

        old_keys = []
        for key in access_keys:
            if key.get("Status") == "Active" and key.get("AgeDays", 0) > 90:
                old_keys.append({"AccessKeyId": key.get("AccessKeyId"), "AgeDays": key.get("AgeDays")})

        if old_keys:
            return RuleResult(
                matched=True,
                evidence={"OldAccessKeys": old_keys, "RotationThresholdDays": 90},
                reason=f"IAM user has {len(old_keys)} active access key(s) exceeding the 90-day rotation threshold.",
                remediation=self.remediation,
                severity=self.severity,
            )

        return RuleResult(matched=False)


class IAM004UnusedCredentialsRule(BaseRule):
    rule_id = "IAM-004"
    title = "IAM credentials inactive or unused"
    description = "Detects credentials or access keys explicitly marked inactive or unused for extended periods."
    service = "IAM"
    resource_type = "aws_iam_user"
    severity = "MEDIUM"
    category = "Credential Security"
    remediation = "Remove or disable unused IAM access keys and dormant user credentials."
    references = ["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_finding-unused.html", "CIS AWS Foundations Benchmark 1.12"]

    def evaluate(self, resource: DiscoveredResource) -> RuleResult:
        cfg = resource.configuration or {}
        access_keys = cfg.get("AccessKeys", [])

        inactive_keys = [k for k in access_keys if k.get("Status") == "Inactive"]
        if inactive_keys:
            return RuleResult(
                matched=True,
                evidence={"InactiveKeys": inactive_keys},
                reason=f"IAM user has {len(inactive_keys)} inactive credential(s) that should be deleted.",
                remediation=self.remediation,
                severity=self.severity,
            )

        return RuleResult(matched=False)


class IAM005RootAccountSecurityRule(BaseRule):
    rule_id = "IAM-005"
    title = "AWS Root account security posture violation"
    description = "Verifies root account security: hardware/virtual MFA must be active and no root access keys should exist."
    service = "IAM"
    resource_type = "aws_iam_root"
    severity = "CRITICAL"
    category = "Identity & Access"
    remediation = "Delete all root account access keys immediately and enable hardware Multi-Factor Authentication on the root account."
    references = ["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html", "CIS AWS Foundations Benchmark 1.1"]

    def evaluate(self, resource: DiscoveredResource) -> RuleResult:
        cfg = resource.configuration or {}
        violations = []
        evidence = {}

        if not cfg.get("AccountMFAEnabled", True):
            violations.append("Root account does not have MFA enabled")
            evidence["AccountMFAEnabled"] = False

        if cfg.get("RootAccessKeysPresent", False):
            violations.append("Active access keys exist for the root account")
            evidence["RootAccessKeysPresent"] = True

        if violations:
            return RuleResult(
                matched=True,
                evidence=evidence,
                reason="; ".join(violations) + ".",
                remediation=self.remediation,
                severity=self.severity,
            )

        return RuleResult(matched=False)
