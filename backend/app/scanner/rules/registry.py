import logging
from typing import Dict, List, Optional, Set
from app.scanner.rules.base import BaseRule
from app.scanner.providers.base import DiscoveredResource

# Concrete rules
from app.scanner.rules.s3 import (
    S3001PublicAccessRule,
    S3002MissingEncryptionRule,
    S3003VersioningDisabledRule,
    S3004LoggingDisabledRule,
    S3005InsecurePolicyRule,
)
from app.scanner.rules.iam import (
    IAM001UserWithoutMFARule,
    IAM002OverlyPermissivePolicyRule,
    IAM003OldAccessKeysRule,
    IAM004UnusedCredentialsRule,
    IAM005RootAccountSecurityRule,
)
from app.scanner.rules.ec2 import (
    EC2001UnrestrictedSecurityGroupRule,
    EC2002UnrestrictedSSHRule,
    EC2003UnrestrictedRDPRule,
    EC2004EbsEncryptionDisabledRule,
    EC2005PublicInstanceExposureRule,
)
from app.scanner.rules.network import (
    NET001UnrestrictedSSHInboundRule,
    NET002UnrestrictedRDPInboundRule,
    NET003UnrestrictedSensitivePortsRule,
    NET004OverlyPermissiveInboundRule,
    NET005OverlyPermissiveOutboundRule,
)
from app.scanner.rules.cloudtrail import (
    CT001CloudTrailNotEnabledRule,
    CT002CloudTrailLoggingDisabledRule,
    CT003CloudTrailMultiRegionIssueRule,
)
from app.scanner.rules.rds import (
    RDS001PublicAccessibilityRule,
    RDS002StorageEncryptionDisabledRule,
    RDS003WeakNetworkExposureRule,
)

logger = logging.getLogger("cspm.rules.registry")


class RuleRegistry:
    """
    Central repository for security misconfiguration detection rules.
    Maintains active rule instances, ensures rule_id uniqueness, and indexes
    rules by service and resource type for optimal execution.
    """

    def __init__(self):
        self._rules: Dict[str, BaseRule] = {}

    def register(self, rule: BaseRule) -> None:
        """Registers a rule instance. Raises ValueError on duplicate rule_id."""
        if rule.rule_id in self._rules:
            raise ValueError(f"Security rule with ID '{rule.rule_id}' is already registered.")
        self._rules[rule.rule_id] = rule
        logger.debug(f"Registered security rule: {rule.rule_id} ({rule.service})")

    def get_rule(self, rule_id: str) -> Optional[BaseRule]:
        """Retrieves a rule by its canonical ID."""
        return self._rules.get(rule_id)

    def get_all_rules(self) -> List[BaseRule]:
        """Returns all registered rules sorted by rule_id."""
        return sorted(list(self._rules.values()), key=lambda r: r.rule_id)

    def get_rules_for_service(self, service: str) -> List[BaseRule]:
        """Returns rules matching the given AWS service family."""
        return [r for r in self._rules.values() if r.service.upper() == service.upper()]

    def get_applicable_rules(self, resource: DiscoveredResource) -> List[BaseRule]:
        """Returns rules applicable to the given discovered cloud asset."""
        return [r for r in self._rules.values() if r.applies_to(resource)]

    def get_enabled_rules(self, disabled_rule_ids: Optional[Set[str]] = None) -> List[BaseRule]:
        """Returns list of active rules filtering out any disabled IDs."""
        disabled = disabled_rule_ids or set()
        return [r for r in self._rules.values() if r.rule_id not in disabled]

    def count(self) -> int:
        """Returns total count of registered rules."""
        return len(self._rules)


def create_default_registry() -> RuleRegistry:
    """Creates and returns a registry populated with all 26 core CSPM security rules."""
    reg = RuleRegistry()

    # S3 (5 rules)
    reg.register(S3001PublicAccessRule())
    reg.register(S3002MissingEncryptionRule())
    reg.register(S3003VersioningDisabledRule())
    reg.register(S3004LoggingDisabledRule())
    reg.register(S3005InsecurePolicyRule())

    # IAM (5 rules)
    reg.register(IAM001UserWithoutMFARule())
    reg.register(IAM002OverlyPermissivePolicyRule())
    reg.register(IAM003OldAccessKeysRule())
    reg.register(IAM004UnusedCredentialsRule())
    reg.register(IAM005RootAccountSecurityRule())

    # EC2 (5 rules)
    reg.register(EC2001UnrestrictedSecurityGroupRule())
    reg.register(EC2002UnrestrictedSSHRule())
    reg.register(EC2003UnrestrictedRDPRule())
    reg.register(EC2004EbsEncryptionDisabledRule())
    reg.register(EC2005PublicInstanceExposureRule())

    # Network / Security Groups (5 rules)
    reg.register(NET001UnrestrictedSSHInboundRule())
    reg.register(NET002UnrestrictedRDPInboundRule())
    reg.register(NET003UnrestrictedSensitivePortsRule())
    reg.register(NET004OverlyPermissiveInboundRule())
    reg.register(NET005OverlyPermissiveOutboundRule())

    # CloudTrail (3 rules)
    reg.register(CT001CloudTrailNotEnabledRule())
    reg.register(CT002CloudTrailLoggingDisabledRule())
    reg.register(CT003CloudTrailMultiRegionIssueRule())

    # RDS (3 rules)
    reg.register(RDS001PublicAccessibilityRule())
    reg.register(RDS002StorageEncryptionDisabledRule())
    reg.register(RDS003WeakNetworkExposureRule())

    return reg


# Global default rule registry singleton
default_registry = create_default_registry()
