from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from app.scanner.providers.base import DiscoveredResource


@dataclass
class RuleResult:
    """
    Structured outcome of a security rule evaluation against a resource.
    Must contain concrete evidence extracted from configuration when matched is True.
    """
    matched: bool
    evidence: Dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    remediation: str = ""
    severity: str = "MEDIUM"


class BaseRule(ABC):
    """
    Abstract Base Class for all CSPM security misconfiguration detection rules.
    Ensures pure detection logic without side-effects or cloud resource modification.
    """
    rule_id: str
    title: str
    description: str
    service: str
    resource_type: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    category: str  # Data Exposure, Identity & Access, Network Security, Encryption, etc.
    remediation: str
    references: List[str]

    def applies_to(self, resource: DiscoveredResource) -> bool:
        """
        Determines whether this rule is applicable to the given resource.
        Prevents cross-service false execution.
        """
        return (
            resource.service.upper() == self.service.upper()
            and resource.resource_type.lower() == self.resource_type.lower()
        )

    @abstractmethod
    def evaluate(self, resource: DiscoveredResource) -> RuleResult:
        """
        Evaluates the resource configuration against the security rule criteria.
        Returns a RuleResult indicating if a violation occurred with supporting evidence.
        """
        pass
