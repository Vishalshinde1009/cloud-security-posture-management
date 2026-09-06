from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional


@dataclass
class DiscoveredResource:
    """Normalized multi-service cloud asset representation."""
    provider: str
    account_id: str
    service: str
    resource_type: str
    resource_id: str
    resource_name: Optional[str] = None
    region: Optional[str] = "us-east-1"
    tags: Dict[str, Any] = field(default_factory=dict)
    configuration: Dict[str, Any] = field(default_factory=dict)
    security_status: str = "PENDING_ANALYSIS"


class CloudProvider(ABC):
    """Abstract interface decoupling scanner logic from concrete cloud SDKs."""

    @abstractmethod
    def get_provider_name(self) -> str:
        """Returns the canonical provider identifier (e.g. 'MOCK', 'AWS')."""
        pass

    @abstractmethod
    def get_account_info(self) -> Dict[str, Any]:
        """Returns target account identification metadata."""
        pass

    @abstractmethod
    def discover_resources(self) -> List[DiscoveredResource]:
        """Discovers and returns normalized cloud resources across all supported services."""
        pass

    @abstractmethod
    def collect_configuration(self, service: str, resource_type: str, resource_id: str) -> Dict[str, Any]:
        """Gathers granular configuration evidence for a specific cloud asset."""
        pass
