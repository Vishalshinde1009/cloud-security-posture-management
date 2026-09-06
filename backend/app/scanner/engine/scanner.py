import logging
from typing import List, Dict, Any
from app.scanner.providers.base import CloudProvider, DiscoveredResource

logger = logging.getLogger("cspm.engine")


class ScannerEngine:
    """
    Core CSPM Scanner Engine orchestrating asset discovery, configuration collection,
    normalization, and baseline security classification.
    """

    def __init__(self, provider: CloudProvider):
        self.provider = provider

    def run_discovery_pipeline(self) -> List[DiscoveredResource]:
        """
        Runs the discovery and normalization pipeline.
        Executes basic demonstration validation to classify resource security status.
        """
        logger.info(f"Initiating discovery pipeline using provider: {self.provider.get_provider_name()}")
        raw_resources = self.provider.discover_resources()
        logger.info(f"Discovered {len(raw_resources)} cloud resources across {len(set(r.service for r in raw_resources))} services.")

        processed: List[DiscoveredResource] = []
        for resource in raw_resources:
            # Evaluate baseline demonstration security check to set security_status
            status = self._evaluate_baseline_security(resource)
            resource.security_status = status
            processed.append(resource)

        return processed

    def _evaluate_baseline_security(self, res: DiscoveredResource) -> str:
        """
        Applies Phase-4 demonstration rules to classify resource security status.
        Full 20+ rule engine with explainable risk scoring is built in Phase 5 & 6.
        """
        cfg = res.configuration or {}

        # S3 Public Access Check
        if res.service == "S3":
            pab = cfg.get("PublicAccessBlockConfiguration")
            if not pab or not pab.get("BlockPublicAcls", False):
                return "AT_RISK"
            enc = cfg.get("ServerSideEncryptionConfiguration")
            if not enc:
                return "AT_RISK"
            return "SECURE"

        # Security Group Unrestricted Ingress Check
        if res.service == "VPC" and res.resource_type == "aws_security_group":
            for perm in cfg.get("IpPermissions", []):
                for ip_range in perm.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        from_port = perm.get("FromPort")
                        if from_port in [22, 3389, 3306, 5432]:
                            return "AT_RISK"
            return "SECURE"

        # IAM User MFA Check
        if res.service == "IAM" and res.resource_type == "aws_iam_user":
            if not cfg.get("MFADevices"):
                return "AT_RISK"
            for key in cfg.get("AccessKeys", []):
                if key.get("AgeDays", 0) > 90:
                    return "AT_RISK"
            return "SECURE"

        # IAM Root Config Check
        if res.service == "IAM" and res.resource_type == "aws_iam_root":
            if not cfg.get("AccountMFAEnabled", False) or cfg.get("RootAccessKeysPresent", False):
                return "AT_RISK"
            return "SECURE"

        # EC2 Unencrypted Volume or Open Security Check
        if res.service == "EC2" and res.resource_type == "aws_ec2_instance":
            for mapping in cfg.get("BlockDeviceMappings", []):
                ebs = mapping.get("Ebs", {})
                if not ebs.get("Encrypted", True):
                    return "AT_RISK"
            return "SECURE"

        # CloudTrail Logging Check
        if res.service == "CloudTrail":
            trail_status = cfg.get("Status", {})
            if not trail_status.get("IsLogging", False) or not cfg.get("IsMultiRegionTrail", False):
                return "AT_RISK"
            return "SECURE"

        # RDS Public Exposure Check
        if res.service == "RDS":
            if cfg.get("PubliclyAccessible", False) or not cfg.get("StorageEncrypted", True):
                return "AT_RISK"
            return "SECURE"

        return "PENDING_ANALYSIS"
