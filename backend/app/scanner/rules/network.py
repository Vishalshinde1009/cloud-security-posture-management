from typing import Dict, Any, List
from app.scanner.providers.base import DiscoveredResource
from app.scanner.rules.base import BaseRule, RuleResult

SENSITIVE_PORTS = {
    22: "SSH",
    23: "Telnet",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    27017: "MongoDB",
    1521: "Oracle DB",
}


def _matches_cidr(perm: Dict[str, Any], target_cidr: str = "0.0.0.0/0") -> bool:
    """Checks if permission contains target CIDR or IPv6 all (::/0)."""
    for ip_range in perm.get("IpRanges", []):
        if ip_range.get("CidrIp") == target_cidr:
            return True
    for ipv6_range in perm.get("Ipv6Ranges", []):
        if ipv6_range.get("CidrIpv6") == "::/0":
            return True
    return False


def _port_in_range(perm: Dict[str, Any], port: int) -> bool:
    """Checks if port falls within from_port and to_port."""
    from_port = perm.get("FromPort")
    to_port = perm.get("ToPort")
    protocol = perm.get("IpProtocol")

    if protocol == "-1":
        return True
    if from_port is not None and to_port is not None:
        return from_port <= port <= to_port
    return False


class NET001UnrestrictedSSHInboundRule(BaseRule):
    rule_id = "NET-001"
    title = "Security group allows unrestricted inbound SSH (port 22)"
    description = "Checks if security group ingress rules allow direct SSH connection (port 22) from the entire public internet (0.0.0.0/0)."
    service = "VPC"
    resource_type = "aws_security_group"
    severity = "HIGH"
    category = "Network Security"
    remediation = "Remove 0.0.0.0/0 from inbound rule for port 22 and restrict to trusted management CIDRs or corporate VPN."
    references = ["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html", "CIS AWS Foundations Benchmark 5.2"]

    def evaluate(self, resource: DiscoveredResource) -> RuleResult:
        cfg = resource.configuration or {}
        ip_permissions = cfg.get("IpPermissions", [])

        for perm in ip_permissions:
            if _matches_cidr(perm, "0.0.0.0/0") and _port_in_range(perm, 22):
                return RuleResult(
                    matched=True,
                    evidence={
                        "GroupId": cfg.get("GroupId"),
                        "GroupName": cfg.get("GroupName"),
                        "Protocol": perm.get("IpProtocol"),
                        "FromPort": perm.get("FromPort"),
                        "ToPort": perm.get("ToPort"),
                        "Source": "0.0.0.0/0",
                    },
                    reason="Inbound SSH port 22 is open to the entire public internet (0.0.0.0/0).",
                    remediation=self.remediation,
                    severity=self.severity,
                )

        return RuleResult(matched=False)


class NET002UnrestrictedRDPInboundRule(BaseRule):
    rule_id = "NET-002"
    title = "Security group allows unrestricted inbound RDP (port 3389)"
    description = "Checks if security group ingress rules allow direct RDP connection (port 3389) from the entire public internet (0.0.0.0/0)."
    service = "VPC"
    resource_type = "aws_security_group"
    severity = "HIGH"
    category = "Network Security"
    remediation = "Remove 0.0.0.0/0 from inbound rule for port 3389 and enforce VPN or bastion host authentication."
    references = ["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html", "CIS AWS Foundations Benchmark 5.3"]

    def evaluate(self, resource: DiscoveredResource) -> RuleResult:
        cfg = resource.configuration or {}
        ip_permissions = cfg.get("IpPermissions", [])

        for perm in ip_permissions:
            if _matches_cidr(perm, "0.0.0.0/0") and _port_in_range(perm, 3389):
                return RuleResult(
                    matched=True,
                    evidence={
                        "GroupId": cfg.get("GroupId"),
                        "GroupName": cfg.get("GroupName"),
                        "Protocol": perm.get("IpProtocol"),
                        "FromPort": perm.get("FromPort"),
                        "ToPort": perm.get("ToPort"),
                        "Source": "0.0.0.0/0",
                    },
                    reason="Inbound RDP port 3389 is open to the entire public internet (0.0.0.0/0).",
                    remediation=self.remediation,
                    severity=self.severity,
                )

        return RuleResult(matched=False)


class NET003UnrestrictedSensitivePortsRule(BaseRule):
    rule_id = "NET-003"
    title = "Security group exposes sensitive database or management ports to 0.0.0.0/0"
    description = "Detects security group ingress rules allowing access to sensitive database or management ports (23, 3306, 5432, 1433, 27017) from 0.0.0.0/0."
    service = "VPC"
    resource_type = "aws_security_group"
    severity = "HIGH"
    category = "Network Security"
    remediation = "Restrict database and management ports to specific internal application tier security groups or subnets."
    references = ["https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html"]

    def evaluate(self, resource: DiscoveredResource) -> RuleResult:
        cfg = resource.configuration or {}
        ip_permissions = cfg.get("IpPermissions", [])

        # Check for sensitive non-HTTP ports (ignore 80/443 and exclude pure 22/3389 handled specifically by NET-001/002)
        targeted_ports = {3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL", 27017: "MongoDB", 23: "Telnet"}

        for perm in ip_permissions:
            if _matches_cidr(perm, "0.0.0.0/0"):
                for port, service_name in targeted_ports.items():
                    if _port_in_range(perm, port):
                        return RuleResult(
                            matched=True,
                            evidence={
                                "GroupId": cfg.get("GroupId"),
                                "GroupName": cfg.get("GroupName"),
                                "ExposedPort": port,
                                "Service": service_name,
                                "Source": "0.0.0.0/0",
                            },
                            reason=f"Sensitive port {port} ({service_name}) is exposed to the entire internet (0.0.0.0/0).",
                            remediation=self.remediation,
                            severity=self.severity,
                        )

        return RuleResult(matched=False)


class NET004OverlyPermissiveInboundRule(BaseRule):
    rule_id = "NET-004"
    title = "Security group allows unrestricted ingress on all ports ('-1')"
    description = "Identifies security groups allowing unrestricted ingress on all protocols (-1) or port range 0-65535 from 0.0.0.0/0."
    service = "VPC"
    resource_type = "aws_security_group"
    severity = "HIGH"
    category = "Network Security"
    remediation = "Replace wide-open ingress rules (-1 or 0-65535) with strictly required individual application ports."
    references = ["https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html"]

    def evaluate(self, resource: DiscoveredResource) -> RuleResult:
        cfg = resource.configuration or {}
        ip_permissions = cfg.get("IpPermissions", [])

        for perm in ip_permissions:
            if _matches_cidr(perm, "0.0.0.0/0"):
                protocol = perm.get("IpProtocol")
                from_port = perm.get("FromPort")
                to_port = perm.get("ToPort")

                if protocol == "-1" or (from_port == 0 and to_port == 65535):
                    return RuleResult(
                        matched=True,
                        evidence={
                            "GroupId": cfg.get("GroupId"),
                            "GroupName": cfg.get("GroupName"),
                            "Protocol": protocol,
                            "FromPort": from_port,
                            "ToPort": to_port,
                            "Source": "0.0.0.0/0",
                        },
                        reason="Security group permits unrestricted inbound traffic on all ports and protocols from 0.0.0.0/0.",
                        remediation=self.remediation,
                        severity=self.severity,
                    )

        return RuleResult(matched=False)


class NET005OverlyPermissiveOutboundRule(BaseRule):
    rule_id = "NET-005"
    title = "Security group allows unrestricted outbound egress to sensitive protocols"
    description = "Audits outbound egress rules: detects unusual outbound rules granting unrestricted access to sensitive protocols."
    service = "VPC"
    resource_type = "aws_security_group"
    severity = "MEDIUM"
    category = "Network Security"
    remediation = "Audit outbound security group rules to restrict egress traffic to approved destinations."
    references = ["https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html"]

    def evaluate(self, resource: DiscoveredResource) -> RuleResult:
        cfg = resource.configuration or {}
        egress = cfg.get("IpPermissionsEgress", [])

        # Flag if egress is explicitly set to unrestricted Telnet or unencrypted legacy services
        for perm in egress:
            if _matches_cidr(perm, "0.0.0.0/0") and perm.get("FromPort") == 23 and perm.get("ToPort") == 23:
                return RuleResult(
                    matched=True,
                    evidence={
                        "GroupId": cfg.get("GroupId"),
                        "Protocol": perm.get("IpProtocol"),
                        "Port": 23,
                        "Destination": "0.0.0.0/0",
                    },
                    reason="Security group explicitly allows unencrypted outbound Telnet (port 23) to 0.0.0.0/0.",
                    remediation=self.remediation,
                    severity=self.severity,
                )

        return RuleResult(matched=False)
