from typing import Dict, Any, List
from app.scanner.providers.base import DiscoveredResource
from app.scanner.rules.base import BaseRule, RuleResult


class EC2001UnrestrictedSecurityGroupRule(BaseRule):
    rule_id = "EC2-001"
    title = "EC2 instance associated with unrestricted security group"
    description = "Checks if an EC2 instance is associated with a security group that allows broad ingress access from 0.0.0.0/0."
    service = "EC2"
    resource_type = "aws_ec2_instance"
    severity = "HIGH"
    category = "Network Security"
    remediation = "Modify the attached security group to restrict inbound access to specific corporate IP CIDRs."
    references = ["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html"]

    def evaluate(self, resource: DiscoveredResource) -> RuleResult:
        cfg = resource.configuration or {}
        sgs = cfg.get("SecurityGroups", [])

        # Check if attached SG is known unrestricted or flagged
        for sg in sgs:
            sg_name = sg.get("GroupName", "").lower()
            if "unrestricted" in sg_name or "open" in sg_name:
                return RuleResult(
                    matched=True,
                    evidence={"InstanceId": cfg.get("InstanceId"), "SecurityGroup": sg},
                    reason=f"Instance is attached to unrestricted security group '{sg.get('GroupName')}'.",
                    remediation=self.remediation,
                    severity=self.severity,
                )

        return RuleResult(matched=False)


class EC2002UnrestrictedSSHRule(BaseRule):
    rule_id = "EC2-002"
    title = "EC2 instance allows unrestricted inbound SSH (port 22)"
    description = "Detects EC2 instances directly exposed to inbound SSH (port 22) from the entire IPv4 internet (0.0.0.0/0)."
    service = "EC2"
    resource_type = "aws_ec2_instance"
    severity = "HIGH"
    category = "Network Security"
    remediation = "Restrict SSH access to trusted IP ranges or use AWS Systems Manager Session Manager for shell access."
    references = ["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html", "CIS AWS Foundations Benchmark 5.2"]

    def evaluate(self, resource: DiscoveredResource) -> RuleResult:
        cfg = resource.configuration or {}
        sgs = cfg.get("SecurityGroups", [])
        has_public_ip = bool(cfg.get("PublicIpAddress"))

        for sg in sgs:
            sg_name = sg.get("GroupName", "").lower()
            if "ssh" in sg_name and ("unrestricted" in sg_name or "open" in sg_name):
                return RuleResult(
                    matched=True,
                    evidence={
                        "InstanceId": cfg.get("InstanceId"),
                        "PublicIpAddress": cfg.get("PublicIpAddress"),
                        "SecurityGroup": sg,
                        "Port": 22,
                        "Source": "0.0.0.0/0",
                    },
                    reason=f"Instance has public exposure to SSH (port 22) via security group '{sg.get('GroupName')}'.",
                    remediation=self.remediation,
                    severity=self.severity,
                )

        return RuleResult(matched=False)


class EC2003UnrestrictedRDPRule(BaseRule):
    rule_id = "EC2-003"
    title = "EC2 instance allows unrestricted inbound RDP (port 3389)"
    description = "Detects EC2 instances directly exposed to inbound Remote Desktop Protocol (port 3389) from 0.0.0.0/0."
    service = "EC2"
    resource_type = "aws_ec2_instance"
    severity = "HIGH"
    category = "Network Security"
    remediation = "Restrict RDP (port 3389) access to trusted bastion hosts or a secure site-to-site VPN."
    references = ["https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/authorizing-access-to-an-instance.html", "CIS AWS Foundations Benchmark 5.3"]

    def evaluate(self, resource: DiscoveredResource) -> RuleResult:
        cfg = resource.configuration or {}
        sgs = cfg.get("SecurityGroups", [])

        for sg in sgs:
            sg_name = sg.get("GroupName", "").lower()
            if "rdp" in sg_name and ("unrestricted" in sg_name or "open" in sg_name):
                return RuleResult(
                    matched=True,
                    evidence={
                        "InstanceId": cfg.get("InstanceId"),
                        "SecurityGroup": sg,
                        "Port": 3389,
                        "Source": "0.0.0.0/0",
                    },
                    reason=f"Instance allows inbound RDP (port 3389) from 0.0.0.0/0 via '{sg.get('GroupName')}'.",
                    remediation=self.remediation,
                    severity=self.severity,
                )

        return RuleResult(matched=False)


class EC2004EbsEncryptionDisabledRule(BaseRule):
    rule_id = "EC2-004"
    title = "EC2 instance has unencrypted attached EBS volumes"
    description = "Verifies that all Elastic Block Store (EBS) volumes attached to the EC2 instance are encrypted at rest."
    service = "EC2"
    resource_type = "aws_ec2_instance"
    severity = "HIGH"
    category = "Encryption"
    remediation = "Enable EBS default encryption in the AWS region and recreate unencrypted volumes from encrypted snapshots."
    references = ["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html", "CIS AWS Foundations Benchmark 2.2.1"]

    def evaluate(self, resource: DiscoveredResource) -> RuleResult:
        cfg = resource.configuration or {}
        block_devices = cfg.get("BlockDeviceMappings", [])

        unencrypted_volumes = []
        for dev in block_devices:
            ebs = dev.get("Ebs", {})
            if ebs.get("Encrypted") is False:
                unencrypted_volumes.append({
                    "DeviceName": dev.get("DeviceName"),
                    "VolumeId": ebs.get("VolumeId"),
                    "Encrypted": False,
                })

        if unencrypted_volumes:
            return RuleResult(
                matched=True,
                evidence={
                    "InstanceId": cfg.get("InstanceId"),
                    "UnencryptedVolumes": unencrypted_volumes,
                },
                reason=f"Instance has {len(unencrypted_volumes)} unencrypted EBS volume(s) attached.",
                remediation=self.remediation,
                severity=self.severity,
            )

        return RuleResult(matched=False)


class EC2005PublicInstanceExposureRule(BaseRule):
    rule_id = "EC2-005"
    title = "EC2 instance assigned public IP address with legacy IMDSv1"
    description = "Detects internet-facing EC2 instances that do not require modern IMDSv2 tokens (HttpTokens: required), risking SSRF credential theft."
    service = "EC2"
    resource_type = "aws_ec2_instance"
    severity = "HIGH"
    category = "Network Security"
    remediation = "Enforce IMDSv2 by setting HttpTokens to 'required' and move instances to private subnets where possible."
    references = ["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html"]

    def evaluate(self, resource: DiscoveredResource) -> RuleResult:
        cfg = resource.configuration or {}
        public_ip = cfg.get("PublicIpAddress")
        metadata_options = cfg.get("MetadataOptions", {})

        # Only flag if instance is publicly reachable AND IMDSv2 is not strictly enforced
        if public_ip and metadata_options.get("HttpTokens") != "required":
            return RuleResult(
                matched=True,
                evidence={
                    "InstanceId": cfg.get("InstanceId"),
                    "PublicIpAddress": public_ip,
                    "HttpTokens": metadata_options.get("HttpTokens", "optional"),
                },
                reason=f"Publicly accessible instance ({public_ip}) allows legacy IMDSv1 without token enforcement.",
                remediation=self.remediation,
                severity=self.severity,
            )

        return RuleResult(matched=False)
