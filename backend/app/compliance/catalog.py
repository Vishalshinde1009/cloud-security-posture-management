"""
Comprehensive Compliance Framework Catalog and Security Rule Mappings.
Maps 26 security detection rules to CIS AWS, NIST SP 800-53, ISO 27001, and PCI DSS.
Note: These mappings represent security-control alignment and potential gap detection.
They do not constitute formal regulatory certification.
"""

from typing import Dict, Any, List

COMPLIANCE_FRAMEWORKS = {
    "CIS_AWS": {
        "name": "CIS AWS Foundations Benchmark",
        "version": "v2.0.0 / v3.0.0",
        "description": "Prescriptive industry guidelines for establishing a secure baseline configuration for AWS environments.",
        "icon": "ShieldCheck",
    },
    "NIST": {
        "name": "NIST SP 800-53 Rev. 5",
        "version": "Revision 5",
        "description": "Security and Privacy Controls for Federal Information Systems and Organizations.",
        "icon": "FileCheck2",
    },
    "ISO27001": {
        "name": "ISO/IEC 27001:2022",
        "version": "2022 Edition",
        "description": "Information security management systems specifications and Annex A operational security controls.",
        "icon": "Award",
    },
    "PCI_DSS": {
        "name": "PCI DSS v4.0",
        "version": "Version 4.0",
        "description": "Payment Card Industry Data Security Standard for protecting cardholder data environments.",
        "icon": "CreditCard",
    },
}

# Catalog of Security Controls across the 4 Frameworks
COMPLIANCE_CONTROLS: List[Dict[str, str]] = [
    # -------------------------------------------------------------------------
    # CIS AWS Foundations Benchmark
    # -------------------------------------------------------------------------
    {"framework": "CIS_AWS", "control_id": "CIS-1.1", "title": "Avoid Root Account Usage & Enforce MFA", "description": "Ensure the root user account is not used for everyday tasks and has hardware/virtual MFA enabled."},
    {"framework": "CIS_AWS", "control_id": "CIS-1.5", "title": "MFA Enabled for All IAM Users", "description": "Ensure multi-factor authentication (MFA) is enabled for all IAM users with console passwords."},
    {"framework": "CIS_AWS", "control_id": "CIS-1.12", "title": "Credentials Unused for 90 Days Disabled", "description": "Ensure credentials (passwords and access keys) unused for 90 days or greater are disabled or removed."},
    {"framework": "CIS_AWS", "control_id": "CIS-1.14", "title": "Access Keys Rotated Every 90 Days", "description": "Ensure all active IAM access keys are rotated within the recommended 90-day threshold."},
    {"framework": "CIS_AWS", "control_id": "CIS-1.16", "title": "IAM Least Privilege Enforcement", "description": "Ensure IAM policies adhere to least privilege and avoid full administrative wildcards ('*:*')."},
    {"framework": "CIS_AWS", "control_id": "CIS-2.1.1", "title": "S3 Default Server-Side Encryption", "description": "Ensure S3 bucket default server-side encryption is enforced using SSE-S3 or AWS KMS."},
    {"framework": "CIS_AWS", "control_id": "CIS-2.1.3", "title": "S3 Object Versioning Enabled", "description": "Ensure S3 bucket versioning is enabled to protect against unintended object overwrites and deletions."},
    {"framework": "CIS_AWS", "control_id": "CIS-2.1.4", "title": "S3 Server Access Logging Enabled", "description": "Ensure S3 bucket access logging is enabled to record all incoming requests for audit compliance."},
    {"framework": "CIS_AWS", "control_id": "CIS-2.1.5", "title": "S3 Block Public Access Enforced", "description": "Ensure S3 Block Public Access settings are enabled at bucket and account levels to prevent public leakage."},
    {"framework": "CIS_AWS", "control_id": "CIS-2.2.1", "title": "EBS Volume Default Encryption", "description": "Ensure EBS volume encryption at rest is enabled for all attached storage in all operating regions."},
    {"framework": "CIS_AWS", "control_id": "CIS-2.3.1", "title": "RDS Database Not Publicly Accessible", "description": "Ensure Amazon RDS database instances are not directly accessible from the public internet."},
    {"framework": "CIS_AWS", "control_id": "CIS-2.3.2", "title": "RDS Storage Encryption Enabled", "description": "Ensure storage encryption at rest using AWS KMS is enabled for all RDS database instances."},
    {"framework": "CIS_AWS", "control_id": "CIS-2.3.3", "title": "RDS Security Groups Restrict Traffic", "description": "Ensure security groups associated with RDS instances restrict ingress strictly to authorized app tiers."},
    {"framework": "CIS_AWS", "control_id": "CIS-3.1", "title": "CloudTrail Enabled in All Regions", "description": "Ensure CloudTrail is enabled across all multi-region partitions to capture all AWS management events."},
    {"framework": "CIS_AWS", "control_id": "CIS-3.2", "title": "CloudTrail Log File Validation Enabled", "description": "Ensure CloudTrail log file validation is enabled to provide cryptographic proof of log integrity."},
    {"framework": "CIS_AWS", "control_id": "CIS-5.1", "title": "Security Groups Ingress Restrictive", "description": "Ensure no VPC security groups allow unrestricted inbound access across all ports (0.0.0.0/0)."},
    {"framework": "CIS_AWS", "control_id": "CIS-5.2", "title": "No Unrestricted SSH Access (Port 22)", "description": "Ensure no security groups allow unrestricted ingress from 0.0.0.0/0 to SSH port 22."},
    {"framework": "CIS_AWS", "control_id": "CIS-5.3", "title": "No Unrestricted RDP Access (Port 3389)", "description": "Ensure no security groups allow unrestricted ingress from 0.0.0.0/0 to RDP port 3389."},
    {"framework": "CIS_AWS", "control_id": "CIS-5.4", "title": "Enforce IMDSv2 on EC2 Instances", "description": "Ensure EC2 instances enforce IMDSv2 token session authentication (HttpTokens: required)."},
    {"framework": "CIS_AWS", "control_id": "CIS-5.5", "title": "Control Outbound Traffic in Security Groups", "description": "Ensure security groups restrict outbound egress to required destinations rather than blanket 0.0.0.0/0."},

    # -------------------------------------------------------------------------
    # NIST SP 800-53 Rev. 5
    # -------------------------------------------------------------------------
    {"framework": "NIST", "control_id": "NIST-AC-2", "title": "Account Management", "description": "Manage information system accounts, including establishing, activating, modifying, and terminating accounts."},
    {"framework": "NIST", "control_id": "NIST-AC-3", "title": "Access Enforcement", "description": "Enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies."},
    {"framework": "NIST", "control_id": "NIST-AC-4", "title": "Information Flow Enforcement", "description": "Enforce approved authorizations for controlling the flow of information within the system and between interconnected systems."},
    {"framework": "NIST", "control_id": "NIST-AC-6", "title": "Least Privilege", "description": "Employ the principle of least privilege, allowing only authorized access for users and processes necessary to accomplish assigned tasks."},
    {"framework": "NIST", "control_id": "NIST-AU-2", "title": "Event Logging", "description": "Identify and record events on the system that are significant and relevant to the security of the information system."},
    {"framework": "NIST", "control_id": "NIST-AU-3", "title": "Content of Audit Records", "description": "Ensure audit records contain information that establishes what type of event occurred, when it occurred, and where."},
    {"framework": "NIST", "control_id": "NIST-AU-9", "title": "Protection of Audit Information", "description": "Protect audit information and audit tools from unauthorized access, modification, and deletion."},
    {"framework": "NIST", "control_id": "NIST-AU-12", "title": "Audit Record Generation", "description": "Provide audit record generation capability for auditable events on all system components."},
    {"framework": "NIST", "control_id": "NIST-CM-7", "title": "Least Functionality", "description": "Configure the information system to provide only essential capabilities and prohibit or restrict the use of nonessential ports and services."},
    {"framework": "NIST", "control_id": "NIST-CP-9", "title": "Information System Backup", "description": "Conduct backups of user-level information contained in the system and protect backup integrity."},
    {"framework": "NIST", "control_id": "NIST-IA-2", "title": "Identification and Authentication (Organizational Users)", "description": "Uniquely identify and authenticate organizational users (or processes acting on behalf of users) using MFA."},
    {"framework": "NIST", "control_id": "NIST-IA-5", "title": "Authenticator Management", "description": "Manage information system authenticators, including periodic rotation and deactivating dormant credentials."},
    {"framework": "NIST", "control_id": "NIST-SC-7", "title": "Boundary Protection", "description": "Monitor and control communications at external boundaries of the system and key internal boundaries."},
    {"framework": "NIST", "control_id": "NIST-SC-13", "title": "Cryptographic Protection", "description": "Implement cryptographic mechanisms to prevent unauthorized disclosure and modification of sensitive information."},
    {"framework": "NIST", "control_id": "NIST-SC-28", "title": "Protection of Information at Rest", "description": "Protect the confidentiality and integrity of information at rest using cryptographic mechanisms."},
    {"framework": "NIST", "control_id": "NIST-SI-4", "title": "Information System Monitoring", "description": "Monitor the information system to detect attacks and indicators of potential compromise."},

    # -------------------------------------------------------------------------
    # ISO/IEC 27001:2022
    # -------------------------------------------------------------------------
    {"framework": "ISO27001", "control_id": "ISO-A.9.2.1", "title": "User Registration and De-registration", "description": "A formal user registration and de-registration process must be implemented to enable assignment of access rights."},
    {"framework": "ISO27001", "control_id": "ISO-A.9.2.3", "title": "Management of Privileged Access Rights", "description": "The allocation and use of privileged access rights must be restricted and tightly controlled."},
    {"framework": "ISO27001", "control_id": "ISO-A.9.2.6", "title": "Removal or Adjustment of Access Rights", "description": "Access rights of all employees and external parties must be removed upon termination or adjusted upon change."},
    {"framework": "ISO27001", "control_id": "ISO-A.9.4.1", "title": "Information Access Restriction", "description": "Access to information and application system functions must be restricted in accordance with the access control policy."},
    {"framework": "ISO27001", "control_id": "ISO-A.9.4.2", "title": "Secure Log-on Procedures", "description": "Where required by the access control policy, access to systems and applications must be controlled by a secure log-on procedure with MFA."},
    {"framework": "ISO27001", "control_id": "ISO-A.9.4.3", "title": "Password Management System", "description": "Password management systems must be interactive and must ensure quality passwords and periodic credential rotation."},
    {"framework": "ISO27001", "control_id": "ISO-A.10.1.1", "title": "Policy on Cryptographic Controls", "description": "A policy on the use of cryptographic controls for protection of information must be developed and implemented."},
    {"framework": "ISO27001", "control_id": "ISO-A.12.3.1", "title": "Information Backup", "description": "Backup copies of information, software, and system images must be taken and tested regularly in accordance with an agreed backup policy."},
    {"framework": "ISO27001", "control_id": "ISO-A.12.4.1", "title": "Event Logging", "description": "Event logs recording user activities, exceptions, faults, and information security events must be produced, kept, and regularly reviewed."},
    {"framework": "ISO27001", "control_id": "ISO-A.12.4.3", "title": "Administrator and Operator Logs", "description": "System administrator and system operator activities must be logged and the logs protected and regularly reviewed."},
    {"framework": "ISO27001", "control_id": "ISO-A.12.6.1", "title": "Management of Technical Vulnerabilities", "description": "Information about technical vulnerabilities of information systems being used must be obtained in a timely fashion."},
    {"framework": "ISO27001", "control_id": "ISO-A.13.1.1", "title": "Network Controls", "description": "Networks must be managed and controlled to protect information in systems and applications."},
    {"framework": "ISO27001", "control_id": "ISO-A.13.1.2", "title": "Security of Network Services", "description": "Security mechanisms, service levels, and management requirements of all network services must be identified and included in network services agreements."},
    {"framework": "ISO27001", "control_id": "ISO-A.13.1.3", "title": "Segregation in Networks", "description": "Groups of information services, users, and information systems must be segregated on networks."},

    # -------------------------------------------------------------------------
    # PCI DSS v4.0
    # -------------------------------------------------------------------------
    {"framework": "PCI_DSS", "control_id": "PCI-1.1.6", "title": "Review Firewall and Router Rule Sets", "description": "Review network configuration and security group rule sets at least once every six months."},
    {"framework": "PCI_DSS", "control_id": "PCI-1.2.1", "title": "Restrict Inbound and Outbound Traffic", "description": "Restrict inbound and outbound traffic to that which is necessary for the cardholder data environment."},
    {"framework": "PCI_DSS", "control_id": "PCI-1.3.1", "title": "Inbound Traffic Limited to Required Protocols", "description": "Inbound traffic is limited to only necessary protocols, ports, and designated application components."},
    {"framework": "PCI_DSS", "control_id": "PCI-1.3.2", "title": "Limit Inbound & Outbound Internet Traffic", "description": "Limit inbound and outbound internet traffic to IP addresses that are explicitly verified and authorized."},
    {"framework": "PCI_DSS", "control_id": "PCI-1.3.4", "title": "Do Not Allow Direct Public Access to Data Stores", "description": "Do not allow direct public access between the internet and any system component in the cardholder data environment."},
    {"framework": "PCI_DSS", "control_id": "PCI-1.3.7", "title": "Do Not Disclose Private IP Addresses", "description": "Do not disclose private IP addresses and routing information to unauthorized internal or external entities."},
    {"framework": "PCI_DSS", "control_id": "PCI-2.2.2", "title": "Enable Only Necessary Protocols (No Open SSH)", "description": "Enable only necessary services, protocols, and daemons; all unnecessary functions must be disabled."},
    {"framework": "PCI_DSS", "control_id": "PCI-2.2.3", "title": "Configure System Security Parameters", "description": "Configure system security parameters to prevent misuse, such as disabling administrative ports (RDP 3389)."},
    {"framework": "PCI_DSS", "control_id": "PCI-3.4", "title": "Render Cardholder Data Unreadable at Rest", "description": "Render cardholder data unreadable anywhere it is stored by using strong cryptography with associated key-management processes."},
    {"framework": "PCI_DSS", "control_id": "PCI-3.4.1", "title": "Store Cryptographic Keys Securely", "description": "Protect cryptographic keys used to encrypt cardholder data against both disclosure and misuse."},
    {"framework": "PCI_DSS", "control_id": "PCI-6.5.8", "title": "Protect Against SSRF / Cross-Site Request Forgery", "description": "Protect against server-side request forgery (SSRF) by enforcing metadata token protection (IMDSv2)."},
    {"framework": "PCI_DSS", "control_id": "PCI-7.1", "title": "Limit Access to System Components", "description": "Limit access to system components and cardholder data to only those individuals whose jobs require such access."},
    {"framework": "PCI_DSS", "control_id": "PCI-7.2", "title": "Establish Access Control System", "description": "Establish an access control system for systems components that restricts access based on a user's need to know."},
    {"framework": "PCI_DSS", "control_id": "PCI-8.1.4", "title": "Remove Inactive User Accounts", "description": "Remove or disable inactive user accounts within 90 days of inactivity."},
    {"framework": "PCI_DSS", "control_id": "PCI-8.2.4", "title": "Change User Passwords & Keys Periodically", "description": "Change user passwords and API access keys at least once every 90 days."},
    {"framework": "PCI_DSS", "control_id": "PCI-8.3", "title": "Incorporate Multi-Factor Authentication", "description": "Incorporate multi-factor authentication (MFA) for all administrative personnel and console access."},
    {"framework": "PCI_DSS", "control_id": "PCI-10.1", "title": "Implement Audit Trails for All Access", "description": "Implement audit trails to link all access to system components to each individual user."},
    {"framework": "PCI_DSS", "control_id": "PCI-10.2", "title": "Implement Automated Audit Trails", "description": "Implement automated audit trails for all system components to reconstruct events."},
    {"framework": "PCI_DSS", "control_id": "PCI-10.5", "title": "Secure Audit Trails from Alteration", "description": "Secure audit trails so they cannot be altered; use log file integrity validation."},
    {"framework": "PCI_DSS", "control_id": "PCI-10.5.5", "title": "Use File Integrity Monitoring & Data Protection", "description": "Use file-integrity monitoring or change-detection software on logs and sensitive data stores."},
]

# Mapping of every detection rule to corresponding framework controls
RULE_COMPLIANCE_MAPPINGS: Dict[str, Dict[str, str]] = {
    # -------------------------------------------------------------------------
    # S3 Rules
    # -------------------------------------------------------------------------
    "S3-001": {
        "CIS_AWS": "CIS-2.1.5",
        "NIST": "NIST-AC-3",
        "ISO27001": "ISO-A.9.4.1",
        "PCI_DSS": "PCI-1.3.4",
    },
    "S3-002": {
        "CIS_AWS": "CIS-2.1.1",
        "NIST": "NIST-SC-13",
        "ISO27001": "ISO-A.10.1.1",
        "PCI_DSS": "PCI-3.4",
    },
    "S3-003": {
        "CIS_AWS": "CIS-2.1.3",
        "NIST": "NIST-CP-9",
        "ISO27001": "ISO-A.12.3.1",
        "PCI_DSS": "PCI-10.5.5",
    },
    "S3-004": {
        "CIS_AWS": "CIS-2.1.4",
        "NIST": "NIST-AU-2",
        "ISO27001": "ISO-A.12.4.1",
        "PCI_DSS": "PCI-10.1",
    },
    "S3-005": {
        "CIS_AWS": "CIS-2.1.5",
        "NIST": "NIST-AC-4",
        "ISO27001": "ISO-A.9.4.2",
        "PCI_DSS": "PCI-1.2.1",
    },

    # -------------------------------------------------------------------------
    # IAM Rules
    # -------------------------------------------------------------------------
    "IAM-001": {
        "CIS_AWS": "CIS-1.5",
        "NIST": "NIST-IA-2",
        "ISO27001": "ISO-A.9.4.2",
        "PCI_DSS": "PCI-8.3",
    },
    "IAM-002": {
        "CIS_AWS": "CIS-1.16",
        "NIST": "NIST-AC-6",
        "ISO27001": "ISO-A.9.2.3",
        "PCI_DSS": "PCI-7.1",
    },
    "IAM-003": {
        "CIS_AWS": "CIS-1.14",
        "NIST": "NIST-IA-5",
        "ISO27001": "ISO-A.9.4.3",
        "PCI_DSS": "PCI-8.2.4",
    },
    "IAM-004": {
        "CIS_AWS": "CIS-1.12",
        "NIST": "NIST-AC-2",
        "ISO27001": "ISO-A.9.2.6",
        "PCI_DSS": "PCI-8.1.4",
    },
    "IAM-005": {
        "CIS_AWS": "CIS-1.1",
        "NIST": "NIST-AC-2",
        "ISO27001": "ISO-A.9.2.1",
        "PCI_DSS": "PCI-7.2",
    },

    # -------------------------------------------------------------------------
    # EC2 Rules
    # -------------------------------------------------------------------------
    "EC2-001": {
        "CIS_AWS": "CIS-5.1",
        "NIST": "NIST-AC-4",
        "ISO27001": "ISO-A.13.1.1",
        "PCI_DSS": "PCI-1.3",
    },
    "EC2-002": {
        "CIS_AWS": "CIS-5.2",
        "NIST": "NIST-SC-7",
        "ISO27001": "ISO-A.13.1.2",
        "PCI_DSS": "PCI-2.2.2",
    },
    "EC2-003": {
        "CIS_AWS": "CIS-5.3",
        "NIST": "NIST-SC-7",
        "ISO27001": "ISO-A.13.1.2",
        "PCI_DSS": "PCI-2.2.3",
    },
    "EC2-004": {
        "CIS_AWS": "CIS-2.2.1",
        "NIST": "NIST-SC-28",
        "ISO27001": "ISO-A.10.1.1",
        "PCI_DSS": "PCI-3.4.1",
    },
    "EC2-005": {
        "CIS_AWS": "CIS-5.4",
        "NIST": "NIST-SI-4",
        "ISO27001": "ISO-A.12.6.1",
        "PCI_DSS": "PCI-6.5.8",
    },

    # -------------------------------------------------------------------------
    # Network / VPC Rules
    # -------------------------------------------------------------------------
    "NET-001": {
        "CIS_AWS": "CIS-5.2",
        "NIST": "NIST-SC-7",
        "ISO27001": "ISO-A.13.1.1",
        "PCI_DSS": "PCI-1.2",
    },
    "NET-002": {
        "CIS_AWS": "CIS-5.3",
        "NIST": "NIST-SC-7",
        "ISO27001": "ISO-A.13.1.1",
        "PCI_DSS": "PCI-1.2.1",
    },
    "NET-003": {
        "CIS_AWS": "CIS-5.1",
        "NIST": "NIST-CM-7",
        "ISO27001": "ISO-A.13.1.3",
        "PCI_DSS": "PCI-1.3.1",
    },
    "NET-004": {
        "CIS_AWS": "CIS-5.1",
        "NIST": "NIST-AC-4",
        "ISO27001": "ISO-A.13.1.1",
        "PCI_DSS": "PCI-1.1.6",
    },
    "NET-005": {
        "CIS_AWS": "CIS-5.5",
        "NIST": "NIST-SC-7",
        "ISO27001": "ISO-A.13.1.1",
        "PCI_DSS": "PCI-1.3.2",
    },

    # -------------------------------------------------------------------------
    # CloudTrail Rules
    # -------------------------------------------------------------------------
    "CT-001": {
        "CIS_AWS": "CIS-3.1",
        "NIST": "NIST-AU-12",
        "ISO27001": "ISO-A.12.4.1",
        "PCI_DSS": "PCI-10.1",
    },
    "CT-002": {
        "CIS_AWS": "CIS-3.2",
        "NIST": "NIST-AU-9",
        "ISO27001": "ISO-A.12.4.3",
        "PCI_DSS": "PCI-10.5",
    },
    "CT-003": {
        "CIS_AWS": "CIS-3.1",
        "NIST": "NIST-AU-3",
        "ISO27001": "ISO-A.12.4.1",
        "PCI_DSS": "PCI-10.2",
    },

    # -------------------------------------------------------------------------
    # RDS Rules
    # -------------------------------------------------------------------------
    "RDS-001": {
        "CIS_AWS": "CIS-2.3.1",
        "NIST": "NIST-AC-3",
        "ISO27001": "ISO-A.13.1.3",
        "PCI_DSS": "PCI-1.3.7",
    },
    "RDS-002": {
        "CIS_AWS": "CIS-2.3.2",
        "NIST": "NIST-SC-28",
        "ISO27001": "ISO-A.10.1.1",
        "PCI_DSS": "PCI-3.4",
    },
    "RDS-003": {
        "CIS_AWS": "CIS-2.3.3",
        "NIST": "NIST-SC-7",
        "ISO27001": "ISO-A.13.1.1",
        "PCI_DSS": "PCI-1.3.1",
    },
}
