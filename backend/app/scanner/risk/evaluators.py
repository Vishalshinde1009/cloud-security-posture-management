"""
Transparent, deterministic risk factor evaluators for CSPM findings.
Calculates normalized factor scores (0-100) and contextual reasons for each dimension:
- Base Severity (40%)
- Internet Exposure (20%)
- Asset Criticality (15%)
- Exploitability (10%)
- Data Sensitivity (10%)
- Configuration Weakness (5%)
"""

from typing import Dict, Any, Tuple, Optional


SEVERITY_BASE_SCORES: Dict[str, int] = {
    "CRITICAL": 100,
    "HIGH": 80,
    "MEDIUM": 55,
    "LOW": 25,
    "INFORMATIONAL": 0,
    "INFO": 0,
}


def evaluate_severity(severity: str) -> int:
    """
    Evaluates the base severity factor (0-100) from rule definition.
    CRITICAL = 100, HIGH = 80, MEDIUM = 55, LOW = 25.
    """
    return SEVERITY_BASE_SCORES.get(severity.upper(), 50)


def evaluate_exposure(
    resource_type: str,
    configuration: Dict[str, Any],
    evidence: Dict[str, Any],
    rule_id: str,
) -> Tuple[int, str]:
    """
    Evaluates exposure factor (0-100) based strictly on configuration evidence.
    - Internet-wide exposure (0.0.0.0/0, broad public access): 100
    - Broad public exposure (public IP, public block disabled): 90
    - Publicly reachable (public subnet, IGW attached, DB publicly accessible): 80
    - Internal network (private VPC, restricted CIDRs): 40
    - Private/internal (IAM, private subnet): 10
    - Unknown: 30
    """
    rule_upper = rule_id.upper()
    cidr = evidence.get("cidr") or evidence.get("exposed_cidr")

    # Internet-wide exposure checks
    if cidr in ["0.0.0.0/0", "::/0"] or rule_upper in ["NET-001", "NET-002", "NET-004", "EC2-002", "EC2-003"]:
        return 100, "Internet-wide exposure (0.0.0.0/0 unrestricted ingress)"

    if rule_upper == "S3-001":
        return 100, "Internet-wide public read/write access allowed by bucket policy or ACL"

    if rule_upper == "RDS-001" or configuration.get("publicly_accessible") is True:
        # Check if also open to internet
        if cidr == "0.0.0.0/0" or any(rule.get("cidr") == "0.0.0.0/0" for rule in evidence.get("rules", [])):
            return 100, "Database is publicly accessible with unrestricted internet ingress"
        return 80, "Database is configured as publicly reachable"

    # Broad public exposure checks
    if rule_upper == "EC2-005":
        # IMDSv1 on public instance
        if configuration.get("public_ip"):
            return 90, "Publicly reachable instance running legacy IMDSv1 metadata service"
        return 60, "Instance running legacy IMDSv1 metadata service"

    if configuration.get("public_ip"):
        return 90, "Public IP address assigned to resource"

    # Public block disabled on S3
    if configuration.get("public_access_block", {}).get("block_public_acls") is False:
        return 90, "S3 Public Access Block protections disabled"

    # Sensitive ports check
    if rule_upper in ["NET-003", "RDS-003"]:
        return 85, "Sensitive database/administrative port exposed to external network"

    # Internal network vs Private
    if "vpc" in resource_type.lower() or "subnet" in resource_type.lower() or "ec2" in resource_type.lower():
        if not configuration.get("public_ip"):
            return 40, "Contained within private or internal VPC network"

    if "iam" in resource_type.lower() or "cloudtrail" in resource_type.lower():
        return 10, "Internal cloud management plane (no direct data-plane network ingress)"

    if "s3" in resource_type.lower():
        return 30, "Cloud storage resource without verified public policy"

    return 30, "Default baseline exposure for unclassified asset"


def evaluate_asset_criticality(
    resource_type: str,
    resource_name: Optional[str],
    tags: Dict[str, Any],
    configuration: Dict[str, Any],
    rule_id: str,
) -> Tuple[int, str]:
    """
    Evaluates asset criticality (0-100) from environment metadata, tags, and role.
    - CRITICAL (100): Root account, Production Database
    - HIGH (80): Production Compute / Storage / Security Groups
    - MEDIUM (60): Staging / Development Assets
    - LOW (30): Test / Sandbox Assets
    - UNKNOWN (50): Default when environment metadata is indeterminate
    """
    name_lower = (resource_name or "").lower()
    tags_lower = {str(k).lower(): str(v).lower() for k, v in tags.items()}
    env_tag = tags_lower.get("environment") or tags_lower.get("env") or tags_lower.get("stage")

    # Root Account is always CRITICAL
    if rule_id.upper() == "IAM-005" or name_lower == "root" or "root" in name_lower:
        return 100, "Root account identity credential (maximum blast radius)"

    # Production Database
    is_prod = env_tag in ["prod", "production"] or "prod" in name_lower
    if "rds" in resource_type.lower() or "database" in resource_type.lower():
        if is_prod:
            return 100, "Production relational database instance hosting critical operational data"
        return 80, "Relational database instance"

    # Production resource
    if is_prod:
        return 80, "Resource explicitly tagged or identified as a Production workload"

    # Test / Sandbox
    is_test = env_tag in ["test", "sandbox", "qa", "devtest"] or any(
        sub in name_lower for sub in ["test", "sandbox", "temp"]
    )
    if is_test:
        return 30, "Resource tagged or identified as non-production test/sandbox environment"

    # Dev / Staging
    is_dev = env_tag in ["dev", "development", "stage", "staging"] or any(
        sub in name_lower for sub in ["dev", "stage"]
    )
    if is_dev:
        return 60, "Resource tagged or identified as development/staging environment"

    # Core infrastructure defaults
    if "iam" in resource_type.lower():
        return 70, "Core IAM security credential/identity resource"

    return 50, "Asset environment unclassified (baseline criticality applied)"


def evaluate_exploitability(
    resource_type: str,
    configuration: Dict[str, Any],
    evidence: Dict[str, Any],
    rule_id: str,
    severity: str,
) -> Tuple[int, str]:
    """
    Evaluates exploitability factor (0-100).
    - Direct internet exposure + admin service (SSH/RDP/DB): 95
    - Public data exposure (S3 public, unencrypted DB): 85
    - Wildcard admin policy: 90
    - Internal configuration weakness: 55
    - Low-impact configuration issue: 30
    - Unknown/Default: 50
    """
    rule_upper = rule_id.upper()

    # Direct internet admin exposure
    if rule_upper in ["NET-001", "NET-002", "EC2-002", "EC2-003"]:
        return 95, "Administrative port (SSH/RDP) directly reachable by unauthenticated internet scanners"

    if rule_upper == "NET-004":
        return 95, "Unrestricted ingress for all protocols and ports allows broad adversarial reconnaissance"

    if rule_upper == "IAM-002":
        return 90, "Overly permissive wildcard ('*') admin policy enables instant privilege escalation"

    if rule_upper == "S3-001":
        return 85, "Public bucket policy permits anonymous unauthenticated object reads or writes"

    if rule_upper in ["RDS-001", "RDS-003"]:
        return 85, "Database endpoint exposed directly or to broad external ingress"

    if rule_upper == "EC2-005":
        return 80, "IMDSv1 susceptible to SSRF-based metadata and credential theft"

    if rule_upper in ["IAM-001", "IAM-005"]:
        return 70, "Missing MFA weakens authentication against credential stuffing and brute-force attacks"

    if rule_upper in ["EC2-004", "RDS-002", "S3-002"]:
        return 55, "Data at rest stored without encryption; accessible upon physical or volume snapshot compromise"

    if rule_upper in ["IAM-003", "IAM-004"]:
        return 50, "Stale or unrotated credentials increase window of opportunity for leaked keys"

    if rule_upper in ["CT-001", "CT-002", "CT-003"]:
        return 40, "Audit logging disabled; hinders security incident detection and forensic analysis"

    if rule_upper in ["S3-003", "S3-004", "NET-005"]:
        return 30, "Configuration hygiene issue with limited immediate direct exploitation vector"

    return 50, "Standard exploitability based on configuration flaw"


def evaluate_data_sensitivity(
    resource_type: str,
    resource_name: Optional[str],
    tags: Dict[str, Any],
    configuration: Dict[str, Any],
) -> Tuple[int, str]:
    """
    Evaluates whether the affected resource stores or processes sensitive data (0-100).
    - HIGH (90): Confirmed RDS databases, S3 buckets with data/customer/backup tags
    - MEDIUM-HIGH (70): IAM credentials, authentication materials
    - MEDIUM (50): General S3 buckets, EBS storage volumes
    - LOW (25): Network security groups, VPCs, compute instances without data roles
    - UNKNOWN (50): Default
    """
    name_lower = (resource_name or "").lower()
    tags_lower = {str(k).lower(): str(v).lower() for k, v in tags.items()}
    res_type_lower = resource_type.lower()

    sensitive_keywords = ["data", "db", "customer", "backup", "finance", "pii", "payment", "user", "order", "prod"]

    # RDS instances always represent data persistence
    if "rds" in res_type_lower or "database" in res_type_lower:
        if any(kw in name_lower for kw in sensitive_keywords):
            return 90, "Database instance designated for sensitive business or operational records"
        return 80, "Relational database instance hosting structured application data"

    # S3 buckets with sensitive keywords
    if "s3" in res_type_lower or "bucket" in res_type_lower:
        if any(kw in name_lower for kw in sensitive_keywords):
            return 90, "Storage bucket designated for customer records, backups, or business data"
        if any(kw in str(tags_lower) for kw in sensitive_keywords):
            return 85, "Storage bucket explicitly tagged with sensitive data classification"
        return 50, "General cloud object storage repository"

    # IAM Credentials
    if "iam" in res_type_lower:
        return 70, "Identity resource managing API access keys or authentication credentials"

    # EBS Volumes
    if "volume" in res_type_lower or "ebs" in res_type_lower:
        return 50, "Block storage volume persisting virtual machine filesystem state"

    # Network infrastructure
    res_clean = res_type_lower.replace("_", "")
    if any(term in res_clean for term in ["securitygroup", "network", "vpc", "subnet"]):
        return 20, "Network routing or packet filtering infrastructure (non-data resource)"

    # Compute
    if "instance" in res_clean or "ec2" in res_clean:
        if any(kw in name_lower for kw in sensitive_keywords):
            return 60, "Compute instance associated with sensitive application workload"
        return 35, "Stateless or standard compute workload"

    return 50, "Standard data sensitivity classification"


def evaluate_config_weakness(
    rule_id: str,
    evidence: Dict[str, Any],
    severity: str,
    configuration: Dict[str, Any],
) -> Tuple[int, str]:
    """
    Evaluates the severity of the configuration deviation (0-100).
    - Extreme / compounded deviation: 95
    - Direct unrestricted exposure or full admin wildcard: 90
    - Missing encryption at rest: 75
    - Missing MFA: 70
    - Missing versioning: 50
    - Missing logging: 30
    """
    rule_upper = rule_id.upper()

    # Compounded failure: Public DB + unencrypted
    if rule_upper == "RDS-001" and configuration.get("storage_encrypted") is False:
        return 95, "Compounded configuration vulnerability: public exposure combined with unencrypted storage"

    if rule_upper in ["NET-004", "EC2-002", "EC2-003", "NET-001", "NET-002"]:
        return 90, "Critical network perimeter violation allowing unrestricted ingress"

    if rule_upper == "IAM-002":
        return 90, "Severe IAM misconfiguration granting full administrative privileges"

    if rule_upper in ["S3-001", "RDS-001"]:
        return 85, "Severe access control failure exposing private resource to the public internet"

    if rule_upper in ["EC2-004", "RDS-002", "S3-002"]:
        return 75, "Cryptographic failure: default server-side encryption disabled"

    if rule_upper in ["IAM-001", "IAM-005"]:
        return 70, "Identity failure: missing multi-factor authentication on privileged identity"

    if rule_upper == "EC2-005":
        return 70, "Architectural flaw: legacy IMDSv1 hop allowed on instance"

    if rule_upper in ["CT-001", "CT-002", "CT-003"]:
        return 60, "Audit logging disabled or integrity checking absent across regions"

    if rule_upper in ["IAM-003", "IAM-004"]:
        return 55, "Credential hygiene deviation: stale unrotated access keys"

    if rule_upper == "S3-003":
        return 50, "Missing data resilience protection: object versioning disabled"

    if rule_upper in ["S3-004", "NET-005"]:
        return 30, "Observability or non-critical configuration deviation"

    return 50, "Standard misconfiguration deviation"
