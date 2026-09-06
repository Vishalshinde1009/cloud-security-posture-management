# CSPM Security Rules Catalog & Detection Architecture

## 1. Overview
The Cloud Security Posture Management (CSPM) platform enforces a modular, detection-only security rule engine. Each rule is implemented as an independent Python class inheriting from `BaseRule` ([`base.py`](file:///c:/Users/LENOVO/OneDrive/Documents/ChatGPT/project-ESE/backend/app/scanner/rules/base.py)), evaluating normalized configuration dictionaries extracted from cloud resources.

### Architectural Principles
- **Evidence-Backed Detections**: A rule must never fire simply because a resource exists. Every finding must extract and store the offending configuration snippet as proof (e.g., specific CIDR ranges, open ports, or missing encryption blocks).
- **Zero Resource Mutation**: Rules are pure functions of configuration state. They never modify, delete, or reconfigure cloud assets.
- **Fault-Tolerant Execution**: The `RuleExecutor` wraps each rule execution in localized exception containment. An error in one rule never interrupts the scan or prevents other rules from evaluating.
- **Deterministic Deduplication**: Findings are fingerprinted using `sha256(f"{cloud_account_id}:{resource_id}:{rule_id}")`. Re-running scans updates `last_detected` without creating duplicate records. When a resource is reconfigured and becomes compliant, its finding transitions to `RESOLVED`.

---

## 2. Rule Catalog (26 Detection Rules)

### 2.1 Amazon S3 Storage
| Rule ID | Rule Name | Severity | Category | Target Resource | Detection Logic | CIS Reference |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **S3-001** | S3 bucket allows public access | `CRITICAL` | Data Exposure | `aws_s3_bucket` | Checks `PublicAccessBlockConfiguration`: flags if block is missing or any of `BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets` is `False`. | CIS 2.1.5 |
| **S3-002** | S3 bucket missing default server-side encryption | `HIGH` | Encryption | `aws_s3_bucket` | Checks `ServerSideEncryptionConfiguration`: flags if `Rules` are empty or `SSEAlgorithm` is missing. | CIS 2.1.1 |
| **S3-003** | S3 bucket versioning is disabled | `MEDIUM` | Configuration Management | `aws_s3_bucket` | Checks `Versioning.Status`: flags if status is not explicitly `Enabled`. | Best Practice |
| **S3-004** | S3 bucket server access logging not configured | `MEDIUM` | Logging & Monitoring | `aws_s3_bucket` | Checks `Logging.TargetBucket`: flags if logging configuration is null or target bucket is undefined. | CIS 2.1.3 |
| **S3-005** | S3 bucket policy contains insecure permissions | `HIGH` | Data Exposure | `aws_s3_bucket` | Inspects `Policy.Statement`: flags `Effect: Allow` granted to `Principal: *` without condition restrictions. | Best Practice |

### 2.2 AWS Identity & Access Management (IAM)
| Rule ID | Rule Name | Severity | Category | Target Resource | Detection Logic | CIS Reference |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **IAM-001** | IAM user without Multi-Factor Authentication (MFA) | `HIGH` | Identity & Access | `aws_iam_user` | Checks `MFADevices`: flags console users having an empty list of active MFA tokens. | CIS 1.5 |
| **IAM-002** | IAM entity has overly broad administrative permissions | `CRITICAL` | Identity & Access | `aws_iam_user` | Checks `AttachedPolicies`: flags users directly attached with `AdministratorAccess` or wildcard policies. | CIS 1.16 |
| **IAM-003** | IAM access keys not rotated within 90 days | `MEDIUM` | Credential Security | `aws_iam_user` | Checks `AccessKeys`: flags any key with `Status: Active` and `AgeDays > 90`. | CIS 1.14 |
| **IAM-004** | IAM credentials inactive or unused | `MEDIUM` | Credential Security | `aws_iam_user` | Checks `AccessKeys`: flags keys marked `Status: Inactive` that should be decommissioned. | CIS 1.12 |
| **IAM-005** | AWS Root account security posture violation | `CRITICAL` | Identity & Access | `aws_iam_root` | Checks `AccountMFAEnabled` (must be `True`) and `RootAccessKeysPresent` (must be `False`). | CIS 1.1 |

### 2.3 Amazon EC2 Compute
| Rule ID | Rule Name | Severity | Category | Target Resource | Detection Logic | CIS Reference |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **EC2-001** | EC2 instance associated with unrestricted security group | `HIGH` | Network Security | `aws_ec2_instance` | Inspects `SecurityGroups`: flags instances attached to security groups named or configured as unrestricted. | Best Practice |
| **EC2-002** | EC2 instance allows unrestricted inbound SSH (port 22) | `HIGH` | Network Security | `aws_ec2_instance` | Flags instances with public IPs attached to security groups allowing inbound port 22 from `0.0.0.0/0`. | CIS 5.2 |
| **EC2-003** | EC2 instance allows unrestricted inbound RDP (port 3389) | `HIGH` | Network Security | `aws_ec2_instance` | Flags instances attached to security groups allowing inbound port 3389 from `0.0.0.0/0`. | CIS 5.3 |
| **EC2-004** | EC2 instance has unencrypted attached EBS volumes | `HIGH` | Encryption | `aws_ec2_instance` | Inspects `BlockDeviceMappings`: flags instances with any volume where `Ebs.Encrypted == False`. | CIS 2.2.1 |
| **EC2-005** | EC2 instance assigned public IP with legacy IMDSv1 | `HIGH` | Network Security | `aws_ec2_instance` | Flags public instances (`PublicIpAddress != None`) with `MetadataOptions.HttpTokens != 'required'`. | Best Practice |

### 2.4 Amazon VPC / Security Groups
| Rule ID | Rule Name | Severity | Category | Target Resource | Detection Logic | CIS Reference |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **NET-001** | Security group allows unrestricted inbound SSH (port 22) | `HIGH` | Network Security | `aws_security_group` | Inspects `IpPermissions`: flags ingress rules opening port 22 to `0.0.0.0/0` or `::/0`. | CIS 5.2 |
| **NET-002** | Security group allows unrestricted inbound RDP (port 3389) | `HIGH` | Network Security | `aws_security_group` | Inspects `IpPermissions`: flags ingress rules opening port 3389 to `0.0.0.0/0` or `::/0`. | CIS 5.3 |
| **NET-003** | Security group exposes sensitive database/admin ports | `HIGH` | Network Security | `aws_security_group` | Inspects `IpPermissions`: flags ingress rules opening ports 23, 3306, 5432, 1433, or 27017 to `0.0.0.0/0`. | Best Practice |
| **NET-004** | Security group allows unrestricted ingress on all ports | `HIGH` | Network Security | `aws_security_group` | Inspects `IpPermissions`: flags rules with `IpProtocol: -1` or port range `0-65535` from `0.0.0.0/0`. | Best Practice |
| **NET-005** | Security group allows unrestricted outbound Telnet | `MEDIUM` | Network Security | `aws_security_group` | Inspects `IpPermissionsEgress`: flags egress rules allowing unencrypted port 23 to `0.0.0.0/0`. | Best Practice |

### 2.5 AWS CloudTrail
| Rule ID | Rule Name | Severity | Category | Target Resource | Detection Logic | CIS Reference |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **CT-001** | CloudTrail trail is not actively logging | `HIGH` | Logging & Monitoring | `aws_cloudtrail_trail` | Inspects `Status.IsLogging`: flags audit trails where logging is stopped (`False`). | CIS 3.1 |
| **CT-002** | CloudTrail log file validation is disabled | `HIGH` | Logging & Monitoring | `aws_cloudtrail_trail` | Inspects `LogFileValidationEnabled`: flags trails where cryptographic validation is disabled. | CIS 3.2 |
| **CT-003** | CloudTrail trail is not configured for multi-region logging | `MEDIUM` | Logging & Monitoring | `aws_cloudtrail_trail` | Inspects `IsMultiRegionTrail`: flags single-region trails (`False`). | CIS 3.1 |

### 2.6 Amazon RDS Databases
| Rule ID | Rule Name | Severity | Category | Target Resource | Detection Logic | CIS Reference |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **RDS-001** | RDS database instance is publicly accessible | `CRITICAL` | Database Security | `aws_rds_instance` | Inspects `PubliclyAccessible`: flags instances where public internet exposure is enabled (`True`). | CIS 2.3.1 |
| **RDS-002** | RDS database storage encryption is disabled | `HIGH` | Encryption | `aws_rds_instance` | Inspects `StorageEncrypted`: flags instances where KMS storage encryption at rest is disabled (`False`). | CIS 2.3.2 |
| **RDS-003** | RDS database associated with insecure open security group | `HIGH` | Database Security | `aws_rds_instance` | Inspects `VpcSecurityGroups`: flags databases attached to publicly open security groups. | Best Practice |

---

## 3. Resource Posture Derivation

The posture status of every cloud resource (`Resource.security_status`) is dynamically derived from its open findings:

```text
Open Findings on Resource:
  ├─ Any CRITICAL finding exists  ──────────>  CRITICAL
  ├─ Any HIGH or MEDIUM finding exists ────>  AT_RISK
  └─ No open findings exist  ───────────────>  SECURE
```
