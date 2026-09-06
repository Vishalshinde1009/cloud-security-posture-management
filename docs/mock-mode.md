# CSPM Mock Mode & Safe Demonstration Environment

## 1. Purpose of Mock Mode

The **Mock Provider** allows students, evaluators, developers, and CI/CD pipelines to run full end-to-end CSPM security scans without requiring active AWS accounts, paid cloud infrastructure, or internet connectivity.

### Guardrails & Safety Guarantees
- **Zero AWS Credentials Required**: Mock mode does not read, request, or require AWS access keys, secret keys, or IAM roles.
- **Offline & Deterministic**: Runs entirely offline with deterministic results. Tests and demonstrations behave identically on all machines.
- **Explicit Provenance Labeling**: All generated assets and database records explicitly carry `provider: "MOCK"` and are bound to the simulated account `mock-account-001`.
- **Realistic AWS Schemas**: Configurations match the exact response structures returned by the official AWS SDK (`boto3`), including nested objects like `PublicAccessBlockConfiguration`, `ServerSideEncryptionConfiguration`, `IpPermissions`, and `MFADevices`.

---

## 2. Simulated Cloud Asset Inventory

The `MockProvider` simulates 17+ assets across 6 core AWS services, intentionally providing a mix of compliant and misconfigured resources to exercise the detection pipeline:

### 1. Amazon S3 Storage
| Resource Name | Configuration Highlights | Expected Status |
| :--- | :--- | :--- |
| `secure-production-bucket` | Block Public Access enabled, SSE-AES256 encryption, Versioning enabled, SSL enforced | `SECURE` |
| `public-test-bucket` | Public access block disabled, no server-side encryption, public read policy | `AT_RISK` |
| `unencrypted-storage-bucket`| Public access blocked, but unencrypted at rest | `AT_RISK` |

### 2. AWS Identity and Access Management (IAM)
| Resource Name | Configuration Highlights | Expected Status |
| :--- | :--- | :--- |
| `root-account-config` | Root account without MFA active, root access keys present | `AT_RISK` |
| `admin-user` | Hardware MFA active, password policy compliant, access keys rotated | `SECURE` |
| `analyst-user` | Virtual MFA active, access keys rotated within 30 days | `SECURE` |
| `developer-user-no-mfa` | No MFA devices registered, active access key > 120 days old | `AT_RISK` |
| `service-account-ci` | Machine user without console password, keys active | `SECURE` |

### 3. Amazon Elastic Compute Cloud (EC2)
| Resource Name | Configuration Highlights | Expected Status |
| :--- | :--- | :--- |
| `prod-api-server-01` | Private IP only, IMDSv2 required, EBS volume encrypted | `SECURE` |
| `dev-test-instance-01` | Public IPv4 assigned, unencrypted root EBS volume | `AT_RISK` |
| `internal-worker-node` | Private subnet, encrypted volumes, no public IP | `SECURE` |

### 4. Amazon Virtual Private Cloud (VPC & Security Groups)
| Resource Name | Configuration Highlights | Expected Status |
| :--- | :--- | :--- |
| `web-tier-sg` | Ingress limited to HTTP (80) and HTTPS (443) from `0.0.0.0/0` | `SECURE` |
| `unrestricted-ssh-sg` | Ingress allows SSH (port 22) from `0.0.0.0/0` | `AT_RISK` |
| `database-internal-sg`| Ingress allows PostgreSQL (port 5432) only from VPC CIDR `10.0.0.0/16` | `SECURE` |
| `exposed-mysql-sg` | Ingress allows MySQL (port 3306) from `0.0.0.0/0` | `AT_RISK` |

### 5. AWS CloudTrail Audit Logging
| Resource Name | Configuration Highlights | Expected Status |
| :--- | :--- | :--- |
| `organization-audit-trail` | Multi-region trail, active logging, log file validation enabled, KMS encrypted | `SECURE` |
| `unencrypted-dev-trail` | Single-region trail, logging stopped, unencrypted S3 bucket | `AT_RISK` |

### 6. Amazon Relational Database Service (RDS)
| Resource Name | Configuration Highlights | Expected Status |
| :--- | :--- | :--- |
| `production-aurora-cluster`| Multi-AZ enabled, storage encrypted with KMS, publicly inaccessible | `SECURE` |
| `test-legacy-postgres-db` | `PubliclyAccessible: True`, storage unencrypted, automated backups disabled | `AT_RISK` |

---

## 3. Switching Between Modes

The platform's execution mode is controlled via the `CSPM_MODE` environment variable:

```env
# Safe Offline Mock Mode (Default)
CSPM_MODE=mock

# Real Read-Only Cloud Mode (requires AWS credentials in .env)
# CSPM_MODE=aws
```

When `CSPM_MODE=mock`:
- All scan triggers automatically use `MockProvider`.
- No outbound network connections to AWS endpoints are made.
- The UI displays the persistent badge **`MOCK / DEMO MODE`**.
