# Cloud Security Posture Management (CSPM) — Final Architecture

## System Architecture Overview

The CSPM platform is a production-grade cloud security system designed to discover cloud assets, detect security misconfigurations, calculate explainable risk scores, map findings to compliance frameworks, and present actionable intelligence via a modern Security Operations Center (SOC) dashboard.

```
+-------------------------------------------------------------------------+
|                        Frontend SOC Dashboard                           |
|      (React 18 + TypeScript + Vite + Tailwind CSS + Lucide Icons)       |
|                                                                         |
|  [Posture & Delta]  [Risk Breakdown]  [Compliance Matrix]  [Audit Logs] |
|  [Findings Triage]  [Report Engine]   [Rules Config]       [Alert Bell] |
+------------------------------------+------------------------------------+
                                     |  REST API (JWT Auth + RBAC)
+------------------------------------v------------------------------------+
|                         FastAPI Application                             |
|                                                                         |
|  +--------------------+  +--------------------+  +-------------------+  |
|  |  Auth & RBAC       |  | Findings & Triage  |  | Reports & PDF     |  |
|  |  (ADMIN/ANALYST/   |  | (Lifecycle & Notes |  | (ReportLab        |  |
|  |   VIEWER)          |  |  Sanitization)     |  |  Platypus Engine) |  |
|  +--------------------+  +--------------------+  +-------------------+  |
|  +--------------------+  +--------------------+  +-------------------+  |
|  | Compliance Engine  |  | Scheduler Service  |  | Audit Logger      |  |
|  | (CIS, NIST, ISO,   |  | (MANUAL/DAILY/     |  | (Immutable Event  |  |
|  |  PCI DSS Matrix)   |  |  WEEKLY Triggers)  |  |  Trail)           |  |
|  +--------------------+  +--------------------+  +-------------------+  |
+------------------------------------+------------------------------------+
                                     |
+------------------------------------v------------------------------------+
|                      Scanning & Analytics Engine                        |
|                                                                         |
|  1. Provider Layer:                                                     |
|     - MockProvider (Deterministic, Zero AWS Credential Dependency)      |
|     - Real AWS Read-Only Provider (boto3, Strict Read-Only Policy)      |
|                                                                         |
|  2. Discovery & Normalization:                                          |
|     - S3, IAM, EC2, VPC, Security Groups, CloudTrail, RDS               |
|     - Standardized NormalizedResource Schema                            |
|                                                                         |
|  3. Security Rule Engine:                                               |
|     - 26 Deterministic Detection Rules across all 6 core services       |
|     - Reproducible Evidence Extraction & Finding Fingerprinting         |
|                                                                         |
|  4. Explainable Risk Engine:                                            |
|     - Finding Risk Score: 0-100 (Weighted Multi-Factor Formula)         |
|     - Security Posture Score: 0-100 (Asset Count & Severity Decay)      |
|     - Posture Letter Ratings (A through F)                              |
+------------------------------------+------------------------------------+
                                     |
+------------------------------------v------------------------------------+
|                    PostgreSQL Persistence Layer                         |
|                                                                         |
|  - Users & Roles (ADMIN, SECURITY_ANALYST, VIEWER)                      |
|  - Cloud Accounts (Provider Metadata, Region, Read-Only State)          |
|  - Scans & Snapshots (Historical Comparison & Trend Data)               |
|  - Resources (Normalized JSON Configs & Security Status)                |
|  - Findings & Finding Notes (Fingerprint Dedup, Audit History)          |
|  - Compliance Controls & Mappings (4 Framework Catalogs)                |
|  - Audit Logs & In-App Notifications                                    |
+-------------------------------------------------------------------------+
```

---

## Key Subsystems

### 1. Cloud Provider Abstraction
- Abstract base class `CloudProvider` with concrete implementations:
  - `MockProvider`: Pure Python, zero-credential simulation producing realistic cloud configurations.
  - `AWSProvider`: Strict read-only AWS client powered by `boto3`. Strictly prohibits mutating API operations (Delete, Put, Modify, Terminate, Create).

### 2. Detection Rule Registry
- 26 active security rules covering:
  - **IAM**: MFA enforcement, policy wildcards, key age, inactive accounts, root credentials.
  - **S3**: Public read/write permissions, missing default encryption, versioning, access logging, insecure transport policy.
  - **EC2 & VPC**: Overly permissive security groups, open SSH/RDP ports, unencrypted EBS volumes, public IPs.
  - **RDS**: Public accessibility, storage encryption disabled, VPC security group associations.
  - **CloudTrail**: Multi-region trail validation, log integrity, inactive trails.
- Dynamic rule toggle mechanism restricted to `ADMIN` users.

### 3. Risk Scoring & Posture Engine
- Multi-factor deterministic calculation:
  - Formula: $\text{Score} = (\text{Severity} \times 0.35) + (\text{Exposure} \times 0.25) + (\text{Asset Criticality} \times 0.15) + (\text{Exploitability} \times 0.15) + (\text{Data Sensitivity} \times 0.10)$
  - Environment Posture Score: Normalized 0–100 scale showing security health with historical delta tracking ("Previous: X, Current: Y, Change: +Z").

### 4. Compliance Mapping Engine
- Mappings for CIS AWS Foundations, NIST SP 800-53, ISO 27001, and PCI DSS.
- Control status (`COMPLIANT` vs `NON_COMPLIANT`) determined automatically from underlying findings.
- Clear academic disclaimer clarifying posture assessment vs regulatory certification.

### 5. Reporting & Notifications
- Server-side PDF generation using ReportLab Platypus.
- Executive Summary & Technical Deep-Dive reports.
- Zero credential leakage and path-traversal resistant storage.
- Real-time in-app notification alerts for critical findings and scan conclusions.
