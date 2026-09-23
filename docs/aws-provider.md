# AWS Cloud Provider Architecture & Integration Guide

The Cloud Security Posture Management (CSPM) platform integrates with real AWS environments via the `AWSProvider` module (`app/scanner/providers/aws/provider.py`).

---

## 1. Architectural Highlights

```
┌─────────────────────────────────────────────────────────────┐
│                    ScanService Execution                    │
└──────────────────────────────┬──────────────────────────────┘
                               │
               ┌───────────────┴───────────────┐
               ▼                               ▼
    ┌──────────────────────┐        ┌──────────────────────┐
    │     MockProvider     │        │     AWSProvider      │
    │ (Safe Offline Demo)  │        │ (Strict Read-Only)   │
    └──────────────────────┘        └──────────┬───────────┘
                                               │
                                 ┌─────────────┴─────────────┐
                                 ▼                           ▼
                      ┌──────────────────────┐    ┌──────────────────────┐
                      │   AWSClientFactory   │    │   ReadOnlyGuard      │
                      │  (Credential Chain)  │    │ (Zero Mutating Calls)│
                      └──────────┬───────────┘    └──────────────────────┘
                                 │
     ┌───────────────────────────┼───────────────────────────┐
     ▼                           ▼                           ▼
Environment Vars           Named AWS Profile         IAM Role / STS Assume
(AWS_ACCESS_KEY_ID)        (AWS_PROFILE)             (EC2 / ECS / Lambda)
```

---

## 2. Operational Modes (`CSPM_MODE`)

The CSPM platform supports two distinct operation modes, controlled by the environment variable `CSPM_MODE`:

1. **`CSPM_MODE=mock` (Default)**:
   - Evaluates a realistic, deterministic simulated cloud environment across 17+ assets.
   - Zero AWS credentials required.
   - Ideal for CI/CD pipelines, offline academic demonstrations, and deterministic testing.

2. **`CSPM_MODE=aws`**:
   - Executes live, read-only discovery scans against real AWS infrastructure.
   - Connects to S3, IAM, EC2, VPC, CloudTrail, and RDS via `boto3`.
   - Normalizes live metadata into standard `DiscoveredResource` models.
   - Evaluates the normalized configuration against the 26 security rules and Phase 6 risk scoring engine.
   - **Strict Guarantee:** If credentials cannot be found or authenticated, the scan marks itself as `FAILED` with a descriptive error. There is **no silent fallback** to mock mode.

---

## 3. Credential Resolution Chain

The platform uses the standard AWS credential chain via `boto3.Session`:
1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_DEFAULT_REGION`).
2. AWS credentials file (`~/.aws/credentials` or `AWS_PROFILE`).
3. IAM Instance Profile or ECS Task execution role.
4. Optional AssumeRole via STS if `AWS_ASSUME_ROLE_ARN` is specified.

> **Security Note:** AWS secrets and session tokens are **never** stored in the database, **never** output in API responses, and **never** logged to the console or log files.

---

## 4. Discovered Services & Rule Coverage

| AWS Service | API Operations Used | Discovered Resources | Matched Rules |
| :--- | :--- | :--- | :--- |
| **S3** | `list_buckets`, `get_bucket_*` | `aws_s3_bucket` | `S3-001` through `S3-005` |
| **IAM** | `list_users`, `list_*`, `get_account_summary` | `aws_iam_user`, `aws_iam_root` | `IAM-001` through `IAM-005` |
| **EC2** | `describe_instances`, `describe_volumes` | `aws_ec2_instance` | `EC2-001` through `EC2-005` |
| **VPC** | `describe_security_groups` | `aws_security_group` | `NET-001` through `NET-005` |
| **CloudTrail** | `describe_trails`, `get_trail_status` | `aws_cloudtrail_trail` | `CT-001` through `CT-003` |
| **RDS** | `describe_db_instances` | `aws_rds_instance` | `RDS-001` through `RDS-003` |
