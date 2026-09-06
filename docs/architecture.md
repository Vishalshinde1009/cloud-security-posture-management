# Cloud Security Posture Management (CSPM) - Architecture & System Design

## 1. Executive Summary
The CSPM platform is an automated cloud compliance and security scanning engine designed to audit AWS cloud infrastructure against security best practices, industry benchmarks (CIS AWS Foundations Benchmark), and cloud security controls.

The architecture is explicitly designed around two operating modes:
- **`CSPM_MODE=mock`**: A deterministic simulation engine reproducing realistic AWS infrastructure configurations with deliberate security misconfigurations for offline analysis, CI/CD testing, and demonstration without cloud costs or security risk.
- **`CSPM_MODE=aws`**: A strictly read-only scanner using AWS SDK (`boto3`) to query AWS APIs, gather real-time metadata, and identify live vulnerabilities.

---

## 2. High-Level Architectural Pipeline

```text
+-----------------------+        +-----------------------+
|   AWS Infrastructure  |        |    Mock Environment   |
|   (Boto3 Read-Only)   |        |   (Deterministic Data)|
+-----------+-----------+        +-----------+-----------+
            \                                /
             \                              /
              v                            v
        +----------------------------------------+
        |        Cloud Provider Adapter          |
        |      (Resource Discovery Engine)       |
        +-------------------+--------------------+
                            |
                            v
        +----------------------------------------+
        |    Configuration Collection Service    |
        |   (S3, IAM, EC2, VPC, CloudTrail, RDS) |
        +-------------------+--------------------+
                            |
                            v
        +----------------------------------------+
        |    Normalization & Resource Model      |
        |      (Standard Resource Schema)        |
        +-------------------+--------------------+
                            |
                            v
        +----------------------------------------+
        |         Security Rule Engine           |
        |    (Rule Registry, Isolated Runner)    |
        +-------------------+--------------------+
                            |
                            v
        +----------------------------------------+
        |        Explainable Risk Engine         |
        |  (Risk = Severity * Exposure * Asset)  |
        |  (Overall Posture: 0 - 100 Score)      |
        +-------------------+--------------------+
                            |
                            v
        +----------------------------------------+
        |   Persistence Layer (SQLAlchemy ORM)   |
        |     (PostgreSQL / SQLite Storage)      |
        +-------------------+--------------------+
                            |
            +---------------+---------------+
            |                               |
            v                               v
+-----------------------+       +-----------------------+
|  FastAPI REST API     |       |  PDF Report Generator |
|  & Background Workers |       |    (Executive / Tech) |
+-----------+-----------+       +-----------------------+
            |
            v
+-----------------------+
| React SOC Dashboard   |
| (Vite, TS, Tailwind)  |
+-----------------------+
```

---

## 3. Core Subsystems

### 3.1 Cloud Provider Interface
- Abstract Base Class: `CloudProvider` (`backend/app/scanner/providers/base.py`)
- Implementation: `AWSProvider` (`backend/app/scanner/providers/aws/provider.py`)
- Mock Implementation: `MockAWSProvider` (`backend/app/scanner/providers/mock/provider.py`)

### 3.2 Discovery & Collector Pipeline
- Independent collectors per AWS service (`s3_collector.py`, `iam_collector.py`, `ec2_collector.py`, etc.).
- Normalization into unified `CloudResource` schema.
- Non-blocking pagination and graceful error recovery.

### 3.3 Rule Engine (`backend/app/scanner/engine/`)
- Base Rule: `BaseRule` requiring `rule_id`, `service`, `severity`, `category`, and `evaluate(resource)`.
- Error Boundary: If a rule raises an unhandled exception, it logs the error, records a diagnostic alert, and continues without aborting the scan.

### 3.4 Risk & Posture Scoring Engine
- Calculates finding risk score (0–100) based on severity, network exposure, sensitive data markers, and resource criticality.
- Aggregates overall posture score (0–100) using penalty weighting.

### 3.5 Storage & Audit Logging
- Stores historical scans for drift analysis (detecting new, resolved, and persistent findings).
- Tamper-evident audit logging for SOC traceability.
