# Database Architecture & Persistence Specification

## 1. Overview
The CSPM platform utilizes **PostgreSQL** as its enterprise-grade production relational store, with full support for **SQLite** as a zero-setup local development and in-memory testing dialect via SQLAlchemy 2.0 ORM and Alembic migrations.

### Key Design Principles:
1. **Zero Secret Storage**: Plaintext AWS secret keys, session tokens, or raw credentials are never stored in the database. `CloudAccount.credential_mode` identifies the credential source (e.g. `ENVIRONMENT`, `IAM_ROLE`).
2. **Audit Preservation & Non-Destructive Deletes**: High-value security findings, scans, and audit logs utilize restricted foreign keys (`ondelete="RESTRICT"`) to guarantee historical data cannot be deleted accidentally.
3. **Deterministic Fingerprints**: Every `Finding` record includes a deterministic `finding_identifier` to track configuration drift, re-identifying persistent, resolved, and new findings across sequential scans.
4. **Normalized JSON Configuration**: Unstructured or evolving cloud resource metadata and audit evidence are stored using indexed `JSON` columns.

---

## 2. Entity Relationship Overview

```text
+----------------+          +--------------------+
|     users      |<--M:N--->|       roles        |
+-------+--------+          +---------+----------+
        |                             |
        | 1:N                         | M:N
        v                             v
+-------+--------+          +---------+----------+
|   audit_logs   |          |    permissions     |
+----------------+          +--------------------+

+--------------------+       1:N      +--------------------+
|   cloud_accounts   |--------------->|       scans        |
+---------+----------+                +---------+----------+
          |                                     |
          | 1:N                                 | 1:N
          v                                     v
+---------+----------+       1:N      +---------+----------+
|     resources      |<---------------|      findings      |
+--------------------+                +----+----------+----+
                                           |          |
                                  N:1      |          | M:N
                                           v          v
                                +----------+----+  +--+-------------------+
                                | security_rules|  | compliance_controls  |
                                +---------------+  +----------------------+
```

---

## 3. Database Tables & Schema Reference

### 3.1 Authentication & RBAC
- **`users`**: Identity store storing username, email, `bcrypt` password hash, active flag, and timestamps.
- **`roles`**: Security roles (`ADMIN`, `SECURITY_ANALYST`, `VIEWER`).
- **`permissions`**: Granular authorizations (`read:findings`, `write:findings`, `run:scans`, `manage:accounts`, `manage:rules`, etc.).
- **`user_roles`**: Many-to-many junction table between `users` and `roles`.
- **`role_permissions`**: Many-to-many junction table between `roles` and `permissions`.

### 3.2 Cloud Infrastructure & Scans
- **`cloud_accounts`**: Monitored AWS accounts. Stores AWS Account ID, default region, credential mode, and active status.
- **`scans`**: Historical audit scans tracking execution status (`QUEUED`, `RUNNING`, `COMPLETED`, `FAILED`), runtime duration, resources inspected, severity counts, and aggregate security score (0–100).
- **`resources`**: Cloud inventory asset records tracking service (`S3`, `IAM`, `EC2`, `VPC`, `CloudTrail`, `RDS`), resource identifier, region, tags (`JSON`), and raw configuration (`JSON`).

### 3.3 Detection Rules & Findings
- **`security_rules`**: Detection rule catalog specifying unique `rule_id` (e.g. `S3-001`, `IAM-001`), title, severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), remediation steps, and references.
- **`findings`**: Detected misconfigurations with explainable risk score (0–100), status (`OPEN`, `IN_PROGRESS`, `RESOLVED`, `ACCEPTED_RISK`, `FALSE_POSITIVE`), structured evidence (`JSON`), and audit timestamps.

### 3.4 Compliance & Operations
- **`compliance_controls`**: Security standards (e.g. `CIS_AWS`, `NIST`, `ISO27001`, `PCI_DSS`) and control identifiers.
- **`finding_compliance`**: Many-to-many mapping connecting findings to failed compliance controls with status and evidence notes.
- **`audit_logs`**: Tamper-evident log of security events (login, scan initiated, status changed) with context metadata.
- **`reports`**: Generated security posture reports (Executive / Technical).
- **`notifications`**: User alert queue for critical misconfigurations and scan updates.

---

## 4. Migrations with Alembic

Alembic manages schema migrations. Database URLs are dynamically injected from `app.core.config.settings.DATABASE_URL`.

### Run Migrations to Head:
```bash
alembic upgrade head
```

### Rollback Previous Migration:
```bash
alembic downgrade -1
```

### Generate a New Migration:
```bash
alembic revision --autogenerate -m "description_of_change"
```

---

## 5. Development Seed Data

To populate safe development seed data (standard roles, permissions, sample rules, CIS controls, and a default admin user):
```bash
python backend/app/database/seed.py
```
*Note: The seed script is strictly idempotent and does not overwrite existing records.*

---

## 6. Testing Database Strategy

Unit and integration tests run against an **isolated in-memory SQLite database** (`sqlite:///:memory:`) using pytest fixtures (`backend/tests/test_database.py`).
- No developer or production database is altered during automated test execution.
- Tests verify schema creation, constraints, unique indexes, relationships, and foreign key rules.
