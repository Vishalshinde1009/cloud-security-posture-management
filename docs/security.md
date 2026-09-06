# Security Design & Threat Model (Phase 1 Baseline)

## 1. Security Principles
The Cloud Security Posture Management (CSPM) system is designed in accordance with defense-in-depth, least privilege, and zero-trust engineering principles.

### 1.1 Zero Hardcoded Secrets Policy
- **No Credentials in Code**: AWS access keys, AWS secret keys, session tokens, JWT signing secrets, and database credentials must never be committed to source control.
- **Environment Isolation**: The `.env` file is explicitly ignored in `.gitignore`. A sanitized template `.env.example` provides default configuration keys without sensitive values.
- **Runtime Secret Injection**: Secrets are injected strictly via environment variables or cloud provider metadata services (e.g., IAM Instance Profiles / ECS Task Execution Roles).

### 1.2 Non-Destructive, Read-Only Auditing
- The scanner architecture enforces read-only access to audited environments.
- Active cloud modification APIs (`Create*`, `Update*`, `Delete*`, `Put*`) are forbidden in scanner roles.
- Automated remediation is strictly disabled by default to prevent accidental outages or infrastructure destabilization.

### 1.3 Transport and Header Security
FastAPI middleware enforces modern security HTTP headers on all responses:
- `X-Content-Type-Options: nosniff`: Mitigates MIME-type confusion attacks.
- `X-Frame-Options: DENY`: Prevents clickjacking by prohibiting iframe rendering.
- `X-XSS-Protection: 1; mode=block`: Activates browser XSS filtering.
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`: Mandates HTTPS transport in production.

### 1.4 Cryptographic Primitives
- **Password Hashing**: Implemented via Passlib using the `bcrypt` algorithm.
- **Token Management**: Implemented via `PyJWT` using HMAC SHA-256 (`HS256`) with strict signature validation and configurable expiration lifetimes (`ACCESS_TOKEN_EXPIRE_MINUTES`).

---

## 2. Threat Modeling

| Threat | Target | Phase 1 Mitigation |
| :--- | :--- | :--- |
| **Credential Leakage** | Repository / Version Control | `.gitignore` rules for `.env`, `*.pem`, `*.key`, and secret patterns. Strict verification in CI/CD. |
| **Infrastructure Tampering** | Target AWS Account | Scanner uses read-only IAM policies (`Describe*`, `Get*`, `List*`). |
| **Tampering with Local Config** | SQLite / Local Database | Database files (`*.db`, `*.sqlite*`) gitignored; connection strings parameterized via SQLAlchemy ORM. |
| **Clickjacking / MIME Attacks** | Frontend & API consumers | Security headers middleware attached to all FastAPI HTTP responses. |
| **Cross-Origin Abuse** | API Endpoints | Configurable `CORS_ORIGINS` whitelist; wildcard `*` prohibited in production. |

---

## 3. Implementation Status
- [x] Security headers middleware verified
- [x] Zero hardcoded secrets verified
- [x] Password hashing & JWT primitives implemented (`backend/app/core/security.py`)
- [x] User authentication endpoints (`/api/auth/login`, `/logout`, `/me`) verified
- [x] Role-Based Access Control (`ADMIN`, `SECURITY_ANALYST`, `VIEWER`) verified
- [x] Authentication and RBAC audit trail logging verified (`AuditLog`)
- [ ] AWS read-only scanner pipeline (Scheduled for Phase 7)
- [ ] Security rules engine (Scheduled for Phase 5-8)
- [ ] PDF reporting engine (Scheduled for Phase 13)

