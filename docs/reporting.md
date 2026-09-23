# Report Generation Architecture

## Overview

The CSPM platform provides server-side PDF report compilation utilizing ReportLab Platypus. Reports synthesize scanned asset inventories, misconfiguration findings, security posture metrics, and compliance framework coverage into downloadable artifacts suitable for stakeholders.

---

## Report Types

1. **Executive Summary Report (`EXECUTIVE_SUMMARY`)**:
   - High-level overview tailored for CISOs, compliance officers, and executive leadership.
   - Includes overall Security Posture Score (0–100) and letter rating.
   - Severity and risk level breakdown tables.
   - Cross-framework compliance coverage rates (CIS AWS, NIST, ISO 27001, PCI DSS).
   - Top prioritized security risks requiring strategic mitigation.

2. **Technical Details Report (`TECHNICAL_FINDINGS`)**:
   - Deep-dive report designed for cloud engineers, DevSecOps practitioners, and security analysts.
   - Includes complete inventory of detected non-compliant cloud resources.
   - Full finding dossiers: Resource ID, Service, Severity, Risk Score, and Detection Timestamp.
   - Detailed evidence excerpts and reproduction parameters.
   - Step-by-step remediation guidance and AWS CLI / Terraform remediation snippets.

---

## Security & Path Integrity Controls

- **Zero Secret Leakage**:
  - The report generator strictly suppresses any AWS credentials, IAM secret keys, session tokens, or API secrets from finding evidence fields before rendering.
- **Safe Directory Containment**:
  - Generated reports are written exclusively to `data/reports/`.
  - Report filenames are constructed deterministically using UUIDs and sanitized timestamps.
  - Path traversal protections (`os.path.abspath` validation) prevent directory traversal vulnerabilities during retrieval and download.
- **Role-Based Access Control**:
  - `POST /api/reports`: Authorized for `ADMIN` and `SECURITY_ANALYST` (requires `reports:generate`).
  - `GET /api/reports` & `GET /api/reports/{id}/download`: Available to all authenticated users with `reports:read`.

---

## API Endpoints

- `POST /api/reports`: Asynchronously or synchronously triggers PDF report compilation for a scan.
- `GET /api/reports`: Lists historical reports with generation timestamp and status.
- `GET /api/reports/{id}`: Retrieves report metadata and generation status.
- `GET /api/reports/{id}/download`: Streams the binary PDF file to the client with `application/pdf` MIME type.
