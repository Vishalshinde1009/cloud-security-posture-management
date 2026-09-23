# Audit Logging System

## Overview

The CSPM platform records immutable audit logs for all security-sensitive actions and operational events across the system to support incident response, compliance tracking, and governance.

---

## Log Schema

Audit events are persisted to PostgreSQL in the `audit_logs` table with the following structured schema:

| Column | Type | Description |
| :--- | :--- | :--- |
| `id` | `Integer` | Unique primary key identifier |
| `timestamp` | `DateTime` | UTC timestamp of event occurrence |
| `user_id` | `Integer` (Nullable) | User ID who performed the action (null for system automated jobs) |
| `username` | `String` (Nullable) | Denormalized username for historical traceability |
| `action` | `String` | Categorical action verb (e.g. `USER_LOGIN`, `TRIGGER_SCAN`, `RULE_TOGGLED`) |
| `entity_type` | `String` | Impacted entity type (`USER`, `SCAN`, `FINDING`, `SECURITY_RULE`, `CLOUD_ACCOUNT`) |
| `entity_id` | `String` (Nullable) | Identifier of the specific impacted entity |
| `ip_address` | `String` (Nullable) | Originating client IP address |
| `user_agent` | `String` (Nullable) | Client User-Agent string |
| `status` | `String` | Outcome status (`SUCCESS` or `FAILURE`) |
| `details` | `JSON` | Additional event-specific contextual metadata and parameter diffs |

---

## Recorded Event Categories

1. **Authentication & Identity**:
   - `USER_LOGIN`: User login attempts (success or bad credentials).
   - `USER_LOGOUT`: Explicit token revocation / logout.
   - `USER_REGISTERED`: Creation of user accounts.
2. **Scanner Operations**:
   - `TRIGGER_SCAN`: Manual or automated scan initiations.
   - `SCAN_COMPLETED`: Successful scan cycle completion.
   - `SCAN_FAILED`: Error conditions or timeouts during scanning.
3. **Finding Workflow & Triage**:
   - `UPDATE_FINDING_STATUS`: Transitioning finding lifecycle state (`RESOLVED`, `ACCEPTED_RISK`, `FALSE_POSITIVE`, etc.).
   - `CREATE_FINDING_NOTE`: Safe, sanitized analyst notes appended to findings.
4. **Administration & Configuration**:
   - `RULE_TOGGLED`: Administrators enabling or disabling security detection rules.
   - `CREATE_CLOUD_ACCOUNT`: Onboarding cloud accounts.
   - `REPORT_GENERATED`: Compiling compliance or technical PDF reports.

---

## Security & RBAC Access

- Audit logs are **read-only**; no API or application route permits modification or deletion of existing audit records.
- Access to `GET /api/audit-logs` is strictly restricted to users with the `ADMIN` role or `read:audit_logs` permission.
- The API supports filtering by:
  - `action`: Specific action code
  - `username`: User who took the action
  - `status`: `SUCCESS` or `FAILURE`
  - `start_date` / `end_date`: ISO date range filters
