# Role-Based Access Control (RBAC) Specification

## 1. Overview
The CSPM platform enforces Role-Based Access Control (RBAC) across both API endpoints (enforced authoritatively on the backend) and UI navigation (rendered conditionally for optimal UX).

---

## 2. Role Persona Definitions

| Role | Intended Persona | Scope of Authority |
| :--- | :--- | :--- |
| **`ADMIN`** | Chief Information Security Officer (CISO) / Lead DevSecOps Engineer | Full platform configuration, user account lifecycle, cloud account registration, rule catalog modification, and audit log inspection. |
| **`SECURITY_ANALYST`** | SOC Analyst / Cloud Security Engineer | Day-to-day scanning, inspecting misconfiguration findings, evaluating technical evidence, updating finding remediation statuses, and downloading security reports. |
| **`VIEWER`** | Auditor / Executive / Read-Only Stakeholder | Read-only inspection of the security dashboard, discovered cloud resources, and compliance status. Forbidden from triggering scans or altering findings. |

---

## 3. Role & Permission Matrix

| Capability / Permission | ADMIN | SECURITY_ANALYST | VIEWER |
| :--- | :---: | :---: | :---: |
| **View Security Dashboard** (`dashboard:read`) | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| **View Cloud Resources** (`resources:read`) | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| **View Detection Rules** (`rules:read`) | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| **View Compliance Status** (`compliance:read`) | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| **View Findings & Evidence** (`findings:read`) | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| **Trigger Cloud Scans** (`scans:create`) | :white_check_mark: | :white_check_mark: | :x: |
| **Update Finding Status** (`findings:update`) | :white_check_mark: | :white_check_mark: | :x: |
| **Export Security Reports** (`reports:download`) | :white_check_mark: | :white_check_mark: | :x: |
| **Enable/Disable Rules** (`rules:manage`) | :white_check_mark: | :x: | :x: |
| **Manage Cloud Accounts** (`cloud_accounts:manage`)| :white_check_mark: | :x: | :x: |
| **Manage Users & Roles** (`users:manage`) | :white_check_mark: | :x: | :x: |
| **Inspect SOC Audit Logs** (`audit_logs:read`) | :white_check_mark: | :x: | :x: |

---

## 4. FastAPI Dependency Usage

Protected routes enforce authorization declaratively using FastAPI dependency injection (`backend/app/api/deps.py`):

### 4.1 Authenticated User Dependency
```python
@router.get("/protected")
def get_protected_data(current_user: User = Depends(get_current_user)):
    return {"message": f"Hello {current_user.username}"}
```

### 4.2 Role-Restricted Dependency
```python
@router.get("/admin-only")
def admin_only_action(current_user: User = Depends(require_role(["ADMIN"]))):
    return {"message": "Admin action executed"}

@router.get("/analyst-or-admin")
def analyst_action(current_user: User = Depends(require_role(["ADMIN", "SECURITY_ANALYST"]))):
    return {"message": "Analyst action executed"}
```

### 4.3 Permission-Restricted Dependency
```python
@router.post("/scans")
def trigger_scan(current_user: User = Depends(require_permission("scans:create"))):
    return {"message": "Scan queued"}
```

If an authenticated user lacks the required role or permission:
1. An `ACCESS_DENIED` entry is recorded in the `audit_logs` table (including user ID, requested endpoint, and client IP).
2. FastAPI returns `HTTP 403 Forbidden` with detail `"Access forbidden: requires one of roles ['ADMIN']"`.
