# Authentication Architecture & JWT Specification

## 1. Overview
The CSPM platform implements a stateless, token-based authentication mechanism using **JSON Web Tokens (JWT)** and **Bcrypt** cryptographic password hashing. Authentication is strictly separated from authorization (Role-Based Access Control) and integrated with tamper-evident audit logging.

---

## 2. Password Security & Storage

### 2.1 Hashing Algorithm
- All passwords are encrypted using the industry-standard **Bcrypt** adaptive hashing algorithm via direct bindings in `backend/app/core/security.py`.
- Plaintext passwords are never stored, never written to disk, and never output in application logs.
- Password hashes are never returned across any REST API endpoint (prohibited by Pydantic response schemas).

### 2.2 Password Validation Policy
Passwords must satisfy the following minimum criteria before hashing:
- Minimum length: **8 characters**
- Maximum length: **72 bytes** (strictly adheres to the bcrypt specification to prevent silent truncation attacks)
- At least one uppercase character (`[A-Z]`)
- At least one lowercase character (`[a-z]`)
- At least one digit or special symbol (`[0-9\W_]`)

---

## 3. JWT Token Specification

### 3.1 Token Format & Claims
Access tokens are signed using HMAC SHA-256 (`HS256`) with a key configured via `SECRET_KEY`.

Payload contains only minimal non-sensitive identifiers:
```json
{
  "sub": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "username": "sec_admin",
  "email": "admin@cspm-security.local",
  "roles": ["ADMIN"],
  "iat": 1725624000,
  "exp": 1725627600
}
```

### 3.2 Token Lifecycle & Expiration
- Lifetime is configured via `ACCESS_TOKEN_EXPIRE_MINUTES` (default: 60 minutes).
- Expired or signature-tampered tokens return `HTTP 401 Unauthorized`.
- The frontend Axios interceptor automatically detects 401 responses, purges session tokens, and redirects the user to `/login`.

---

## 4. Authentication Endpoints (`/api/auth`)

### 4.1 `POST /api/auth/login`
- **Request Body**:
  ```json
  {
    "username_or_email": "admin@cspm-security.local",
    "password": "AdminSecurePass123!"
  }
  ```
- **Response (HTTP 200)**:
  ```json
  {
    "access_token": "eyJhbGciOi...",
    "token_type": "bearer",
    "expires_in": 3600,
    "user": {
      "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
      "username": "admin",
      "email": "admin@cspm-security.local",
      "roles": ["ADMIN"],
      "is_active": true,
      "created_at": "2026-09-06T18:00:00Z"
    }
  }
  ```
- **Anti-Enumeration Guard**: Both invalid usernames and incorrect passwords return a generic HTTP 401: `"Invalid email/username or password."`
- **Inactive Accounts**: Deactivated accounts return HTTP 401: `"User account is disabled. Please contact an administrator."`

### 4.2 `POST /api/auth/logout`
- Requires `Authorization: Bearer <token>`.
- Records a `LOGOUT` audit log event.
- Returns `HTTP 200`: `{"message": "Successfully logged out."}`.

### 4.3 `GET /api/auth/me`
- Returns profile, assigned roles, and granular permissions for the current authenticated user.

---

## 5. Audit Logging for Auth Events
Every authentication attempt creates an immutable `AuditLog` entry in the database:
- `LOGIN_SUCCESS`: Records user ID, client IP, and active roles.
- `LOGIN_FAILURE`: Records attempted identifier and client IP. Never records submitted password.
- `LOGOUT`: Records user ID and timestamp.
- `ACCESS_DENIED`: Records unauthorized endpoint access attempt and required privileges.
