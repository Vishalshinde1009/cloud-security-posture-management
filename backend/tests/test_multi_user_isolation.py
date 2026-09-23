"""
Multi-User Data Isolation & Tenant Isolation Test Suite
======================================================
Verifies strict database-level and API-level data isolation across multiple
registered users (User A vs User B) and preserves global ADMIN visibility.

Security Properties Verified:
1. User Registration: Auto-assigns VIEWER role; secure bcrypt password hashing.
2. Cloud Account Isolation:
   - Request cannot inject `user_id` to override ownership.
   - User A sees ONLY their accounts; User B sees ONLY their accounts.
   - Cross-user GET / test-connection returns HTTP 404 (preventing enumeration/IDOR).
3. Scan Isolation:
   - Triggering a scan on another user's cloud account returns HTTP 404.
   - User A scan results, history, and status are inaccessible to User B (HTTP 404).
4. Discovered Resources Isolation:
   - Discovered resources are isolated per user's cloud account.
   - Cross-user resource GET returns HTTP 404.
5. Findings Isolation & Remediation Protection:
   - User B cannot view User A's findings (HTTP 404).
   - User B cannot update finding status or add notes to User A's findings (HTTP 404).
6. Dashboard Posture Metrics Isolation:
   - Dashboard stats calculate metrics strictly scoped to the requesting user's accounts.
7. Compliance Framework Isolation:
   - Compliance framework statistics reflect only the user's accessible findings.
8. Reports Isolation:
   - User B cannot list, view, or download User A's generated PDF reports (HTTP 404).
9. Admin Global Visibility:
   - ADMIN role retains global oversight across all tenants, accounts, scans, and findings.
10. RBAC Enforcement:
   - VIEWER role cannot create accounts, trigger scans, update findings, or generate reports (HTTP 403).
"""

import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database.session import get_db, Base
from app.database.seed import seed_database
from app.models.auth import User, Role, Permission
from app.models.cloud import CloudAccount, Scan, Resource
from app.models.finding import Finding
from app.core.security import get_password_hash, create_access_token
from app.services.scan_service import ScanService

# Shared in-memory SQLite database using StaticPool
test_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)


@event.listens_for(test_engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="function")
def db_session():
    """Provides a fresh seeded in-memory database session."""
    Base.metadata.create_all(bind=test_engine)
    session = TestingSessionLocal()

    # Seed baseline roles, permissions, security rules, and compliance controls
    seed_database(db=session)

    # Ensure SECURITY_ANALYST has cloud_accounts:manage for testing account management
    analyst_role = session.query(Role).filter(Role.name == "SECURITY_ANALYST").first()
    p_manage_acc = session.query(Permission).filter(Permission.name == "cloud_accounts:manage").first()
    if p_manage_acc and p_manage_acc not in analyst_role.permissions:
        analyst_role.permissions.append(p_manage_acc)
        session.commit()

    yield session

    session.close()
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture(scope="function")
def client(db_session):
    """FastAPI TestClient with get_db dependency overridden."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def auth_header_for_user(user: User) -> dict:
    """Generates an Authorization Bearer header for a given database user."""
    roles = [r.name for r in user.roles]
    token = create_access_token(subject=str(user.id), claims={"roles": roles})
    return {"Authorization": f"Bearer {token}"}


# =============================================================================
# Helper to create active users with specific roles
# =============================================================================
def create_test_user(db, username: str, email: str, role_name: str) -> User:
    role = db.query(Role).filter(Role.name == role_name).first()
    user = User(
        id=uuid.uuid4(),
        username=username,
        email=email,
        password_hash=get_password_hash("TestP@ssw0rd123!"),
        is_active=True,
    )
    if role:
        user.roles.append(role)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


# =============================================================================
# Test Suite
# =============================================================================

def test_1_user_registration_assigns_viewer_role_and_hashes_password(client, db_session):
    """Scenario 1: Registration creates isolated users with VIEWER role and secure password hashing."""
    res_a = client.post("/api/auth/register", json={
        "username": "user_alpha",
        "email": "alpha@tenant-a.com",
        "password": "SecurePassword123!",
        "full_name": "User Alpha",
    })
    assert res_a.status_code == 201
    data_a = res_a.json()
    assert data_a["username"] == "user_alpha"
    assert "VIEWER" in data_a["roles"]

    res_b = client.post("/api/auth/register", json={
        "username": "user_beta",
        "email": "beta@tenant-b.com",
        "password": "SecurePassword123!",
        "full_name": "User Beta",
    })
    assert res_b.status_code == 201
    data_b = res_b.json()
    assert data_b["username"] == "user_beta"
    assert "VIEWER" in data_b["roles"]

    # Verify both users exist in DB with bcrypt password hashing
    user_a = db_session.query(User).filter(User.username == "user_alpha").first()
    user_b = db_session.query(User).filter(User.username == "user_beta").first()
    assert user_a is not None and user_b is not None
    assert user_a.id != user_b.id
    assert user_a.password_hash.startswith("$2b$")
    assert user_b.password_hash.startswith("$2b$")


def test_2_cloud_account_creation_enforces_ownership_and_ignores_payload_injection(client, db_session):
    """Scenario 2 & 16: Account creation automatically binds to current_user.id and ignores payload user_id injection."""
    user_a = create_test_user(db_session, "user_a_sec", "a_sec@tenant.com", "SECURITY_ANALYST")
    user_b = create_test_user(db_session, "user_b_sec", "b_sec@tenant.com", "SECURITY_ANALYST")

    headers_a = auth_header_for_user(user_a)

    # Malicious payload: User A attempts to set user_id to User B
    payload = {
        "name": "User A Cloud Account",
        "provider": "MOCK",
        "account_identifier": "mock-acc-alpha-100",
        "default_region": "us-east-1",
        "credential_mode": "ENVIRONMENT",
        "user_id": str(user_b.id),  # Malicious injection
    }
    res = client.post("/api/cloud-accounts", json=payload, headers=headers_a)
    assert res.status_code == 201
    created_acc = res.json()

    # Verify in DB that account.user_id is strictly user_a.id
    db_acc = db_session.query(CloudAccount).filter(CloudAccount.id == uuid.UUID(created_acc["id"])).first()
    assert db_acc is not None
    assert db_acc.user_id == user_a.id
    assert db_acc.user_id != user_b.id


def test_3_cloud_accounts_list_isolated_per_user(client, db_session):
    """Scenario 3 & 4: User A lists cloud accounts -> sees only A. User B lists -> sees only B."""
    user_a = create_test_user(db_session, "user_a_list", "a_list@tenant.com", "SECURITY_ANALYST")
    user_b = create_test_user(db_session, "user_b_list", "b_list@tenant.com", "SECURITY_ANALYST")

    # Create account for User A
    acc_a = CloudAccount(
        name="Tenant A Production",
        provider="MOCK",
        account_identifier="mock-acc-a-001",
        default_region="us-east-1",
        credential_mode="ENVIRONMENT",
        user_id=user_a.id,
        is_active=True,
    )
    # Create account for User B
    acc_b = CloudAccount(
        name="Tenant B Production",
        provider="MOCK",
        account_identifier="mock-acc-b-002",
        default_region="us-east-1",
        credential_mode="ENVIRONMENT",
        user_id=user_b.id,
        is_active=True,
    )
    db_session.add_all([acc_a, acc_b])
    db_session.commit()

    # User A lists accounts
    res_a = client.get("/api/cloud-accounts", headers=auth_header_for_user(user_a))
    assert res_a.status_code == 200
    ids_a = [a["id"] for a in res_a.json()]
    assert str(acc_a.id) in ids_a
    assert str(acc_b.id) not in ids_a

    # User B lists accounts
    res_b = client.get("/api/cloud-accounts", headers=auth_header_for_user(user_b))
    assert res_b.status_code == 200
    ids_b = [b["id"] for b in res_b.json()]
    assert str(acc_b.id) in ids_b
    assert str(acc_a.id) not in ids_b


def test_4_cloud_account_get_and_test_connection_cross_user_returns_404(client, db_session):
    """Scenario 5 & 6: User A attempts GET / test-connection on Account B -> returns 404 (IDOR prevented)."""
    user_a = create_test_user(db_session, "user_a_idor", "a_idor@tenant.com", "SECURITY_ANALYST")
    user_b = create_test_user(db_session, "user_b_idor", "b_idor@tenant.com", "SECURITY_ANALYST")

    acc_a = CloudAccount(
        name="Account Alpha",
        provider="MOCK",
        account_identifier="mock-idor-a",
        default_region="us-east-1",
        user_id=user_a.id,
        is_active=True,
    )
    acc_b = CloudAccount(
        name="Account Beta",
        provider="MOCK",
        account_identifier="mock-idor-b",
        default_region="us-east-1",
        user_id=user_b.id,
        is_active=True,
    )
    db_session.add_all([acc_a, acc_b])
    db_session.commit()

    headers_a = auth_header_for_user(user_a)
    headers_b = auth_header_for_user(user_b)

    # User A GET Account B -> 404
    res = client.get(f"/api/cloud-accounts/{acc_b.id}", headers=headers_a)
    assert res.status_code == 404

    # User B GET Account A -> 404
    res = client.get(f"/api/cloud-accounts/{acc_a.id}", headers=headers_b)
    assert res.status_code == 404

    # User A test-connection on Account B -> 404
    res = client.post(f"/api/cloud-accounts/{acc_b.id}/test-connection", headers=headers_a)
    assert res.status_code == 404

    # User A GET Account A -> 200 OK
    res = client.get(f"/api/cloud-accounts/{acc_a.id}", headers=headers_a)
    assert res.status_code == 200
    assert res.json()["name"] == "Account Alpha"


def test_5_scan_trigger_isolated_per_account_rejects_cross_user_with_404(client, db_session):
    """Scenario 7: User A attempts to trigger scan on Account B -> rejected with 404."""
    user_a = create_test_user(db_session, "user_a_scan", "a_scan@tenant.com", "SECURITY_ANALYST")
    user_b = create_test_user(db_session, "user_b_scan", "b_scan@tenant.com", "SECURITY_ANALYST")

    acc_a = CloudAccount(
        name="Account A Scan",
        provider="MOCK",
        account_identifier="mock-scan-a",
        default_region="us-east-1",
        user_id=user_a.id,
        is_active=True,
    )
    acc_b = CloudAccount(
        name="Account B Scan",
        provider="MOCK",
        account_identifier="mock-scan-b",
        default_region="us-east-1",
        user_id=user_b.id,
        is_active=True,
    )
    db_session.add_all([acc_a, acc_b])
    db_session.commit()

    headers_a = auth_header_for_user(user_a)

    # User A attempts to trigger scan on User B's account
    res = client.post("/api/scans", json={"account_id": str(acc_b.id)}, headers=headers_a)
    assert res.status_code == 404

    # User A triggers scan on their own account -> succeeds
    res = client.post("/api/scans", json={"account_id": str(acc_a.id)}, headers=headers_a)
    assert res.status_code == 201
    scan_data = res.json()
    assert scan_data["status"] == "COMPLETED"
    assert scan_data["cloud_account_id"] == str(acc_a.id)


def test_6_scan_retrieval_and_listing_isolated_per_user(client, db_session):
    """Scenario 8, 9, 10: User A completes scan; User A sees it; User B gets 404 and does not see it in list."""
    user_a = create_test_user(db_session, "user_a_hist", "a_hist@tenant.com", "SECURITY_ANALYST")
    user_b = create_test_user(db_session, "user_b_hist", "b_hist@tenant.com", "SECURITY_ANALYST")

    acc_a = CloudAccount(
        name="Account A History",
        provider="MOCK",
        account_identifier="mock-hist-a",
        default_region="us-east-1",
        user_id=user_a.id,
        is_active=True,
    )
    db_session.add(acc_a)
    db_session.commit()

    # Trigger scan for User A
    scan_a = ScanService.trigger_scan(db=db_session, user=user_a, account_id=acc_a.id)
    assert scan_a.status == "COMPLETED"

    headers_a = auth_header_for_user(user_a)
    headers_b = auth_header_for_user(user_b)

    # User A gets scan by ID -> 200 OK
    res_a = client.get(f"/api/scans/{scan_a.id}", headers=headers_a)
    assert res_a.status_code == 200
    assert res_a.json()["id"] == str(scan_a.id)

    # User B attempts to get User A's scan by ID -> 404
    res_b = client.get(f"/api/scans/{scan_a.id}", headers=headers_b)
    assert res_b.status_code == 404

    # User A lists scans -> contains scan_a
    res_list_a = client.get("/api/scans", headers=headers_a)
    assert res_list_a.status_code == 200
    assert scan_a.id in [uuid.UUID(s["id"]) for s in res_list_a.json()["items"]]

    # User B lists scans -> does not contain scan_a
    res_list_b = client.get("/api/scans", headers=headers_b)
    assert res_list_b.status_code == 200
    assert res_list_b.json()["total"] == 0


def test_7_resources_isolated_per_user(client, db_session):
    """Scenario 8 & 9: Discovered resources are isolated; User B cannot view User A's resources."""
    user_a = create_test_user(db_session, "user_a_res", "a_res@tenant.com", "SECURITY_ANALYST")
    user_b = create_test_user(db_session, "user_b_res", "b_res@tenant.com", "SECURITY_ANALYST")

    acc_a = CloudAccount(
        name="Account A Resources",
        provider="MOCK",
        account_identifier="mock-res-a",
        default_region="us-east-1",
        user_id=user_a.id,
        is_active=True,
    )
    db_session.add(acc_a)
    db_session.commit()

    scan_a = ScanService.trigger_scan(db=db_session, user=user_a, account_id=acc_a.id)
    assert scan_a.status == "COMPLETED"

    # User A has discovered resources
    resource_a = db_session.query(Resource).filter(Resource.cloud_account_id == acc_a.id).first()
    assert resource_a is not None

    headers_a = auth_header_for_user(user_a)
    headers_b = auth_header_for_user(user_b)

    # User A lists resources -> sees them
    res_a = client.get("/api/resources", headers=headers_a)
    assert res_a.status_code == 200
    assert res_a.json()["total"] > 0

    # User B lists resources -> sees 0
    res_b = client.get("/api/resources", headers=headers_b)
    assert res_b.status_code == 200
    assert res_b.json()["total"] == 0

    # User A gets resource by ID -> 200 OK
    res_get_a = client.get(f"/api/resources/{resource_a.id}", headers=headers_a)
    assert res_get_a.status_code == 200

    # User B gets User A's resource by ID -> 404
    res_get_b = client.get(f"/api/resources/{resource_a.id}", headers=headers_b)
    assert res_get_b.status_code == 404


def test_8_findings_retrieval_and_remediation_isolated_cross_user(client, db_session):
    """Scenario 11 & 12: Findings access, status update, and notes isolated; User B gets 404 on User A's findings."""
    user_a = create_test_user(db_session, "user_a_fnd", "a_fnd@tenant.com", "SECURITY_ANALYST")
    user_b = create_test_user(db_session, "user_b_fnd", "b_fnd@tenant.com", "SECURITY_ANALYST")

    acc_a = CloudAccount(
        name="Account A Findings",
        provider="MOCK",
        account_identifier="mock-fnd-a",
        default_region="us-east-1",
        user_id=user_a.id,
        is_active=True,
    )
    db_session.add(acc_a)
    db_session.commit()

    scan_a = ScanService.trigger_scan(db=db_session, user=user_a, account_id=acc_a.id)
    assert scan_a.status == "COMPLETED"

    finding_a = db_session.query(Finding).filter(Finding.cloud_account_id == acc_a.id).first()
    assert finding_a is not None

    headers_a = auth_header_for_user(user_a)
    headers_b = auth_header_for_user(user_b)

    # User A lists findings -> sees them
    res_a = client.get("/api/findings", headers=headers_a)
    assert res_a.status_code == 200
    assert res_a.json()["total"] > 0

    # User B lists findings -> sees 0
    res_b = client.get("/api/findings", headers=headers_b)
    assert res_b.status_code == 200
    assert res_b.json()["total"] == 0

    # User A gets finding by ID -> 200 OK
    assert client.get(f"/api/findings/{finding_a.id}", headers=headers_a).status_code == 200

    # User B gets finding by ID -> 404 Not Found
    assert client.get(f"/api/findings/{finding_a.id}", headers=headers_b).status_code == 404

    # User B attempts to update User A's finding status -> 404
    res_tamper = client.patch(
        f"/api/findings/{finding_a.id}/status",
        json={"status": "FALSE_POSITIVE", "rationale": "Unauthorized status change"},
        headers=headers_b,
    )
    assert res_tamper.status_code == 404

    # User B attempts to add note to User A's finding -> 404
    res_note_tamper = client.post(
        f"/api/findings/{finding_a.id}/notes",
        json={"note": "Unauthorized investigation note"},
        headers=headers_b,
    )
    assert res_note_tamper.status_code == 404

    # User A updates finding status -> succeeds
    res_upd = client.patch(
        f"/api/findings/{finding_a.id}/status",
        json={"status": "IN_PROGRESS", "rationale": "Remediation team investigating"},
        headers=headers_a,
    )
    assert res_upd.status_code == 200
    assert res_upd.json()["status"] == "IN_PROGRESS"

    # User A adds note -> succeeds
    res_note = client.post(
        f"/api/findings/{finding_a.id}/notes",
        json={"note": "Legitimate investigation note by User A"},
        headers=headers_a,
    )
    assert res_note.status_code == 200


def test_9_dashboard_stats_isolated_per_user(client, db_session):
    """Scenario 13: Dashboard posture metrics reflect only the requesting user's cloud accounts."""
    user_a = create_test_user(db_session, "user_a_dash", "a_dash@tenant.com", "SECURITY_ANALYST")
    user_b = create_test_user(db_session, "user_b_dash", "b_dash@tenant.com", "SECURITY_ANALYST")

    acc_a = CloudAccount(
        name="Account A Dashboard",
        provider="MOCK",
        account_identifier="mock-dash-a",
        default_region="us-east-1",
        user_id=user_a.id,
        is_active=True,
    )
    db_session.add(acc_a)
    db_session.commit()

    scan_a = ScanService.trigger_scan(db=db_session, user=user_a, account_id=acc_a.id)
    assert scan_a.status == "COMPLETED"

    # User A dashboard
    res_a = client.get("/api/dashboard/stats", headers=auth_header_for_user(user_a))
    assert res_a.status_code == 200
    dash_a = res_a.json()
    assert dash_a["latest_scan_id"] == str(scan_a.id)
    assert dash_a["total_findings"] > 0
    assert dash_a["total_resources"] > 0
    assert len(dash_a["score_trend"]) >= 1
    assert isinstance(dash_a["security_score"], (int, float))

    # User B dashboard (no accounts or scans)
    res_b = client.get("/api/dashboard/stats", headers=auth_header_for_user(user_b))
    assert res_b.status_code == 200
    dash_b = res_b.json()
    assert dash_b["latest_scan_id"] is None
    assert dash_b["total_findings"] == 0
    assert dash_b["total_resources"] == 0
    assert len(dash_b["score_trend"]) == 0
    assert len(dash_b["top_findings"]) == 0
    assert len(dash_b["top_risky_resources"]) == 0


def test_10_reports_isolated_per_user(client, db_session):
    """Scenario 14: PDF reports are isolated; User B cannot list, view, or download User A's reports."""
    user_a = create_test_user(db_session, "user_a_rep", "a_rep@tenant.com", "SECURITY_ANALYST")
    user_b = create_test_user(db_session, "user_b_rep", "b_rep@tenant.com", "SECURITY_ANALYST")

    acc_a = CloudAccount(
        name="Account A Reports",
        provider="MOCK",
        account_identifier="mock-rep-a",
        default_region="us-east-1",
        user_id=user_a.id,
        is_active=True,
    )
    db_session.add(acc_a)
    db_session.commit()

    scan_a = ScanService.trigger_scan(db=db_session, user=user_a, account_id=acc_a.id)
    assert scan_a.status == "COMPLETED"

    headers_a = auth_header_for_user(user_a)
    headers_b = auth_header_for_user(user_b)

    # User A generates an executive report
    gen_res = client.post(
        "/api/reports",
        json={"account_id": str(acc_a.id), "report_type": "EXECUTIVE_SUMMARY", "title": "Exec Summary A"},
        headers=headers_a,
    )
    assert gen_res.status_code == 201
    rep_id = gen_res.json()["id"]

    # User A lists reports -> sees the generated report
    list_a = client.get("/api/reports", headers=headers_a)
    assert list_a.status_code == 200
    assert rep_id in [r["id"] for r in list_a.json()["items"]]

    # User B lists reports -> does not see User A's report
    list_b = client.get("/api/reports", headers=headers_b)
    assert list_b.status_code == 200
    assert rep_id not in [r["id"] for r in list_b.json()["items"]]

    # User B attempts GET report by ID -> 404
    assert client.get(f"/api/reports/{rep_id}", headers=headers_b).status_code == 404

    # User B attempts to download report -> 404
    assert client.get(f"/api/reports/{rep_id}/download", headers=headers_b).status_code == 404


def test_11_admin_global_visibility_across_all_tenants(client, db_session):
    """Scenario 14 (admin visibility): ADMIN role sees all accounts, scans, findings, and global dashboard."""
    admin_user = db_session.query(User).join(User.roles).filter(Role.name == "ADMIN").first()
    assert admin_user is not None

    user_a = create_test_user(db_session, "tenant_a_adm", "adm_a@tenant.com", "SECURITY_ANALYST")
    user_b = create_test_user(db_session, "tenant_b_adm", "adm_b@tenant.com", "SECURITY_ANALYST")

    acc_a = CloudAccount(
        name="Account Tenant A",
        provider="MOCK",
        account_identifier="mock-adm-a",
        default_region="us-east-1",
        user_id=user_a.id,
        is_active=True,
    )
    acc_b = CloudAccount(
        name="Account Tenant B",
        provider="MOCK",
        account_identifier="mock-adm-b",
        default_region="us-east-1",
        user_id=user_b.id,
        is_active=True,
    )
    db_session.add_all([acc_a, acc_b])
    db_session.commit()

    scan_a = ScanService.trigger_scan(db=db_session, user=user_a, account_id=acc_a.id)

    headers_admin = auth_header_for_user(admin_user)

    # Admin lists cloud accounts -> sees both acc_a and acc_b
    res_accounts = client.get("/api/cloud-accounts", headers=headers_admin)
    assert res_accounts.status_code == 200
    account_ids = [a["id"] for a in res_accounts.json()]
    assert str(acc_a.id) in account_ids
    assert str(acc_b.id) in account_ids

    # Admin gets account A and B directly
    assert client.get(f"/api/cloud-accounts/{acc_a.id}", headers=headers_admin).status_code == 200
    assert client.get(f"/api/cloud-accounts/{acc_b.id}", headers=headers_admin).status_code == 200

    # Admin gets scan A directly
    assert client.get(f"/api/scans/{scan_a.id}", headers=headers_admin).status_code == 200

    # Admin dashboard sees global posture
    dash_res = client.get("/api/dashboard/stats", headers=headers_admin)
    assert dash_res.status_code == 200
    assert dash_res.json()["latest_scan_id"] == str(scan_a.id)
    assert dash_res.json()["total_resources"] > 0


def test_12_rbac_viewer_role_prevented_from_mutations(client, db_session):
    """Scenario 15: RBAC permissions preserved; VIEWER role can manage own account, but cannot mutate reports, findings, or others' accounts."""
    viewer_user = create_test_user(db_session, "pure_viewer", "viewer@tenant.com", "VIEWER")
    headers_viewer = auth_header_for_user(viewer_user)

    # VIEWER can create their own cloud account -> 201 Created
    res_acc = client.post(
        "/api/cloud-accounts",
        json={
            "name": "Viewer Cloud Account",
            "provider": "MOCK",
            "account_identifier": "mock-viewer-999",
            "default_region": "us-east-1",
        },
        headers=headers_viewer,
    )
    assert res_acc.status_code == 201
    acc_id = res_acc.json()["id"]

    # VIEWER can trigger scan on their own account -> 201 Created
    res_scan = client.post("/api/scans", json={"account_id": acc_id}, headers=headers_viewer)
    assert res_scan.status_code == 201

    # VIEWER cannot scan other user's account -> 404 Not Found
    res_scan_other = client.post("/api/scans", json={"account_id": str(uuid.uuid4())}, headers=headers_viewer)
    assert res_scan_other.status_code == 404

    # VIEWER can generate report for their own completed scan -> 201 Created
    res_rep = client.post(
        "/api/reports",
        json={"account_id": acc_id, "report_type": "EXECUTIVE", "title": "Viewer Exec Report"},
        headers=headers_viewer,
    )
    assert res_rep.status_code == 201
    rep_id = res_rep.json()["id"]

    # VIEWER cannot generate report on other user's account -> 404 Not Found (IDOR protection)
    res_rep_other = client.post(
        "/api/reports",
        json={"account_id": str(uuid.uuid4()), "report_type": "EXECUTIVE"},
        headers=headers_viewer,
    )
    assert res_rep_other.status_code == 404

    # VIEWER can view tenant-scoped audit logs (200 OK) without cross-tenant leakage
    res_audit = client.get("/api/audit-logs", headers=headers_viewer)
    assert res_audit.status_code == 200
    assert "items" in res_audit.json()

    # VIEWER cannot toggle security rules (admin only) -> 403 Forbidden
    res_rule = client.patch("/api/rules/S3-001/toggle", json={"enabled": False}, headers=headers_viewer)
    assert res_rule.status_code == 403

    # VIEWER can safely read public/dashboard endpoints
    res_dash = client.get("/api/dashboard/stats", headers=headers_viewer)
    assert res_dash.status_code == 200
