"""
Audit Logs RBAC & Tenant Isolation Test Suite
============================================
Verifies:
1. VIEWER can access Audit Logs (200 OK).
2. VIEWER only sees own tenant events (logins, account events, scan events).
3. VIEWER cannot see another user's events.
4. VIEWER cannot manipulate user_id query param to access another tenant.
5. VIEWER cannot manipulate account_id query param to access another tenant.
6. ADMIN retains global audit visibility.
7. SECURITY ANALYST retains existing audit visibility.
8. Pagination remains tenant-safe.
9. Audit counts remain tenant-safe.
10. Search/filtering remains tenant-safe.
11. Unauthenticated request rejected (401).
12. Sensitive tokens/passwords never leaked in audit log responses.
"""

import uuid
from typing import Optional
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database.session import get_db, Base
from app.database.seed import seed_database
from app.models.auth import User, Role
from app.models.cloud import CloudAccount, Scan
from app.models.audit import AuditLog
from app.models.base import utc_now
from app.core.security import get_password_hash, create_access_token


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
    Base.metadata.create_all(bind=test_engine)
    session = TestingSessionLocal()
    seed_database(db=session)
    yield session
    session.close()
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture(scope="function")
def client(db_session):
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
    roles = [r.name for r in user.roles]
    token = create_access_token(subject=str(user.id), claims={"roles": roles, "username": user.username})
    return {"Authorization": f"Bearer {token}"}


def create_user(db, username: str, email: str, role_name: str) -> User:
    role = db.query(Role).filter(Role.name == role_name).first()
    user = User(
        id=uuid.uuid4(),
        username=username,
        email=email,
        password_hash=get_password_hash("TestPass123!"),
        is_active=True,
    )
    if role:
        user.roles.append(role)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def create_cloud_account(db, user: Optional[User], name="Viewer AWS Account") -> CloudAccount:
    acc = CloudAccount(
        id=uuid.uuid4(),
        user_id=user.id if user else None,
        name=name,
        provider="AWS",
        account_identifier="123456789012",
        default_region="us-east-1",
        credential_mode="ROLE",
        role_arn="arn:aws:iam::123456789012:role/ViewerRole",
        external_id=str(uuid.uuid4()),
        is_active=True,
    )
    db.add(acc)
    db.commit()
    db.refresh(acc)
    return acc


def create_audit_entry(
    db,
    user_id: Optional[uuid.UUID],
    action: str,
    resource_type: str = "cloud_account",
    resource_id: Optional[str] = None,
    metadata_json: Optional[dict] = None,
) -> AuditLog:
    log = AuditLog(
        id=uuid.uuid4(),
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id or str(uuid.uuid4()),
        result="SUCCESS",
        metadata_json=metadata_json or {},
        ip_address="127.0.0.1",
        timestamp=utc_now(),
    )
    db.add(log)
    db.commit()
    db.refresh(log)
    return log


# =============================================================================
# 1. VIEWER can access Audit Logs (200 OK)
# =============================================================================
def test_viewer_can_access_audit_logs(client, db_session):
    """VIEWER role receives 200 OK instead of 403 Forbidden."""
    viewer = create_user(db_session, "viewer_1", "viewer1@test.local", "VIEWER")
    headers = auth_header_for_user(viewer)

    res = client.get("/api/audit-logs", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "items" in data
    assert "total" in data
    assert data["page"] == 1


# =============================================================================
# 2. VIEWER only sees own tenant events
# =============================================================================
def test_viewer_only_sees_own_tenant_events(client, db_session):
    """VIEWER sees audit events they initiated or that targeted their own cloud accounts."""
    viewer = create_user(db_session, "viewer_tenant_a", "viewer_a@test.local", "VIEWER")
    headers = auth_header_for_user(viewer)

    acc = create_cloud_account(db_session, viewer, name="Viewer A AWS Account")

    # Event 1: Viewer's login
    log1 = create_audit_entry(db_session, viewer.id, "USER_LOGIN_SUCCESS", resource_type="user", resource_id=str(viewer.id))
    # Event 2: Viewer's cloud account creation
    log2 = create_audit_entry(db_session, viewer.id, "CLOUD_ACCOUNT_REGISTERED", resource_type="cloud_account", resource_id=str(acc.id))
    # Event 3: Background scan on viewer's account (user_id=None or system)
    log3 = create_audit_entry(db_session, None, "MONITORING_SCHEDULED_RUN", resource_type="cloud_account", resource_id=str(acc.id))

    res = client.get("/api/audit-logs", headers=headers)
    assert res.status_code == 200
    items = res.json()["items"]
    item_ids = [it["id"] for it in items]

    assert str(log1.id) in item_ids
    assert str(log2.id) in item_ids
    assert str(log3.id) in item_ids


# =============================================================================
# 3. VIEWER cannot see another user's events
# =============================================================================
def test_viewer_cannot_see_another_users_events(client, db_session):
    """VIEWER never receives events belonging to another tenant or other users."""
    viewer_a = create_user(db_session, "viewer_iso_a", "viewer_iso_a@test.local", "VIEWER")
    viewer_b = create_user(db_session, "viewer_iso_b", "viewer_iso_b@test.local", "VIEWER")

    acc_b = create_cloud_account(db_session, viewer_b, name="Viewer B Secret Account")

    # Event belonging to User B
    log_b1 = create_audit_entry(db_session, viewer_b.id, "USER_LOGIN_SUCCESS", resource_type="user", resource_id=str(viewer_b.id))
    log_b2 = create_audit_entry(db_session, viewer_b.id, "CLOUD_ACCOUNT_REGISTERED", resource_type="cloud_account", resource_id=str(acc_b.id))

    # User A requests audit logs
    headers_a = auth_header_for_user(viewer_a)
    res_a = client.get("/api/audit-logs", headers=headers_a)

    assert res_a.status_code == 200
    items_a = res_a.json()["items"]
    item_ids_a = [it["id"] for it in items_a]

    assert str(log_b1.id) not in item_ids_a
    assert str(log_b2.id) not in item_ids_a


# =============================================================================
# 4. VIEWER cannot manipulate user_id to access another tenant
# =============================================================================
def test_viewer_cannot_manipulate_user_id(client, db_session):
    """Supplying ?user_id=<other_user> does not bypass isolation."""
    viewer_a = create_user(db_session, "viewer_probe_a", "probe_a@test.local", "VIEWER")
    viewer_b = create_user(db_session, "viewer_probe_b", "probe_b@test.local", "VIEWER")

    log_b = create_audit_entry(db_session, viewer_b.id, "USER_LOGIN_SUCCESS", resource_type="user", resource_id=str(viewer_b.id))

    headers_a = auth_header_for_user(viewer_a)
    # Attempt to query User B's user_id
    res = client.get(f"/api/audit-logs?user_id={viewer_b.id}", headers=headers_a)
    assert res.status_code == 200
    items = res.json()["items"]
    item_ids = [it["id"] for it in items]

    assert str(log_b.id) not in item_ids
    assert len(items) == 0


# =============================================================================
# 5. VIEWER cannot manipulate tenant/account filters to bypass isolation
# =============================================================================
def test_viewer_cannot_manipulate_account_id(client, db_session):
    """Supplying ?account_id=<other_account> returns 0 items for VIEWER."""
    viewer_a = create_user(db_session, "viewer_acc_a", "acc_a@test.local", "VIEWER")
    viewer_b = create_user(db_session, "viewer_acc_b", "acc_b@test.local", "VIEWER")

    acc_b = create_cloud_account(db_session, viewer_b, name="Private Account B")
    log_b = create_audit_entry(db_session, viewer_b.id, "SCAN_STARTED", resource_type="cloud_account", resource_id=str(acc_b.id))

    headers_a = auth_header_for_user(viewer_a)
    res = client.get(f"/api/audit-logs?account_id={acc_b.id}", headers=headers_a)
    assert res.status_code == 200
    items = res.json()["items"]

    assert len(items) == 0


# =============================================================================
# 6. ADMIN retains global audit visibility
# =============================================================================
def test_admin_retains_global_audit_visibility(client, db_session):
    """ADMIN sees all audit records across all tenants."""
    admin = create_user(db_session, "super_admin_audit", "sadmin@test.local", "ADMIN")
    user1 = create_user(db_session, "tenant_u1", "u1@test.local", "VIEWER")
    user2 = create_user(db_session, "tenant_u2", "u2@test.local", "VIEWER")

    log1 = create_audit_entry(db_session, user1.id, "CLOUD_ACCOUNT_REGISTERED")
    log2 = create_audit_entry(db_session, user2.id, "SCAN_COMPLETED")

    headers_admin = auth_header_for_user(admin)
    res = client.get("/api/audit-logs", headers=headers_admin)
    assert res.status_code == 200
    items = res.json()["items"]
    item_ids = [it["id"] for it in items]

    assert str(log1.id) in item_ids
    assert str(log2.id) in item_ids


# =============================================================================
# 7. SECURITY ANALYST retains existing audit visibility
# =============================================================================
def test_security_analyst_retains_audit_visibility(client, db_session):
    """SECURITY_ANALYST (possessing read:audit_logs) retains global audit visibility."""
    analyst = create_user(db_session, "analyst_audit_user", "analyst_audit@test.local", "SECURITY_ANALYST")
    user = create_user(db_session, "random_tenant", "rt@test.local", "VIEWER")

    log = create_audit_entry(db_session, user.id, "ALERT_CREATED")

    headers_analyst = auth_header_for_user(analyst)
    res = client.get("/api/audit-logs", headers=headers_analyst)
    assert res.status_code == 200
    item_ids = [it["id"] for it in res.json()["items"]]

    assert str(log.id) in item_ids


# =============================================================================
# 8. Pagination remains tenant-safe
# =============================================================================
def test_pagination_remains_tenant_safe(client, db_session):
    """Pagination offsets and limits only traverse the viewer's own records."""
    viewer = create_user(db_session, "page_viewer", "page@test.local", "VIEWER")
    other = create_user(db_session, "page_other", "other@test.local", "VIEWER")

    # Create 5 logs for other user
    for i in range(5):
        create_audit_entry(db_session, other.id, f"OTHER_ACTION_{i}")

    # Create 3 logs for viewer
    for i in range(3):
        create_audit_entry(db_session, viewer.id, f"VIEWER_ACTION_{i}")

    headers = auth_header_for_user(viewer)
    res = client.get("/api/audit-logs?page=1&limit=10", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 3
    assert len(data["items"]) == 3
    for it in data["items"]:
        assert "VIEWER_ACTION" in it["action"]


# =============================================================================
# 9. Audit counts remain tenant-safe
# =============================================================================
def test_audit_counts_remain_tenant_safe(client, db_session):
    """Total count matches only records belonging to the viewer."""
    viewer = create_user(db_session, "count_viewer", "count@test.local", "VIEWER")
    other = create_user(db_session, "count_other", "count_other@test.local", "ADMIN")

    for _ in range(10):
        create_audit_entry(db_session, other.id, "ADMIN_EVENT")

    create_audit_entry(db_session, viewer.id, "VIEWER_EVENT")

    headers = auth_header_for_user(viewer)
    res = client.get("/api/audit-logs", headers=headers)
    assert res.status_code == 200
    assert res.json()["total"] == 1


# =============================================================================
# 10. Search/filtering remains tenant-safe
# =============================================================================
def test_search_remains_tenant_safe(client, db_session):
    """Searching actions does not expose matches from other tenants."""
    viewer = create_user(db_session, "search_viewer", "search@test.local", "VIEWER")
    other = create_user(db_session, "search_other", "search_other@test.local", "VIEWER")

    # Both have a SCAN event
    log_other = create_audit_entry(db_session, other.id, "SCAN_EXECUTION_STARTED")
    log_viewer = create_audit_entry(db_session, viewer.id, "SCAN_EXECUTION_STARTED")

    headers = auth_header_for_user(viewer)
    res = client.get("/api/audit-logs?action=SCAN", headers=headers)
    assert res.status_code == 200
    item_ids = [it["id"] for it in res.json()["items"]]

    assert str(log_viewer.id) in item_ids
    assert str(log_other.id) not in item_ids


# =============================================================================
# 11. Unauthenticated request rejected (401)
# =============================================================================
def test_unauthenticated_request_rejected(client):
    """Requests without a token receive 401 Unauthorized."""
    res = client.get("/api/audit-logs")
    assert res.status_code == 401


# =============================================================================
# 12. Sensitive tokens/passwords never leaked in audit log responses
# =============================================================================
def test_sensitive_tokens_and_other_emails_not_leaked(client, db_session):
    """Metadata containing credentials or other users' emails is sanitized."""
    viewer = create_user(db_session, "clean_viewer", "clean@test.local", "VIEWER")
    acc = create_cloud_account(db_session, viewer, name="Clean Account")

    # Create log with sensitive keys and another email
    create_audit_entry(
        db_session,
        viewer.id,
        "CONFIG_UPDATED",
        resource_id=str(acc.id),
        metadata_json={
            "safe_param": "visible",
            "password": "SecretPassword123!",
            "smtp_password": "smtp_secret",
            "access_key": "AKIAIOSFODNN7EXAMPLE",
            "other_user_email": "other@victim.com",
            "email": "clean@test.local",
        }
    )

    headers = auth_header_for_user(viewer)
    res = client.get("/api/audit-logs", headers=headers)
    assert res.status_code == 200
    items = res.json()["items"]
    assert len(items) >= 1

    meta = items[0]["metadata_json"]
    assert "safe_param" in meta
    assert "password" not in meta
    assert "smtp_password" not in meta
    assert "access_key" not in meta
    assert "other_user_email" not in meta
    assert meta.get("email") == "clean@test.local"
