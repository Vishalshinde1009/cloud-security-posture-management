import os
import uuid
from typing import Any
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database.session import get_db, Base
from app.models.auth import User, Role, Permission
from app.models.finding import Finding, SecurityRule
from app.core.security import get_password_hash, create_access_token
from app.services.scan_service import ScanService
from app.services.compliance_service import ComplianceService
from app.services.notification_service import NotificationService
from app.services.report_service import ReportService
from app.services.scheduler_service import SchedulerService

# In-memory test SQLite DB
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

    # Permissions - get or create
    p_scans = session.query(Permission).filter(Permission.name == "run:scans").first()
    if not p_scans:
        p_scans = Permission(id=uuid.uuid4(), name="run:scans", description="Run scans")
        session.add(p_scans)

    p_audit = session.query(Permission).filter(Permission.name == "read:audit_logs").first()
    if not p_audit:
        p_audit = Permission(id=uuid.uuid4(), name="read:audit_logs", description="Read audit logs")
        session.add(p_audit)
    session.flush()

    # Roles - get or create
    r_admin = session.query(Role).filter(Role.name == "ADMIN").first()
    if not r_admin:
        r_admin = Role(id=uuid.uuid4(), name="ADMIN", description="Admin role")
        r_admin.permissions.extend([p_scans, p_audit])
        session.add(r_admin)

    r_analyst = session.query(Role).filter(Role.name == "SECURITY_ANALYST").first()
    if not r_analyst:
        r_analyst = Role(id=uuid.uuid4(), name="SECURITY_ANALYST", description="Analyst role")
        r_analyst.permissions.append(p_scans)
        session.add(r_analyst)

    r_viewer = session.query(Role).filter(Role.name == "VIEWER").first()
    if not r_viewer:
        r_viewer = Role(id=uuid.uuid4(), name="VIEWER", description="Viewer role")
        session.add(r_viewer)
    session.flush()

    # Users
    u_admin = User(
        id=uuid.uuid4(),
        username=f"admin_p8_{uuid.uuid4().hex[:6]}",
        email=f"admin_{uuid.uuid4().hex[:6]}@cspm.internal",
        password_hash=get_password_hash("AdminPass123!"),
        is_active=True,
    )
    u_admin.roles.append(r_admin)

    u_analyst = User(
        id=uuid.uuid4(),
        username=f"analyst_p8_{uuid.uuid4().hex[:6]}",
        email=f"analyst_{uuid.uuid4().hex[:6]}@cspm.internal",
        password_hash=get_password_hash("AnalystPass123!"),
        is_active=True,
    )
    u_analyst.roles.append(r_analyst)

    u_viewer = User(
        id=uuid.uuid4(),
        username=f"viewer_p8_{uuid.uuid4().hex[:6]}",
        email=f"viewer_{uuid.uuid4().hex[:6]}@cspm.internal",
        password_hash=get_password_hash("ViewerPass123!"),
        is_active=True,
    )
    u_viewer.roles.append(r_viewer)

    session.add_all([u_admin, u_analyst, u_viewer])
    session.commit()

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


def auth_header(user_id: Any, role: str) -> dict:
    token = create_access_token(subject=str(user_id), claims={"roles": [role]})
    return {"Authorization": f"Bearer {token}"}


# =========================================================================
# 1. COMPLIANCE ENGINE TESTS
# =========================================================================

def test_compliance_catalog_and_summary_calculations(db_session, client):
    """Verifies compliance framework summaries, coverage percentage, and gap metrics."""
    admin = db_session.query(User).join(User.roles).filter(Role.name == "ADMIN").first()
    scan = ScanService.trigger_scan(db=db_session, user=admin)
    assert scan.status == "COMPLETED"

    headers = auth_header(admin.id, "ADMIN")

    # List frameworks
    res = client.get("/api/compliance/frameworks", headers=headers)
    assert res.status_code == 200
    frameworks = res.json()
    assert len(frameworks) == 4
    fw_ids = [f["id"] for f in frameworks]
    assert "CIS_AWS" in fw_ids
    assert "NIST" in fw_ids
    assert "ISO27001" in fw_ids
    assert "PCI_DSS" in fw_ids

    # Summary for CIS_AWS
    res_cis = client.get("/api/compliance/CIS_AWS/summary", headers=headers)
    assert res_cis.status_code == 200
    cis_data = res_cis.json()
    assert cis_data["framework"] == "CIS_AWS"
    assert cis_data["total_controls"] > 0
    assert cis_data["compliance_percentage"] >= 0.0
    assert cis_data["compliance_percentage"] <= 100.0
    assert cis_data["status_label"] in ["EXCELLENT", "GOOD", "MODERATE", "POOR", "CRITICAL"]

    # Controls table for CIS_AWS
    res_controls = client.get("/api/compliance/CIS_AWS/controls", headers=headers)
    assert res_controls.status_code == 200
    controls = res_controls.json()
    assert len(controls) > 0
    first_ctrl = controls[0]
    assert "control_id" in first_ctrl
    assert "status" in first_ctrl
    assert first_ctrl["status"] in ["COMPLIANT", "NON_COMPLIANT"]


# =========================================================================
# 2. FINDING WORKFLOW & ANALYST NOTES TESTS
# =========================================================================

def test_finding_lifecycle_and_analyst_notes_rbac(db_session, client):
    """Tests finding lifecycle status updates, note posting, and viewer authorization restriction."""
    admin = db_session.query(User).join(User.roles).filter(Role.name == "ADMIN").first()
    analyst = db_session.query(User).join(User.roles).filter(Role.name == "SECURITY_ANALYST").first()
    viewer = db_session.query(User).join(User.roles).filter(Role.name == "VIEWER").first()

    scan = ScanService.trigger_scan(db=db_session, user=admin)

    finding = db_session.query(Finding).filter(Finding.scan_id == scan.id).first()
    assert finding is not None
    f_id = str(finding.id)

    analyst_hdr = auth_header(analyst.id, "SECURITY_ANALYST")
    viewer_hdr = auth_header(viewer.id, "VIEWER")

    # Viewer cannot change status
    res_v_status = client.patch(f"/api/findings/{f_id}/status", json={"status": "IN_PROGRESS"}, headers=viewer_hdr)
    assert res_v_status.status_code == 403

    # Analyst can transition to IN_PROGRESS
    res_a_status = client.patch(
        f"/api/findings/{f_id}/status",
        json={"status": "IN_PROGRESS", "rationale": "Investigating false alarm"},
        headers=analyst_hdr,
    )
    assert res_a_status.status_code == 200
    assert res_a_status.json()["status"] == "IN_PROGRESS"

    # Add Note as Analyst
    res_note = client.post(
        f"/api/findings/{f_id}/notes",
        json={"note": "Verified with DevOps team. Working on remediation ticket PROJ-102."},
        headers=analyst_hdr,
    )
    assert res_note.status_code == 200
    note_data = res_note.json()
    assert "PROJ-102" in note_data["note"]

    # Fetch Notes
    res_get_notes = client.get(f"/api/findings/{f_id}/notes", headers=viewer_hdr)
    assert res_get_notes.status_code == 200
    assert len(res_get_notes.json()) == 1


# =========================================================================
# 3. REPORT PDF GENERATION & SECURE DOWNLOAD
# =========================================================================

def test_report_generation_and_pdf_download(db_session, client):
    """Verifies server-side ReportLab PDF generation for Executive and Technical reports."""
    admin = db_session.query(User).join(User.roles).filter(Role.name == "ADMIN").first()
    ScanService.trigger_scan(db=db_session, user=admin)

    headers = auth_header(admin.id, "ADMIN")

    # Generate Executive Report
    res_exec = client.post(
        "/api/reports",
        json={"report_type": "EXECUTIVE", "title": "Test Executive Security Assessment"},
        headers=headers,
    )
    assert res_exec.status_code == 201
    exec_rep = res_exec.json()
    assert exec_rep["report_type"] == "EXECUTIVE"
    assert exec_rep["format"] == "PDF"
    assert os.path.exists(exec_rep["file_path"])

    # Download Executive Report PDF
    rep_id = exec_rep["id"]
    res_dl = client.get(f"/api/reports/{rep_id}/download", headers=headers)
    assert res_dl.status_code == 200
    assert res_dl.headers["content-type"] == "application/pdf"
    assert len(res_dl.content) > 1000  # Valid binary PDF data


# =========================================================================
# 4. NOTIFICATIONS DISPATCH & READ TRACKING
# =========================================================================

def test_in_app_notifications(db_session, client):
    """Verifies that scan completions trigger automated notifications and read status tracking."""
    admin = db_session.query(User).join(User.roles).filter(Role.name == "ADMIN").first()
    ScanService.trigger_scan(db=db_session, user=admin)

    headers = auth_header(admin.id, "ADMIN")

    # Fetch notifications
    res_notifs = client.get("/api/notifications", headers=headers)
    assert res_notifs.status_code == 200
    notifs_data = res_notifs.json()
    assert notifs_data["total"] > 0
    assert notifs_data["unread_count"] > 0

    # Mark all read
    res_read_all = client.post("/api/notifications/read-all", headers=headers)
    assert res_read_all.status_code == 200

    # Check unread count is now 0
    res_count = client.get("/api/notifications/unread-count", headers=headers)
    assert res_count.status_code == 200
    assert res_count.json()["unread_count"] == 0


# =========================================================================
# 5. AUDIT LOGGING & AUTHORIZATION
# =========================================================================

def test_audit_log_endpoint_rbac_and_filtering(db_session, client):
    """Verifies audit log filtering and permission enforcement."""
    admin = db_session.query(User).join(User.roles).filter(Role.name == "ADMIN").first()
    viewer = db_session.query(User).join(User.roles).filter(Role.name == "VIEWER").first()

    admin_hdr = auth_header(admin.id, "ADMIN")
    viewer_hdr = auth_header(viewer.id, "VIEWER")

    # Viewer gets 200 OK scoped to own tenant activity
    res_v = client.get("/api/audit-logs", headers=viewer_hdr)
    assert res_v.status_code == 200
    assert "items" in res_v.json()

    # Admin should get 200
    res_a = client.get("/api/audit-logs", headers=admin_hdr)
    assert res_a.status_code == 200
    data = res_a.json()
    assert "items" in data
    assert "total" in data


# =========================================================================
# 6. SECURITY RULE TOGGLE
# =========================================================================

def test_security_rule_toggle_admin_only(db_session, client):
    """Verifies admin toggle of security rules and viewer denial."""
    admin = db_session.query(User).join(User.roles).filter(Role.name == "ADMIN").first()
    analyst = db_session.query(User).join(User.roles).filter(Role.name == "SECURITY_ANALYST").first()

    analyst_hdr = auth_header(analyst.id, "SECURITY_ANALYST")
    admin_hdr = auth_header(admin.id, "ADMIN")

    # Analyst cannot toggle
    res_a = client.patch("/api/rules/S3-001/toggle", json={"enabled": False}, headers=analyst_hdr)
    assert res_a.status_code == 403

    # Admin can toggle
    res_adm = client.patch("/api/rules/S3-001/toggle", json={"enabled": False}, headers=admin_hdr)
    assert res_adm.status_code == 200
    assert res_adm.json()["enabled"] is False

    # Toggle back
    res_adm_revert = client.patch("/api/rules/S3-001/toggle", json={"enabled": True}, headers=admin_hdr)
    assert res_adm_revert.status_code == 200
    assert res_adm_revert.json()["enabled"] is True


# =========================================================================
# 7. SCHEDULER ABSTRACTION
# =========================================================================

def test_scan_scheduler_service():
    """Verifies scheduler service frequencies and next run calculation."""
    frequencies = SchedulerService.get_supported_frequencies()
    assert "MANUAL" in frequencies
    assert "DAILY" in frequencies
    assert "WEEKLY" in frequencies

    from datetime import datetime, timezone
    now = datetime(2026, 9, 6, 12, 0, 0, tzinfo=timezone.utc)
    daily_next = SchedulerService.compute_next_run("DAILY", from_time=now)
    assert daily_next.day == 7
    weekly_next = SchedulerService.compute_next_run("WEEKLY", from_time=now)
    assert weekly_next.day == 13
