"""
Phase 9C: User Email Security Alerts Test Suite
================================================
Comprehensive test suite verifying all 20 Phase 9C requirements:
1. Email notification enabled
2. Email notification disabled
3. Correct owner receives notification
4. Cross-tenant email isolation
5. HIGH new finding sends email
6. CRITICAL new finding sends email
7. MEDIUM finding does not send email
8. LOW finding does not send email
9. Risk increase sends email when HIGH/CRITICAL
10. Risk increase medium does not send email
11. Scan failure sends email
12. Duplicate detection does not send duplicate email
13. Resolved -> new finding sends a new email
14. Email failure does not fail monitoring
15. SMTP credentials never appear in API responses
16. User can disable email notifications
17. User preference is tenant-isolated
18. Audit logs email sent and failed
19. No silent MOCK fallback
20. Real AWS ROLE monitoring remains read-only
"""

import uuid
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database.session import get_db, Base
from app.database.seed import seed_database
from app.models.auth import User, Role
from app.models.cloud import CloudAccount, Scan, Resource
from app.models.finding import Finding, SecurityRule
from app.models.monitoring import MonitoringConfig, SecurityAlert
from app.models.audit import AuditLog
from app.models.base import utc_now
from app.core.security import get_password_hash, create_access_token
from app.core.config import settings
from app.notifications.email_service import EmailService
from app.notifications.notification_service import NotificationService
from app.monitoring.alert_service import AlertService
from app.monitoring.monitoring_service import MonitoringService


# In-memory test database for isolated execution
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


def create_user(db, username: str, email: str, role_name: str, email_alerts_enabled: bool = True) -> User:
    role = db.query(Role).filter(Role.name == role_name).first()
    user = User(
        id=uuid.uuid4(),
        username=username,
        email=email,
        password_hash=get_password_hash("TestPass123!"),
        is_active=True,
        email_alerts_enabled=email_alerts_enabled,
    )
    if role:
        user.roles.append(role)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def create_cloud_account(
    db, 
    user: Optional[User], 
    name="Production Account", 
    provider="AWS", 
    cred_mode="ROLE", 
    role_arn="arn:aws:iam::181137999524:role/CSPM-ReadOnly-Role"
) -> CloudAccount:
    acc = CloudAccount(
        id=uuid.uuid4(),
        user_id=user.id if user else None,
        name=name,
        provider=provider,
        account_identifier="181137999524",
        default_region="us-east-1",
        credential_mode=cred_mode,
        role_arn=role_arn,
        external_id=str(uuid.uuid4()),
        is_active=True,
    )
    db.add(acc)
    db.commit()
    db.refresh(acc)
    return acc


def create_sample_alert(
    db,
    account: CloudAccount,
    alert_type: str = "NEW_FINDING",
    severity: str = "HIGH",
    title: str = "S3 bucket missing default server-side encryption",
    status: str = "OPEN",
) -> SecurityAlert:
    alert = SecurityAlert(
        id=uuid.uuid4(),
        cloud_account_id=account.id,
        finding_id=None,
        alert_type=alert_type,
        severity=severity,
        title=title,
        description=f"Security violation: {title}",
        previous_value=None,
        current_value=severity,
        status=status,
        first_detected_at=utc_now(),
        last_detected_at=utc_now(),
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


# =============================================================================
# 1. Email notification enabled
# =============================================================================
def test_email_notification_enabled(db_session):
    """When CSPM_EMAIL_ENABLED=True, send_alert_email calls SMTP sender successfully."""
    user = create_user(db_session, "email_u1", "owner1@example.com", "ADMIN")
    acc = create_cloud_account(db_session, user)
    alert = create_sample_alert(db_session, acc, "NEW_FINDING", "HIGH")

    with patch("app.notifications.email_service.settings") as mock_settings:
        mock_settings.CSPM_EMAIL_ENABLED = True
        mock_settings.CSPM_SMTP_HOST = "smtp.example.com"
        mock_settings.CSPM_SMTP_PORT = 587
        mock_settings.CSPM_SMTP_USERNAME = "user"
        mock_settings.CSPM_SMTP_PASSWORD = "secret"
        mock_settings.CSPM_SMTP_FROM = "alerts@cspm.local"
        mock_settings.CSPM_SMTP_USE_TLS = True
        mock_settings.CSPM_FRONTEND_URL = "http://localhost:5173"

        with patch("smtplib.SMTP") as mock_smtp_cls:
            mock_server = MagicMock()
            mock_smtp_cls.return_value.__enter__.return_value = mock_server

            success, msg = EmailService.send_alert_email(
                recipient_email=user.email,
                alert=alert,
                cloud_account=acc,
            )

            assert success is True
            assert "Email sent successfully" in msg
            mock_server.send_message.assert_called_once()


# =============================================================================
# 2. Email notification disabled
# =============================================================================
def test_email_notification_disabled(db_session):
    """When CSPM_EMAIL_ENABLED=False, send_alert_email returns False without sending."""
    user = create_user(db_session, "email_u2", "owner2@example.com", "ADMIN")
    acc = create_cloud_account(db_session, user)
    alert = create_sample_alert(db_session, acc, "NEW_FINDING", "HIGH")

    with patch("app.notifications.email_service.settings") as mock_settings:
        mock_settings.CSPM_EMAIL_ENABLED = False

        with patch("smtplib.SMTP") as mock_smtp:
            success, msg = EmailService.send_alert_email(
                recipient_email=user.email,
                alert=alert,
                cloud_account=acc,
            )

            assert success is False
            assert "disabled" in msg
            mock_smtp.assert_not_called()


# =============================================================================
# 3. Correct owner receives notification
# =============================================================================
def test_correct_owner_receives_notification(db_session):
    """NotificationService sends email specifically to CloudAccount.user.email."""
    user = create_user(db_session, "target_owner", "target_owner@company.local", "ADMIN")
    acc = create_cloud_account(db_session, user, name="Target Cloud Workload")
    alert = create_sample_alert(db_session, acc, "NEW_FINDING", "HIGH")

    with patch.object(EmailService, "is_enabled", return_value=True):
        with patch.object(EmailService, "send_alert_email", return_value=(True, "OK")) as mock_send:
            res = NotificationService.notify_alert(db=db_session, alert=alert, is_new=True)

            assert res is not None
            assert res["status"] == "SENT"
            assert res["recipient"] == "target_owner@company.local"
            mock_send.assert_called_once()
            args, kwargs = mock_send.call_args
            assert kwargs["recipient_email"] == "target_owner@company.local"


# =============================================================================
# 4. Cross-tenant email isolation
# =============================================================================
def test_cross_tenant_email_isolation(db_session):
    """Alert for Tenant A's account is sent strictly to Tenant A, never Tenant B."""
    tenant_a = create_user(db_session, "tenant_a", "tenant_a@sec.corp", "SECURITY_ANALYST")
    tenant_b = create_user(db_session, "tenant_b", "tenant_b@sec.corp", "SECURITY_ANALYST")

    acc_a = create_cloud_account(db_session, tenant_a, name="Tenant A AWS Account")
    alert_a = create_sample_alert(db_session, acc_a, "NEW_FINDING", "CRITICAL")

    sent_recipients = []

    def mock_sender(recipient_email, alert, cloud_account):
        sent_recipients.append(recipient_email)
        return True, "Sent"

    with patch.object(EmailService, "is_enabled", return_value=True):
        with patch.object(EmailService, "send_alert_email", side_effect=mock_sender):
            NotificationService.notify_alert(db=db_session, alert=alert_a, is_new=True)

    assert "tenant_a@sec.corp" in sent_recipients
    assert "tenant_b@sec.corp" not in sent_recipients


# =============================================================================
# 5. HIGH new finding sends email
# =============================================================================
def test_high_new_finding_sends_email(db_session):
    """NEW_FINDING with HIGH severity triggers an email."""
    user = create_user(db_session, "high_u", "high@corp.local", "ADMIN")
    acc = create_cloud_account(db_session, user)
    alert = create_sample_alert(db_session, acc, "NEW_FINDING", "HIGH")

    with patch.object(EmailService, "is_enabled", return_value=True):
        with patch.object(EmailService, "send_alert_email", return_value=(True, "OK")) as mock_send:
            res = NotificationService.notify_alert(db=db_session, alert=alert, is_new=True)
            assert res is not None
            assert res["status"] == "SENT"
            mock_send.assert_called_once()


# =============================================================================
# 6. CRITICAL new finding sends email
# =============================================================================
def test_critical_new_finding_sends_email(db_session):
    """NEW_FINDING with CRITICAL severity triggers an email."""
    user = create_user(db_session, "crit_u", "crit@corp.local", "ADMIN")
    acc = create_cloud_account(db_session, user)
    alert = create_sample_alert(db_session, acc, "NEW_FINDING", "CRITICAL")

    with patch.object(EmailService, "is_enabled", return_value=True):
        with patch.object(EmailService, "send_alert_email", return_value=(True, "OK")) as mock_send:
            res = NotificationService.notify_alert(db=db_session, alert=alert, is_new=True)
            assert res is not None
            assert res["status"] == "SENT"
            mock_send.assert_called_once()


# =============================================================================
# 7. MEDIUM finding does not send email
# =============================================================================
def test_medium_finding_does_not_send_email(db_session):
    """NEW_FINDING with MEDIUM severity is excluded from email alerts."""
    user = create_user(db_session, "med_u", "med@corp.local", "ADMIN")
    acc = create_cloud_account(db_session, user)
    alert = create_sample_alert(db_session, acc, "NEW_FINDING", "MEDIUM")

    with patch.object(EmailService, "is_enabled", return_value=True):
        with patch.object(EmailService, "send_alert_email") as mock_send:
            res = NotificationService.notify_alert(db=db_session, alert=alert, is_new=True)
            assert res is None
            mock_send.assert_not_called()


# =============================================================================
# 8. LOW finding does not send email
# =============================================================================
def test_low_finding_does_not_send_email(db_session):
    """NEW_FINDING with LOW severity is excluded from email alerts."""
    user = create_user(db_session, "low_u", "low@corp.local", "ADMIN")
    acc = create_cloud_account(db_session, user)
    alert = create_sample_alert(db_session, acc, "NEW_FINDING", "LOW")

    with patch.object(EmailService, "is_enabled", return_value=True):
        with patch.object(EmailService, "send_alert_email") as mock_send:
            res = NotificationService.notify_alert(db=db_session, alert=alert, is_new=True)
            assert res is None
            mock_send.assert_not_called()


# =============================================================================
# 9. Risk increase sends email when HIGH/CRITICAL
# =============================================================================
def test_risk_increase_sends_email_when_high_or_critical(db_session):
    """RISK_INCREASED with HIGH severity triggers an email."""
    user = create_user(db_session, "risk_inc_u", "risk_inc@corp.local", "ADMIN")
    acc = create_cloud_account(db_session, user)
    alert = create_sample_alert(db_session, acc, "RISK_INCREASED", "HIGH")

    with patch.object(EmailService, "is_enabled", return_value=True):
        with patch.object(EmailService, "send_alert_email", return_value=(True, "OK")) as mock_send:
            res = NotificationService.notify_alert(db=db_session, alert=alert, is_new=True)
            assert res is not None
            assert res["status"] == "SENT"
            mock_send.assert_called_once()


# =============================================================================
# 10. Risk increase medium does not send email
# =============================================================================
def test_risk_increase_medium_does_not_send_email(db_session):
    """RISK_INCREASED with MEDIUM severity does not trigger an email."""
    user = create_user(db_session, "risk_med_u", "risk_med@corp.local", "ADMIN")
    acc = create_cloud_account(db_session, user)
    alert = create_sample_alert(db_session, acc, "RISK_INCREASED", "MEDIUM")

    with patch.object(EmailService, "is_enabled", return_value=True):
        with patch.object(EmailService, "send_alert_email") as mock_send:
            res = NotificationService.notify_alert(db=db_session, alert=alert, is_new=True)
            assert res is None
            mock_send.assert_not_called()


# =============================================================================
# 11. Scan failure sends email
# =============================================================================
def test_scan_failure_sends_email(db_session):
    """SCAN_FAILED alert triggers an email notification."""
    user = create_user(db_session, "fail_u", "fail@corp.local", "ADMIN")
    acc = create_cloud_account(db_session, user)
    alert = create_sample_alert(db_session, acc, "SCAN_FAILED", "HIGH", title="Cloud Scan Failed")

    with patch.object(EmailService, "is_enabled", return_value=True):
        with patch.object(EmailService, "send_alert_email", return_value=(True, "OK")) as mock_send:
            res = NotificationService.notify_alert(db=db_session, alert=alert, is_new=True)
            assert res is not None
            assert res["status"] == "SENT"
            mock_send.assert_called_once()


# =============================================================================
# 12. Duplicate detection does not send duplicate email
# =============================================================================
def test_duplicate_detection_does_not_send_duplicate_email(db_session):
    """Repeated detection of an unresolved alert does not send duplicate emails."""
    user = create_user(db_session, "dedup_u", "dedup@corp.local", "ADMIN")
    acc = create_cloud_account(db_session, user)
    alert = create_sample_alert(db_session, acc, "NEW_FINDING", "HIGH")

    with patch.object(EmailService, "is_enabled", return_value=True):
        with patch.object(EmailService, "send_alert_email", return_value=(True, "OK")) as mock_send:
            # First scan: alert is new -> sends email
            res1 = NotificationService.notify_alert(db=db_session, alert=alert, is_new=True)
            assert res1 is not None
            assert res1["status"] == "SENT"
            assert mock_send.call_count == 1

            # Second scan: same unresolved condition -> is_new=False -> NO email
            res2 = NotificationService.notify_alert(db=db_session, alert=alert, is_new=False)
            assert res2 is None
            assert mock_send.call_count == 1

            # Third scan: even if is_new=True is passed, is_already_notified prevents re-emailing
            res3 = NotificationService.notify_alert(db=db_session, alert=alert, is_new=True)
            assert res3 is None
            assert mock_send.call_count == 1


# =============================================================================
# 13. Resolved -> new finding sends a new email
# =============================================================================
def test_resolved_then_new_finding_sends_new_email(db_session):
    """When a resolved finding reappears, a new alert is generated and emails."""
    user = create_user(db_session, "reappear_u", "reappear@corp.local", "ADMIN")
    acc = create_cloud_account(db_session, user)

    # First alert was created and resolved
    alert1 = create_sample_alert(db_session, acc, "NEW_FINDING", "HIGH", status="RESOLVED")

    # Record that alert1 had an email sent
    db_session.add(AuditLog(
        user_id=user.id,
        action="EMAIL_ALERT_SENT",
        resource_type="security_alert",
        resource_id=str(alert1.id),
        result="SUCCESS",
        metadata_json={"alert_id": str(alert1.id)},
    ))
    db_session.commit()

    # Finding later reappears -> new alert instance with new UUID
    alert2 = create_sample_alert(db_session, acc, "NEW_FINDING", "HIGH", status="OPEN")

    with patch.object(EmailService, "is_enabled", return_value=True):
        with patch.object(EmailService, "send_alert_email", return_value=(True, "OK")) as mock_send:
            res = NotificationService.notify_alert(db=db_session, alert=alert2, is_new=True)
            assert res is not None
            assert res["status"] == "SENT"
            mock_send.assert_called_once()


# =============================================================================
# 14. Email failure does not fail monitoring
# =============================================================================
def test_email_failure_does_not_fail_monitoring(db_session):
    """SMTP delivery failure is gracefully handled and does not raise an exception."""
    user = create_user(db_session, "smtp_fail_u", "smtp_fail@corp.local", "ADMIN")
    acc = create_cloud_account(db_session, user)
    alert = create_sample_alert(db_session, acc, "NEW_FINDING", "HIGH")

    with patch.object(EmailService, "is_enabled", return_value=True):
        with patch.object(
            EmailService, "send_alert_email", return_value=(False, "Connection refused")
        ):
            # Must NOT raise exception
            res = NotificationService.notify_alert(db=db_session, alert=alert, is_new=True)
            assert res is not None
            assert res["status"] == "FAILED"

    # Verify EMAIL_ALERT_FAILED audit log is recorded
    fail_log = db_session.query(AuditLog).filter(
        AuditLog.action == "EMAIL_ALERT_FAILED",
        AuditLog.resource_id == str(alert.id),
    ).first()
    assert fail_log is not None
    assert fail_log.result == "FAILED"


# =============================================================================
# 15. SMTP credentials never appear in API responses
# =============================================================================
def test_smtp_credentials_never_appear_in_api_responses(client, db_session):
    """Ensures no SMTP password, host, or secrets are exposed in API endpoints."""
    user = create_user(db_session, "sec_checker", "sec_checker@corp.local", "ADMIN")
    headers = auth_header_for_user(user)

    secret_marker = "SuperSecretSMTPPassword123!"

    with patch("app.core.config.settings.CSPM_SMTP_PASSWORD", secret_marker):
        # 1. /api/auth/me
        me_res = client.get("/api/auth/me", headers=headers)
        assert me_res.status_code == 200
        assert secret_marker not in me_res.text

        # 2. /api/auth/preferences
        pref_res = client.get("/api/auth/preferences", headers=headers)
        assert pref_res.status_code == 200
        assert secret_marker not in pref_res.text
        assert "password" not in pref_res.text.lower()
        assert "smtp" not in pref_res.text.lower()

        # 3. /api/alerts
        alerts_res = client.get("/api/alerts", headers=headers)
        assert alerts_res.status_code == 200
        assert secret_marker not in alerts_res.text


# =============================================================================
# 16. User can disable email notifications
# =============================================================================
def test_user_can_disable_email_notifications(client, db_session):
    """User can toggle off email alerts; subsequent alerts are skipped."""
    user = create_user(db_session, "optout_user", "optout@corp.local", "SECURITY_ANALYST", email_alerts_enabled=True)
    headers = auth_header_for_user(user)
    acc = create_cloud_account(db_session, user)

    # Disable email alerts via API
    put_res = client.put(
        "/api/auth/preferences",
        json={"email_alerts_enabled": False},
        headers=headers,
    )
    assert put_res.status_code == 200
    assert put_res.json()["email_alerts_enabled"] is False

    db_session.refresh(user)
    assert user.email_alerts_enabled is False

    # Generate alert
    alert = create_sample_alert(db_session, acc, "NEW_FINDING", "CRITICAL")

    with patch.object(EmailService, "is_enabled", return_value=True):
        with patch.object(EmailService, "send_alert_email") as mock_send:
            res = NotificationService.notify_alert(db=db_session, alert=alert, is_new=True)
            assert res is not None
            assert res["status"] == "SKIPPED"
            assert res["reason"] == "user_preferences_disabled"
            mock_send.assert_not_called()


# =============================================================================
# 17. User preference is tenant-isolated
# =============================================================================
def test_user_preference_is_tenant_isolated(client, db_session):
    """User A cannot modify User B's preference; preference changes are fully isolated."""
    user_a = create_user(db_session, "iso_a", "iso_a@corp.local", "SECURITY_ANALYST", email_alerts_enabled=True)
    user_b = create_user(db_session, "iso_b", "iso_b@corp.local", "SECURITY_ANALYST", email_alerts_enabled=True)

    headers_a = auth_header_for_user(user_a)

    # User A disables preferences
    put_res = client.put(
        "/api/auth/preferences",
        json={"email_alerts_enabled": False},
        headers=headers_a,
    )
    assert put_res.status_code == 200
    assert put_res.json()["email"] == "iso_a@corp.local"
    assert put_res.json()["email_alerts_enabled"] is False

    db_session.refresh(user_a)
    db_session.refresh(user_b)

    # User A is disabled, User B remains enabled
    assert user_a.email_alerts_enabled is False
    assert user_b.email_alerts_enabled is True

    # Alert on User B's account still sends email
    acc_b = create_cloud_account(db_session, user_b, name="User B Account")
    alert_b = create_sample_alert(db_session, acc_b, "NEW_FINDING", "HIGH")

    with patch.object(EmailService, "is_enabled", return_value=True):
        with patch.object(EmailService, "send_alert_email", return_value=(True, "Sent")) as mock_send:
            res_b = NotificationService.notify_alert(db=db_session, alert=alert_b, is_new=True)
            assert res_b is not None
            assert res_b["status"] == "SENT"
            assert res_b["recipient"] == "iso_b@corp.local"


# =============================================================================
# 18. Audit logs email sent and failed
# =============================================================================
def test_audit_logs_email_sent_and_failed(db_session):
    """Audit logs are recorded with correct action names and sanitized metadata."""
    user = create_user(db_session, "audit_u", "audit_test@corp.local", "ADMIN")
    acc = create_cloud_account(db_session, user)
    alert1 = create_sample_alert(db_session, acc, "NEW_FINDING", "HIGH")
    alert2 = create_sample_alert(db_session, acc, "SCAN_FAILED", "HIGH")

    with patch.object(EmailService, "is_enabled", return_value=True):
        # 1. Success case
        with patch.object(EmailService, "send_alert_email", return_value=(True, "Success")):
            NotificationService.notify_alert(db=db_session, alert=alert1, is_new=True)

        # 2. Failure case
        with patch.object(EmailService, "send_alert_email", return_value=(False, "SMTP Timeout")):
            NotificationService.notify_alert(db=db_session, alert=alert2, is_new=True)

    sent_log = db_session.query(AuditLog).filter(
        AuditLog.action == "EMAIL_ALERT_SENT",
        AuditLog.resource_id == str(alert1.id),
    ).first()
    assert sent_log is not None
    assert sent_log.result == "SUCCESS"
    assert sent_log.metadata_json["recipient_email"] == "audit_test@corp.local"

    failed_log = db_session.query(AuditLog).filter(
        AuditLog.action == "EMAIL_ALERT_FAILED",
        AuditLog.resource_id == str(alert2.id),
    ).first()
    assert failed_log is not None
    assert failed_log.result == "FAILED"
    assert "SMTP Timeout" in failed_log.metadata_json["error"]


# =============================================================================
# 19. No silent MOCK fallback
# =============================================================================
def test_no_silent_mock_fallback(db_session):
    """
    When an AWS scan encounters an STS AssumeRole error, the system must record
    SCAN_FAILED and NOT silently fall back to MOCK provider.
    """
    user = create_user(db_session, "nofb_user", "nofb@corp.local", "ADMIN")
    acc = create_cloud_account(db_session, user, provider="AWS", cred_mode="ROLE", role_arn="arn:aws:iam::181137999524:role/FailingRole")

    with patch.object(EmailService, "is_enabled", return_value=True):
        with patch.object(EmailService, "send_alert_email", return_value=(True, "OK")):
            # Simulate scan failure
            alert = AlertService.record_scan_failure(
                db=db_session,
                account=acc,
                error_message="AccessDenied: User is not authorized to perform sts:AssumeRole",
                user_id=user.id,
            )

    assert alert.alert_type == "SCAN_FAILED"
    assert alert.severity == "HIGH"
    # Ensure account provider was not mutated to MOCK
    assert acc.provider == "AWS"
    assert acc.credential_mode == "ROLE"


# =============================================================================
# 20. Real AWS ROLE monitoring remains read-only
# =============================================================================
def test_real_aws_role_monitoring_remains_read_only(db_session):
    """
    Verifies that the read_only_guard prevents write actions during monitoring
    and preserves read-only security posture.
    """
    from app.scanner.providers.aws.read_only_guard import (
        assert_read_only_operation,
        AWSReadOnlyViolationError,
    )

    # Read operations allowed (do not raise)
    assert_read_only_operation("list_buckets")
    assert_read_only_operation("describe_instances")
    assert_read_only_operation("get_bucket_encryption")
    assert_read_only_operation("head_bucket")

    # Mutating / write operations strictly blocked
    with pytest.raises(AWSReadOnlyViolationError):
        assert_read_only_operation("put_bucket_policy")

    with pytest.raises(AWSReadOnlyViolationError):
        assert_read_only_operation("delete_bucket")

    with pytest.raises(AWSReadOnlyViolationError):
        assert_read_only_operation("terminate_instances")

    with pytest.raises(AWSReadOnlyViolationError):
        assert_read_only_operation("create_user")
