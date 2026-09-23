"""
Phase 9C: Notification Service for Security Alerts
==================================================
Coordinates dispatch of security alert notifications to the verified owner of the CloudAccount.
- Strict tenant isolation: CloudAccount.user_id -> User.email.
- Event filtering: HIGH/CRITICAL new findings, HIGH/CRITICAL risk increases, and scan failures only.
- Strict deduplication: prevents duplicate notifications for repeated detections of unresolved alerts.
- User preferences: respects User.email_alerts_enabled.
- System switch: respects settings.CSPM_EMAIL_ENABLED.
- Failure resilience: never raises exceptions or rolls back scan results on email failure.
"""

import logging
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.monitoring import SecurityAlert
from app.models.cloud import CloudAccount
from app.models.auth import User
from app.models.audit import AuditLog
from app.notifications.email_service import EmailService

logger = logging.getLogger("cspm.notifications.service")


class NotificationService:
    """
    Coordinates tenant-isolated security alert notification delivery.
    """

    @classmethod
    def should_notify_event(cls, alert: SecurityAlert) -> bool:
        """
        Evaluates whether an alert matches the strictly defined notification criteria:
        A. NEW HIGH finding
        B. NEW CRITICAL finding
        C. RISK_INCREASED with resulting risk HIGH or CRITICAL
        D. SCAN_FAILED
        Excludes: LOW/MEDIUM findings, posture changes, resolutions, normal completions.
        """
        alert_type = alert.alert_type.upper()
        severity = alert.severity.upper()

        if alert_type == "NEW_FINDING" and severity in ["HIGH", "CRITICAL"]:
            return True

        if alert_type == "RISK_INCREASED" and severity in ["HIGH", "CRITICAL"]:
            return True

        if alert_type == "SCAN_FAILED":
            return True

        return False

    @classmethod
    def is_already_notified(cls, db: Session, alert_id: Any) -> bool:
        """
        Checks whether an alert notification has already been transmitted for this alert.
        Prevents repeated email blasts during periodic scheduler runs.
        """
        existing_sent_log = db.query(AuditLog).filter(
            AuditLog.action == "EMAIL_ALERT_SENT",
            AuditLog.resource_id == str(alert_id),
        ).first()
        return existing_sent_log is not None

    @classmethod
    def notify_alert(
        cls,
        db: Session,
        alert: SecurityAlert,
        is_new: bool = True,
    ) -> Optional[Dict[str, Any]]:
        """
        Evaluates and dispatches a security alert notification to the verified CloudAccount owner.
        Guaranteed non-blocking: any exception or SMTP failure is caught and logged.
        """
        try:
            # 1. Check event eligibility
            if not cls.should_notify_event(alert):
                logger.debug(
                    f"Alert {alert.id} ({alert.alert_type}, {alert.severity}) does not meet notification criteria. Skipping."
                )
                return None

            # 2. Check deduplication (only notify on brand-new alert generation)
            if not is_new:
                logger.debug(
                    f"Alert {alert.id} is an existing unresolved alert. Skipping duplicate notification."
                )
                return None

            if cls.is_already_notified(db, alert.id):
                logger.debug(
                    f"Alert {alert.id} has already had an email sent. Skipping duplicate notification."
                )
                return None

            # 3. Resolve Cloud Account and verified Owner
            account = alert.cloud_account
            if not account:
                account = db.query(CloudAccount).filter(CloudAccount.id == alert.cloud_account_id).first()

            if not account:
                logger.warning(f"Notification skipped: CloudAccount {alert.cloud_account_id} not found.")
                return None

            if not account.user_id:
                logger.info(
                    f"Notification skipped: CloudAccount '{account.name}' ({account.id}) has no assigned owner."
                )
                db.add(AuditLog(
                    user_id=None,
                    action="EMAIL_ALERT_SKIPPED",
                    resource_type="security_alert",
                    resource_id=str(alert.id),
                    result="SKIPPED",
                    metadata_json={
                        "cloud_account_id": str(account.id),
                        "reason": "no_account_owner",
                        "alert_type": alert.alert_type,
                        "severity": alert.severity,
                    },
                ))
                db.commit()
                return {"status": "SKIPPED", "reason": "no_account_owner"}

            # Resolve User
            user = account.user
            if not user:
                user = db.query(User).filter(User.id == account.user_id).first()

            if not user or not user.email:
                logger.warning(
                    f"Notification skipped: Owner user {account.user_id} has no registered email."
                )
                db.add(AuditLog(
                    user_id=account.user_id,
                    action="EMAIL_ALERT_SKIPPED",
                    resource_type="security_alert",
                    resource_id=str(alert.id),
                    result="SKIPPED",
                    metadata_json={
                        "cloud_account_id": str(account.id),
                        "reason": "no_user_email",
                        "alert_type": alert.alert_type,
                        "severity": alert.severity,
                    },
                ))
                db.commit()
                return {"status": "SKIPPED", "reason": "no_user_email"}

            # 4. Check User Preference (Tenant-Isolated)
            if getattr(user, "email_alerts_enabled", True) is False:
                logger.info(
                    f"User {user.email} has disabled email security alerts. Skipping notification."
                )
                db.add(AuditLog(
                    user_id=user.id,
                    action="EMAIL_ALERT_SKIPPED",
                    resource_type="security_alert",
                    resource_id=str(alert.id),
                    result="SKIPPED",
                    metadata_json={
                        "cloud_account_id": str(account.id),
                        "reason": "user_preferences_disabled",
                        "recipient_user_id": str(user.id),
                        "alert_type": alert.alert_type,
                        "severity": alert.severity,
                    },
                ))
                db.commit()
                return {"status": "SKIPPED", "reason": "user_preferences_disabled"}

            # 5. Check System Switch (CSPM_EMAIL_ENABLED)
            if not EmailService.is_enabled():
                logger.debug("System email notifications are disabled (CSPM_EMAIL_ENABLED=false).")
                db.add(AuditLog(
                    user_id=user.id,
                    action="EMAIL_ALERT_SKIPPED",
                    resource_type="security_alert",
                    resource_id=str(alert.id),
                    result="SKIPPED",
                    metadata_json={
                        "cloud_account_id": str(account.id),
                        "reason": "system_email_disabled",
                        "recipient_user_id": str(user.id),
                        "alert_type": alert.alert_type,
                        "severity": alert.severity,
                    },
                ))
                db.commit()
                return {"status": "SKIPPED", "reason": "system_email_disabled"}

            # 6. Attempt Email Transmission
            success, message = EmailService.send_alert_email(
                recipient_email=user.email,
                alert=alert,
                cloud_account=account,
            )

            if success:
                db.add(AuditLog(
                    user_id=user.id,
                    action="EMAIL_ALERT_SENT",
                    resource_type="security_alert",
                    resource_id=str(alert.id),
                    result="SUCCESS",
                    metadata_json={
                        "cloud_account_id": str(account.id),
                        "recipient_user_id": str(user.id),
                        "recipient_email": user.email,
                        "alert_type": alert.alert_type,
                        "severity": alert.severity,
                    },
                ))
                db.commit()
                return {
                    "status": "SENT",
                    "recipient": user.email,
                    "alert_id": str(alert.id),
                }
            else:
                db.add(AuditLog(
                    user_id=user.id,
                    action="EMAIL_ALERT_FAILED",
                    resource_type="security_alert",
                    resource_id=str(alert.id),
                    result="FAILED",
                    metadata_json={
                        "cloud_account_id": str(account.id),
                        "recipient_user_id": str(user.id),
                        "recipient_email": user.email,
                        "alert_type": alert.alert_type,
                        "severity": alert.severity,
                        "error": message,
                    },
                ))
                db.commit()
                return {
                    "status": "FAILED",
                    "recipient": user.email,
                    "error": message,
                }

        except Exception as e:
            logger.error(
                f"NotificationService error while dispatching alert {alert.id}: {e}",
                exc_info=True,
            )
            # Guarantee: Scanner and monitoring flows never break due to notification failures
            try:
                db.add(AuditLog(
                    user_id=None,
                    action="EMAIL_ALERT_FAILED",
                    resource_type="security_alert",
                    resource_id=str(alert.id),
                    result="FAILED",
                    metadata_json={
                        "alert_id": str(alert.id),
                        "error": str(e),
                    },
                ))
                db.commit()
            except Exception:
                pass
            return {"status": "ERROR", "error": str(e)}
