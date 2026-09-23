import uuid
import logging
from typing import List, Optional, Dict, Any
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_, and_

from app.models.monitoring import SecurityAlert
from app.models.cloud import CloudAccount, Scan
from app.models.finding import Finding
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.base import utc_now
from app.monitoring.change_detector import ChangeDetectionResult

logger = logging.getLogger("cspm.monitoring.alert_service")


class AlertService:
    """
    Manages SecurityAlert lifecycle: creation, deduplication, resolution, and audit tracking.
    Guarantees that duplicate alerts are not continuously spawned on every scan cycle.
    """

    @staticmethod
    def process_changes(
        db: Session,
        account: CloudAccount,
        changes: ChangeDetectionResult,
        user_id: Optional[uuid.UUID] = None,
    ) -> List[SecurityAlert]:
        now = utc_now()
        created_or_updated: List[SecurityAlert] = []
        newly_created: List[SecurityAlert] = []

        # 1. Process New Findings (NEW_FINDING)
        for nf in changes.new_findings:
            # Check for existing OPEN or ACKNOWLEDGED alert for this finding
            existing_alert = db.query(SecurityAlert).filter(
                SecurityAlert.cloud_account_id == account.id,
                SecurityAlert.finding_id == nf.id,
                SecurityAlert.alert_type == "NEW_FINDING",
                SecurityAlert.status.in_(["OPEN", "ACKNOWLEDGED"]),
            ).first()

            res_name = nf.resource.resource_name if nf.resource else "cloud resource"
            if existing_alert:
                existing_alert.last_detected_at = now
                existing_alert.current_value = nf.severity
                created_or_updated.append(existing_alert)
            else:
                alert = SecurityAlert(
                    id=uuid.uuid4(),
                    cloud_account_id=account.id,
                    finding_id=nf.id,
                    alert_type="NEW_FINDING",
                    severity=nf.severity,
                    title=f"New Finding: {nf.title}",
                    description=f"New security violation detected on {res_name}: {nf.description}",
                    previous_value=None,
                    current_value=nf.severity,
                    status="OPEN",
                    first_detected_at=now,
                    last_detected_at=now,
                )
                db.add(alert)
                created_or_updated.append(alert)
                newly_created.append(alert)

                # Record Audit Log
                db.add(AuditLog(
                    user_id=user_id,
                    action="ALERT_CREATED",
                    resource_type="security_alert",
                    resource_id=str(alert.id),
                    result="SUCCESS",
                    metadata_json={
                        "cloud_account_id": str(account.id),
                        "alert_type": "NEW_FINDING",
                        "severity": nf.severity,
                        "finding_id": str(nf.id),
                        "title": nf.title,
                    }
                ))

        # 2. Process Risk Increases (RISK_INCREASED)
        for nf, prev_risk, new_risk in changes.risk_increases:
            existing_alert = db.query(SecurityAlert).filter(
                SecurityAlert.cloud_account_id == account.id,
                SecurityAlert.finding_id == nf.id,
                SecurityAlert.alert_type == "RISK_INCREASED",
                SecurityAlert.status.in_(["OPEN", "ACKNOWLEDGED"]),
            ).first()

            res_name = nf.resource.resource_name if nf.resource else "cloud resource"
            if existing_alert:
                existing_alert.last_detected_at = now
                existing_alert.previous_value = f"{prev_risk:.1f}"
                existing_alert.current_value = f"{new_risk:.1f}"
                created_or_updated.append(existing_alert)
            else:
                alert = SecurityAlert(
                    id=uuid.uuid4(),
                    cloud_account_id=account.id,
                    finding_id=nf.id,
                    alert_type="RISK_INCREASED",
                    severity=nf.severity,
                    title=f"Risk Increased: {nf.title}",
                    description=f"Calculated risk on {res_name} increased from {prev_risk:.1f} to {new_risk:.1f}",
                    previous_value=f"{prev_risk:.1f}",
                    current_value=f"{new_risk:.1f}",
                    status="OPEN",
                    first_detected_at=now,
                    last_detected_at=now,
                )
                db.add(alert)
                created_or_updated.append(alert)

                db.add(AuditLog(
                    user_id=user_id,
                    action="ALERT_CREATED",
                    resource_type="security_alert",
                    resource_id=str(alert.id),
                    result="SUCCESS",
                    metadata_json={
                        "cloud_account_id": str(account.id),
                        "alert_type": "RISK_INCREASED",
                        "severity": nf.severity,
                        "finding_id": str(nf.id),
                        "previous_risk": prev_risk,
                        "new_risk": new_risk,
                    }
                ))

        # 3. Process Resolved Findings (FINDING_RESOLVED)
        for pf in changes.resolved_findings:
            # Mark open alerts for this finding as RESOLVED
            open_alerts_for_finding = db.query(SecurityAlert).filter(
                SecurityAlert.cloud_account_id == account.id,
                SecurityAlert.finding_id == pf.id,
                SecurityAlert.status.in_(["OPEN", "ACKNOWLEDGED"]),
            ).all()

            for old_al in open_alerts_for_finding:
                old_al.status = "RESOLVED"
                old_al.resolved_at = now
                old_al.last_detected_at = now
                db.add(AuditLog(
                    user_id=user_id,
                    action="ALERT_RESOLVED",
                    resource_type="security_alert",
                    resource_id=str(old_al.id),
                    result="SUCCESS",
                    metadata_json={
                        "cloud_account_id": str(account.id),
                        "finding_id": str(pf.id),
                        "reason": "Finding no longer detected in scan",
                    }
                ))

            # Create distinct FINDING_RESOLVED alert for audit trail
            res_name = pf.resource.resource_name if pf.resource else "cloud resource"
            res_alert = SecurityAlert(
                id=uuid.uuid4(),
                cloud_account_id=account.id,
                finding_id=pf.id,
                alert_type="FINDING_RESOLVED",
                severity="INFO",
                title=f"Finding Resolved: {pf.title}",
                description=f"Security finding on {res_name} is no longer detected: {pf.description}",
                previous_value="OPEN",
                current_value="RESOLVED",
                status="RESOLVED",
                first_detected_at=now,
                last_detected_at=now,
                resolved_at=now,
            )
            db.add(res_alert)
            created_or_updated.append(res_alert)

        # 4. Posture Degraded (POSTURE_DEGRADED)
        if changes.is_posture_degraded:
            # Avoid duplicate open POSTURE_DEGRADED alert
            existing_deg = db.query(SecurityAlert).filter(
                SecurityAlert.cloud_account_id == account.id,
                SecurityAlert.alert_type == "POSTURE_DEGRADED",
                SecurityAlert.status.in_(["OPEN", "ACKNOWLEDGED"]),
            ).first()

            prev_s = f"{changes.prev_security_score}%" if changes.prev_security_score is not None else "--"
            new_s = f"{changes.new_security_score}%" if changes.new_security_score is not None else "--"

            if existing_deg:
                existing_deg.last_detected_at = now
                existing_deg.previous_value = prev_s
                existing_deg.current_value = new_s
                created_or_updated.append(existing_deg)
            else:
                deg_alert = SecurityAlert(
                    id=uuid.uuid4(),
                    cloud_account_id=account.id,
                    finding_id=None,
                    alert_type="POSTURE_DEGRADED",
                    severity="HIGH",
                    title="Security Posture Degraded",
                    description=f"Security posture dropped from {prev_s} to {new_s} ({changes.posture_change:.1f} pts).",
                    previous_value=prev_s,
                    current_value=new_s,
                    status="OPEN",
                    first_detected_at=now,
                    last_detected_at=now,
                )
                db.add(deg_alert)
                created_or_updated.append(deg_alert)

                db.add(AuditLog(
                    user_id=user_id,
                    action="ALERT_CREATED",
                    resource_type="security_alert",
                    resource_id=str(deg_alert.id),
                    result="SUCCESS",
                    metadata_json={
                        "cloud_account_id": str(account.id),
                        "alert_type": "POSTURE_DEGRADED",
                        "posture_change": changes.posture_change,
                    }
                ))

        # 5. Posture Improved (POSTURE_IMPROVED)
        if changes.is_posture_improved:
            # Resolve any active posture degraded alerts
            open_degraded = db.query(SecurityAlert).filter(
                SecurityAlert.cloud_account_id == account.id,
                SecurityAlert.alert_type == "POSTURE_DEGRADED",
                SecurityAlert.status.in_(["OPEN", "ACKNOWLEDGED"]),
            ).all()
            for od in open_degraded:
                od.status = "RESOLVED"
                od.resolved_at = now
                od.last_detected_at = now

            prev_s = f"{changes.prev_security_score}%" if changes.prev_security_score is not None else "--"
            new_s = f"{changes.new_security_score}%" if changes.new_security_score is not None else "--"
            imp_alert = SecurityAlert(
                id=uuid.uuid4(),
                cloud_account_id=account.id,
                finding_id=None,
                alert_type="POSTURE_IMPROVED",
                severity="LOW",
                title="Security Posture Improved",
                description=f"Security posture improved from {prev_s} to {new_s} (+{changes.posture_change:.1f} pts).",
                previous_value=prev_s,
                current_value=new_s,
                status="RESOLVED",
                first_detected_at=now,
                last_detected_at=now,
                resolved_at=now,
            )
            db.add(imp_alert)
            created_or_updated.append(imp_alert)

        db.commit()

        # Phase 9C: Dispatch notifications for newly generated alerts to CloudAccount owner
        for new_alert in newly_created:
            try:
                from app.notifications.notification_service import NotificationService
                NotificationService.notify_alert(db=db, alert=new_alert, is_new=True)
            except Exception as notif_err:
                logger.error(f"Error dispatching notification for alert {new_alert.id}: {notif_err}")

        return created_or_updated

    @staticmethod
    def record_scan_failure(
        db: Session,
        account: CloudAccount,
        error_message: str,
        user_id: Optional[uuid.UUID] = None,
    ) -> SecurityAlert:
        """
        Creates or updates a SCAN_FAILED alert for the target account without unbounded duplicates.
        """
        now = utc_now()
        existing = db.query(SecurityAlert).filter(
            SecurityAlert.cloud_account_id == account.id,
            SecurityAlert.alert_type == "SCAN_FAILED",
            SecurityAlert.status == "OPEN",
        ).first()

        is_new_failure = (existing is None)

        if existing:
            existing.last_detected_at = now
            existing.description = f"Scan execution failed: {error_message}"
            alert = existing
        else:
            alert = SecurityAlert(
                id=uuid.uuid4(),
                cloud_account_id=account.id,
                finding_id=None,
                alert_type="SCAN_FAILED",
                severity="HIGH",
                title="Cloud Scan Failed",
                description=f"Continuous monitoring scan execution failed: {error_message}",
                previous_value="RUNNING",
                current_value="FAILED",
                status="OPEN",
                first_detected_at=now,
                last_detected_at=now,
            )
            db.add(alert)

        db.add(AuditLog(
            user_id=user_id,
            action="MONITORING_SCAN_FAILED",
            resource_type="cloud_account",
            resource_id=str(account.id),
            result="FAILURE",
            metadata_json={"error": error_message}
        ))
        db.commit()
        db.refresh(alert)

        # Phase 9C: Dispatch notification for newly created scan failure
        if is_new_failure:
            try:
                from app.notifications.notification_service import NotificationService
                NotificationService.notify_alert(db=db, alert=alert, is_new=True)
            except Exception as notif_err:
                logger.error(f"Error dispatching notification for scan failure alert {alert.id}: {notif_err}")

        return alert

    @staticmethod
    def acknowledge_alert(
        db: Session,
        alert: SecurityAlert,
        user: User,
    ) -> SecurityAlert:
        now = utc_now()
        alert.status = "ACKNOWLEDGED"
        alert.last_detected_at = now
        db.add(AuditLog(
            user_id=user.id,
            action="ALERT_ACKNOWLEDGED",
            resource_type="security_alert",
            resource_id=str(alert.id),
            result="SUCCESS",
            metadata_json={
                "cloud_account_id": str(alert.cloud_account_id),
                "alert_type": alert.alert_type,
            }
        ))
        db.commit()
        db.refresh(alert)
        return alert

    @staticmethod
    def resolve_alert(
        db: Session,
        alert: SecurityAlert,
        user: User,
    ) -> SecurityAlert:
        now = utc_now()
        alert.status = "RESOLVED"
        alert.resolved_at = now
        alert.last_detected_at = now
        db.add(AuditLog(
            user_id=user.id,
            action="ALERT_RESOLVED",
            resource_type="security_alert",
            resource_id=str(alert.id),
            result="SUCCESS",
            metadata_json={
                "cloud_account_id": str(alert.cloud_account_id),
                "alert_type": alert.alert_type,
            }
        ))
        db.commit()
        db.refresh(alert)
        return alert
