import uuid
import logging
from typing import Dict, Any, Optional
from datetime import timedelta
from sqlalchemy.orm import Session
from sqlalchemy import desc
from fastapi import HTTPException, status

from app.models.cloud import CloudAccount, Scan
from app.models.monitoring import MonitoringConfig
from app.models.auth import User
from app.models.audit import AuditLog
from app.models.base import utc_now
from app.api.deps import verify_account_access, verify_account_ownership
from app.services.scan_service import ScanService
from app.monitoring.change_detector import ChangeDetector
from app.monitoring.alert_service import AlertService

logger = logging.getLogger("cspm.monitoring.service")


class MonitoringService:
    """
    Coordinates continuous monitoring execution on top of the existing scan service.
    Guarantees strict tenant isolation and preserves the existing read-only scanner pipeline.
    """

    @staticmethod
    def get_or_create_config(db: Session, account_id: uuid.UUID) -> MonitoringConfig:
        config = db.query(MonitoringConfig).filter(
            MonitoringConfig.cloud_account_id == account_id
        ).first()

        if not config:
            now = utc_now()
            config = MonitoringConfig(
                id=uuid.uuid4(),
                cloud_account_id=account_id,
                enabled=False,
                scan_interval_minutes=60,
                created_at=now,
                updated_at=now,
            )
            db.add(config)
            db.commit()
            db.refresh(config)

        return config

    @staticmethod
    def update_config(
        db: Session,
        account: CloudAccount,
        enabled: bool,
        scan_interval_minutes: int,
        user: User,
    ) -> MonitoringConfig:
        if scan_interval_minutes < 5:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Monitoring scan interval must be at least 5 minutes.",
            )

        config = db.query(MonitoringConfig).filter(
            MonitoringConfig.cloud_account_id == account.id
        ).first()

        now = utc_now()
        is_transitioning = False
        action_name = ""

        if not config:
            config = MonitoringConfig(
                id=uuid.uuid4(),
                cloud_account_id=account.id,
                enabled=enabled,
                scan_interval_minutes=scan_interval_minutes,
                next_scan_at=now + timedelta(minutes=scan_interval_minutes) if enabled else None,
                created_at=now,
                updated_at=now,
            )
            db.add(config)
            is_transitioning = True
            action_name = "MONITORING_ENABLED" if enabled else "MONITORING_DISABLED"
        else:
            if config.enabled != enabled:
                is_transitioning = True
                action_name = "MONITORING_ENABLED" if enabled else "MONITORING_DISABLED"

            prev_interval = config.scan_interval_minutes
            config.enabled = enabled
            config.scan_interval_minutes = scan_interval_minutes
            config.updated_at = now

            if enabled:
                # Always recalculate next_scan_at when enabling or changing interval
                config.next_scan_at = now + timedelta(minutes=scan_interval_minutes)
            else:
                config.next_scan_at = None

        if is_transitioning:
            db.add(AuditLog(
                user_id=user.id,
                action=action_name,
                resource_type="cloud_account",
                resource_id=str(account.id),
                result="SUCCESS",
                metadata_json={
                    "account_name": account.name,
                    "enabled": enabled,
                    "interval_minutes": scan_interval_minutes,
                }
            ))

        db.commit()
        db.refresh(config)
        return config

    @staticmethod
    def run_monitoring(
        db: Session,
        account_id: uuid.UUID,
        user: User,
        client_ip: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Executes an on-demand continuous monitoring cycle:
        1. Verifies tenant ownership / authorization
        2. Validates that monitoring is enabled for the account
        3. Identifies the baseline / immediately previous completed scan
        4. Triggers discovery and posture audit via existing ScanService
        5. Compares new scan vs previous scan via ChangeDetector
        6. Ingests changes into AlertService (with deduplication)
        7. Advances next_scan_at timestamp and logs audit event
        """
        account = verify_account_access(db, user, account_id)

        config = db.query(MonitoringConfig).filter(
            MonitoringConfig.cloud_account_id == account.id
        ).first()

        if not config or not config.enabled:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Continuous monitoring is not enabled for this cloud account. Please enable monitoring first.",
            )

        # 3. Find latest completed scan prior to this execution
        prev_scan = db.query(Scan).filter(
            Scan.cloud_account_id == account.id,
            Scan.status == "COMPLETED",
        ).order_by(desc(Scan.completed_at)).first()

        # 4. Trigger scan using existing ScanService
        new_scan = ScanService.trigger_scan(
            db=db,
            user=user,
            account_id=account.id,
            client_ip=client_ip,
        )

        if new_scan.status == "FAILED":
            err_msg = new_scan.error_message or "Scan execution failed."
            AlertService.record_scan_failure(
                db=db,
                account=account,
                error_message=err_msg,
                user_id=user.id,
            )
            return {
                "cloud_account_id": str(account.id),
                "account_name": account.name,
                "scan_id": str(new_scan.id),
                "previous_scan_id": str(prev_scan.id) if prev_scan else None,
                "status": "FAILED",
                "error": err_msg,
                "alerts_created": 1,
            }

        # 5. Run Change Detection
        changes = ChangeDetector.compare_scans(
            db=db,
            new_scan=new_scan,
            previous_scan=prev_scan,
        )

        # 6. Generate / update Security Alerts
        alerts = AlertService.process_changes(
            db=db,
            account=account,
            changes=changes,
            user_id=user.id,
        )

        # 7. Update Monitoring Config timestamps
        now = utc_now()
        config.last_scan_at = now
        config.next_scan_at = now + timedelta(minutes=config.scan_interval_minutes)

        db.add(AuditLog(
            user_id=user.id,
            action="MONITORING_RUN",
            resource_type="cloud_account",
            resource_id=str(account.id),
            result="SUCCESS",
            metadata_json={
                "scan_id": str(new_scan.id),
                "previous_scan_id": str(prev_scan.id) if prev_scan else None,
                "new_findings": changes.new_findings_count,
                "risk_increases": changes.risk_increases_count,
                "resolved_findings": changes.resolved_findings_count,
                "posture_change": changes.posture_change,
                "alerts_created": len(alerts),
            },
            ip_address=client_ip,
        ))
        db.commit()

        return {
            "cloud_account_id": str(account.id),
            "account_name": account.name,
            "scan_id": str(new_scan.id),
            "previous_scan_id": str(prev_scan.id) if prev_scan else None,
            "new_findings": changes.new_findings_count,
            "risk_increases": changes.risk_increases_count,
            "resolved_findings": changes.resolved_findings_count,
            "posture_change": changes.posture_change,
            "alerts_created": len(alerts),
        }
