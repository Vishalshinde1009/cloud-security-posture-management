"""
Notification Service for in-app CSPM security alerts and scan notifications.
Supports user isolation, unread tracking, and automated alert generation.
"""

import uuid
import logging
from typing import List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_

from app.models.notification import Notification
from app.models.cloud import Scan
from app.models.finding import Finding
from app.models.base import utc_now

logger = logging.getLogger("cspm.services.notifications")


class NotificationService:
    @staticmethod
    def create_notification(
        db: Session,
        notification_type: str,
        message: str,
        user_id: Optional[uuid.UUID] = None,
        finding_id: Optional[uuid.UUID] = None,
    ) -> Notification:
        """Creates and persists an in-app security notification."""
        notif = Notification(
            id=uuid.uuid4(),
            user_id=user_id,
            finding_id=finding_id,
            notification_type=notification_type,
            status="UNREAD",
            message=message,
            created_at=utc_now(),
        )
        db.add(notif)
        db.commit()
        db.refresh(notif)
        logger.info(f"Created notification {notif.id} [{notification_type}]: {message[:80]}...")
        return notif

    @staticmethod
    def create_scan_notifications(
        db: Session,
        scan: Scan,
        user_id: uuid.UUID,
        active_findings: List[Finding],
        security_score: int,
    ) -> List[Notification]:
        """Automatically generates relevant notifications upon scan completion."""
        notifications: List[Notification] = []
        account_name = scan.cloud_account.name if scan.cloud_account else "Target Environment"

        # 1. Critical findings alert
        crit_count = sum(1 for f in active_findings if f.severity.upper() == "CRITICAL")
        if crit_count > 0:
            crit_notif = Notification(
                id=uuid.uuid4(),
                user_id=user_id,
                notification_type="CRITICAL_FINDING",
                status="UNREAD",
                message=(
                    f"CRITICAL ALERT: {crit_count} critical severity finding(s) detected in '{account_name}'. "
                    f"Immediate remediation required."
                ),
                created_at=utc_now(),
            )
            db.add(crit_notif)
            notifications.append(crit_notif)

        # 2. High findings alert
        high_count = sum(1 for f in active_findings if f.severity.upper() == "HIGH")
        if high_count > 0:
            high_notif = Notification(
                id=uuid.uuid4(),
                user_id=user_id,
                notification_type="HIGH_RISK_FINDING",
                status="UNREAD",
                message=(
                    f"HIGH RISK ALERT: {high_count} high severity finding(s) identified in '{account_name}'."
                ),
                created_at=utc_now(),
            )
            db.add(high_notif)
            notifications.append(high_notif)

        # 3. Scan completion summary
        summary_notif = Notification(
            id=uuid.uuid4(),
            user_id=user_id,
            notification_type="SCAN_COMPLETED",
            status="UNREAD",
            message=(
                f"Scan completed for '{account_name}'. Discovered {scan.resources_scanned} assets with "
                f"posture score {security_score}% ({len(active_findings)} total findings)."
            ),
            created_at=utc_now(),
        )
        db.add(summary_notif)
        notifications.append(summary_notif)

        db.commit()
        return notifications

    @staticmethod
    def get_user_notifications(
        db: Session,
        user_id: uuid.UUID,
        limit: int = 50,
        offset: int = 0,
        unread_only: bool = False,
    ) -> Tuple[List[Notification], int]:
        """Returns paginated notifications visible to a specific user (personal + broadcast)."""
        query = db.query(Notification).filter(
            or_(Notification.user_id == user_id, Notification.user_id.is_(None))
        )
        if unread_only:
            query = query.filter(Notification.status == "UNREAD")

        total = query.count()
        items = query.order_by(desc(Notification.created_at)).offset(offset).limit(limit).all()
        return items, total

    @staticmethod
    def get_unread_count(db: Session, user_id: uuid.UUID) -> int:
        """Returns count of unread notifications for a user."""
        return db.query(Notification).filter(
            or_(Notification.user_id == user_id, Notification.user_id.is_(None)),
            Notification.status == "UNREAD",
        ).count()

    @staticmethod
    def mark_as_read(db: Session, notification_id: uuid.UUID, user_id: uuid.UUID) -> Optional[Notification]:
        """Marks a notification as read with user isolation."""
        notif = db.query(Notification).filter(
            Notification.id == notification_id,
            or_(Notification.user_id == user_id, Notification.user_id.is_(None)),
        ).first()

        if notif:
            notif.status = "READ"
            db.commit()
            db.refresh(notif)
        return notif

    @staticmethod
    def mark_all_as_read(db: Session, user_id: uuid.UUID) -> int:
        """Marks all unread notifications for a user as read."""
        unread = db.query(Notification).filter(
            or_(Notification.user_id == user_id, Notification.user_id.is_(None)),
            Notification.status == "UNREAD",
        ).all()

        for n in unread:
            n.status = "READ"
        db.commit()
        return len(unread)
