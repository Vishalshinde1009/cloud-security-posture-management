"""
Phase 9C: Notifications Package
===============================
Provides email notification dispatch for CloudAccount security alerts.
"""

from app.notifications.email_service import EmailService
from app.notifications.notification_service import NotificationService

__all__ = ["EmailService", "NotificationService"]
