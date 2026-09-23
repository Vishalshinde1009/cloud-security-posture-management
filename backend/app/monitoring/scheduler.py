"""
Phase 9B: Automatic Scheduled Monitoring — Background Scheduler
================================================================
Lightweight thread-based periodic scheduler.
- No Celery, Redis, RabbitMQ, or external infra.
- Controlled entirely by CSPM_MONITORING_ENABLED env variable.
- Polls MonitoringConfig records every CSPM_MONITORING_POLL_SECONDS (default 60).
- Calls existing MonitoringService.run_monitoring() path for each due account.
- Failures → SCAN_FAILED alert + advance next_scan_at; never MOCK fallback.
- Graceful shutdown via threading.Event.
"""

import logging
import threading
import time
from typing import List, Dict, Any, Optional, Callable
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.monitoring import MonitoringConfig
from app.models.cloud import CloudAccount
from app.models.auth import User
from app.models.audit import AuditLog
from app.models.base import utc_now
from app.monitoring.monitoring_service import MonitoringService

logger = logging.getLogger("cspm.monitoring.scheduler")

# Module-level flag: prevents double-start under uvicorn --reload
_scheduler_started = False
_scheduler_lock = threading.Lock()


class MonitoringScheduler:
    """
    Lightweight periodic monitoring scheduler.
    Integrates with FastAPI lifespan; uses a daemon thread so the process
    can exit cleanly even if the stop event is never signalled.
    """

    def __init__(self, db_session_factory: Optional[Callable[[], Session]] = None):
        """
        Args:
            db_session_factory: Zero-arg callable that returns a new SQLAlchemy Session.
                                Required for real operation; can be None in unit tests
                                where run_due_jobs() is called with an explicit db param.
        """
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._db_session_factory = db_session_factory

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @staticmethod
    def is_enabled() -> bool:
        """Returns True iff CSPM_MONITORING_ENABLED=true in environment."""
        return bool(getattr(settings, "CSPM_MONITORING_ENABLED", False))

    @staticmethod
    def poll_seconds() -> int:
        """Returns the scheduler poll interval in seconds (default 60)."""
        return int(getattr(settings, "CSPM_MONITORING_POLL_SECONDS", 60))

    @staticmethod
    def get_due_configs(db: Session) -> List[MonitoringConfig]:
        """
        Returns MonitoringConfig records that are currently due for a scheduled scan:
          - enabled=True
          - cloud_account.is_active=True
          - next_scan_at IS NULL  OR  next_scan_at <= utc_now()
        Handles both timezone-aware and timezone-naive datetimes (SQLite stores naive).
        """
        now_aware = utc_now()
        now_naive = now_aware.replace(tzinfo=None)

        configs = db.query(MonitoringConfig).join(
            CloudAccount, CloudAccount.id == MonitoringConfig.cloud_account_id
        ).filter(
            MonitoringConfig.enabled == True,
            CloudAccount.is_active == True,
        ).all()

        def _is_due(next_scan_at) -> bool:
            if next_scan_at is None:
                return True
            if next_scan_at.tzinfo is None:
                # Timezone-naive (SQLite) — compare against naive UTC
                return next_scan_at <= now_naive
            else:
                # Timezone-aware — compare against aware UTC
                return next_scan_at <= now_aware

        due = [c for c in configs if _is_due(c.next_scan_at)]
        return due

    @classmethod
    def run_due_jobs(
        cls,
        db: Session,
        fallback_admin_user: Optional[User] = None,
    ) -> List[Dict[str, Any]]:
        """
        Executes monitoring for all accounts due for a scheduled scan.
        - Safe against partial failures; each account is wrapped in its own
          try/except so one bad account never blocks others.
        - Failures create a SCAN_FAILED alert and advance next_scan_at.
        - No MOCK fallback is performed on AWS errors.
        """
        if not cls.is_enabled():
            logger.debug(
                "Monitoring scheduler invoked but CSPM_MONITORING_ENABLED is False. Skipping."
            )
            return []

        due_configs = cls.get_due_configs(db)
        logger.info(
            f"Scheduler: {len(due_configs)} account(s) due for continuous monitoring scan."
        )

        results = []
        for cfg in due_configs:
            account = cfg.cloud_account
            if not account:
                continue

            # Determine acting user: account owner → fallback admin → any active user
            acting_user: Optional[User] = account.user
            if not acting_user:
                if fallback_admin_user:
                    acting_user = fallback_admin_user
                else:
                    acting_user = (
                        db.query(User)
                        .filter(User.is_active == True)
                        .first()
                    )

            if not acting_user:
                logger.warning(
                    f"Scheduler: No valid user to execute monitoring scan for account "
                    f"'{account.name}' ({account.id}). Skipping."
                )
                continue

            # Audit log: MONITORING_SCHEDULED_RUN
            try:
                db.add(AuditLog(
                    user_id=acting_user.id,
                    action="MONITORING_SCHEDULED_RUN",
                    resource_type="cloud_account",
                    resource_id=str(account.id),
                    result="STARTED",
                    metadata_json={
                        "account_name": account.name,
                        "provider": account.provider,
                        "scheduled": True,
                    },
                    ip_address="scheduler",
                ))
                db.commit()
            except Exception as audit_err:
                logger.warning(f"Scheduler: Failed to write audit log for account {account.id}: {audit_err}")

            # Execute monitoring
            try:
                res = MonitoringService.run_monitoring(
                    db=db,
                    account_id=account.id,
                    user=acting_user,
                    client_ip="127.0.0.1 (Scheduler)",
                )
                logger.info(
                    f"Scheduler: Completed monitoring run for '{account.name}' — "
                    f"new_findings={res.get('new_findings', 0)}, "
                    f"alerts_created={res.get('alerts_created', 0)}"
                )
                results.append(res)

            except Exception as e:
                logger.error(
                    f"Scheduler: Monitoring run failed for '{account.name}' ({account.id}): {e}",
                    exc_info=True,
                )

                # Record SCAN_FAILED audit log
                try:
                    from app.monitoring.alert_service import AlertService
                    AlertService.record_scan_failure(
                        db=db,
                        account=account,
                        error_message=str(e),
                        user_id=acting_user.id,
                    )
                except Exception as alert_err:
                    logger.error(
                        f"Scheduler: Failed to record SCAN_FAILED alert for account {account.id}: {alert_err}"
                    )

                # Advance next_scan_at even on failure so we retry after interval
                try:
                    from datetime import timedelta
                    cfg_refresh = db.query(MonitoringConfig).filter(
                        MonitoringConfig.cloud_account_id == account.id
                    ).first()
                    if cfg_refresh and cfg_refresh.enabled:
                        cfg_refresh.next_scan_at = utc_now() + timedelta(
                            minutes=cfg_refresh.scan_interval_minutes
                        )
                        db.commit()
                except Exception as ts_err:
                    logger.error(
                        f"Scheduler: Failed to advance next_scan_at for account {account.id}: {ts_err}"
                    )

                # Audit log: MONITORING_SCAN_FAILED
                try:
                    db.add(AuditLog(
                        user_id=acting_user.id,
                        action="MONITORING_SCAN_FAILED",
                        resource_type="cloud_account",
                        resource_id=str(account.id),
                        result="FAILED",
                        metadata_json={
                            "account_name": account.name,
                            "error": str(e),
                            "scheduled": True,
                        },
                        ip_address="scheduler",
                    ))
                    db.commit()
                except Exception as audit_err2:
                    logger.warning(
                        f"Scheduler: Failed to write MONITORING_SCAN_FAILED audit log: {audit_err2}"
                    )

                results.append({
                    "cloud_account_id": str(account.id),
                    "account_name": account.name,
                    "status": "ERROR",
                    "error": str(e),
                })

        return results

    # ------------------------------------------------------------------
    # Background thread management
    # ------------------------------------------------------------------

    def start(self) -> bool:
        """
        Start the scheduler background thread.
        Returns True if started, False if already running or disabled.
        Guards against double-start under uvicorn --reload via module-level flag.
        """
        global _scheduler_started

        if not self.is_enabled():
            logger.info(
                "Monitoring scheduler is DISABLED (CSPM_MONITORING_ENABLED=false). "
                "No background thread started."
            )
            return False

        with _scheduler_lock:
            if _scheduler_started:
                logger.warning(
                    "Monitoring scheduler is already running; double-start prevented."
                )
                return False
            _scheduler_started = True

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="cspm-monitoring-scheduler",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            f"Monitoring scheduler started (poll_interval={self.poll_seconds()}s, "
            f"CSPM_MONITORING_ENABLED=true)."
        )
        return True

    def stop(self, timeout: float = 5.0) -> None:
        """
        Signal the background thread to stop and wait for it to exit.
        Safe to call even if start() was never called.
        """
        global _scheduler_started

        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
            if self._thread.is_alive():
                logger.warning(
                    "Monitoring scheduler thread did not exit within timeout; "
                    "continuing shutdown anyway."
                )
            else:
                logger.info("Monitoring scheduler stopped cleanly.")

        with _scheduler_lock:
            _scheduler_started = False

    def is_running(self) -> bool:
        """Returns True if the background thread is alive."""
        return self._thread is not None and self._thread.is_alive()

    # ------------------------------------------------------------------
    # Internal polling loop
    # ------------------------------------------------------------------

    def _run_loop(self) -> None:
        """
        Main loop executed by the daemon thread.
        Polls every poll_seconds() for due monitoring configs and runs them.
        Exits when _stop_event is set or an unrecoverable error occurs.
        """
        logger.info("Monitoring scheduler loop started.")
        poll = self.poll_seconds()

        while not self._stop_event.is_set():
            try:
                self._tick()
            except Exception as e:
                logger.error(
                    f"Monitoring scheduler: unexpected error in tick: {e}",
                    exc_info=True,
                )

            # Sleep in short increments so we respond quickly to stop events
            for _ in range(poll):
                if self._stop_event.is_set():
                    break
                time.sleep(1)

        logger.info("Monitoring scheduler loop exited.")

    def _tick(self) -> None:
        """Single polling tick: open a DB session, run due jobs, close session."""
        if self._db_session_factory is None:
            logger.warning(
                "Monitoring scheduler: no db_session_factory configured; "
                "cannot execute scheduled jobs."
            )
            return

        db: Optional[Session] = None
        try:
            db = self._db_session_factory()
            self.run_due_jobs(db=db)
        except Exception as e:
            logger.error(
                f"Monitoring scheduler tick failed: {e}", exc_info=True
            )
        finally:
            if db is not None:
                try:
                    db.close()
                except Exception:
                    pass
