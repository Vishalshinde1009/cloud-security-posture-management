"""
Scan Scheduling Service Abstraction.
Defines frequency definitions (MANUAL, DAILY, WEEKLY) and safe scheduling configurations.
Decouples scheduling contracts from background worker daemons (e.g. Celery, AWS EventBridge, or Cron).
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

logger = logging.getLogger("cspm.services.scheduler")

SCHEDULE_FREQUENCIES = {
    "MANUAL": {"label": "On-Demand Only", "cron": None, "interval_hours": None},
    "DAILY": {"label": "Daily Recurrent Scan", "cron": "0 2 * * *", "interval_hours": 24},
    "WEEKLY": {"label": "Weekly Audit Scan", "cron": "0 3 * * 0", "interval_hours": 168},
}


class ScanScheduleConfig:
    def __init__(
        self,
        account_identifier: str,
        frequency: str = "MANUAL",
        enabled: bool = True,
        next_run: Optional[datetime] = None,
    ):
        if frequency not in SCHEDULE_FREQUENCIES:
            raise ValueError(f"Invalid frequency '{frequency}'. Supported: {list(SCHEDULE_FREQUENCIES.keys())}")

        self.account_identifier = account_identifier
        self.frequency = frequency
        self.enabled = enabled
        self.next_run = next_run

    def to_dict(self) -> Dict[str, Any]:
        info = SCHEDULE_FREQUENCIES[self.frequency]
        return {
            "account_identifier": self.account_identifier,
            "frequency": self.frequency,
            "frequency_label": info["label"],
            "cron_expression": info["cron"],
            "interval_hours": info["interval_hours"],
            "enabled": self.enabled,
            "next_run": str(self.next_run) if self.next_run else None,
        }


class ScanSchedulerService:
    """
    Manages safe scan schedule metadata without spawning rogue background processes.
    Designed for clean integration with external cron runners or AWS EventBridge rules.
    """

    _registry: Dict[str, ScanScheduleConfig] = {}

    @classmethod
    def set_schedule(cls, account_identifier: str, frequency: str = "MANUAL", enabled: bool = True) -> Dict[str, Any]:
        """Configures or updates scan schedule preferences for a target account."""
        cfg = ScanScheduleConfig(
            account_identifier=account_identifier,
            frequency=frequency,
            enabled=enabled,
        )
        cls._registry[account_identifier] = cfg
        logger.info(f"Updated scan schedule for account '{account_identifier}' to {frequency} (enabled={enabled})")
        return cfg.to_dict()

    @classmethod
    def get_schedule(cls, account_identifier: str) -> Dict[str, Any]:
        """Retrieves schedule preferences for an account (defaults to MANUAL)."""
        if account_identifier in cls._registry:
            return cls._registry[account_identifier].to_dict()
        return ScanScheduleConfig(account_identifier=account_identifier, frequency="MANUAL").to_dict()

    @classmethod
    def list_schedules(cls) -> List[Dict[str, Any]]:
        """Lists all configured schedules."""
        return [cfg.to_dict() for cfg in cls._registry.values()]

    @classmethod
    def get_supported_frequencies(cls) -> List[str]:
        """Returns list of supported scheduling frequencies."""
        return list(SCHEDULE_FREQUENCIES.keys())

    @classmethod
    def compute_next_run(cls, frequency: str, from_time: Optional[datetime] = None) -> Optional[datetime]:
        """Calculates expected next execution timestamp based on frequency."""
        from datetime import timedelta
        if frequency not in SCHEDULE_FREQUENCIES:
            raise ValueError(f"Unknown frequency '{frequency}'")
        
        hours = SCHEDULE_FREQUENCIES[frequency]["interval_hours"]
        if not hours:
            return None
        
        base = from_time or datetime.now(timezone.utc)
        return base + timedelta(hours=hours)


SchedulerService = ScanSchedulerService
