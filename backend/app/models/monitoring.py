import uuid
from typing import Optional
from datetime import datetime
from sqlalchemy import String, Boolean, Integer, Text, DateTime, ForeignKey, Uuid, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.session import Base
from app.models.base import TimestampMixin, UUIDMixin, utc_now


class MonitoringConfig(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "monitoring_configs"

    cloud_account_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("cloud_accounts.id", ondelete="CASCADE"),
        unique=True,
        index=True,
        nullable=False,
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    scan_interval_minutes: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    last_scan_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    next_scan_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    cloud_account: Mapped["CloudAccount"] = relationship("CloudAccount", back_populates="monitoring_config")

    def __repr__(self) -> str:
        return f"<MonitoringConfig(account_id={self.cloud_account_id}, enabled={self.enabled}, interval={self.scan_interval_minutes}m)>"


class SecurityAlert(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "security_alerts"

    cloud_account_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("cloud_accounts.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    finding_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("findings.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )
    alert_type: Mapped[str] = mapped_column(
        String(50),
        index=True,
        nullable=False,
    )  # NEW_FINDING, RISK_INCREASED, FINDING_RESOLVED, POSTURE_DEGRADED, POSTURE_IMPROVED, SCAN_FAILED
    severity: Mapped[str] = mapped_column(
        String(50),
        index=True,
        nullable=False,
    )  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    previous_value: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    current_value: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(
        String(50),
        default="OPEN",
        index=True,
        nullable=False,
    )  # OPEN, ACKNOWLEDGED, RESOLVED
    first_detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    last_detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    resolved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    cloud_account: Mapped["CloudAccount"] = relationship("CloudAccount", back_populates="alerts")
    finding: Mapped[Optional["Finding"]] = relationship("Finding")

    __table_args__ = (
        Index("ix_security_alerts_account_status", "cloud_account_id", "status"),
        Index("ix_security_alerts_account_type", "cloud_account_id", "alert_type"),
        Index("ix_security_alerts_account_finding_type", "cloud_account_id", "finding_id", "alert_type"),
    )

    def __repr__(self) -> str:
        return f"<SecurityAlert(id={self.id}, type='{self.alert_type}', severity='{self.severity}', status='{self.status}')>"
