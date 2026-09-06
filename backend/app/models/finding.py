import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime
from sqlalchemy import String, Boolean, Float, Text, DateTime, JSON, ForeignKey, Uuid, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.session import Base
from app.models.base import TimestampMixin, UUIDMixin, utc_now


class SecurityRule(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "security_rules"

    rule_id: Mapped[str] = mapped_column(String(50), unique=True, index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    service: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    references: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True, nullable=False)

    # Relationships
    findings: Mapped[List["Finding"]] = relationship(
        "Finding",
        back_populates="rule",
        passive_deletes="all",
    )

    def __repr__(self) -> str:
        return f"<SecurityRule(rule_id='{self.rule_id}', service='{self.service}', severity='{self.severity}')>"


class Finding(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "findings"

    rule_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("security_rules.id", ondelete="RESTRICT"),
        index=True,
        nullable=False,
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("scans.id", ondelete="RESTRICT"),
        index=True,
        nullable=False,
    )
    cloud_account_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("cloud_accounts.id", ondelete="RESTRICT"),
        index=True,
        nullable=False,
    )
    resource_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("resources.id", ondelete="RESTRICT"),
        index=True,
        nullable=False,
    )

    # Unique deterministic fingerprint for finding deduplication & scan drift
    finding_identifier: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="OPEN", index=True, nullable=False)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Specific evidence configuration dictionary
    evidence: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    first_detected: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_detected: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    rule: Mapped["SecurityRule"] = relationship("SecurityRule", back_populates="findings")
    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")
    cloud_account: Mapped["CloudAccount"] = relationship("CloudAccount", back_populates="findings")
    resource: Mapped["Resource"] = relationship("Resource", back_populates="findings")
    compliance_mappings: Mapped[List["FindingCompliance"]] = relationship(
        "FindingCompliance",
        back_populates="finding",
        cascade="all, delete-orphan",
    )
    notifications: Mapped[List["Notification"]] = relationship(
        "Notification",
        back_populates="finding",
    )

    __table_args__ = (
        Index("ix_findings_scan_severity", "scan_id", "severity"),
        Index("ix_findings_scan_status", "scan_id", "status"),
        Index("ix_findings_account_status", "cloud_account_id", "status"),
        Index("ix_findings_identifier_status", "finding_identifier", "status"),
    )

    def __repr__(self) -> str:
        return f"<Finding(id={self.id}, rule='{self.rule_id}', severity='{self.severity}', status='{self.status}')>"
