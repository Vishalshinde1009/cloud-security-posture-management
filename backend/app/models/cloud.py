import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime
from sqlalchemy import String, Boolean, Integer, Float, Text, DateTime, JSON, ForeignKey, Uuid, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.session import Base
from app.models.base import TimestampMixin, UUIDMixin, utc_now


class CloudAccount(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "cloud_accounts"

    name: Mapped[str] = mapped_column(String(150), nullable=False)
    provider: Mapped[str] = mapped_column(String(50), default="AWS", nullable=False)
    account_identifier: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    default_region: Mapped[str] = mapped_column(String(50), default="us-east-1", nullable=False)
    credential_mode: Mapped[str] = mapped_column(String(50), default="ENVIRONMENT", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Relationships - Protect security audit history from accidental cascades
    scans: Mapped[List["Scan"]] = relationship(
        "Scan",
        back_populates="cloud_account",
        passive_deletes="all",
    )
    resources: Mapped[List["Resource"]] = relationship(
        "Resource",
        back_populates="cloud_account",
        passive_deletes="all",
    )
    findings: Mapped[List["Finding"]] = relationship(
        "Finding",
        back_populates="cloud_account",
        passive_deletes="all",
    )

    def __repr__(self) -> str:
        return f"<CloudAccount(id={self.id}, name='{self.name}', account='{self.account_identifier}')>"


class Scan(Base, UUIDMixin):
    __tablename__ = "scans"

    cloud_account_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("cloud_accounts.id", ondelete="RESTRICT"),
        index=True,
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        default="QUEUED",
        index=True,
        nullable=False,
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    duration: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Aggregated metrics for fast reporting
    resources_scanned: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    critical_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    high_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    medium_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    low_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    security_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        index=True,
        nullable=False,
    )

    # Relationships
    cloud_account: Mapped["CloudAccount"] = relationship("CloudAccount", back_populates="scans")
    resources: Mapped[List["Resource"]] = relationship("Resource", back_populates="scan")
    findings: Mapped[List["Finding"]] = relationship("Finding", back_populates="scan")
    reports: Mapped[List["Report"]] = relationship("Report", back_populates="scan")

    def __repr__(self) -> str:
        return f"<Scan(id={self.id}, status='{self.status}', score={self.security_score})>"


class Resource(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "resources"

    cloud_account_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("cloud_accounts.id", ondelete="RESTRICT"),
        index=True,
        nullable=False,
    )
    scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("scans.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )
    provider: Mapped[str] = mapped_column(String(50), default="AWS", nullable=False)
    service: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    resource_type: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    resource_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    resource_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    region: Mapped[Optional[str]] = mapped_column(String(50), index=True, nullable=True)

    # Flexible metadata storage
    tags: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    configuration: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    security_status: Mapped[str] = mapped_column(String(50), default="UNKNOWN", index=True, nullable=False)

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Relationships
    cloud_account: Mapped["CloudAccount"] = relationship("CloudAccount", back_populates="resources")
    scan: Mapped[Optional["Scan"]] = relationship("Scan", back_populates="resources")
    findings: Mapped[List["Finding"]] = relationship("Finding", back_populates="resource")

    __table_args__ = (
        Index("ix_resources_account_service", "cloud_account_id", "service"),
        Index("ix_resources_account_resource_id", "cloud_account_id", "resource_id"),
    )

    def __repr__(self) -> str:
        return f"<Resource(id={self.id}, service='{self.service}', resource_id='{self.resource_id}')>"
