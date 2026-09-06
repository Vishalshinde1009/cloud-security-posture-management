import uuid
from typing import List, Optional
from datetime import datetime
from sqlalchemy import String, Text, DateTime, ForeignKey, Uuid, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.session import Base
from app.models.base import TimestampMixin, UUIDMixin, utc_now


class ComplianceControl(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "compliance_controls"

    framework: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    control_id: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    # Relationships
    finding_mappings: Mapped[List["FindingCompliance"]] = relationship(
        "FindingCompliance",
        back_populates="compliance_control",
        passive_deletes="all",
    )

    __table_args__ = (
        UniqueConstraint("framework", "control_id", name="uq_framework_control_id"),
    )

    def __repr__(self) -> str:
        return f"<ComplianceControl(framework='{self.framework}', control_id='{self.control_id}')>"


class FindingCompliance(Base, UUIDMixin):
    __tablename__ = "finding_compliance"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("findings.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    compliance_control_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("compliance_controls.id", ondelete="RESTRICT"),
        index=True,
        nullable=False,
    )
    status: Mapped[str] = mapped_column(String(20), default="FAIL", nullable=False)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Relationships
    finding: Mapped["Finding"] = relationship("Finding", back_populates="compliance_mappings")
    compliance_control: Mapped["ComplianceControl"] = relationship("ComplianceControl", back_populates="finding_mappings")

    __table_args__ = (
        UniqueConstraint("finding_id", "compliance_control_id", name="uq_finding_control"),
    )

    def __repr__(self) -> str:
        return f"<FindingCompliance(finding_id={self.finding_id}, control_id={self.compliance_control_id}, status='{self.status}')>"
