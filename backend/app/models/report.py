import uuid
from typing import Optional
from datetime import datetime
from sqlalchemy import String, DateTime, ForeignKey, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.session import Base
from app.models.base import UUIDMixin, utc_now


class Report(Base, UUIDMixin):
    __tablename__ = "reports"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    generated_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )
    report_type: Mapped[str] = mapped_column(String(50), default="EXECUTIVE", nullable=False)
    file_reference: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="PENDING", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        index=True,
        nullable=False,
    )

    # Relationships
    scan: Mapped["Scan"] = relationship("Scan", back_populates="reports")
    generated_by_user: Mapped[Optional["User"]] = relationship("User", back_populates="reports_generated")

    def __repr__(self) -> str:
        return f"<Report(id={self.id}, scan_id={self.scan_id}, type='{self.report_type}', status='{self.status}')>"
