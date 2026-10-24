import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING
from sqlalchemy import CheckConstraint, ForeignKey, Index, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import CHAR, UUID, TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column, relationship

from pentefino_domain.base import Base, UUIDMixin

if TYPE_CHECKING:
    from pentefino_domain.models.program import Program
    from pentefino_domain.models.asset import Asset
    from pentefino_domain.models.template import TemplateCatalog
    from pentefino_domain.models.evidence import Evidence


class Finding(Base, UUIDMixin):
    """Vulnerability finding with granular deduplication and lifecycle state machine."""

    __tablename__ = "findings"

    program_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("programs.id", ondelete="CASCADE", name="fk_findings_program_id"),
        nullable=False,
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE", name="fk_findings_asset_id"),
        nullable=False,
    )
    dedup_key: Mapped[str] = mapped_column(CHAR(64), nullable=False)
    detector_id: Mapped[str] = mapped_column(
        Text,
        ForeignKey("template_catalog.id", ondelete="RESTRICT", name="fk_findings_detector_id"),
        nullable=False,
    )
    advisory_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_level: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[str] = mapped_column(Text, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
    )
    last_seen: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('candidate', 'validated', 'false_positive', 'reported', 'accepted', 'remediated', 'resolved', 'reopened')",
            name="chk_findings_status",
        ),
        CheckConstraint(
            "evidence_level IN ('E0', 'E1', 'E2', 'E3')",
            name="chk_findings_evidence_level",
        ),
        CheckConstraint(
            "confidence IN ('low', 'medium', 'high')",
            name="chk_findings_confidence",
        ),
        UniqueConstraint("program_id", "dedup_key", name="uq_findings_prog_dedup"),
        Index("ix_findings_prog_status", "program_id", "status"),
        Index("ix_findings_prog_evidence", "program_id", "evidence_level"),
        Index("ix_findings_asset_id", "asset_id"),
    )

    # Relationships
    program: Mapped["Program"] = relationship("Program", back_populates="findings")
    asset: Mapped["Asset"] = relationship("Asset", back_populates="findings")
    detector: Mapped["TemplateCatalog"] = relationship(
        "TemplateCatalog", back_populates="findings"
    )
    evidence_items: Mapped[list["Evidence"]] = relationship(
        "Evidence",
        back_populates="finding",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
