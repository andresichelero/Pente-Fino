import uuid
from typing import TYPE_CHECKING
from sqlalchemy import CheckConstraint, ForeignKey, Index, Text
from sqlalchemy.dialects.postgresql import CHAR, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from pentefino_domain.base import Base, UUIDMixin, TimestampMixin

if TYPE_CHECKING:
    from pentefino_domain.models.finding import Finding


class Evidence(Base, UUIDMixin, TimestampMixin):
    """Forensic evidence metadata pointer to raw/sanitized artifacts stored in SeaweedFS."""

    __tablename__ = "evidence"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("findings.id", ondelete="CASCADE", name="fk_evidence_finding_id"),
        nullable=False,
    )
    run_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    evidence_type: Mapped[str] = mapped_column(Text, nullable=False)
    original_sha256: Mapped[str | None] = mapped_column(CHAR(64), nullable=True)
    sanitized_sha256: Mapped[str] = mapped_column(CHAR(64), nullable=False)
    seaweed_object_key: Mapped[str] = mapped_column(Text, nullable=False)
    redaction_profile: Mapped[str] = mapped_column(
        Text, nullable=False, default="bounty-safe-v1", server_default="bounty-safe-v1"
    )

    __table_args__ = (
        CheckConstraint(
            "evidence_type IN ('dns', 'http_interaction', 'tls', 'fingerprint')",
            name="chk_evidence_type",
        ),
        Index("ix_evidence_finding_id", "finding_id"),
        Index("ix_evidence_run_id", "run_id"),
        Index("ix_evidence_sanitized_sha", "sanitized_sha256"),
    )

    # Relationships
    finding: Mapped["Finding"] = relationship("Finding", back_populates="evidence_items")
