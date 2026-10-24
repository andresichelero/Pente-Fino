import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING
from sqlalchemy import CheckConstraint, ForeignKey, Index, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID, TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column, relationship

from pentefino_domain.base import Base, UUIDMixin

if TYPE_CHECKING:
    from pentefino_domain.models.program import Program
    from pentefino_domain.models.finding import Finding


class Asset(Base, UUIDMixin):
    """Discovered or scoped target entity (domain, IP, host, URL)."""

    __tablename__ = "assets"

    program_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("programs.id", ondelete="CASCADE", name="fk_assets_program_id"),
        nullable=False,
    )
    canonical_key: Mapped[str] = mapped_column(Text, nullable=False)
    asset_type: Mapped[str] = mapped_column(Text, nullable=False)
    scope_state: Mapped[str] = mapped_column(Text, nullable=False)
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
            "scope_state IN ('in_scope_explicit', 'in_scope_derived', 'candidate', 'out_of_scope')",
            name="chk_assets_scope_state",
        ),
        UniqueConstraint(
            "program_id", "asset_type", "canonical_key", name="uq_assets_prog_type_canonical"
        ),
        Index("ix_assets_prog_scope_state", "program_id", "scope_state"),
        Index("ix_assets_canonical_key", "canonical_key"),
    )

    # Relationships
    program: Mapped["Program"] = relationship("Program", back_populates="assets")
    findings: Mapped[list["Finding"]] = relationship(
        "Finding",
        back_populates="asset",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
