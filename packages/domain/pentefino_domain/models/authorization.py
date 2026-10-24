import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any
from sqlalchemy import CHAR, ForeignKey, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID, TIMESTAMP, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from pentefino_domain.base import Base, UUIDMixin, TimestampMixin

if TYPE_CHECKING:
    from pentefino_domain.models.program import Program


class AuthorizationSnapshot(Base, UUIDMixin, TimestampMixin):
    """Immutable snapshot of bug bounty terms and legal authorization scope."""

    __tablename__ = "authorization_snapshots"

    program_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("programs.id", ondelete="RESTRICT", name="fk_auth_snapshots_program_id"),
        nullable=False,
    )
    source_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    policy_hash: Mapped[str] = mapped_column(CHAR(64), nullable=False)
    rules_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    valid_from: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
    )
    valid_until: Mapped[datetime | None] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )

    __table_args__ = (
        UniqueConstraint(
            "program_id", "policy_hash", name="uq_auth_snapshots_program_policy"
        ),
    )

    # Relationships
    program: Mapped["Program"] = relationship(
        "Program", back_populates="authorization_snapshots"
    )
