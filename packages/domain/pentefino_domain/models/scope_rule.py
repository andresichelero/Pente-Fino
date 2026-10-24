import uuid
from typing import TYPE_CHECKING
from sqlalchemy import CheckConstraint, ForeignKey, Index, Integer, Text
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from pentefino_domain.base import Base, UUIDMixin, TimestampMixin

if TYPE_CHECKING:
    from pentefino_domain.models.program import Program


class ScopeRule(Base, UUIDMixin, TimestampMixin):
    """Explicit scope rule evaluated by the fail-closed scope engine."""

    __tablename__ = "scope_rules"

    program_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("programs.id", ondelete="CASCADE", name="fk_scope_rules_program_id"),
        nullable=False,
    )
    priority: Mapped[int] = mapped_column(
        Integer, nullable=False, default=100, server_default="100"
    )
    asset_type: Mapped[str] = mapped_column(Text, nullable=False)
    pattern: Mapped[str] = mapped_column(Text, nullable=False)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    allowed_ports: Mapped[list[int] | None] = mapped_column(ARRAY(Integer), nullable=True)
    denied_paths: Mapped[list[str] | None] = mapped_column(ARRAY(Text), nullable=True)
    max_impact_class: Mapped[str] = mapped_column(
        Text, nullable=False, default="safe_read_only", server_default="safe_read_only"
    )

    __table_args__ = (
        CheckConstraint(
            "asset_type IN ('domain', 'wildcard_domain', 'hostname', 'url', 'cidr', 'ip')",
            name="chk_scope_rules_asset_type",
        ),
        CheckConstraint(
            "action IN ('allow', 'deny', 'discover_only')",
            name="chk_scope_rules_action",
        ),
        CheckConstraint(
            "max_impact_class IN ('passive', 'safe_read_only', 'active_reviewed', 'stateful', 'intrusive', 'lab_only')",
            name="chk_scope_rules_max_impact",
        ),
        Index("ix_scope_rules_prog_priority", "program_id", "priority"),
        Index("ix_scope_rules_prog_action", "program_id", "action"),
    )

    # Relationships
    program: Mapped["Program"] = relationship("Program", back_populates="scope_rules")
