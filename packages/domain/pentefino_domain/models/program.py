from typing import TYPE_CHECKING
from sqlalchemy import CheckConstraint, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from pentefino_domain.base import Base, UUIDMixin, TimestampMixin

if TYPE_CHECKING:
    from pentefino_domain.models.authorization import AuthorizationSnapshot
    from pentefino_domain.models.scope_rule import ScopeRule
    from pentefino_domain.models.asset import Asset
    from pentefino_domain.models.finding import Finding


class Program(Base, UUIDMixin, TimestampMixin):
    """Bug bounty program representation and governance root."""

    __tablename__ = "programs"

    slug: Mapped[str] = mapped_column(Text, unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    platform: Mapped[str] = mapped_column(Text, nullable=False)
    state: Mapped[str] = mapped_column(Text, nullable=False)
    default_policy_id: Mapped[str] = mapped_column(
        Text, nullable=False, default="bounty-safe", server_default="bounty-safe"
    )

    __table_args__ = (
        CheckConstraint(
            "platform IN ('hackerone', 'bugcrowd', 'intigriti', 'private', 'lab')",
            name="chk_programs_platform",
        ),
        CheckConstraint(
            "state IN ('active', 'suspended', 'archived')",
            name="chk_programs_state",
        ),
    )

    # Relationships
    authorization_snapshots: Mapped[list["AuthorizationSnapshot"]] = relationship(
        "AuthorizationSnapshot",
        back_populates="program",
        passive_deletes="all",
    )
    scope_rules: Mapped[list["ScopeRule"]] = relationship(
        "ScopeRule",
        back_populates="program",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    assets: Mapped[list["Asset"]] = relationship(
        "Asset",
        back_populates="program",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    findings: Mapped[list["Finding"]] = relationship(
        "Finding",
        back_populates="program",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
