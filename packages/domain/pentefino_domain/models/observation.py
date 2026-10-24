import uuid
from typing import TYPE_CHECKING, Any, Optional
from sqlalchemy import ForeignKey, Index, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from pentefino_domain.base import Base, TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    from pentefino_domain.models.asset import Asset


class Observation(Base, UUIDMixin, TimestampMixin):
    """Raw or structured observation collected against an asset (e.g. DNS, HTTP probe)."""

    __tablename__ = "observations"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE", name="fk_observations_asset_id"),
        nullable=False,
    )
    observation_type: Mapped[str] = mapped_column(
        Text, nullable=False
    )  # e.g. 'dns', 'http', 'subdomain_discovery'
    raw_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default="{}"
    )

    __table_args__ = (
        Index("ix_observations_asset_id", "asset_id"),
        Index("ix_observations_type", "observation_type"),
    )

    # Relationships
    asset: Mapped["Asset"] = relationship("Asset", backref="observations")

    @property
    def normalized(self) -> dict[str, Any]:
        """Convenience alias for metadata_json."""
        return self.metadata_json

    @normalized.setter
    def normalized(self, value: dict[str, Any]) -> None:
        self.metadata_json = value
