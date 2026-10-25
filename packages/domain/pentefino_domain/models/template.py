from datetime import datetime, timezone
from typing import TYPE_CHECKING
from sqlalchemy import CheckConstraint, Index, Text, func
from sqlalchemy.dialects.postgresql import ARRAY, CHAR, TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column, relationship

from pentefino_domain.base import Base

if TYPE_CHECKING:
    from pentefino_domain.models.finding import Finding


class TemplateCatalog(Base):
    """Local repository and index of reviewed security templates (Nuclei and custom rules)."""

    __tablename__ = "template_catalog"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    file_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    upstream_revision: Mapped[str] = mapped_column(Text, nullable=False)
    bundle_hash: Mapped[str] = mapped_column(CHAR(64), nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    protocol: Mapped[str] = mapped_column(Text, nullable=False)
    http_methods: Mapped[list[str] | None] = mapped_column(ARRAY(Text), nullable=True)
    impact_class: Mapped[str] = mapped_column(Text, nullable=False)
    cve_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    cwe_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str | None] = mapped_column(Text, nullable=True)
    technologies: Mapped[list[str] | None] = mapped_column(ARRAY(Text), nullable=True)
    tags: Mapped[list[str] | None] = mapped_column(ARRAY(Text), nullable=True)
    raw_yaml: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
    )

    __table_args__ = (
        CheckConstraint(
            "impact_class IN ('passive', 'safe_read_only', 'active_reviewed', 'stateful', 'intrusive', 'lab_only')",
            name="chk_template_impact_class",
        ),
        Index("ix_template_catalog_cve_id", "cve_id"),
        Index("ix_template_catalog_impact", "impact_class"),
        Index("ix_template_catalog_protocol", "protocol"),
    )

    # Relationships
    findings: Mapped[list["Finding"]] = relationship(
        "Finding", back_populates="detector"
    )
