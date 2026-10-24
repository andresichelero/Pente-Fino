from datetime import datetime, timezone
from typing import Any
from sqlalchemy import BigInteger, Index, Text, func
from sqlalchemy.dialects.postgresql import JSONB, TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from pentefino_domain.base import Base


class AuditEvent(Base):
    """Strictly append-only audit event log for compliance and operational tracking."""

    __tablename__ = "audit_events"

    sequence: Mapped[int] = mapped_column(
        BigInteger, primary_key=True, autoincrement=True
    )
    actor: Mapped[str] = mapped_column(
        Text, nullable=False, default="system", server_default="system"
    )
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    object_type: Mapped[str] = mapped_column(Text, nullable=False)
    object_id: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
    )

    __table_args__ = (
        Index("ix_audit_events_type_time", "event_type", "occurred_at"),
        Index("ix_audit_events_object", "object_type", "object_id"),
    )
