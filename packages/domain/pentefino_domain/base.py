import uuid
from datetime import datetime, timezone
from sqlalchemy import func
from sqlalchemy.dialects.postgresql import UUID, TIMESTAMP
from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(AsyncAttrs, DeclarativeBase):
    """Root declarative base for all PenteFino domain entities."""
    pass


class UUIDMixin:
    """Provides a native PostgreSQL UUID primary key generated via gen_random_uuid()."""
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )


UUIDPrimaryKeyMixin = UUIDMixin


class TimestampMixin:
    """Provides standardized created_at with UTC timezone awareness."""
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
    )
