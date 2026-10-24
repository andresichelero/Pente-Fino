from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any
import uuid

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pentefino_domain.models.audit import AuditEvent
from pentefino_domain.models.program import Program
from pentefino_domain.session import get_async_session


async def get_db_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding an async database session."""
    async with get_async_session() as session:
        yield session


async def record_api_audit(
    session: AsyncSession,
    event_type: str,
    object_type: str,
    object_id: uuid.UUID | str,
    payload: dict[str, Any],
    actor: str = "api",
) -> AuditEvent:
    """Append an audit event to the database."""
    event = AuditEvent(
        actor=actor,
        event_type=event_type,
        object_type=object_type,
        object_id=str(object_id),
        payload=payload,
    )
    session.add(event)
    await session.flush()
    return event


async def get_program_or_404(session: AsyncSession, slug: str) -> Program:
    """Fetch a Program by slug or raise 404 HTTPException."""
    stmt = select(Program).where(Program.slug == slug)
    result = await session.execute(stmt)
    program = result.scalar_one_or_none()
    if not program:
        raise HTTPException(
            status_code=404,
            detail=f"Program '{slug}' not found.",
        )
    return program
