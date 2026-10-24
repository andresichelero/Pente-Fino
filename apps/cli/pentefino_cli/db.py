from __future__ import annotations

import asyncio
import threading
from collections.abc import Coroutine
from typing import Any, Optional, TypeVar
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pentefino_domain.models import AuditEvent, Program

T = TypeVar("T")

_loop: Optional[asyncio.AbstractEventLoop] = None
_thread: Optional[threading.Thread] = None
_lock = threading.Lock()


def _get_background_loop() -> asyncio.AbstractEventLoop:
    """Ensure a long-running background event loop is running on a dedicated daemon thread."""
    global _loop, _thread
    with _lock:
        if _loop is None or not _loop.is_running() or _loop.is_closed():
            _loop = asyncio.new_event_loop()
            _thread = threading.Thread(target=_loop.run_forever, daemon=True)
            _thread.start()
        return _loop


def run_async(coro: Coroutine[Any, Any, T]) -> T:
    """Run an asynchronous coroutine thread-safely on the dedicated background loop."""
    loop = _get_background_loop()
    future = asyncio.run_coroutine_threadsafe(coro, loop)
    return future.result()


async def get_program_by_slug(session: AsyncSession, slug: str) -> Optional[Program]:
    """Fetch a Program entity by unique slug."""
    stmt = select(Program).where(Program.slug == slug)
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def record_audit_event(
    session: AsyncSession,
    event_type: str,
    object_type: str,
    object_id: str | UUID,
    payload: dict[str, Any],
    actor: str = "cli",
) -> AuditEvent:
    """Record an immutable audit log entry."""
    audit = AuditEvent(
        actor=actor,
        event_type=event_type,
        object_type=object_type,
        object_id=str(object_id),
        payload=payload,
    )
    session.add(audit)
    return audit
