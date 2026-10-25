import asyncio
import os
import time
import weakref
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Optional
from urllib.parse import urlparse

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

DEFAULT_DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://pentefino:pentefino_secure_pass@127.0.0.1:5432/pentefino",
)

_engine: Optional[AsyncEngine] = None
_session_factory: Optional[async_sessionmaker[AsyncSession]] = None

# Fast circuit-breaker state to avoid 4.06s Windows TCP SYN timeouts when PostgreSQL is offline
_db_probe_ok: bool = False
_db_probe_expires_at: float = 0.0


def _normalize_db_url(url: str) -> str:
    """Replace @localhost with @127.0.0.1 on Windows to avoid 2s IPv6 [::1] SYN timeouts."""
    if os.name == "nt" and "@localhost" in url:
        return url.replace("@localhost", "@127.0.0.1")
    return url


def mark_db_offline(cooldown_seconds: float = 5.0) -> None:
    """Trip the circuit breaker immediately when a database connection error occurs."""
    global _db_probe_ok, _db_probe_expires_at
    _db_probe_ok = False
    _db_probe_expires_at = time.monotonic() + cooldown_seconds


async def check_db_available(
    database_url: Optional[str] = None,
    cooldown_seconds: float = 2.0,
    probe_timeout: float = 1.0,
) -> bool:
    """Fast-fail TCP circuit breaker (0ms cached, <=1.0s cold probe)."""
    global _db_probe_ok, _db_probe_expires_at
    now = time.monotonic()
    if database_url is None and now < _db_probe_expires_at:
        return _db_probe_ok

    raw_url = _normalize_db_url(database_url or DEFAULT_DATABASE_URL)
    parsed = urlparse(raw_url.replace("postgresql+asyncpg://", "postgresql://"))
    host = parsed.hostname or "127.0.0.1"
    if os.name == "nt" and host == "localhost":
        host = "127.0.0.1"
    port = parsed.port or 5432

    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=probe_timeout,
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        if database_url is None:
            _db_probe_ok = True
            _db_probe_expires_at = now + 2.5
        return True
    except (OSError, asyncio.TimeoutError):
        if database_url is None:
            _db_probe_ok = False
            _db_probe_expires_at = now + cooldown_seconds
        return False


def _current_loop() -> Optional[asyncio.AbstractEventLoop]:
    try:
        return asyncio.get_running_loop()
    except RuntimeError:
        return None


# Weak reference, not id(): a new loop can reuse a dead loop's id().
_engine_loop_ref: Optional["weakref.ReferenceType[asyncio.AbstractEventLoop]"] = None


def _engine_belongs_to_current_loop() -> bool:
    loop = _current_loop()
    owner = _engine_loop_ref() if _engine_loop_ref is not None else None
    return owner is loop


def get_async_engine(database_url: Optional[str] = None, echo: bool = False) -> AsyncEngine:
    """Creates or returns the cached async SQLAlchemy engine.

    The cache is per event loop: asyncpg connections are bound to the loop that opened
    them, so an engine created under one `asyncio.run()` (e.g. a CLI command) must not be
    reused by another loop (e.g. the API, or the next CLI command in the same process).
    """
    global _engine, _session_factory, _engine_loop_ref
    url = _normalize_db_url(database_url or DEFAULT_DATABASE_URL)
    if database_url is None and _engine is not None and not _engine_belongs_to_current_loop():
        _engine = None
        _session_factory = None
    if _engine is None or database_url is not None:
        connect_args = {"timeout": 2.0} if "asyncpg" in url else {}
        engine = create_async_engine(
            url,
            echo=echo,
            future=True,
            pool_pre_ping=True,
            connect_args=connect_args,
        )
        if database_url is None:
            _engine = engine
            loop = _current_loop()
            _engine_loop_ref = weakref.ref(loop) if loop is not None else None
        return engine
    return _engine


def get_async_session_factory(
    database_url: Optional[str] = None,
) -> async_sessionmaker[AsyncSession]:
    """Creates or returns the cached async session factory (bound to the current loop's engine)."""
    global _session_factory
    if database_url is None and _engine is not None and not _engine_belongs_to_current_loop():
        get_async_engine()
    if _session_factory is None or database_url is not None:
        engine = get_async_engine(database_url=database_url)
        factory = async_sessionmaker(
            bind=engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )
        if database_url is None:
            _session_factory = factory
        return factory
    return _session_factory


@asynccontextmanager
async def get_async_session(
    database_url: Optional[str] = None,
) -> AsyncIterator[AsyncSession]:
    """Async context manager yielding a database session."""
    factory = get_async_session_factory(database_url=database_url)
    async with factory() as session:
        try:
            yield session
            if session.in_transaction():
                await session.commit()
        except Exception as exc:
            if isinstance(exc, (OSError, TimeoutError, ConnectionError)):
                mark_db_offline()
            try:
                if session.in_transaction():
                    await session.rollback()
            except Exception:
                pass
            raise
        finally:
            try:
                await session.close()
            except Exception:
                pass
