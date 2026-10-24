import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Optional

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

DEFAULT_DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://pentefino:pentefino_secure_pass@localhost:5432/pentefino",
)

_engine: Optional[AsyncEngine] = None
_session_factory: Optional[async_sessionmaker[AsyncSession]] = None


def get_async_engine(database_url: Optional[str] = None, echo: bool = False) -> AsyncEngine:
    """Creates or returns the cached async SQLAlchemy engine."""
    global _engine
    url = database_url or DEFAULT_DATABASE_URL
    if _engine is None or database_url is not None:
        engine = create_async_engine(
            url,
            echo=echo,
            future=True,
            pool_pre_ping=True,
        )
        if database_url is None:
            _engine = engine
        return engine
    return _engine


def get_async_session_factory(
    database_url: Optional[str] = None,
) -> async_sessionmaker[AsyncSession]:
    """Creates or returns the cached async session factory."""
    global _session_factory
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
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
