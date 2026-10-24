from __future__ import annotations

from collections.abc import AsyncIterator
import os
import uuid

import httpx
from httpx import ASGITransport
import pytest_asyncio
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from pentefino_api.deps import get_db_session
from pentefino_api.main import app
from pentefino_domain.models.authorization import AuthorizationSnapshot
from pentefino_domain.models.program import Program
from pentefino_domain.session import DEFAULT_DATABASE_URL

TEST_DATABASE_URL = os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL)


@pytest_asyncio.fixture
async def db_engine() -> AsyncIterator[AsyncEngine]:
    """Create an isolated NullPool async engine per test to avoid event-loop binding issues."""
    engine = create_async_engine(
        TEST_DATABASE_URL,
        poolclass=NullPool,
        future=True,
    )
    try:
        yield engine
    finally:
        await engine.dispose()


@pytest_asyncio.fixture
async def db_session(db_engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    """Provide an async database session for test seeding and assertions."""
    factory = async_sessionmaker(
        bind=db_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )
    async with factory() as session:
        yield session


@pytest_asyncio.fixture
async def async_client(db_engine: AsyncEngine) -> AsyncIterator[httpx.AsyncClient]:
    """Provide an httpx.AsyncClient bound to the FastAPI ASGI app with NullPool DB sessions."""
    factory = async_sessionmaker(
        bind=db_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )

    async def _override_get_db_session() -> AsyncIterator[AsyncSession]:
        async with factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()

    app.dependency_overrides[get_db_session] = _override_get_db_session
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def test_slug(db_engine: AsyncEngine) -> AsyncIterator[str]:
    """Generate a unique program slug and automatically clean up the program after the test."""
    slug = f"pytest-api-{uuid.uuid4().hex[:10]}"
    try:
        yield slug
    finally:
        factory = async_sessionmaker(
            bind=db_engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
        async with factory() as cleanup_session:
            prog_ids_subq = select(Program.id).where(Program.slug == slug)
            await cleanup_session.execute(
                delete(AuthorizationSnapshot).where(
                    AuthorizationSnapshot.program_id.in_(prog_ids_subq)
                )
            )
            await cleanup_session.execute(
                delete(Program).where(Program.slug == slug)
            )
            await cleanup_session.commit()
