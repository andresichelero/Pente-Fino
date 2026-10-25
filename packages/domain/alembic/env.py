import asyncio
import os
import sys
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

# Ensure packages/domain is in sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
package_root = os.path.abspath(os.path.join(current_dir, ".."))
if package_root not in sys.path:
    sys.path.insert(0, package_root)

# Also ensure project root is in sys.path
project_root = os.path.abspath(os.path.join(package_root, "..", ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from pentefino_domain.base import Base  # noqa: E402
import pentefino_domain.models  # noqa: F401, E402

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def get_url() -> str:
    url = os.getenv(
        "DATABASE_URL",
        config.get_main_option(
            "sqlalchemy.url",
            "postgresql+asyncpg://pentefino:pentefino_secure_pass@127.0.0.1:5432/pentefino",
        ),
    )
    if os.name == "nt" and "@localhost" in url:
        url = url.replace("@localhost", "@127.0.0.1")
    # Ensure async driver for postgresql
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    elif url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+asyncpg://", 1)
    return url


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Run migrations in 'online' mode with an async engine."""
    connectable = config.attributes.get("connection", None)

    if connectable is not None:
        if isinstance(connectable, Connection):
            do_run_migrations(connectable)
            return
        # If it's an AsyncConnection
        await connectable.run_sync(do_run_migrations)
        return

    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = get_url()

    connectable = async_engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    # Check if a synchronous connection was passed in config.attributes
    connectable = config.attributes.get("connection", None)
    if connectable is not None and isinstance(connectable, Connection):
        do_run_migrations(connectable)
        return

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        # If already in an event loop (e.g. within an async test runner)
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(lambda: asyncio.run(run_async_migrations()))
            future.result()
    else:
        asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
