from __future__ import annotations

import socket
import pytest


def is_postgres_running(host: str = "localhost", port: int = 5432, timeout: float = 0.2) -> bool:
    """Check if PostgreSQL server is accepting TCP connections."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def pytest_collection_modifyitems(config, items) -> None:
    """Skip live-database-dependent integration tests if PostgreSQL is offline."""
    if not is_postgres_running():
        skip_pg = pytest.mark.skip(
            reason="PostgreSQL not running on localhost:5432 (Docker daemon offline)"
        )
        for item in items:
            if "test_db_migrations.py" in str(item.fspath):
                if not item.name.startswith("test_model_") and not item.name.startswith("test_dedup_key_"):
                    item.add_marker(skip_pg)
