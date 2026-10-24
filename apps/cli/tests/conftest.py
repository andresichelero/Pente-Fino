from __future__ import annotations

import socket
import pytest
from typer.testing import CliRunner


def is_postgres_running(host: str = "127.0.0.1", port: int = 5432, timeout: float = 0.2) -> bool:
    """Check if PostgreSQL server is accepting TCP connections."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


@pytest.fixture
def runner() -> CliRunner:
    """Fixture providing a Typer CLI test runner with wide terminal to prevent truncation."""
    return CliRunner(env={"COLUMNS": "200"})


def pytest_collection_modifyitems(config, items) -> None:
    """Skip live-database-dependent Phase 1 CLI tests if PostgreSQL is offline."""
    if not is_postgres_running():
        skip_pg = pytest.mark.skip(
            reason="PostgreSQL not running on localhost:5432 (Docker daemon offline)"
        )
        for item in items:
            if "test_cli.py" in str(item.fspath):
                if item.name not in (
                    "test_cli_help",
                    "test_cli_version",
                    "test_program_validation",
                    "test_api_and_gui_cli_commands",
                ):
                    item.add_marker(skip_pg)
