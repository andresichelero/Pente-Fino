from __future__ import annotations

from contextlib import asynccontextmanager
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from typer.testing import CliRunner

from pentefino_cli.main import app
from pentefino_domain.models import TemplateCatalog


@pytest.fixture
def sample_templates() -> list[TemplateCatalog]:
    return [
        TemplateCatalog(
            id="nginx-version",
            name="Nginx Version Disclosure",
            protocol="http",
            impact_class="safe_read_only",
            severity="info",
            technologies=["nginx"],
            tags=["nginx", "version"],
            upstream_revision="rev-123456",
            bundle_hash="a" * 64,
            raw_yaml="id: nginx-version\ninfo:\n  name: Nginx Version Disclosure",
        ),
        TemplateCatalog(
            id="apache-cve-2021-41773",
            name="Apache 2.4.49 - Path Traversal",
            protocol="http",
            impact_class="safe_read_only",
            severity="high",
            cve_id="CVE-2021-41773",
            cwe_id="CWE-22",
            technologies=["apache"],
            tags=["apache", "cve"],
            upstream_revision="rev-123456",
            bundle_hash="b" * 64,
            raw_yaml="id: apache-cve-2021-41773\ninfo:\n  name: Apache 2.4.49",
        ),
        TemplateCatalog(
            id="wordpress-login-check",
            name="WordPress Default Login",
            protocol="http",
            impact_class="active_reviewed",
            severity="medium",
            technologies=["wordpress"],
            tags=["wordpress", "auth"],
            upstream_revision="rev-123456",
            bundle_hash="c" * 64,
            raw_yaml="id: wordpress-login-check\ninfo:\n  name: WordPress Login",
        ),
    ]


def test_template_help(runner: CliRunner) -> None:
    """Verify template top-level and subcommands help outputs."""
    res = runner.invoke(app, ["template", "--help"])
    assert res.exit_code == 0
    assert "sync" in res.output
    assert "list" in res.output

    sync_res = runner.invoke(app, ["template", "sync", "--help"])
    assert sync_res.exit_code == 0
    assert "--repo" in sync_res.output
    assert "--path" in sync_res.output
    assert "--json" in sync_res.output

    list_res = runner.invoke(app, ["template", "list", "--help"])
    assert list_res.exit_code == 0
    assert "--impact" in list_res.output
    assert "--tech" in list_res.output
    assert "--severity" in list_res.output
    assert "--limit" in list_res.output
    assert "--json" in list_res.output


def test_template_sync_execution(runner: CliRunner, tmp_path: Path) -> None:
    """Verify template sync clones/pulls, classifies files, and ingests into database."""
    # Create sample template YAML files in tmp_path
    template_file = tmp_path / "test-nginx.yaml"
    template_file.write_text(
        """
id: test-nginx
info:
  name: Test Nginx Header
  severity: info
  tags: nginx,headers
http:
  - method: GET
    path:
      - "{{BaseURL}}"
""",
        encoding="utf-8",
    )

    mock_session = AsyncMock()

    @asynccontextmanager
    async def mock_get_async_session():
        yield mock_session

    with patch("pentefino_cli.commands.template.get_async_session", mock_get_async_session), \
         patch("pentefino_cli.commands.template.TemplateSyncManager.sync", AsyncMock(return_value="9abcdef0")), \
         patch("pentefino_cli.commands.template.TemplateSyncManager.get_templates_dir", return_value=tmp_path), \
         patch("pentefino_cli.commands.template.TemplateCatalogIngester.ingest_batch", AsyncMock(return_value=1)):

        # Rich text output
        res_text = runner.invoke(app, ["template", "sync", "--path", str(tmp_path)])
        assert res_text.exit_code == 0
        assert "Template Catalog Synchronized" in res_text.output
        assert "9abcdef0" in res_text.output

        # JSON output
        res_json = runner.invoke(app, ["template", "sync", "--path", str(tmp_path), "--json"])
        assert res_json.exit_code == 0
        parsed = json.loads(res_json.output)
        assert parsed["status"] == "synced"
        assert parsed["revision"] == "9abcdef0"
        assert parsed["classified_count"] == 1
        assert parsed["ingested_count"] == 1


def test_template_list_table_rendering(
    runner: CliRunner, sample_templates: list[TemplateCatalog]
) -> None:
    """Verify querying templates and rendering Rich formatted table."""
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = sample_templates
    mock_session.execute.return_value = mock_result

    @asynccontextmanager
    async def mock_get_async_session():
        yield mock_session

    with patch("pentefino_cli.commands.template.get_async_session", mock_get_async_session):
        res = runner.invoke(app, ["template", "list"])
        assert res.exit_code == 0
        assert "Template Catalog" in res.output
        assert "nginx-version" in res.output
        assert "apache-cve-2021-41773" in res.output
        assert "wordpress-login-check" in res.output


def test_template_list_json_output(
    runner: CliRunner, sample_templates: list[TemplateCatalog]
) -> None:
    """Verify querying templates outputs clean machine-readable JSON."""
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = sample_templates
    mock_session.execute.return_value = mock_result

    @asynccontextmanager
    async def mock_get_async_session():
        yield mock_session

    with patch("pentefino_cli.commands.template.get_async_session", mock_get_async_session):
        res = runner.invoke(app, ["template", "list", "--json"])
        assert res.exit_code == 0
        parsed = json.loads(res.output)
        assert isinstance(parsed, list)
        assert len(parsed) == 3
        assert parsed[0]["id"] == "nginx-version"
        assert parsed[1]["id"] == "apache-cve-2021-41773"
        assert parsed[1]["cve_id"] == "CVE-2021-41773"
        assert parsed[2]["impact_class"] == "active_reviewed"


def test_template_list_technology_filtering(
    runner: CliRunner, sample_templates: list[TemplateCatalog]
) -> None:
    """Verify technology filtering matches only templates associated with target technology."""
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = sample_templates
    mock_session.execute.return_value = mock_result

    @asynccontextmanager
    async def mock_get_async_session():
        yield mock_session

    with patch("pentefino_cli.commands.template.get_async_session", mock_get_async_session):
        res = runner.invoke(app, ["template", "list", "--tech", "apache", "--json"])
        assert res.exit_code == 0
        parsed = json.loads(res.output)
        assert len(parsed) == 1
        assert parsed[0]["id"] == "apache-cve-2021-41773"
        assert "apache" in parsed[0]["technologies"]
