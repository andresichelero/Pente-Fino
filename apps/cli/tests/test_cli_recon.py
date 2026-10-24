from __future__ import annotations

from contextlib import asynccontextmanager
import json
from unittest.mock import AsyncMock, patch
import uuid

import pytest
from typer.testing import CliRunner

from pentefino_adapters.models import (
    DiscoveredCandidate,
    DnsRecord,
    HttpProbeRecord,
    ReconResult,
    TechnologyComponent,
)
from pentefino_cli.main import app
from pentefino_domain.enums import ScopeState
from pentefino_domain.models import Program


@pytest.fixture
def sample_program() -> Program:
    prog_id = uuid.uuid4()
    return Program(
        id=prog_id,
        slug="example-corp",
        name="Example Corporation Bounty",
        platform="hackerone",
        state="active",
        default_policy_id="default_bounty",
    )


def test_recon_help(runner: CliRunner) -> None:
    """Verify recon and recon run help outputs contain expected options."""
    res = runner.invoke(app, ["recon", "--help"])
    assert res.exit_code == 0
    assert "run" in res.output

    run_res = runner.invoke(app, ["recon", "run", "--help"])
    assert run_res.exit_code == 0
    assert "--program" in run_res.output
    assert "--domain" in run_res.output
    assert "--bruteforce" in run_res.output
    assert "--async" in run_res.output
    assert "--json" in run_res.output


def test_recon_missing_required_arguments(runner: CliRunner) -> None:
    """Verify missing required --program or --domain flags produce error."""
    res_no_args = runner.invoke(app, ["recon", "run"])
    assert res_no_args.exit_code != 0

    res_missing_domain = runner.invoke(app, ["recon", "run", "--program", "test-slug"])
    assert res_missing_domain.exit_code != 0

    res_missing_program = runner.invoke(app, ["recon", "run", "--domain", "example.com"])
    assert res_missing_program.exit_code != 0


def test_recon_program_not_found(runner: CliRunner) -> None:
    """Verify error output when specified program does not exist."""
    mock_session = AsyncMock()

    @asynccontextmanager
    async def mock_get_async_session():
        yield mock_session

    with patch("pentefino_cli.commands.recon.get_async_session", mock_get_async_session), \
         patch("pentefino_cli.commands.recon.get_program_by_slug", AsyncMock(return_value=None)):

        # Rich text output
        res_text = runner.invoke(app, ["recon", "run", "-p", "nonexistent-bounty", "-d", "example.com"])
        assert res_text.exit_code == 1
        assert "Program 'nonexistent-bounty' not found" in res_text.output

        # JSON output
        res_json = runner.invoke(app, ["recon", "run", "-p", "nonexistent-bounty", "-d", "example.com", "--json"])
        assert res_json.exit_code == 1
        parsed = json.loads(res_json.output)
        assert parsed["status"] == "error"
        assert "not found" in parsed["error"]


def test_recon_async_dispatch(runner: CliRunner, sample_program: Program) -> None:
    """Verify asynchronous recon dispatch queues the task and creates audit event."""
    mock_session = AsyncMock()

    @asynccontextmanager
    async def mock_get_async_session():
        yield mock_session

    with patch("pentefino_cli.commands.recon.get_async_session", mock_get_async_session), \
         patch("pentefino_cli.commands.recon.get_program_by_slug", AsyncMock(return_value=sample_program)), \
         patch("pentefino_cli.commands.recon.record_audit_event", AsyncMock()) as mock_audit:

        # Rich text output
        res_text = runner.invoke(app, ["recon", "run", "-p", sample_program.slug, "-d", "example.com", "--async"])
        assert res_text.exit_code == 0
        assert "QUEUED" in res_text.output or "Task ID" in res_text.output
        assert sample_program.slug in res_text.output
        assert mock_audit.called

        # JSON output
        res_json = runner.invoke(
            app, ["recon", "run", "-p", sample_program.slug, "-d", "example.com", "--async", "--json"]
        )
        assert res_json.exit_code == 0
        parsed = json.loads(res_json.output)
        assert parsed["status"] == "queued"
        assert parsed["program"] == sample_program.slug
        assert parsed["domain"] == "example.com"
        assert "task_id" in parsed


def test_recon_sync_pipeline_execution(runner: CliRunner, sample_program: Program) -> None:
    """Verify synchronous ReconPipeline execution produces Rich formatted tables."""
    mock_session = AsyncMock()

    @asynccontextmanager
    async def mock_get_async_session():
        yield mock_session

    mock_result = ReconResult(
        domain="example.com",
        program_id=sample_program.id,
        candidates=[
            DiscoveredCandidate(
                host="api.example.com",
                sources=["subfinder"],
                scope_state=ScopeState.IN_SCOPE_DERIVED,
            ),
            DiscoveredCandidate(
                host="admin.example.com",
                sources=["subfinder"],
                scope_state=ScopeState.OUT_OF_SCOPE,
            ),
        ],
        dns_records=[
            DnsRecord(
                host="api.example.com",
                a=["93.184.216.34"],
                aaaa=["2606:2800:220:1:248:1893:25c8:1946"],
                cname=["lb.example.com"],
            ),
        ],
        http_probes=[
            HttpProbeRecord(
                url="https://api.example.com",
                input_host="api.example.com",
                status_code=200,
                title="Example API Gateway",
                webserver="nginx/1.24.0",
                components=[
                    TechnologyComponent(name="nginx", version="1.24.0"),
                    TechnologyComponent(name="FastAPI"),
                ],
            ),
        ],
        total_discovered=2,
        in_scope_count=1,
        resolved_count=1,
        live_http_count=1,
    )

    with patch("pentefino_cli.commands.recon.get_async_session", mock_get_async_session), \
         patch("pentefino_cli.commands.recon.get_program_by_slug", AsyncMock(return_value=sample_program)), \
         patch("pentefino_cli.commands.recon._load_scope_engine", AsyncMock()), \
         patch("pentefino_cli.commands.recon.ReconPipeline.run", AsyncMock(return_value=mock_result)), \
         patch("pentefino_cli.commands.recon.record_audit_event", AsyncMock()):

        res = runner.invoke(
            app,
            ["recon", "run", "-p", sample_program.slug, "-d", "example.com", "--bruteforce"],
        )
        assert res.exit_code == 0
        assert "Reconnaissance Complete" in res.output
        assert "api.example.com" in res.output
        assert "93.184.216.34" in res.output
        assert "Example API" in res.output
        assert "nginx" in res.output


def test_recon_sync_pipeline_json_output(runner: CliRunner, sample_program: Program) -> None:
    """Verify synchronous ReconPipeline execution produces clean structured JSON."""
    mock_session = AsyncMock()

    @asynccontextmanager
    async def mock_get_async_session():
        yield mock_session

    mock_result = ReconResult(
        domain="example.com",
        program_id=sample_program.id,
        candidates=[
            DiscoveredCandidate(
                host="api.example.com",
                sources=["subfinder"],
                scope_state=ScopeState.IN_SCOPE_DERIVED,
            ),
        ],
        dns_records=[
            DnsRecord(
                host="api.example.com",
                a=["93.184.216.34"],
                aaaa=[],
                cname=[],
            ),
        ],
        http_probes=[
            HttpProbeRecord(
                url="https://api.example.com",
                input_host="api.example.com",
                status_code=200,
                title="Example API Gateway",
                webserver="nginx",
                components=[TechnologyComponent(name="nginx")],
            ),
        ],
        total_discovered=1,
        in_scope_count=1,
        resolved_count=1,
        live_http_count=1,
    )

    with patch("pentefino_cli.commands.recon.get_async_session", mock_get_async_session), \
         patch("pentefino_cli.commands.recon.get_program_by_slug", AsyncMock(return_value=sample_program)), \
         patch("pentefino_cli.commands.recon._load_scope_engine", AsyncMock()), \
         patch("pentefino_cli.commands.recon.ReconPipeline.run", AsyncMock(return_value=mock_result)), \
         patch("pentefino_cli.commands.recon.record_audit_event", AsyncMock()):

        res = runner.invoke(
            app,
            ["recon", "run", "-p", sample_program.slug, "-d", "example.com", "--json"],
        )
        assert res.exit_code == 0
        parsed = json.loads(res.output)
        assert parsed["status"] == "completed"
        assert parsed["program"] == sample_program.slug
        assert parsed["domain"] == "example.com"
        assert parsed["total_discovered"] == 1
        assert parsed["in_scope_count"] == 1
        assert parsed["resolved_count"] == 1
        assert parsed["live_http_count"] == 1
        assert parsed["candidates"][0]["host"] == "api.example.com"
        assert parsed["candidates"][0]["scope_state"] == "in_scope_derived"
        assert parsed["dns_records"][0]["a"] == ["93.184.216.34"]
        assert parsed["http_probes"][0]["status_code"] == 200
        assert "nginx" in parsed["http_probes"][0]["technologies"]
