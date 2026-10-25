from __future__ import annotations

from contextlib import asynccontextmanager
import json
from unittest.mock import AsyncMock, MagicMock, patch
import uuid

import pytest
from typer.testing import CliRunner

from pentefino_cli.main import app
from pentefino_detection.planner import DetectionPlan
from pentefino_domain.enums import AssetType, ScopeState
from pentefino_domain.models import Asset, Finding, Observation, Program


@pytest.fixture
def sample_program() -> Program:
    return Program(
        id=uuid.uuid4(),
        slug="target-corp",
        name="Target Corporation",
        platform="bugcrowd",
        state="active",
        default_policy_id="default_bounty",
    )


@pytest.fixture
def sample_asset(sample_program: Program) -> Asset:
    return Asset(
        id=uuid.uuid4(),
        program_id=sample_program.id,
        canonical_key="api.target-corp.com",
        asset_type=AssetType.DOMAIN.value,
        scope_state=ScopeState.IN_SCOPE_EXPLICIT.value,
    )


@pytest.fixture(autouse=True)
def _scope_allows_by_default():
    """Session mocks here cannot feed a real ScopeEngine; scope gating has its own tests."""
    allowed = MagicMock(allowed=True)
    with patch("pentefino_cli.commands.scan._current_scope_decision", AsyncMock(return_value=allowed)):
        yield


def test_scan_help(runner: CliRunner) -> None:
    """Verify scan and scan run help outputs contain expected options."""
    res = runner.invoke(app, ["scan", "--help"])
    assert res.exit_code == 0
    assert "run" in res.output

    run_res = runner.invoke(app, ["scan", "run", "--help"])
    assert run_res.exit_code == 0
    assert "--program" in run_res.output
    assert "--asset" in run_res.output
    assert "--tags" in run_res.output
    assert "--severity" in run_res.output
    assert "--async" in run_res.output
    assert "--json" in run_res.output


def test_scan_missing_required_arguments(runner: CliRunner) -> None:
    """Verify missing required --program or --asset flags produce error."""
    res_no_args = runner.invoke(app, ["scan", "run"])
    assert res_no_args.exit_code != 0

    res_missing_asset = runner.invoke(app, ["scan", "run", "--program", "test-slug"])
    assert res_missing_asset.exit_code != 0

    res_missing_program = runner.invoke(app, ["scan", "run", "--asset", "target.com"])
    assert res_missing_program.exit_code != 0


def test_scan_program_not_found(runner: CliRunner) -> None:
    """Verify error output when specified program does not exist."""
    mock_session = AsyncMock()

    @asynccontextmanager
    async def mock_get_async_session():
        yield mock_session

    with patch("pentefino_cli.commands.scan.get_async_session", mock_get_async_session), \
         patch("pentefino_cli.commands.scan.get_program_by_slug", AsyncMock(return_value=None)):

        # Rich text output
        res_text = runner.invoke(app, ["scan", "run", "-p", "missing-corp", "-a", "target.com"])
        assert res_text.exit_code == 1
        assert "Program 'missing-corp' not found" in res_text.output

        # JSON output
        res_json = runner.invoke(app, ["scan", "run", "-p", "missing-corp", "-a", "target.com", "--json"])
        assert res_json.exit_code == 1
        parsed = json.loads(res_json.output)
        assert parsed["status"] == "error"
        assert "not found" in parsed["error"]


def test_scan_asset_not_found(runner: CliRunner, sample_program: Program) -> None:
    """Verify error output when target asset does not exist in program scope."""
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_session.execute.return_value = mock_result

    @asynccontextmanager
    async def mock_get_async_session():
        yield mock_session

    with patch("pentefino_cli.commands.scan.get_async_session", mock_get_async_session), \
         patch("pentefino_cli.commands.scan.get_program_by_slug", AsyncMock(return_value=sample_program)):

        res = runner.invoke(app, ["scan", "run", "-p", sample_program.slug, "-a", "unknown.target-corp.com"])
        assert res.exit_code == 1
        assert "Asset 'unknown.target-corp.com' not found" in res.output

        # JSON output
        res_json = runner.invoke(
            app, ["scan", "run", "-p", sample_program.slug, "-a", "unknown.target-corp.com", "--json"]
        )
        assert res_json.exit_code == 1
        parsed = json.loads(res_json.output)
        assert parsed["status"] == "error"


def test_scan_async_dispatch(runner: CliRunner, sample_program: Program, sample_asset: Asset) -> None:
    """Verify asynchronous scan dispatch creates audit event and outputs queued state."""
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = sample_asset
    mock_session.execute.return_value = mock_result

    @asynccontextmanager
    async def mock_get_async_session():
        yield mock_session

    with patch("pentefino_cli.commands.scan.get_async_session", mock_get_async_session), \
         patch("pentefino_cli.commands.scan.get_program_by_slug", AsyncMock(return_value=sample_program)), \
         patch("pentefino_cli.commands.scan.record_audit_event", AsyncMock()) as mock_audit:

        # Rich text output
        res_text = runner.invoke(
            app,
            ["scan", "run", "-p", sample_program.slug, "-a", sample_asset.canonical_key, "--async"],
        )
        assert res_text.exit_code == 0
        assert "QUEUED" in res_text.output or "Run ID" in res_text.output
        assert mock_audit.called

        # JSON output
        res_json = runner.invoke(
            app,
            ["scan", "run", "-p", sample_program.slug, "-a", sample_asset.canonical_key, "--async", "--json"],
        )
        assert res_json.exit_code == 0
        parsed = json.loads(res_json.output)
        assert parsed["status"] == "queued"
        assert parsed["program"] == sample_program.slug
        assert parsed["asset"] == sample_asset.canonical_key
        assert "run_id" in parsed


def test_scan_sync_execution_and_rich_table(
    runner: CliRunner, sample_program: Program, sample_asset: Asset
) -> None:
    """Verify synchronous targeted scan execution, findings persistence, and Rich table rendering."""
    mock_session = AsyncMock()

    # Setup session.execute return values:
    # 1. select(Asset) -> sample_asset
    # 2. select(Observation) -> observation with technologies
    mock_asset_result = MagicMock()
    mock_asset_result.scalar_one_or_none.return_value = sample_asset

    mock_obs = Observation(
        asset_id=sample_asset.id,
        observation_type="http_probe",
        metadata_json={"technologies": ["nginx", "fastapi"]},
    )
    mock_obs_result = MagicMock()
    mock_obs_result.scalars.return_value.all.return_value = [mock_obs]

    mock_session.execute.side_effect = [mock_asset_result, mock_obs_result]

    @asynccontextmanager
    async def mock_get_async_session():
        yield mock_session

    plan = DetectionPlan(
        program_id=sample_program.id,
        asset_id=sample_asset.id,
        asset_canonical_key=sample_asset.canonical_key,
        target_url=f"https://{sample_asset.canonical_key}",
        selected_template_ids=["nginx-version-detect"],
        selected_template_paths=["/templates/nginx-version-detect.yaml"],
        matched_technologies=["nginx"],
        total_templates=1,
    )

    finding = Finding(
        id=uuid.uuid4(),
        program_id=sample_program.id,
        asset_id=sample_asset.id,
        dedup_key="abc123def4567890" * 4,
        detector_id="nginx-version-detect",
        advisory_id=None,
        status="validated",
        evidence_level="E2",
        confidence="high",
    )

    with patch("pentefino_cli.commands.scan.get_async_session", mock_get_async_session), \
         patch("pentefino_cli.commands.scan.get_program_by_slug", AsyncMock(return_value=sample_program)), \
         patch("pentefino_cli.commands.scan.DetectionPlanner.create_plan", AsyncMock(return_value=plan)), \
         patch("pentefino_cli.commands.scan.HardenedNucleiRunner.execute_scan", AsyncMock(return_value=[{"template-id": "nginx-version-detect"}])), \
         patch("pentefino_cli.commands.scan.FindingNormalizer.normalize_and_persist", AsyncMock(return_value=[finding])), \
         patch("pentefino_cli.commands.scan.record_audit_event", AsyncMock()):

        res = runner.invoke(
            app,
            [
                "scan",
                "run",
                "-p",
                sample_program.slug,
                "-a",
                sample_asset.canonical_key,
                "--tags",
                "version",
                "--severity",
                "info",
            ],
        )
        assert res.exit_code == 0
        assert "Targeted Scan Completed" in res.output
        assert "nginx-version-detect" in res.output
        assert sample_asset.canonical_key in res.output


def test_scan_sync_execution_json_output(
    runner: CliRunner, sample_program: Program, sample_asset: Asset
) -> None:
    """Verify synchronous scan execution produces clean structured JSON output."""
    mock_session = AsyncMock()

    mock_asset_result = MagicMock()
    mock_asset_result.scalar_one_or_none.return_value = sample_asset

    mock_obs = Observation(
        asset_id=sample_asset.id,
        observation_type="http_probe",
        metadata_json={"technologies": ["apache"]},
    )
    mock_obs_result = MagicMock()
    mock_obs_result.scalars.return_value.all.return_value = [mock_obs]

    mock_session.execute.side_effect = [mock_asset_result, mock_obs_result]

    @asynccontextmanager
    async def mock_get_async_session():
        yield mock_session

    plan = DetectionPlan(
        program_id=sample_program.id,
        asset_id=sample_asset.id,
        asset_canonical_key=sample_asset.canonical_key,
        target_url=f"https://{sample_asset.canonical_key}",
        selected_template_ids=["apache-cve-2021-41773"],
        selected_template_paths=["/templates/apache-cve-2021-41773.yaml"],
        matched_technologies=["apache"],
        total_templates=1,
    )

    finding = Finding(
        id=uuid.uuid4(),
        program_id=sample_program.id,
        asset_id=sample_asset.id,
        dedup_key="fedcba9876543210" * 4,
        detector_id="apache-cve-2021-41773",
        advisory_id="CVE-2021-41773",
        status="validated",
        evidence_level="E2",
        confidence="high",
    )

    with patch("pentefino_cli.commands.scan.get_async_session", mock_get_async_session), \
         patch("pentefino_cli.commands.scan.get_program_by_slug", AsyncMock(return_value=sample_program)), \
         patch("pentefino_cli.commands.scan.DetectionPlanner.create_plan", AsyncMock(return_value=plan)), \
         patch("pentefino_cli.commands.scan.HardenedNucleiRunner.execute_scan", AsyncMock(return_value=[{"template-id": "apache-cve-2021-41773"}])), \
         patch("pentefino_cli.commands.scan.FindingNormalizer.normalize_and_persist", AsyncMock(return_value=[finding])), \
         patch("pentefino_cli.commands.scan.record_audit_event", AsyncMock()):

        res = runner.invoke(
            app,
            ["scan", "run", "-p", sample_program.slug, "-a", sample_asset.canonical_key, "--json"],
        )
        assert res.exit_code == 0
        parsed = json.loads(res.output)
        assert parsed["status"] == "completed"
        assert parsed["program"] == sample_program.slug
        assert parsed["asset"] == sample_asset.canonical_key
        assert parsed["findings_count"] == 1
        assert parsed["findings"][0]["detector_id"] == "apache-cve-2021-41773"
        assert parsed["findings"][0]["status"] == "validated"
        assert parsed["findings"][0]["evidence_level"] == "E2"


def test_scan_no_findings_detected(
    runner: CliRunner, sample_program: Program, sample_asset: Asset
) -> None:
    """Verify scan output when no vulnerabilities are found."""
    mock_session = AsyncMock()

    mock_asset_result = MagicMock()
    mock_asset_result.scalar_one_or_none.return_value = sample_asset
    mock_obs_result = MagicMock()
    mock_obs_result.scalars.return_value.all.return_value = []

    mock_session.execute.side_effect = [mock_asset_result, mock_obs_result]

    @asynccontextmanager
    async def mock_get_async_session():
        yield mock_session

    plan = DetectionPlan(
        program_id=sample_program.id,
        asset_id=sample_asset.id,
        asset_canonical_key=sample_asset.canonical_key,
        target_url=f"https://{sample_asset.canonical_key}",
        selected_template_ids=[],
        selected_template_paths=[],
        matched_technologies=[],
        total_templates=0,
    )

    with patch("pentefino_cli.commands.scan.get_async_session", mock_get_async_session), \
         patch("pentefino_cli.commands.scan.get_program_by_slug", AsyncMock(return_value=sample_program)), \
         patch("pentefino_cli.commands.scan.DetectionPlanner.create_plan", AsyncMock(return_value=plan)), \
         patch("pentefino_cli.commands.scan.HardenedNucleiRunner.execute_scan", AsyncMock(return_value=[])), \
         patch("pentefino_cli.commands.scan.FindingNormalizer.normalize_and_persist", AsyncMock(return_value=[])), \
         patch("pentefino_cli.commands.scan.record_audit_event", AsyncMock()):

        res = runner.invoke(app, ["scan", "run", "-p", sample_program.slug, "-a", sample_asset.canonical_key])
        assert res.exit_code == 0
        assert "No vulnerabilities detected" in res.output


def test_scan_refuses_asset_denied_by_current_scope(
    runner: CliRunner, sample_program: Program, sample_asset: Asset
) -> None:
    """A stored in_scope state is not enough: the engine is consulted on every run."""
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = sample_asset
    mock_session.execute.return_value = mock_result
    mock_get_async_session = MagicMock()
    mock_get_async_session.return_value.__aenter__.return_value = mock_session
    denied = MagicMock(allowed=False, reason="EXPLICIT_DENY_RULE_MATCHED")
    denied.matched_tier.value = "explicit_deny"
    with patch("pentefino_cli.commands.scan.get_async_session", mock_get_async_session),          patch("pentefino_cli.commands.scan.get_program_by_slug", AsyncMock(return_value=sample_program)),          patch("pentefino_cli.commands.scan._current_scope_decision", AsyncMock(return_value=denied)):
        result = runner.invoke(app, ["scan", "run", "--program", sample_program.slug, "--asset", sample_asset.canonical_key])
    assert "denied by scope engine" in result.stdout
