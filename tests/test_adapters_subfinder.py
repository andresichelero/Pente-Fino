from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from pentefino_adapters.models import DiscoveredCandidate
from pentefino_adapters.subfinder import SubfinderAdapter
from pentefino_domain.enums import AssetType, ScopeState
from pentefino_domain.models import Asset, Observation
from pentefino_runner import EphemeralRunner, RunConfig, RunResult
from pentefino_scope import (
    AssetType as ScopeAssetType,
    AuthorizationSnapshot,
    PrecedenceTier,
    ScopeAction,
    ScopeEngine,
    ScopeRule,
)


@pytest.fixture
def program_id():
    return uuid4()


@pytest.fixture
def active_snapshot(program_id):
    now = datetime.now(timezone.utc)
    return AuthorizationSnapshot(
        program_id=program_id,
        policy_hash="a" * 64,
        rules_json={},
        valid_from=now - timedelta(days=1),
        valid_until=now + timedelta(days=30),
    )


@pytest.fixture
def sample_scope_engine(program_id, active_snapshot):
    rules = [
        ScopeRule(
            program_id=program_id,
            pattern="*.example.com",
            action=ScopeAction.ALLOW,
            asset_type=ScopeAssetType.WILDCARD_DOMAIN,
        ),
        ScopeRule(
            program_id=program_id,
            pattern="admin.example.com",
            action=ScopeAction.DENY,
            asset_type=ScopeAssetType.HOSTNAME,
        ),
    ]
    return ScopeEngine(snapshot=active_snapshot, rules=rules)


@pytest.fixture
def mock_runner():
    runner = MagicMock(spec=EphemeralRunner)
    runner.run = AsyncMock()
    return runner


def test_subfinder_ndjson_parser_success(mock_runner, sample_scope_engine):
    adapter = SubfinderAdapter(runner=mock_runner, scope_engine=sample_scope_engine)

    raw_output = "\n".join(
        [
            json.dumps(
                {
                    "host": "api.example.com",
                    "input": "example.com",
                    "sources": ["crtsh", "virustotal"],
                }
            ),
            json.dumps(
                {
                    "host": "app.example.com",
                    "input": "example.com",
                    "sources": ["alienvault"],
                }
            ),
        ]
    )

    candidates = adapter.parse_ndjson(raw_output)

    assert len(candidates) == 2
    c1, c2 = candidates[0], candidates[1]

    assert c1.host == "api.example.com"
    assert c1.input == "example.com"
    assert "crtsh" in c1.sources
    assert "virustotal" in c1.sources
    assert c1.scope_state == ScopeState.IN_SCOPE_DERIVED
    assert c1.matched_tier == PrecedenceTier.WILDCARD_ALLOW

    assert c2.host == "app.example.com"
    assert c2.scope_state == ScopeState.IN_SCOPE_DERIVED


def test_subfinder_ndjson_parser_handles_malformed_and_empty_lines(
    mock_runner, sample_scope_engine
):
    adapter = SubfinderAdapter(runner=mock_runner, scope_engine=sample_scope_engine)

    raw_output = """
    {"host": "valid.example.com", "input": "example.com", "sources": ["hackertarget"]}
    
    NOT A JSON LINE {{{
    {"incomplete": 123}
    ["array", "not", "object"]
    {"host": "valid2.example.com", "sources": "single_string_source"}
    """

    candidates = adapter.parse_ndjson(raw_output)

    assert len(candidates) == 2
    assert candidates[0].host == "valid.example.com"
    assert candidates[0].sources == ["hackertarget"]
    assert candidates[1].host == "valid2.example.com"
    assert candidates[1].sources == ["single_string_source"]


def test_subfinder_scope_evaluation_wildcard_allow_promotes_to_in_scope_derived(
    mock_runner, sample_scope_engine
):
    adapter = SubfinderAdapter(runner=mock_runner, scope_engine=sample_scope_engine)

    raw_output = "\n".join(
        [
            json.dumps({"host": "api.example.com"}),
            json.dumps({"host": "auth.example.com"}),
            json.dumps({"host": "stage.internal.example.com"}),
        ]
    )

    candidates = adapter.parse_ndjson(raw_output)

    assert len(candidates) == 3
    for cand in candidates:
        assert cand.scope_state == ScopeState.IN_SCOPE_DERIVED
        assert cand.matched_tier == PrecedenceTier.WILDCARD_ALLOW


def test_subfinder_scope_evaluation_explicit_deny_marks_out_of_scope(
    mock_runner, sample_scope_engine
):
    adapter = SubfinderAdapter(runner=mock_runner, scope_engine=sample_scope_engine)

    raw_output = json.dumps({"host": "admin.example.com"})

    candidates = adapter.parse_ndjson(raw_output)

    assert len(candidates) == 1
    assert candidates[0].host == "admin.example.com"
    assert candidates[0].scope_state == ScopeState.OUT_OF_SCOPE
    assert candidates[0].matched_tier == PrecedenceTier.EXPLICIT_DENY


def test_subfinder_scope_evaluation_unmatched_derived_marks_candidate(
    mock_runner, sample_scope_engine
):
    adapter = SubfinderAdapter(runner=mock_runner, scope_engine=sample_scope_engine)

    # Discovered domain outside of *.example.com (e.g. from cert SAN)
    raw_output = json.dumps({"host": "external-partner.com", "sources": ["crtsh"]})

    candidates = adapter.parse_ndjson(raw_output)

    assert len(candidates) == 1
    assert candidates[0].host == "external-partner.com"
    assert candidates[0].scope_state == ScopeState.CANDIDATE
    assert candidates[0].matched_tier == PrecedenceTier.DERIVED_CANDIDATE


@pytest.mark.asyncio
async def test_subfinder_asset_upsert_deduplication(
    mock_runner, sample_scope_engine, program_id
):
    adapter = SubfinderAdapter(runner=mock_runner, scope_engine=sample_scope_engine)

    existing_asset = Asset(
        program_id=program_id,
        canonical_key="api.example.com",
        asset_type=AssetType.HOSTNAME.value,
        scope_state=ScopeState.CANDIDATE.value,
    )

    # Mock AsyncSession
    mock_session = AsyncMock()
    mock_session.add = MagicMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = existing_asset
    mock_session.execute.return_value = mock_result

    candidates = [
        DiscoveredCandidate(
            host="api.example.com",
            sources=["crtsh"],
            input="example.com",
            scope_state=ScopeState.IN_SCOPE_DERIVED,
        )
    ]

    saved = await adapter.persist(mock_session, program_id, candidates)

    assert len(saved) == 1
    # Candidate should be promoted to in_scope_derived
    assert existing_asset.scope_state == ScopeState.IN_SCOPE_DERIVED.value
    # No new asset added, but observation is added
    mock_session.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_subfinder_records_discovery_observation(
    mock_runner, sample_scope_engine, program_id
):
    adapter = SubfinderAdapter(runner=mock_runner, scope_engine=sample_scope_engine)

    mock_session = AsyncMock()
    mock_session.add = MagicMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_session.execute.return_value = mock_result

    candidates = [
        DiscoveredCandidate(
            host="portal.example.com",
            sources=["virustotal", "alienvault"],
            input="example.com",
            scope_state=ScopeState.IN_SCOPE_DERIVED,
            raw_json={"host": "portal.example.com", "sources": ["virustotal"]},
        )
    ]

    saved_assets = await adapter.persist(mock_session, program_id, candidates)

    assert len(saved_assets) == 1
    # Check that session.add was called for both Asset and Observation
    assert mock_session.add.call_count == 2
    added_objects = [call.args[0] for call in mock_session.add.call_args_list]

    asset_obj = next(o for o in added_objects if isinstance(o, Asset))
    obs_obj = next(o for o in added_objects if isinstance(o, Observation))

    assert asset_obj.canonical_key == "portal.example.com"
    assert obs_obj.observation_type == "subdomain_discovery"
    assert obs_obj.metadata_json["sources"] == ["virustotal", "alienvault"]


@pytest.mark.asyncio
async def test_subfinder_discover_calls_runner_with_expected_config(
    mock_runner, sample_scope_engine
):
    adapter = SubfinderAdapter(runner=mock_runner, scope_engine=sample_scope_engine)

    mock_runner.run.return_value = RunResult(
        exit_code=0,
        stdout=json.dumps({"host": "api.example.com", "input": "example.com"}),
        stderr="",
    )

    candidates = await adapter.discover("example.com")

    assert len(candidates) == 1
    mock_runner.run.assert_awaited_once()
    run_config: RunConfig = mock_runner.run.call_args.args[0]
    assert run_config.image == "projectdiscovery/subfinder:v2.6.6"
    assert run_config.command == ["-d", "example.com", "-silent", "-json", "-all"]
