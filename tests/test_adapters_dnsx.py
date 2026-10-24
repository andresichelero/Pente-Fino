from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from pentefino_adapters.dnsx import DnsxAdapter
from pentefino_adapters.models import DnsRecord
from pentefino_domain.enums import AssetType, ScopeState
from pentefino_domain.models import Asset, Observation
from pentefino_runner import EphemeralRunner
from pentefino_scope import (
    AssetType as ScopeAssetType,
    AuthorizationSnapshot,
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
        )
    ]
    return ScopeEngine(snapshot=active_snapshot, rules=rules)


@pytest.fixture
def mock_runner():
    runner = MagicMock(spec=EphemeralRunner)
    runner.run = AsyncMock()
    return runner


def test_dnsx_ndjson_parser_extracts_a_aaaa_cname(mock_runner, sample_scope_engine):
    adapter = DnsxAdapter(runner=mock_runner, scope_engine=sample_scope_engine)

    raw_output = "\n".join(
        [
            json.dumps(
                {
                    "host": "api.example.com",
                    "resolver": ["1.1.1.1:53"],
                    "a": ["93.184.216.34"],
                    "timestamp": "2026-10-24T06:00:00Z",
                }
            ),
            json.dumps(
                {
                    "host": "mail.example.com",
                    "resolver": ["8.8.8.8:53"],
                    "cname": ["ghs.googlehosted.com"],
                    "a": ["142.250.190.19"],
                }
            ),
            json.dumps(
                {
                    "host": "ipv6.example.com",
                    "resolver": ["9.9.9.9:53"],
                    "aaaa": ["2606:2800:220:1:248:1893:25c8:1946"],
                }
            ),
        ]
    )

    records = adapter.parse_ndjson(raw_output)

    assert len(records) == 3
    r1, r2, r3 = records[0], records[1], records[2]

    assert r1.host == "api.example.com"
    assert r1.a == ["93.184.216.34"]
    assert r1.resolver == ["1.1.1.1:53"]
    assert not r1.is_prohibited_ip

    assert r2.host == "mail.example.com"
    assert r2.cname == ["ghs.googlehosted.com"]
    assert r2.a == ["142.250.190.19"]

    assert r3.host == "ipv6.example.com"
    assert r3.aaaa == ["2606:2800:220:1:248:1893:25c8:1946"]


@pytest.mark.asyncio
async def test_dnsx_dns_answers_recorded_as_observations(
    mock_runner, sample_scope_engine, program_id
):
    adapter = DnsxAdapter(runner=mock_runner, scope_engine=sample_scope_engine)

    existing_asset = Asset(
        program_id=program_id,
        canonical_key="api.example.com",
        asset_type=AssetType.HOSTNAME.value,
        scope_state=ScopeState.IN_SCOPE_DERIVED.value,
    )

    mock_session = AsyncMock()
    mock_session.add = MagicMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = existing_asset
    mock_session.execute.return_value = mock_result

    records = [
        DnsRecord(
            host="api.example.com",
            a=["93.184.216.34"],
            resolver=["1.1.1.1:53"],
        )
    ]

    saved_obs = await adapter.persist(mock_session, program_id, records)

    assert len(saved_obs) == 1
    mock_session.add.assert_called_once()
    added_obj = mock_session.add.call_args[0][0]
    assert isinstance(added_obj, Observation)
    assert added_obj.observation_type == "dns"
    assert added_obj.metadata_json["a"] == ["93.184.216.34"]
    mock_session.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_dnsx_ip_invariant_resolved_ips_never_promoted_to_in_scope_assets(
    mock_runner, sample_scope_engine, program_id
):
    """
    CRITICAL INVARIANT TEST:
    Verifies that resolved A/AAAA IP addresses are recorded strictly as observations
    attached to the hostname Asset, and that resolved IPs are NEVER inserted or
    promoted as in-scope Asset records.
    """
    adapter = DnsxAdapter(runner=mock_runner, scope_engine=sample_scope_engine)

    mock_session = AsyncMock()
    mock_session.add = MagicMock()
    # Simulates hostname asset not existing yet
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_session.execute.return_value = mock_result

    records = [
        DnsRecord(
            host="api.example.com",
            a=["93.184.216.34", "104.18.24.1"],
            aaaa=["2606:2800:220:1:248:1893:25c8:1946"],
            resolver=["1.1.1.1"],
        )
    ]

    await adapter.persist(mock_session, program_id, records)

    # Inspect all objects passed to session.add()
    added_objects = [call.args[0] for call in mock_session.add.call_args_list]

    for obj in added_objects:
        if isinstance(obj, Asset):
            # Assert that the only asset added is the hostname, NEVER an IP address!
            assert obj.asset_type == AssetType.HOSTNAME.value
            assert obj.canonical_key == "api.example.com"
            assert obj.canonical_key not in (
                "93.184.216.34",
                "104.18.24.1",
                "2606:2800:220:1:248:1893:25c8:1946",
            )
            assert obj.asset_type != AssetType.IP.value
        elif isinstance(obj, Observation):
            # Verify IP answers are stored strictly inside observation metadata
            assert obj.observation_type == "dns"
            assert "93.184.216.34" in obj.metadata_json["a"]


def test_dnsx_cname_chain_evaluation(mock_runner, sample_scope_engine):
    adapter = DnsxAdapter(runner=mock_runner, scope_engine=sample_scope_engine)

    # Subdomain points to external CNAME outside *.example.com
    raw_output = json.dumps(
        {
            "host": "blog.example.com",
            "cname": ["cname.external-cdn.com"],
            "a": ["198.51.100.1"],
        }
    )

    records = adapter.parse_ndjson(raw_output)

    assert len(records) == 1
    record = records[0]
    assert record.host == "blog.example.com"
    assert "cname.external-cdn.com" in record.cname
    # CNAME target must be evaluated as candidate, not in-scope
    assert record.cname_evaluations["cname.external-cdn.com"] == ScopeState.CANDIDATE


def test_dnsx_anti_ssrf_prohibited_ip_detection(mock_runner, sample_scope_engine):
    adapter = DnsxAdapter(runner=mock_runner, scope_engine=sample_scope_engine)

    # Internal RFC1918 and loopback IPs
    raw_output = "\n".join(
        [
            json.dumps({"host": "dev-internal.example.com", "a": ["10.0.0.1"]}),
            json.dumps({"host": "localhost-test.example.com", "a": ["127.0.0.1"]}),
            json.dumps({"host": "metadata.example.com", "a": ["169.254.169.254"]}),
            json.dumps({"host": "public.example.com", "a": ["93.184.216.34"]}),
        ]
    )

    records = adapter.parse_ndjson(raw_output)

    assert len(records) == 4
    assert records[0].is_prohibited_ip
    assert "PROHIBITED_IP_SPACE" in records[0].prohibited_reason

    assert records[1].is_prohibited_ip
    assert "PROHIBITED_IP_SPACE" in records[1].prohibited_reason

    assert records[2].is_prohibited_ip
    assert "PROHIBITED_IP_SPACE" in records[2].prohibited_reason

    assert not records[3].is_prohibited_ip
    assert records[3].prohibited_reason is None


def test_dnsx_trusted_public_resolvers_enforcement(mock_runner, sample_scope_engine):
    adapter = DnsxAdapter(runner=mock_runner, scope_engine=sample_scope_engine)

    config = adapter.build_run_config(hosts=["api.example.com"])

    assert config.image == "projectdiscovery/dnsx:v1.2.1"
    # Assert public resolvers flag is strictly enforced
    assert "-r" in config.command
    r_index = config.command.index("-r")
    assert config.command[r_index + 1] == "1.1.1.1,8.8.8.8,9.9.9.9"


def test_dnsx_bruteforce_wordlist_argument_construction(mock_runner, sample_scope_engine):
    adapter = DnsxAdapter(runner=mock_runner, scope_engine=sample_scope_engine)

    config = adapter.build_run_config(
        domain="example.com",
        bruteforce=True,
        wordlist_path="/data/wordlists/subdomains-top5k.txt",
    )

    assert "-d" in config.command
    d_index = config.command.index("-d")
    assert config.command[d_index + 1] == "example.com"

    assert "-w" in config.command
    w_index = config.command.index("-w")
    assert config.command[w_index + 1] == "/data/wordlists/subdomains-top5k.txt"
    assert len(config.volumes) == 1
    assert config.volumes[0].mode == "ro"
    assert config.volumes[0].container_path == "/data/wordlists/subdomains-top5k.txt"
    assert Path(config.volumes[0].host_path).is_file()


def test_dnsx_bruteforce_default_wordlist_mounting(mock_runner, sample_scope_engine):
    """Verify build_run_config(bruteforce=True) populates volumes with read-only default wordlist mount."""
    adapter = DnsxAdapter(runner=mock_runner, scope_engine=sample_scope_engine)

    config = adapter.build_run_config(domain="example.com", bruteforce=True)

    assert "-d" in config.command
    d_index = config.command.index("-d")
    assert config.command[d_index + 1] == "example.com"

    assert "-w" in config.command
    w_index = config.command.index("-w")
    assert config.command[w_index + 1] == "/data/wordlists/subdomains-top5k.txt"

    assert len(config.volumes) == 1
    mount = config.volumes[0]
    assert mount.container_path == "/data/wordlists/subdomains-top5k.txt"
    assert mount.mode == "ro"
    assert Path(mount.host_path).is_file()


@pytest.mark.asyncio
async def test_dnsx_persist_evaluates_scope_engine_denied_host_as_out_of_scope(
    mock_runner, active_snapshot, program_id
):
    """Verify that an explicitly denied resolved host is marked OUT_OF_SCOPE upon persistence."""
    rules = [
        ScopeRule(
            program_id=program_id,
            pattern="deny.example.com",
            action=ScopeAction.DENY,
            asset_type=ScopeAssetType.DOMAIN,
        ),
        ScopeRule(
            program_id=program_id,
            pattern="*.example.com",
            action=ScopeAction.ALLOW,
            asset_type=ScopeAssetType.WILDCARD_DOMAIN,
        ),
    ]
    engine = ScopeEngine(snapshot=active_snapshot, rules=rules)
    adapter = DnsxAdapter(runner=mock_runner, scope_engine=engine)

    mock_session = AsyncMock()
    mock_session.add = MagicMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_session.execute.return_value = mock_result

    # deny.example.com is explicitly denied by ScopeRule
    records = [
        DnsRecord(
            host="deny.example.com",
            a=["93.184.216.34"],
            resolver=["1.1.1.1"],
        )
    ]

    await adapter.persist(mock_session, program_id, records)

    # Verify that the added Asset has scope_state == out_of_scope
    added_assets = [
        call.args[0]
        for call in mock_session.add.call_args_list
        if isinstance(call.args[0], Asset)
    ]
    assert len(added_assets) == 1
    assert added_assets[0].canonical_key == "deny.example.com"
    assert added_assets[0].scope_state == ScopeState.OUT_OF_SCOPE.value


@pytest.mark.asyncio
async def test_dnsx_persist_evaluates_wildcard_allow_as_in_scope_derived(
    mock_runner, active_snapshot, program_id
):
    """Verify that a host matching a wildcard allow rule is persisted with IN_SCOPE_DERIVED."""
    rules = [
        ScopeRule(
            program_id=program_id,
            pattern="*.example.com",
            action=ScopeAction.ALLOW,
            asset_type=ScopeAssetType.WILDCARD_DOMAIN,
        )
    ]
    engine = ScopeEngine(snapshot=active_snapshot, rules=rules)
    adapter = DnsxAdapter(runner=mock_runner, scope_engine=engine)

    mock_session = AsyncMock()
    mock_session.add = MagicMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_session.execute.return_value = mock_result

    records = [
        DnsRecord(
            host="app.example.com",
            a=["93.184.216.34"],
            resolver=["1.1.1.1"],
        )
    ]

    await adapter.persist(mock_session, program_id, records)

    added_assets = [
        call.args[0]
        for call in mock_session.add.call_args_list
        if isinstance(call.args[0], Asset)
    ]
    assert len(added_assets) == 1
    assert added_assets[0].canonical_key == "app.example.com"
    assert added_assets[0].scope_state == ScopeState.IN_SCOPE_DERIVED.value


@pytest.mark.asyncio
async def test_dnsx_persist_evaluates_explicit_allow_as_in_scope_explicit(
    mock_runner, active_snapshot, program_id
):
    """Verify that a host matching an explicit domain allow rule is persisted with IN_SCOPE_EXPLICIT."""
    rules = [
        ScopeRule(
            program_id=program_id,
            pattern="target.example.com",
            action=ScopeAction.ALLOW,
            asset_type=ScopeAssetType.DOMAIN,
        )
    ]
    engine = ScopeEngine(snapshot=active_snapshot, rules=rules)
    adapter = DnsxAdapter(runner=mock_runner, scope_engine=engine)

    mock_session = AsyncMock()
    mock_session.add = MagicMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_session.execute.return_value = mock_result

    records = [
        DnsRecord(
            host="target.example.com",
            a=["93.184.216.34"],
            resolver=["1.1.1.1"],
        )
    ]

    await adapter.persist(mock_session, program_id, records)

    added_assets = [
        call.args[0]
        for call in mock_session.add.call_args_list
        if isinstance(call.args[0], Asset)
    ]
    assert len(added_assets) == 1
    assert added_assets[0].canonical_key == "target.example.com"
    assert added_assets[0].scope_state == ScopeState.IN_SCOPE_EXPLICIT.value


@pytest.mark.asyncio
async def test_dnsx_persist_evaluates_discover_only_as_candidate(
    mock_runner, active_snapshot, program_id
):
    """Verify that a host matching discover_only is persisted as CANDIDATE."""
    rules = [
        ScopeRule(
            program_id=program_id,
            pattern="candidate.example.com",
            action=ScopeAction.DISCOVER_ONLY,
            asset_type=ScopeAssetType.DOMAIN,
        )
    ]
    engine = ScopeEngine(snapshot=active_snapshot, rules=rules)
    adapter = DnsxAdapter(runner=mock_runner, scope_engine=engine)

    mock_session = AsyncMock()
    mock_session.add = MagicMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_session.execute.return_value = mock_result

    records = [
        DnsRecord(
            host="candidate.example.com",
            a=["93.184.216.34"],
            resolver=["1.1.1.1"],
        )
    ]

    await adapter.persist(mock_session, program_id, records)

    added_assets = [
        call.args[0]
        for call in mock_session.add.call_args_list
        if isinstance(call.args[0], Asset)
    ]
    assert len(added_assets) == 1
    assert added_assets[0].canonical_key == "candidate.example.com"
    assert added_assets[0].scope_state == ScopeState.CANDIDATE.value


@pytest.mark.asyncio
async def test_dnsx_persist_evaluates_prohibited_ip_as_out_of_scope(
    mock_runner, active_snapshot, program_id
):
    """Verify that a host resolving to a prohibited IP is marked OUT_OF_SCOPE even if domain matches wildcard allow."""
    rules = [
        ScopeRule(
            program_id=program_id,
            pattern="*.example.com",
            action=ScopeAction.ALLOW,
            asset_type=ScopeAssetType.WILDCARD_DOMAIN,
        )
    ]
    engine = ScopeEngine(snapshot=active_snapshot, rules=rules)
    adapter = DnsxAdapter(runner=mock_runner, scope_engine=engine)

    mock_session = AsyncMock()
    mock_session.add = MagicMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_session.execute.return_value = mock_result

    records = [
        DnsRecord(
            host="internal.example.com",
            a=["10.0.0.1"],
            resolver=["1.1.1.1"],
            is_prohibited_ip=True,
            prohibited_reason="PROHIBITED_IP_SPACE: RFC1918 Private (10.0.0.1)",
        )
    ]

    await adapter.persist(mock_session, program_id, records)

    added_assets = [
        call.args[0]
        for call in mock_session.add.call_args_list
        if isinstance(call.args[0], Asset)
    ]
    assert len(added_assets) == 1
    assert added_assets[0].canonical_key == "internal.example.com"
    assert added_assets[0].scope_state == ScopeState.OUT_OF_SCOPE.value


@pytest.mark.asyncio
async def test_dnsx_persist_without_scope_engine_defaults_to_in_scope_derived(
    mock_runner, program_id
):
    """Verify that when scope_engine is None, newly created assets default to IN_SCOPE_DERIVED if not prohibited."""
    adapter = DnsxAdapter(runner=mock_runner, scope_engine=None)

    mock_session = AsyncMock()
    mock_session.add = MagicMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_session.execute.return_value = mock_result

    records = [
        DnsRecord(
            host="app.example.com",
            a=["93.184.216.34"],
            resolver=["1.1.1.1"],
            is_prohibited_ip=False,
        )
    ]

    await adapter.persist(mock_session, program_id, records)

    added_assets = [
        call.args[0]
        for call in mock_session.add.call_args_list
        if isinstance(call.args[0], Asset)
    ]
    assert len(added_assets) == 1
    assert added_assets[0].canonical_key == "app.example.com"
    assert added_assets[0].scope_state == ScopeState.IN_SCOPE_DERIVED.value
