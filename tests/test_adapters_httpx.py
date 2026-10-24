from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from pentefino_adapters.dnsx import DnsxAdapter
from pentefino_adapters.httpx import HttpxAdapter
from pentefino_adapters.models import HttpProbeRecord, TechnologyComponent
from pentefino_adapters.pipeline import ReconPipeline
from pentefino_adapters.subfinder import SubfinderAdapter
from pentefino_domain.enums import AssetType, ScopeState
from pentefino_domain.models import Asset, Observation
from pentefino_runner import EphemeralRunner, RunResult
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
        ),
        ScopeRule(
            program_id=program_id,
            pattern="deny.example.com",
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


def test_httpx_ndjson_parser_extracts_metadata(mock_runner):
    adapter = HttpxAdapter(runner=mock_runner)

    raw_output = json.dumps(
        {
            "timestamp": "2026-10-24T06:15:00Z",
            "url": "https://api.example.com",
            "input": "api.example.com",
            "status_code": 200,
            "title": "API Gateway Console",
            "webserver": "nginx/1.24.0",
            "content_length": 4210,
            "tech": ["Nginx:1.24.0", "FastAPI", "React:18.2.0"],
            "tls": {
                "version": "TLSv1.3",
                "cipher": "TLS_AES_256_GCM_SHA384",
            },
            "chain": [
                {"status_code": 302, "location": "https://api.example.com/docs"}
            ],
            "final_url": "https://api.example.com/docs",
        }
    )

    probes = adapter.parse_ndjson(raw_output)

    assert len(probes) == 1
    probe = probes[0]
    assert probe.url == "https://api.example.com"
    assert probe.input_host == "api.example.com"
    assert probe.status_code == 200
    assert probe.title == "API Gateway Console"
    assert probe.webserver == "nginx/1.24.0"
    assert probe.content_length == 4210
    assert probe.tls["version"] == "TLSv1.3"
    assert probe.final_url == "https://api.example.com/docs"
    assert not probe.failed


def test_httpx_technology_stack_normalization(mock_runner):
    adapter = HttpxAdapter(runner=mock_runner)

    raw_output = json.dumps(
        {
            "url": "https://app.example.com",
            "tech": ["Nginx:1.24.0", "FastAPI", "React:18.2.0"],
        }
    )

    probes = adapter.parse_ndjson(raw_output)

    assert len(probes) == 1
    comps = [(c.name, c.version) for c in probes[0].components]
    assert comps == [
        ("nginx", "1.24.0"),
        ("fastapi", None),
        ("react", "18.2.0"),
    ]
    assert probes[0].technologies == ["nginx", "fastapi", "react"]


def test_httpx_forward_proxy_enforcement(mock_runner):
    proxy_url = "http://pentefino_proxy:8080"
    adapter = HttpxAdapter(runner=mock_runner, proxy_url=proxy_url)

    config = adapter.build_run_config(targets=["api.example.com"])

    assert config.image == "projectdiscovery/httpx:v1.6.0"
    assert config.http_proxy == proxy_url
    assert config.https_proxy == proxy_url

    assert "-http-proxy" in config.command
    proxy_idx = config.command.index("-http-proxy")
    assert config.command[proxy_idx + 1] == proxy_url


def test_httpx_filters_out_candidate_and_out_of_scope_assets(
    mock_runner, sample_scope_engine
):
    adapter = HttpxAdapter(runner=mock_runner, scope_engine=sample_scope_engine)

    # api.example.com is in-scope derived
    # external-domain.com is a candidate (not matching *.example.com)
    # deny.example.com is explicitly denied
    targets = [
        "api.example.com",
        "external-domain.com",
        "deny.example.com",
    ]

    filtered = adapter.filter_targets(targets)

    assert filtered == ["api.example.com"]
    assert "external-domain.com" not in filtered
    assert "deny.example.com" not in filtered


@pytest.mark.asyncio
async def test_httpx_persists_http_observations_and_components(
    mock_runner, program_id
):
    adapter = HttpxAdapter(runner=mock_runner)

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

    probes = [
        HttpProbeRecord(
            url="https://api.example.com",
            input_host="api.example.com",
            status_code=200,
            title="Dashboard",
            webserver="nginx/1.24.0",
            technologies=["nginx", "fastapi"],
            components=[
                TechnologyComponent(name="nginx", version="1.24.0"),
                TechnologyComponent(name="fastapi", version=None),
            ],
            raw_json={"url": "https://api.example.com", "status_code": 200},
        )
    ]

    saved = await adapter.persist(mock_session, program_id, probes)

    assert len(saved) == 1
    mock_session.add.assert_called_once()
    obs: Observation = mock_session.add.call_args[0][0]

    assert obs.observation_type == "http_probe"
    assert obs.metadata_json["status_code"] == 200
    assert obs.metadata_json["title"] == "Dashboard"
    assert obs.metadata_json["technologies"] == ["nginx", "fastapi"]
    assert obs.metadata_json["components"] == [
        {"name": "nginx", "version": "1.24.0"},
        {"name": "fastapi", "version": None},
    ]


def test_httpx_handles_connection_failures_gracefully(mock_runner):
    adapter = HttpxAdapter(runner=mock_runner)

    raw_output = json.dumps(
        {
            "failed": True,
            "err": "connection refused",
            "url": "https://offline.example.com",
            "input": "offline.example.com",
        }
    )

    probes = adapter.parse_ndjson(raw_output)

    assert len(probes) == 1
    assert probes[0].failed is True
    assert probes[0].error == "connection refused"
    assert probes[0].input_host == "offline.example.com"


def test_curated_wordlist_top5k_exact_and_valid():
    """
    Verifies data/wordlists/subdomains-top5k.txt exists and meets all RFC criteria:
    - Exactly 5,000 valid unique lines
    - RFC 1035 / RFC 1123 label compliant: [a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?
    - No empty lines, no comments, no spaces, no uppercase
    """
    wordlist_path = Path("data/wordlists/subdomains-top5k.txt")
    assert wordlist_path.exists(), f"Wordlist not found at {wordlist_path}"

    content = wordlist_path.read_text(encoding="utf-8")
    lines = content.splitlines()

    assert len(lines) == 5000, f"Expected exactly 5,000 lines, found {len(lines)}"
    assert (
        len(set(lines)) == 5000
    ), f"Expected 5,000 unique entries, found {len(set(lines))}"

    label_regex = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

    for idx, entry in enumerate(lines, start=1):
        assert entry.strip() == entry, f"Leading/trailing whitespace at line {idx}"
        assert entry.islower(), f"Uppercase character detected at line {idx}: {entry}"
        assert not entry.startswith("-"), f"Hyphen prefix at line {idx}: {entry}"
        assert not entry.endswith("-"), f"Hyphen suffix at line {idx}: {entry}"
        assert "." not in entry, f"Dot in label at line {idx}: {entry}"
        assert label_regex.match(entry), f"Invalid RFC label at line {idx}: {entry}"


@pytest.mark.asyncio
async def test_recon_pipeline_e2e_orchestration(sample_scope_engine, program_id):
    """Verifies complete ReconPipeline orchestration: Subfinder -> dnsx -> httpx."""
    mock_runner = MagicMock(spec=EphemeralRunner)

    # 1. Subfinder outputs: 1 in-scope, 1 candidate, 1 out-of-scope
    subfinder_stdout = "\n".join(
        [
            json.dumps({"host": "api.example.com"}),
            json.dumps({"host": "external-partner.com"}),
            json.dumps({"host": "deny.example.com"}),
        ]
    )

    # 2. dnsx outputs: api.example.com resolves to public IP
    dnsx_stdout = json.dumps(
        {
            "host": "api.example.com",
            "resolver": ["1.1.1.1"],
            "a": ["93.184.216.34"],
        }
    )

    # 3. httpx outputs: live probe on api.example.com
    httpx_stdout = json.dumps(
        {
            "url": "https://api.example.com",
            "input": "api.example.com",
            "status_code": 200,
            "title": "API Gateway",
            "webserver": "nginx/1.24.0",
            "tech": ["Nginx:1.24.0", "FastAPI"],
        }
    )

    mock_runner.run = AsyncMock(
        side_effect=[
            RunResult(exit_code=0, stdout=subfinder_stdout, stderr=""),
            RunResult(exit_code=0, stdout=dnsx_stdout, stderr=""),
            RunResult(exit_code=0, stdout=httpx_stdout, stderr=""),
        ]
    )

    subfinder_adapter = SubfinderAdapter(runner=mock_runner, scope_engine=sample_scope_engine)
    dnsx_adapter = DnsxAdapter(runner=mock_runner, scope_engine=sample_scope_engine)
    httpx_adapter = HttpxAdapter(runner=mock_runner, scope_engine=sample_scope_engine)

    pipeline = ReconPipeline(
        subfinder=subfinder_adapter,
        dnsx=dnsx_adapter,
        httpx=httpx_adapter,
        scope_engine=sample_scope_engine,
    )

    result = await pipeline.run(domain="example.com", program_id=program_id)

    assert result.domain == "example.com"
    assert result.total_discovered == 3
    assert result.in_scope_count == 1
    assert result.resolved_count == 1
    assert result.live_http_count == 1
    assert len(result.http_probes) == 1
    assert result.http_probes[0].status_code == 200
    assert result.http_probes[0].webserver == "nginx/1.24.0"
