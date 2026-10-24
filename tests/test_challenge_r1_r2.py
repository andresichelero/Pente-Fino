"""Empirical Challenger 1: Adversarial Stress Tests for R1 (Runner) and R2 (Adapters & Wordlist)."""
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
from pentefino_adapters.models import (
    DiscoveredCandidate,
    DnsRecord,
)
from pentefino_adapters.subfinder import SubfinderAdapter
from pentefino_domain.enums import AssetType, ScopeState
from pentefino_domain.models import Asset, Observation
from pentefino_runner.builder import DockerCommandBuilder
from pentefino_runner.config import (
    DEFAULT_HTTP_PROXY,
    DEFAULT_NETWORK,
    RunConfig,
    VolumeMount,
)
from pentefino_runner.runner import EphemeralRunner
from pentefino_scope import (
    AssetType as ScopeAssetType,
    AuthorizationSnapshot,
    PrecedenceTier,
    ScopeAction,
    ScopeEngine,
    ScopeRule,
)


# ==============================================================================
# Fixtures
# ==============================================================================


@pytest.fixture
def program_id():
    return uuid4()


@pytest.fixture
def active_snapshot(program_id):
    now = datetime.now(timezone.utc)
    return AuthorizationSnapshot(
        program_id=program_id,
        policy_hash="b" * 64,
        rules_json={},
        valid_from=now - timedelta(days=2),
        valid_until=now + timedelta(days=60),
    )


@pytest.fixture
def complex_scope_engine(program_id, active_snapshot):
    rules = [
        # Explicit Deny on admin and metadata subdomains
        ScopeRule(
            program_id=program_id,
            pattern="admin.example.com",
            action=ScopeAction.DENY,
            asset_type=ScopeAssetType.HOSTNAME,
        ),
        ScopeRule(
            program_id=program_id,
            pattern="prohibited.example.com",
            action=ScopeAction.DENY,
            asset_type=ScopeAssetType.HOSTNAME,
        ),
        # Wildcard Allow on *.example.com
        ScopeRule(
            program_id=program_id,
            pattern="*.example.com",
            action=ScopeAction.ALLOW,
            asset_type=ScopeAssetType.WILDCARD_DOMAIN,
        ),
        # Explicit Allow on partner domain
        ScopeRule(
            program_id=program_id,
            pattern="partner.corp.com",
            action=ScopeAction.ALLOW,
            asset_type=ScopeAssetType.DOMAIN,
        ),
        # Discover Only on third-party candidate
        ScopeRule(
            program_id=program_id,
            pattern="candidate.partner.com",
            action=ScopeAction.DISCOVER_ONLY,
            asset_type=ScopeAssetType.DOMAIN,
        ),
    ]
    return ScopeEngine(snapshot=active_snapshot, rules=rules)


# ==============================================================================
# 1. Wordlist Adversarial Verification
# ==============================================================================


def test_challenge_wordlist_top5k_strict_properties():
    """Verify data/wordlists/subdomains-top5k.txt meets all 5k strict criteria."""
    wl_path = Path("data/wordlists/subdomains-top5k.txt")
    assert wl_path.is_file(), f"Wordlist missing at {wl_path}"

    raw_bytes = wl_path.read_bytes()
    assert not raw_bytes.startswith(b"\xef\xbb\xbf"), "BOM found"
    assert b"\x00" not in raw_bytes, "Null byte found"

    lines = raw_bytes.decode("utf-8").splitlines()

    # Exact 5000 count & uniqueness
    assert len(lines) == 5000, f"Expected 5,000 lines, found {len(lines)}"
    assert len(set(lines)) == 5000, f"Expected 5,000 unique entries, found {len(set(lines))}"

    # RFC 1035 / RFC 1123 label regex: [a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?
    rfc_label_regex = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

    for idx, entry in enumerate(lines, start=1):
        # Zero whitespace
        assert entry == entry.strip(), f"Whitespace at line {idx}: {repr(entry)}"
        assert not any(c.isspace() for c in entry), f"Internal space at line {idx}: {repr(entry)}"
        assert len(entry) > 0, f"Empty entry at line {idx}"

        # Zero uppercase
        assert not any(c.isupper() for c in entry), f"Uppercase at line {idx}: {entry}"

        # Strict ASCII
        assert entry.isascii(), f"Non-ASCII at line {idx}: {entry}"

        # RFC Compliance
        assert not entry.startswith("-"), f"Leading hyphen at line {idx}: {entry}"
        assert not entry.endswith("-"), f"Trailing hyphen at line {idx}: {entry}"
        assert "." not in entry, f"Dot found in label at line {idx}: {entry}"
        assert "/" not in entry, f"Slash found at line {idx}: {entry}"
        assert len(entry) <= 63, f"Label length exceeds 63 at line {idx}: {entry}"
        assert rfc_label_regex.match(entry), f"RFC non-compliant entry at line {idx}: {entry}"


# ==============================================================================
# 2. Ephemeral Runner Hardening & Edge Cases
# ==============================================================================


def test_challenge_runner_hardening_defaults_and_caps():
    """Verify DockerCommandBuilder strictly applies all required security sandboxing flags."""
    builder = DockerCommandBuilder()
    cfg = RunConfig(
        image="projectdiscovery/subfinder:v2.6.6",
        command=["-d", "example.com"],
    )
    cmd = builder.build_run_command(cfg)

    # 1. Disposable container
    assert cmd[0:3] == ["docker", "run", "--rm"]
    assert "--init" in cmd

    # 2. Hardening defaults
    assert "--read-only" in cmd
    assert "--tmpfs" in cmd
    tmpfs_idx = cmd.index("--tmpfs")
    assert cmd[tmpfs_idx + 1] == "/tmp:rw,noexec,nosuid,size=64m"

    assert "--cap-drop" in cmd
    cap_idx = cmd.index("--cap-drop")
    assert cmd[cap_idx + 1] == "ALL"

    assert "--security-opt" in cmd
    sec_idx = cmd.index("--security-opt")
    assert cmd[sec_idx + 1] == "no-new-privileges:true"

    # 3. Network containment & Proxy envs
    assert "--network" in cmd
    net_idx = cmd.index("--network")
    assert cmd[net_idx + 1] == DEFAULT_NETWORK

    assert "-e" in cmd
    assert f"HTTP_PROXY={DEFAULT_HTTP_PROXY}" in cmd
    assert f"http_proxy={DEFAULT_HTTP_PROXY}" in cmd
    assert f"HTTPS_PROXY={DEFAULT_HTTP_PROXY}" in cmd
    assert f"https_proxy={DEFAULT_HTTP_PROXY}" in cmd

    # 4. Resource limits
    assert "--cpus" in cmd
    assert cmd[cmd.index("--cpus") + 1] == "1.0"
    assert "--memory" in cmd
    assert cmd[cmd.index("--memory") + 1] == "512m"
    assert "--pids-limit" in cmd
    assert cmd[cmd.index("--pids-limit") + 1] == "128"


def test_challenge_runner_custom_env_and_volumes_ordering():
    """Verify custom environment variables, volumes, and entrypoint overrides are placed correctly."""
    builder = DockerCommandBuilder(engine_bin="podman")
    cfg = RunConfig(
        image="alpine@sha256:1234567890abcdef",
        entrypoint=["/bin/entrypoint.sh", "--opt"],
        command=["run", "--fast"],
        env={"ZZZ": "last", "AAA": "first", "MID": "mid"},
        volumes=[
            VolumeMount(host_path="/tmp/w1", container_path="/c1", mode="ro"),
            VolumeMount(host_path="/tmp/w2", container_path="/c2", mode="ro"),
        ],
        working_dir="/workspace",
        user="nobody:nogroup",
    )
    cmd = builder.build_run_command(cfg)

    assert cmd[0] == "podman"
    assert cmd[cmd.index("--user") + 1] == "nobody:nogroup"
    assert cmd[cmd.index("-w") + 1] == "/workspace"
    assert cmd[cmd.index("--entrypoint") + 1] == "/bin/entrypoint.sh"

    # Verify env keys are sorted
    e_indices = [i for i, x in enumerate(cmd) if x == "-e"]
    env_pairs = [cmd[i + 1] for i in e_indices if not ("PROXY" in cmd[i + 1] or "proxy" in cmd[i + 1])]
    assert env_pairs == ["AAA=first", "MID=mid", "ZZZ=last"]

    # Verify volumes
    assert "-v" in cmd
    assert "/tmp/w1:/c1:ro" in cmd
    assert "/tmp/w2:/c2:ro" in cmd

    # Verify entrypoint extra arg injected before command
    img_idx = cmd.index("alpine@sha256:1234567890abcdef")
    assert cmd[img_idx + 1 :] == ["--opt", "run", "--fast"]


# ==============================================================================
# 3. Subfinder Adapter Challenges
# ==============================================================================


def test_challenge_subfinder_ndjson_malformed_and_edge_inputs(complex_scope_engine):
    """Feed extreme malformed, empty, and edge case lines to Subfinder parser."""
    mock_runner = MagicMock(spec=EphemeralRunner)
    adapter = SubfinderAdapter(runner=mock_runner, scope_engine=complex_scope_engine)

    fuzz_output = "\n".join(
        [
            "",  # empty
            "   \t  ",  # whitespace only
            "THIS IS NOT JSON AT ALL",
            "{ incomplete json",
            "12345",  # int json
            '"raw string"',  # str json
            "true",  # bool json
            "null",  # null json
            '["array", "of", "items"]',  # array json
            '{"no_host": "key"}',  # dict missing host
            '{"host": ""}',  # empty host
            '{"host": "   "}',  # blank host
            '{"host": 99999}',  # non-string host
            '{"host": "VALID1.EXAMPLE.COM.", "sources": "crtsh"}',  # uppercase, trailing dot, string source
            '{"host": "  valid1.example.com  ", "sources": ["virustotal"]}',  # duplicate after strip/lower
            '{"host": "admin.example.com"}',  # explicit deny
            '{"host": "partner.corp.com"}',  # explicit allow
            '{"host": "candidate.partner.com"}',  # discover only
            '{"host": "random-external.io"}',  # derived candidate outside scope
            '{"host": "sub2.example.com", "sources": null}',  # sources is None
        ]
    )

    candidates = adapter.parse_ndjson(fuzz_output)

    # Dedup check on valid1.example.com
    assert len([c for c in candidates if c.host == "valid1.example.com"]) == 1
    c1 = next(c for c in candidates if c.host == "valid1.example.com")
    assert c1.scope_state == ScopeState.IN_SCOPE_DERIVED
    assert c1.matched_tier == PrecedenceTier.WILDCARD_ALLOW
    assert c1.sources == ["crtsh"]

    # Explicit deny
    c_admin = next(c for c in candidates if c.host == "admin.example.com")
    assert c_admin.scope_state == ScopeState.OUT_OF_SCOPE
    assert c_admin.matched_tier == PrecedenceTier.EXPLICIT_DENY

    # Explicit allow
    c_partner = next(c for c in candidates if c.host == "partner.corp.com")
    assert c_partner.scope_state == ScopeState.IN_SCOPE_EXPLICIT
    assert c_partner.matched_tier == PrecedenceTier.EXPLICIT_ALLOW

    # Discover only / candidate
    c_cand = next(c for c in candidates if c.host == "candidate.partner.com")
    assert c_cand.scope_state == ScopeState.CANDIDATE

    # Random external
    c_rand = next(c for c in candidates if c.host == "random-external.io")
    assert c_rand.scope_state == ScopeState.CANDIDATE
    assert c_rand.matched_tier == PrecedenceTier.DERIVED_CANDIDATE

    # Sources null -> empty list
    c_sub2 = next(c for c in candidates if c.host == "sub2.example.com")
    assert c_sub2.sources == []


@pytest.mark.asyncio
async def test_challenge_subfinder_persistence_state_transitions(complex_scope_engine, program_id):
    """Verify state transitions: candidate -> in_scope_derived (promoted), in_scope_explicit -> preserved."""
    mock_runner = MagicMock(spec=EphemeralRunner)
    adapter = SubfinderAdapter(runner=mock_runner, scope_engine=complex_scope_engine)

    mock_session = AsyncMock()
    mock_session.add = MagicMock()

    # 1. Existing CANDIDATE promoted to IN_SCOPE_DERIVED
    existing_candidate = Asset(
        id=uuid4(),
        program_id=program_id,
        canonical_key="api.example.com",
        asset_type=AssetType.HOSTNAME.value,
        scope_state=ScopeState.CANDIDATE.value,
    )
    mock_res = MagicMock()
    mock_res.scalar_one_or_none.return_value = existing_candidate
    mock_session.execute.return_value = mock_res

    candidates = [
        DiscoveredCandidate(
            host="api.example.com",
            scope_state=ScopeState.IN_SCOPE_DERIVED,
            sources=["crtsh"],
        )
    ]
    await adapter.persist(mock_session, program_id, candidates)
    assert existing_candidate.scope_state == ScopeState.IN_SCOPE_DERIVED.value

    # 2. Existing IN_SCOPE_EXPLICIT preserved (not demoted)
    existing_explicit = Asset(
        id=uuid4(),
        program_id=program_id,
        canonical_key="partner.corp.com",
        asset_type=AssetType.HOSTNAME.value,
        scope_state=ScopeState.IN_SCOPE_EXPLICIT.value,
    )
    mock_res.scalar_one_or_none.return_value = existing_explicit

    candidates2 = [
        DiscoveredCandidate(
            host="partner.corp.com",
            scope_state=ScopeState.IN_SCOPE_DERIVED,
            sources=["shodan"],
        )
    ]
    await adapter.persist(mock_session, program_id, candidates2)
    assert existing_explicit.scope_state == ScopeState.IN_SCOPE_EXPLICIT.value


# ==============================================================================
# 4. Dnsx Adapter Challenges & Critical IP Invariant
# ==============================================================================


@pytest.mark.asyncio
async def test_challenge_dnsx_critical_ip_invariant_and_multi_ip(complex_scope_engine, program_id):
    """
    CRITICAL INVARIANT PROBE:
    Ensure resolved IP addresses (A/AAAA) are NEVER created as Assets,
    even when a host resolves to 10+ IP addresses.
    """
    mock_runner = MagicMock(spec=EphemeralRunner)
    adapter = DnsxAdapter(runner=mock_runner, scope_engine=complex_scope_engine)

    mock_session = AsyncMock()
    mock_session.add = MagicMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None  # Asset does not exist yet
    mock_session.execute.return_value = mock_result

    ips_a = [f"93.184.216.{i}" for i in range(1, 10)]
    ips_aaaa = [f"2606:2800:220:1:248:1893:25c8:{i:04x}" for i in range(1, 5)]

    records = [
        DnsRecord(
            host="multi-cdn.example.com",
            a=ips_a,
            aaaa=ips_aaaa,
            resolver=["1.1.1.1:53", "8.8.8.8:53"],
        )
    ]

    await adapter.persist(mock_session, program_id, records)

    added_objects = [call.args[0] for call in mock_session.add.call_args_list]

    created_assets = [o for o in added_objects if isinstance(o, Asset)]
    created_observations = [o for o in added_objects if isinstance(o, Observation)]

    # Exactly 1 Asset must be created (the hostname)
    assert len(created_assets) == 1
    assert created_assets[0].canonical_key == "multi-cdn.example.com"
    assert created_assets[0].asset_type == AssetType.HOSTNAME.value

    # NO asset may have canonical_key equal to any resolved IP!
    for ip in ips_a + ips_aaaa:
        assert not any(a.canonical_key == ip for a in created_assets), f"IP promoted to Asset: {ip}"

    # Exactly 1 Observation must be created
    assert len(created_observations) == 1
    obs = created_observations[0]
    assert obs.observation_type == "dns"
    assert obs.metadata_json["a"] == ips_a
    assert obs.metadata_json["aaaa"] == ips_aaaa


def test_challenge_dnsx_anti_ssrf_comprehensive_ip_spaces(complex_scope_engine):
    """Probe anti-SSRF detection across loopback, RFC1918, link-local, cloud metadata, IPv6, and mapped IPs."""
    mock_runner = MagicMock(spec=EphemeralRunner)
    adapter = DnsxAdapter(runner=mock_runner, scope_engine=complex_scope_engine)

    fuzz_dnsx = "\n".join(
        [
            # Loopback 127.0.0.1
            json.dumps({"host": "loopback.example.com", "a": ["127.0.0.1"]}),
            # RFC 1918 10.0.0.1
            json.dumps({"host": "internal-10.example.com", "a": ["10.0.0.1"]}),
            # RFC 1918 172.16.0.1
            json.dumps({"host": "internal-172.example.com", "a": ["172.16.0.1"]}),
            # RFC 1918 192.168.1.1
            json.dumps({"host": "internal-192.example.com", "a": ["192.168.1.1"]}),
            # Cloud Metadata 169.254.169.254
            json.dumps({"host": "metadata.example.com", "a": ["169.254.169.254"]}),
            # 0.0.0.0 / Current network
            json.dumps({"host": "zero.example.com", "a": ["0.0.0.0"]}),
            # IPv6 Loopback ::1
            json.dumps({"host": "ipv6-loop.example.com", "aaaa": ["::1"]}),
            # IPv6 ULA fc00::1
            json.dumps({"host": "ipv6-ula.example.com", "aaaa": ["fc00::1"]}),
            # IPv6 Link-local fe80::1
            json.dumps({"host": "ipv6-ll.example.com", "aaaa": ["fe80::1"]}),
            # Dual-homed: public IP + internal RFC 1918 IP (rebinding / dual stack)
            json.dumps({"host": "dual.example.com", "a": ["93.184.216.34", "10.0.0.1"]}),
            # Pure Public IP (Allowed)
            json.dumps({"host": "public.example.com", "a": ["93.184.216.34"], "aaaa": ["2606:2800:220:1:248:1893:25c8:1946"]}),
        ]
    )

    records = adapter.parse_ndjson(fuzz_dnsx)
    assert len(records) == 11

    prohibited_hosts = [
        "loopback.example.com",
        "internal-10.example.com",
        "internal-172.example.com",
        "internal-192.example.com",
        "metadata.example.com",
        "zero.example.com",
        "ipv6-loop.example.com",
        "ipv6-ula.example.com",
        "ipv6-ll.example.com",
        "dual.example.com",  # Contains at least one prohibited IP
    ]

    for h in prohibited_hosts:
        rec = next(r for r in records if r.host == h)
        assert rec.is_prohibited_ip is True, f"Failed to flag prohibited IP for {h}"
        assert rec.prohibited_reason is not None

    pub_rec = next(r for r in records if r.host == "public.example.com")
    assert pub_rec.is_prohibited_ip is False
    assert pub_rec.prohibited_reason is None


@pytest.mark.asyncio
async def test_challenge_dnsx_prohibited_ip_forces_out_of_scope_asset(complex_scope_engine, program_id):
    """Ensure a host resolving to a prohibited IP is persisted with scope_state=OUT_OF_SCOPE even if matching wildcard allow."""
    mock_runner = MagicMock(spec=EphemeralRunner)
    adapter = DnsxAdapter(runner=mock_runner, scope_engine=complex_scope_engine)

    mock_session = AsyncMock()
    mock_session.add = MagicMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_session.execute.return_value = mock_result

    # Host matches *.example.com (which is WILDCARD_ALLOW), but resolves to 169.254.169.254
    records = [
        DnsRecord(
            host="cloud-meta.example.com",
            a=["169.254.169.254"],
            is_prohibited_ip=True,
            prohibited_reason="PROHIBITED_IP_SPACE: Link-local (169.254.169.254)",
        )
    ]

    await adapter.persist(mock_session, program_id, records)

    created_assets = [
        call.args[0]
        for call in mock_session.add.call_args_list
        if isinstance(call.args[0], Asset)
    ]
    assert len(created_assets) == 1
    assert created_assets[0].canonical_key == "cloud-meta.example.com"
    # MUST BE OUT_OF_SCOPE!
    assert created_assets[0].scope_state == ScopeState.OUT_OF_SCOPE.value


# ==============================================================================
# 5. Httpx Adapter Challenges
# ==============================================================================


def test_challenge_httpx_target_filtering_strict(complex_scope_engine):
    """Verify HttpxAdapter.filter_targets strictly drops out-of-scope and candidate targets."""
    mock_runner = MagicMock(spec=EphemeralRunner)
    adapter = HttpxAdapter(runner=mock_runner, scope_engine=complex_scope_engine)

    targets = [
        "api.example.com",  # IN_SCOPE_DERIVED (allowed)
        "https://partner.corp.com:443",  # IN_SCOPE_EXPLICIT (allowed)
        "admin.example.com",  # EXPLICIT_DENY (blocked)
        "prohibited.example.com",  # EXPLICIT_DENY (blocked)
        "candidate.partner.com",  # DISCOVER_ONLY / CANDIDATE (blocked)
        "unknown-domain.org",  # UNKNOWN / DERIVED CANDIDATE (blocked)
    ]

    filtered = adapter.filter_targets(targets)

    assert "api.example.com" in filtered
    assert "https://partner.corp.com:443" in filtered
    assert "admin.example.com" not in filtered
    assert "prohibited.example.com" not in filtered
    assert "candidate.partner.com" not in filtered
    assert "unknown-domain.org" not in filtered
    assert len(filtered) == 2


def test_challenge_httpx_technology_normalization_matrix():
    """Verify technology string normalization handles colons, spaces, uppercase, and malformed tags."""
    cases = [
        ("Nginx:1.24.0", "nginx", "1.24.0"),
        ("FastAPI", "fastapi", None),
        ("React: 18.2.0 ", "react", "18.2.0"),
        ("Apache:2.4.52:extra", "apache", "2.4.52:extra"),
        ("PHP:", "php", None),
        ("  Vue.js  ", "vue.js", None),
    ]

    for raw, exp_name, exp_ver in cases:
        comp = HttpxAdapter.normalize_technology(raw)
        assert comp.name == exp_name, f"Failed name for {raw}: got {comp.name}"
        assert comp.version == exp_ver, f"Failed version for {raw}: got {comp.version}"


def test_challenge_httpx_ndjson_malformed_stream():
    """Verify HttpxAdapter.parse_ndjson handles malformed lines, failed probes, and missing fields."""
    mock_runner = MagicMock(spec=EphemeralRunner)
    adapter = HttpxAdapter(runner=mock_runner)

    stream = "\n".join(
        [
            "",
            "INVALID NOT JSON",
            "{}",  # empty object
            json.dumps({"failed": True, "err": "timeout exceeded", "url": "https://slow.example.com"}),
            json.dumps(
                {
                    "url": "https://api.example.com",
                    "status_code": "200",  # string status code
                    "title": "API Gateway",
                    "content_length": "1024",  # string content length
                    "tech": ["Nginx:1.24.0", "FastAPI"],
                }
            ),
        ]
    )

    probes = adapter.parse_ndjson(stream)
    # EMPIRICAL CHALLENGE FINDING RESOLUTION:
    # HttpxAdapter now checks `if not url and not input_host: continue`.
    # As a result, '{}' is safely skipped and does not produce an empty HttpProbeRecord.
    assert len(probes) == 2

    # Probe 0: Failed probe with timeout error
    assert probes[0].failed is True
    assert probes[0].error == "timeout exceeded"
    assert probes[0].input_host == "slow.example.com"

    # Probe 1: Valid probe with status code and content-length converted to int
    assert probes[1].failed is False
    assert probes[1].status_code == 200
    assert probes[1].content_length == 1024
    assert probes[1].technologies == ["nginx", "fastapi"]
    assert len(probes[1].components) == 2
