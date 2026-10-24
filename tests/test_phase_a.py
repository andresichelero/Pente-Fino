from __future__ import annotations

import hashlib
import os
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Boolean, CheckConstraint, Float, Index, String, Text

from pentefino_api.main import create_app
from pentefino_domain.models.finding import Finding
from pentefino_domain.models.template import TemplateCatalog
from pentefino_api.schemas import FindingDetailResponse, FindingListItem
from pentefino_proxy.s3_client import S3EvidenceClient
from pentefino_proxy.scope_guard import ScopeGuard
from pentefino_proxy.server import ForwardProxyServer
from pentefino_runner import (
    DockerCommandBuilder,
    EphemeralRunner,
    InvalidImageDigestError,
    RunConfig,
    validate_image_digest,
)


# ============================================================================
# 1. Alembic Migration 0003 & Domain Models Tests
# ============================================================================


def test_migration_0003_metadata_and_operations():
    """Verify Alembic Migration 0003 schema upgrade and downgrade definitions."""
    import importlib.util

    migration_file = os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            "..",
            "packages",
            "domain",
            "alembic",
            "versions",
            "0003_add_filepath_and_threat_intel_columns.py",
        )
    )
    spec = importlib.util.spec_from_file_location("migration_0003", migration_file)
    assert spec is not None and spec.loader is not None
    migration_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration_mod)

    assert migration_mod.revision == "0003_add_filepath_and_threat_intel"
    assert migration_mod.down_revision == "0002_add_observations"

    with patch("alembic.op.add_column") as mock_add_col, \
         patch("alembic.op.create_check_constraint") as mock_create_chk, \
         patch("alembic.op.create_index") as mock_create_idx, \
         patch("alembic.op.drop_column") as mock_drop_col, \
         patch("alembic.op.drop_constraint") as mock_drop_chk, \
         patch("alembic.op.drop_index") as mock_drop_idx:

        # Test upgrade
        migration_mod.upgrade()

        # Check template_catalog.file_path addition
        tc_calls = [c for c in mock_add_col.call_args_list if c[0][0] == "template_catalog"]
        assert len(tc_calls) == 1
        assert tc_calls[0][0][1].name == "file_path"
        assert tc_calls[0][0][1].nullable is True

        # Check findings threat intel columns
        f_calls = [c for c in mock_add_col.call_args_list if c[0][0] == "findings"]
        col_names = {c[0][1].name for c in f_calls}
        assert {"epss_score", "epss_percentile", "in_cisa_kev", "priority_tier"} == col_names

        mock_create_chk.assert_called_once_with(
            "chk_findings_priority_tier",
            "findings",
            "priority_tier IN ('critical_kev', 'high_epss', 'elevated', 'standard')",
        )
        assert mock_create_idx.call_count == 2

        # Test downgrade
        migration_mod.downgrade()
        assert mock_drop_idx.call_count == 2
        mock_drop_chk.assert_called_once_with(
            "chk_findings_priority_tier", "findings", type_="check"
        )
        assert mock_drop_col.call_count == 5


def test_finding_domain_model_and_template_catalog_columns():
    """Verify Finding model and TemplateCatalog model column declarations and defaults."""
    # TemplateCatalog file_path check
    assert hasattr(TemplateCatalog, "file_path")
    assert isinstance(TemplateCatalog.file_path.property.columns[0].type, Text)
    assert TemplateCatalog.file_path.property.columns[0].nullable is True

    # Finding columns check
    assert hasattr(Finding, "epss_score")
    assert isinstance(Finding.epss_score.property.columns[0].type, Float)
    assert Finding.epss_score.property.columns[0].nullable is True

    assert hasattr(Finding, "epss_percentile")
    assert isinstance(Finding.epss_percentile.property.columns[0].type, Float)
    assert Finding.epss_percentile.property.columns[0].nullable is True

    assert hasattr(Finding, "in_cisa_kev")
    assert isinstance(Finding.in_cisa_kev.property.columns[0].type, Boolean)
    assert Finding.in_cisa_kev.property.columns[0].nullable is False

    assert hasattr(Finding, "priority_tier")
    assert isinstance(Finding.priority_tier.property.columns[0].type, String)
    assert Finding.priority_tier.property.columns[0].nullable is False

    # Check table constraints
    table_args = Finding.__table_args__
    check_names = {arg.name for arg in table_args if isinstance(arg, CheckConstraint)}
    assert "chk_findings_priority_tier" in check_names

    index_names = {arg.name for arg in table_args if isinstance(arg, Index)}
    assert "ix_findings_priority_tier" in index_names
    assert "ix_findings_in_cisa_kev" in index_names

    # Test in-memory default instantiation
    f = Finding(
        program_id=uuid.uuid4(),
        asset_id=uuid.uuid4(),
        dedup_key="a" * 64,
        detector_id="nuclei/cve-2024-0001",
        status="candidate",
        evidence_level="E1",
        confidence="high",
    )
    assert f.in_cisa_kev is False
    assert f.priority_tier == "standard"
    assert f.epss_score is None
    assert f.epss_percentile is None


def test_finding_api_schemas_serialization():
    """Verify FindingListItem and FindingDetailResponse expose threat intel attributes."""
    item = FindingListItem(
        id=str(uuid.uuid4()),
        program_id=str(uuid.uuid4()),
        asset_id=str(uuid.uuid4()),
        detector_id="cve-2021-41773",
        status="validated",
        evidence_level="E2",
        confidence="high",
        dedup_key="b" * 64,
        first_seen="2026-10-24T00:00:00Z",
        last_seen="2026-10-24T01:00:00Z",
        epss_score=0.974,
        epss_percentile=0.999,
        in_cisa_kev=True,
        priority_tier="critical_kev",
    )
    dump = item.model_dump()
    assert dump["epss_score"] == 0.974
    assert dump["epss_percentile"] == 0.999
    assert dump["in_cisa_kev"] is True
    assert dump["priority_tier"] == "critical_kev"

    detail = FindingDetailResponse(
        **dump,
        evidence_items=[],
    )
    detail_dump = detail.model_dump()
    assert detail_dump["in_cisa_kev"] is True
    assert detail_dump["priority_tier"] == "critical_kev"


# ============================================================================
# 2. EphemeralRunner Supply Chain Digest Enforcement Tests
# ============================================================================


def test_validate_image_digest_function():
    """Verify validate_image_digest strictly validates ^.+@sha256:[a-fA-F0-9]{64}$."""
    valid_digest = "projectdiscovery/nuclei@sha256:" + "a" * 64
    assert validate_image_digest(valid_digest) is True
    assert validate_image_digest(valid_digest, raise_exc=False) is True

    invalid_images = [
        "alpine:latest",
        "projectdiscovery/subfinder:v2.6.6",
        "nginx",
        "ubuntu@sha256:1234not64chars",
        "ubuntu@sha256:" + "z" * 64,  # non-hex
        "",
    ]
    for inv in invalid_images:
        assert validate_image_digest(inv, raise_exc=False) is False
        with pytest.raises(InvalidImageDigestError):
            validate_image_digest(inv, raise_exc=True)


def test_run_config_strict_digest_validation():
    """Verify RunConfig raises InvalidImageDigestError when strict_digest_validation=True."""
    # When strict, reject unpinned
    with pytest.raises(InvalidImageDigestError) as exc_info:
        RunConfig(image="alpine:latest", strict_digest_validation=True)
    assert "supply chain security policy" in str(exc_info.value)

    # When strict, accept pinned
    valid_img = "docker.io/library/alpine@sha256:" + "0" * 64
    cfg = RunConfig(image=valid_img, strict_digest_validation=True)
    assert cfg.image == valid_img

    # Backward compatibility: unpinned allowed when strict is False (for legacy/dev tests)
    cfg_legacy = RunConfig(image="alpine:latest", strict_digest_validation=False)
    assert cfg_legacy.image == "alpine:latest"


def test_command_builder_strict_digest_enforcement():
    """Verify DockerCommandBuilder rejects unpinned images when strict_digest=True."""
    builder = DockerCommandBuilder(strict_digest=True)
    cfg_unpinned = RunConfig(image="projectdiscovery/httpx:latest", strict_digest_validation=False)

    with pytest.raises(InvalidImageDigestError):
        builder.build_run_command(cfg_unpinned)

    valid_img = "projectdiscovery/httpx@sha256:" + "e" * 64
    cfg_pinned = RunConfig(image=valid_img, strict_digest_validation=False)
    cmd = builder.build_run_command(cfg_pinned)
    assert valid_img in cmd


@pytest.mark.asyncio
async def test_ephemeral_runner_strict_digest_enforcement():
    """Verify EphemeralRunner raises InvalidImageDigestError before executing docker run."""
    runner = EphemeralRunner(strict_digest=True)
    cfg = RunConfig(image="projectdiscovery/subfinder:v2.6.6", strict_digest_validation=False)

    with pytest.raises(InvalidImageDigestError):
        await runner.run(cfg)


def test_runner_dockerfiles_exist_and_are_hardened():
    """Verify that all 4 runner Dockerfiles exist with non-root security contexts."""
    runners_dir = os.path.join(os.path.dirname(__file__), "..", "docker", "runners")
    expected_dockerfiles = [
        "Dockerfile.subfinder",
        "Dockerfile.dnsx",
        "Dockerfile.httpx",
        "Dockerfile.nuclei",
    ]

    for df_name in expected_dockerfiles:
        df_path = os.path.join(runners_dir, df_name)
        assert os.path.isfile(df_path), f"Missing runner Dockerfile: {df_path}"

        with open(df_path, "r", encoding="utf-8") as f:
            content = f.read()

        assert "USER 10001:10001" in content, f"{df_name} must specify non-root USER 10001:10001"
        assert "@sha256:" in content, f"{df_name} must use pinned digest base image"
        assert "ENTRYPOINT" in content, f"{df_name} must define an entrypoint"


# ============================================================================
# 3. Dynamic ScopeGuard <-> PostgreSQL Sync Tests
# ============================================================================


@pytest.mark.asyncio
async def test_scope_guard_sync_from_db():
    """Verify ScopeGuard dynamically loads rules from PostgreSQL session."""
    guard = ScopeGuard(environment_class="bounty")
    prog_id = uuid.uuid4()

    # Mock Program
    mock_prog = MagicMock()
    mock_prog.id = prog_id
    mock_prog.platform = "bounty"

    # Mock ScopeRules
    rule_allow = MagicMock()
    rule_allow.id = uuid.uuid4()
    rule_allow.program_id = prog_id
    rule_allow.priority = 10
    rule_allow.asset_type = "domain"
    rule_allow.pattern = "*.example.com"
    rule_allow.action = "allow"
    rule_allow.allowed_ports = [80, 443]
    rule_allow.denied_paths = []

    rule_deny = MagicMock()
    rule_deny.id = uuid.uuid4()
    rule_deny.program_id = prog_id
    rule_deny.priority = 1
    rule_deny.asset_type = "domain"
    rule_deny.pattern = "internal.example.com"
    rule_deny.action = "deny"
    rule_deny.allowed_ports = []
    rule_deny.denied_paths = []

    # Mock AuthorizationSnapshot
    mock_auth = MagicMock()
    mock_auth.id = uuid.uuid4()
    mock_auth.program_id = prog_id
    mock_auth.source_url = "https://bounty.example.com/policy"
    mock_auth.policy_hash = "h" * 64
    mock_auth.rules_json = {}
    mock_auth.valid_from = datetime.now(timezone.utc)
    mock_auth.valid_until = None

    mock_session = AsyncMock()

    # Configure session.execute to return mock queries
    async def mock_execute(stmt):
        sql_str = str(stmt).lower()
        res = MagicMock()
        if "from programs" in sql_str:
            res.scalar_one_or_none.return_value = mock_prog
        elif "from scope_rules" in sql_str:
            res.scalars.return_value.all.return_value = [rule_deny, rule_allow]
        elif "from authorization_snapshots" in sql_str:
            res.scalar_one_or_none.return_value = mock_auth
        else:
            res.scalars.return_value.all.return_value = []
            res.scalar_one_or_none.return_value = None
        return res

    mock_session.execute = mock_execute

    # Perform DB sync
    await guard.sync_from_db(mock_session, program_id=prog_id)

    # Verify ScopeEngine was created and loaded
    engine = guard.get_engine(prog_id)
    assert engine is not None

    # Test scope evaluation with the loaded rules
    allow_decision = guard.evaluate(
        "https://app.example.com:443/test",
        program_id=prog_id,
        check_dns=False,
    )
    assert allow_decision.allowed is True

    deny_decision = guard.evaluate(
        "https://internal.example.com:443/admin",
        program_id=prog_id,
        check_dns=False,
    )
    assert deny_decision.allowed is False


@pytest.mark.asyncio
async def test_forward_proxy_dynamic_scope_sync_on_request():
    """Verify ForwardProxyServer triggers dynamic sync when program scope is not in memory."""
    guard = ScopeGuard(environment_class="bounty")
    prog_id = uuid.uuid4()

    mock_session = AsyncMock()
    # Mock empty or valid rules
    mock_res = MagicMock()
    mock_res.scalar_one_or_none.return_value = None
    mock_res.scalars.return_value.all.return_value = []
    mock_session.execute = AsyncMock(return_value=mock_res)

    class MockSessionFactory:
        async def __aenter__(self):
            return mock_session
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

    server = ForwardProxyServer(
        scope_guard=guard,
        default_program_id=prog_id,
        async_session_factory=MockSessionFactory,
    )

    with patch.object(guard, "sync_from_db", new_callable=AsyncMock) as mock_sync:
        await server.sync_scope(program_id=prog_id)
        mock_sync.assert_called_once_with(mock_session, program_id=prog_id)


# ============================================================================
# 4. Forensic Evidence Blob Streaming Tests
# ============================================================================


def test_evidence_blob_streaming_endpoint():
    """Verify GET /api/v1/evidence/{evidence_id}/blob retrieves and streams raw blobs."""
    app = create_app()
    client = TestClient(app)

    evidence_id = uuid.uuid4()
    finding_id = uuid.uuid4()
    run_id = uuid.uuid4()
    raw_payload = b'{"response": {"status_code": 200, "body": "FLAG_EVIDENCE_FOUND"}}'
    sanitized_sha256 = hashlib.sha256(raw_payload).hexdigest()
    object_key = f"evidence/{finding_id}/{evidence_id}.json"

    # Populate in-memory S3 store
    s3_client = S3EvidenceClient(use_mock=True)
    s3_client._mock_store.put_object("evidence", object_key, raw_payload)

    mock_evidence = MagicMock()
    mock_evidence.id = evidence_id
    mock_evidence.finding_id = finding_id
    mock_evidence.run_id = run_id
    mock_evidence.evidence_type = "http_interaction"
    mock_evidence.original_sha256 = "0" * 64
    mock_evidence.sanitized_sha256 = sanitized_sha256
    mock_evidence.seaweed_object_key = object_key
    mock_evidence.redaction_profile = "bounty-safe-v1"
    mock_evidence.created_at = datetime.now(timezone.utc)

    mock_session = AsyncMock()
    current_evidence = None

    async def mock_execute(stmt):
        res = MagicMock()
        res.scalar_one_or_none.return_value = current_evidence
        return res

    mock_session.execute = mock_execute

    from pentefino_api.deps import get_db_session

    async def override_get_db_session():
        yield mock_session

    app.dependency_overrides[get_db_session] = override_get_db_session

    try:
        with patch("pentefino_api.routers.evidence.S3EvidenceClient", return_value=s3_client):
            # 1. Invalid UUID format -> 400
            resp_bad = client.get("/api/v1/evidence/not-a-uuid/blob")
            assert resp_bad.status_code == 400

            # 2. Evidence not found in DB -> 404
            current_evidence = None
            random_id = uuid.uuid4()
            resp_missing = client.get(f"/api/v1/evidence/{random_id}/blob")
            assert resp_missing.status_code == 404

            # 3. Successful streaming retrieval -> 200
            current_evidence = mock_evidence
            resp_ok = client.get(f"/api/v1/evidence/{evidence_id}/blob")
            assert resp_ok.status_code == 200
            assert resp_ok.content == raw_payload
            assert resp_ok.headers["x-content-sha256"] == sanitized_sha256
            assert sanitized_sha256 in resp_ok.headers["etag"]
            assert "Content-Disposition" in resp_ok.headers
            assert "application/json" in resp_ok.headers["content-type"]

            # 4. Storage object missing -> 404
            mock_evidence.seaweed_object_key = "evidence/nonexistent/missing.bin"
            resp_no_blob = client.get(f"/api/v1/evidence/{evidence_id}/blob")
            assert resp_no_blob.status_code == 404
            assert "not found in storage" in resp_no_blob.json()["detail"].lower()

            # 5. Metadata endpoint test
            mock_evidence.seaweed_object_key = object_key
            resp_meta = client.get(f"/api/v1/evidence/{evidence_id}")
            assert resp_meta.status_code == 200
            meta_json = resp_meta.json()
            assert meta_json["id"] == str(evidence_id)
            assert meta_json["sanitized_sha256"] == sanitized_sha256
            assert meta_json["evidence_type"] == "http_interaction"
    finally:
        app.dependency_overrides.clear()
