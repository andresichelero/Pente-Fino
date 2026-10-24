import os
import sys
import uuid
import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

# Ensure packages/domain is in sys.path
DOMAIN_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "packages", "domain")
)
if DOMAIN_PATH not in sys.path:
    sys.path.insert(0, DOMAIN_PATH)

from pentefino_domain import (  # noqa: E402
    Asset,
    AssetType,
    AuditEvent,
    AuthorizationSnapshot,
    Base,
    Evidence,
    EvidenceLevel,
    EvidenceType,
    Finding,
    FindingConfidence,
    FindingStatus,
    ImpactClass,
    Program,
    ProgramPlatform,
    ProgramState,
    ScopeAction,
    ScopeRule,
    ScopeState,
    TemplateCatalog,
    compute_finding_dedup_key,
)

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://pentefino:pentefino_secure_pass@localhost:5432/pentefino",
)


@pytest.fixture(scope="session")
def alembic_config() -> Config:
    ini_path = os.path.join(DOMAIN_PATH, "alembic.ini")
    cfg = Config(ini_path)
    cfg.set_main_option("sqlalchemy.url", DATABASE_URL)
    return cfg


@pytest_asyncio.fixture
async def db_engine():
    engine = create_async_engine(DATABASE_URL, pool_pre_ping=True)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(db_engine):
    async with AsyncSession(db_engine, expire_on_commit=False) as session:
        yield session


# ============================================================================
# 1. Model Declarations & Meta Validation Tests
# ============================================================================


def test_model_declarations_and_tables():
    """Validates all 8 core entities are declared in SQLAlchemy metadata."""
    expected_tables = {
        "programs",
        "authorization_snapshots",
        "scope_rules",
        "assets",
        "template_catalog",
        "findings",
        "evidence",
        "audit_events",
    }
    registered_tables = set(Base.metadata.tables.keys())
    assert expected_tables.issubset(registered_tables), (
        f"Missing tables: {expected_tables - registered_tables}"
    )


def test_model_relationships():
    """Validates relationship mappings across domain models."""
    # Program relationships
    assert hasattr(Program, "authorization_snapshots")
    assert hasattr(Program, "scope_rules")
    assert hasattr(Program, "assets")
    assert hasattr(Program, "findings")

    # Finding relationships
    assert hasattr(Finding, "program")
    assert hasattr(Finding, "asset")
    assert hasattr(Finding, "detector")
    assert hasattr(Finding, "evidence_items")

    # Evidence relationship
    assert hasattr(Evidence, "finding")


# ============================================================================
# 2. Deduplication Hashing Algorithm Tests
# ============================================================================


def test_dedup_key_deterministic_and_length():
    """Validates SHA-256 output format and determinism."""
    prog_id = uuid.uuid4()
    key1 = compute_finding_dedup_key(prog_id, "api.example.com", 443, "/v1/users", "cve-2024-1234")
    key2 = compute_finding_dedup_key(prog_id, "api.example.com", 443, "/v1/users", "cve-2024-1234")
    assert key1 == key2
    assert len(key1) == 64
    assert key1 == key1.lower()


def test_dedup_key_normalization_canonical_asset():
    """Validates URL schemes, port suffixes, case, and trailing dots in asset are normalized."""
    prog_id = uuid.uuid4()
    base_key = compute_finding_dedup_key(prog_id, "example.com", 443, "/login", "nuclei-1")

    # Uppercase
    assert compute_finding_dedup_key(prog_id, "EXAMPLE.COM", 443, "/login", "nuclei-1") == base_key
    # Full URL with scheme and port
    assert compute_finding_dedup_key(prog_id, "https://example.com:443/something", 443, "/login", "nuclei-1") == base_key
    # Trailing dot (FQDN)
    assert compute_finding_dedup_key(prog_id, "example.com.", 443, "/login", "nuclei-1") == base_key
    # Host with port
    assert compute_finding_dedup_key(prog_id, "example.com:8443", 443, "/login", "nuclei-1") == base_key


def test_dedup_key_normalization_path():
    """Validates path traversal, consecutive slashes, trailing slashes, and query stripping."""
    prog_id = uuid.uuid4()
    base_key = compute_finding_dedup_key(prog_id, "example.com", 443, "/api/v1/auth", "nuclei-1")

    # Missing leading slash
    assert compute_finding_dedup_key(prog_id, "example.com", 443, "api/v1/auth", "nuclei-1") == base_key
    # Trailing slash stripped
    assert compute_finding_dedup_key(prog_id, "example.com", 443, "/api/v1/auth/", "nuclei-1") == base_key
    # Multiple slashes collapsed
    assert compute_finding_dedup_key(prog_id, "example.com", 443, "///api//v1//auth", "nuclei-1") == base_key
    # Path traversal resolved
    assert compute_finding_dedup_key(prog_id, "example.com", 443, "/api/v2/../v1/auth", "nuclei-1") == base_key
    # Query parameters and fragments excluded
    assert compute_finding_dedup_key(prog_id, "example.com", 443, "/api/v1/auth?redirect=true#token", "nuclei-1") == base_key


def test_dedup_key_collision_avoidance_pipe_delimiters():
    """Validates pipe delimiters prevent boundary ambiguities between fields."""
    prog_id = uuid.uuid4()
    # Case: asset ends with '1' and port is '23', vs asset without '1' and port '123'
    key_a = compute_finding_dedup_key(prog_id, "host1", 23, "/path", "det")
    key_b = compute_finding_dedup_key(prog_id, "host", 123, "/path", "det")
    assert key_a != key_b


# ============================================================================
# 3. Schema Upgrade and Downgrade Migration Cycles
# ============================================================================


def test_migration_upgrade_downgrade_cycle(alembic_config):
    """Executes full Alembic upgrade head -> downgrade base -> upgrade head cycle."""
    # 1. Downgrade to base (clean teardown)
    command.downgrade(alembic_config, "base")

    # 2. Upgrade to head
    command.upgrade(alembic_config, "head")

    # 3. Downgrade to base again
    command.downgrade(alembic_config, "base")

    # 4. Re-upgrade to head (ensures idempotency and clean state for subsequent tests)
    command.upgrade(alembic_config, "head")


# ============================================================================
# 4. Relational CRUD, Constraints, and Invariant Verification
# ============================================================================


@pytest.mark.asyncio
async def test_pgcrypto_extension_enabled(db_session: AsyncSession):
    """Verifies that pgcrypto extension is installed in PostgreSQL."""
    result = await db_session.execute(
        text("SELECT extname FROM pg_extension WHERE extname = 'pgcrypto';")
    )
    ext = result.scalar_one_or_none()
    assert ext == "pgcrypto"


@pytest.mark.asyncio
async def test_crud_and_foreign_key_invariants(db_session: AsyncSession):
    """Inserts a full chain of records across models and asserts relational integrity."""
    unique_slug = f"bounty-test-{uuid.uuid4().hex[:8]}"

    # 1. Create Program
    prog = Program(
        slug=unique_slug,
        name="Test Bounty Program",
        platform=ProgramPlatform.HACKERONE,
        state=ProgramState.ACTIVE,
    )
    db_session.add(prog)
    await db_session.flush()
    assert prog.id is not None
    assert prog.created_at is not None
    assert prog.default_policy_id == "bounty-safe"

    # 2. Create Scope Rule
    rule = ScopeRule(
        program_id=prog.id,
        priority=100,
        asset_type=AssetType.WILDCARD_DOMAIN,
        pattern="*.target.com",
        action=ScopeAction.ALLOW,
        allowed_ports=[80, 443],
        denied_paths=["/admin*"],
        max_impact_class=ImpactClass.SAFE_READ_ONLY,
    )
    db_session.add(rule)

    # 3. Create Asset
    asset = Asset(
        program_id=prog.id,
        canonical_key="api.target.com",
        asset_type=AssetType.DOMAIN,
        scope_state=ScopeState.IN_SCOPE_EXPLICIT,
    )
    db_session.add(asset)
    await db_session.flush()

    # 4. Create Template Catalog Entry
    detector_id = f"custom-detector-{uuid.uuid4().hex[:6]}"
    template = TemplateCatalog(
        id=detector_id,
        upstream_revision="v1.0.0",
        bundle_hash="a" * 64,
        name="Test Detector",
        protocol="http",
        http_methods=["GET"],
        impact_class=ImpactClass.SAFE_READ_ONLY,
        raw_yaml="id: test\ninfo:\n  name: test",
    )
    db_session.add(template)
    await db_session.flush()

    # 5. Create Finding with Dedup Key
    dedup_key = compute_finding_dedup_key(
        prog.id, asset.canonical_key, 443, "/v1/test", detector_id
    )
    finding = Finding(
        program_id=prog.id,
        asset_id=asset.id,
        dedup_key=dedup_key,
        detector_id=detector_id,
        status=FindingStatus.VALIDATED,
        evidence_level=EvidenceLevel.E2,
        confidence=FindingConfidence.HIGH,
    )
    db_session.add(finding)
    await db_session.flush()

    # 6. Create Evidence Item
    evidence = Evidence(
        finding_id=finding.id,
        run_id=uuid.uuid4(),
        evidence_type=EvidenceType.HTTP_INTERACTION,
        original_sha256="b" * 64,
        sanitized_sha256="c" * 64,
        seaweed_object_key=f"evidence/{finding.id}/http_0.json",
    )
    db_session.add(evidence)
    await db_session.commit()

    # 7. Verify Unique Constraint on Finding Deduplication Key
    duplicate_finding = Finding(
        program_id=prog.id,
        asset_id=asset.id,
        dedup_key=dedup_key,
        detector_id=detector_id,
        status=FindingStatus.CANDIDATE,
        evidence_level=EvidenceLevel.E0,
        confidence=FindingConfidence.LOW,
    )
    db_session.add(duplicate_finding)
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()


@pytest.mark.asyncio
async def test_authorization_snapshot_restrict_delete(db_session: AsyncSession):
    """Verifies that AuthorizationSnapshot ON DELETE RESTRICT prevents Program deletion."""
    prog = Program(
        slug=f"restrict-prog-{uuid.uuid4().hex[:8]}",
        name="Restrict Delete Program",
        platform=ProgramPlatform.BUGCROWD,
        state=ProgramState.ACTIVE,
    )
    db_session.add(prog)
    await db_session.flush()

    snapshot = AuthorizationSnapshot(
        program_id=prog.id,
        policy_hash="f" * 64,
        rules_json={"terms": "authorized"},
    )
    db_session.add(snapshot)
    await db_session.commit()

    # Attempting to delete Program directly should violate FK RESTRICT
    await db_session.delete(prog)
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()


# ============================================================================
# 5. Append-Only Audit Trigger Enforcement
# ============================================================================


@pytest.mark.asyncio
async def test_audit_events_append_only_trigger(db_session: AsyncSession):
    """Verifies that PostgreSQL trigger trg_audit_events_immutable blocks UPDATE and DELETE."""
    # 1. Insert audit event is allowed
    event = AuditEvent(
        actor="worker_m3",
        event_type="test.audit_logged",
        object_type="test_object",
        object_id=str(uuid.uuid4()),
        payload={"status": "initial"},
    )
    db_session.add(event)
    await db_session.commit()
    assert event.sequence is not None
    seq = event.sequence

    # 2. Attempt UPDATE - must fail via trigger
    with pytest.raises(Exception) as exc_update:
        await db_session.execute(
            text(f"UPDATE audit_events SET actor = 'tampered' WHERE sequence = {seq};")
        )
        await db_session.commit()
    await db_session.rollback()
    assert "append-only" in str(exc_update.value).lower()

    # 3. Attempt DELETE - must fail via trigger
    with pytest.raises(Exception) as exc_delete:
        await db_session.execute(
            text(f"DELETE FROM audit_events WHERE sequence = {seq};")
        )
        await db_session.commit()
    await db_session.rollback()
    assert "append-only" in str(exc_delete.value).lower()
