"""Integration and unit test suite for Finding Normalizer and Deduplication.

Verifies:
1. Deterministic SHA-256 deduplication key formula invariants.
2. Canonical asset, port, and URL path normalization (query string, fragments, relative segments).
3. Collision avoidance across paths, ports, detectors, assets, and programs.
4. Idempotent database upserts: repeated detections update last_seen without duplicating records.
5. Evidence redaction of Bearer tokens, Basic auth, and Cookies before S3 storage.
6. Evidence model linkage with original_sha256, sanitized_sha256, and seaweed_object_key.
7. Finding lifecycle state transition: automatic reopening of remediated/resolved findings.
"""
from __future__ import annotations

import json
from typing import Any
import uuid

import pytest

from pentefino_detection.normalizer import FindingNormalizer
from pentefino_domain.dedup import compute_finding_dedup_key
from pentefino_domain.enums import FindingStatus
from pentefino_domain.models.evidence import Evidence
from pentefino_domain.models.finding import Finding
from pentefino_proxy.redactor import Redactor
from pentefino_proxy.s3_client import InMemoryS3Store


class InMemoryAsyncSession:
    """State-tracking in-memory AsyncSession for testing finding deduplication and evidence linkage."""

    def __init__(self):
        self.findings: dict[tuple[uuid.UUID, str], Finding] = {}
        self.evidence: list[Evidence] = []
        self._pending_add: list[Any] = []

    def add(self, obj: Any) -> None:
        self._pending_add.append(obj)

    async def execute(self, stmt: Any) -> Any:
        params: dict[str, Any] = {}
        try:
            compiled = stmt.compile()
            params = compiled.params
        except Exception:
            pass

        p_val: uuid.UUID | None = None
        d_val: str | None = None

        for val in params.values():
            if isinstance(val, uuid.UUID):
                p_val = val
            elif isinstance(val, str) and len(val) == 64:
                d_val = val

        matched: list[Finding] = []
        if p_val and d_val:
            key = (p_val, d_val)
            if key in self.findings:
                matched.append(self.findings[key])
        else:
            # Fallback: return all findings if no specific filter
            matched = list(self.findings.values())

        class MockResult:
            def __init__(self, items: list[Finding]):
                self._items = items

            def scalars(self):
                return self

            def first(self) -> Finding | None:
                return self._items[0] if self._items else None

            def all(self) -> list[Finding]:
                return list(self._items)

        return MockResult(matched)

    async def commit(self) -> None:
        for obj in self._pending_add:
            if isinstance(obj, Finding):
                self.findings[(obj.program_id, obj.dedup_key)] = obj
            elif isinstance(obj, Evidence):
                self.evidence.append(obj)
        self._pending_add.clear()


# ============================================================================
# 1. Deduplication Key Normalization Invariants
# ============================================================================


def test_dedup_key_normalization_invariants():
    """Identical detector triggers on the same endpoint must produce matching SHA-256 keys."""
    prog_id = uuid.uuid4()

    # 1. Host and Scheme Variation: lowercase vs uppercase, trailing dot, explicit vs default port
    key1 = compute_finding_dedup_key(
        program_id=prog_id,
        canonical_asset="http://api.target.com:443/v1/users/",
        port=443,
        normalized_path="/v1/users",
        detector_id="cve-2021-41773",
    )
    key2 = compute_finding_dedup_key(
        program_id=str(prog_id),
        canonical_asset="API.TARGET.COM.",
        port="443",
        normalized_path="/v1/users/",
        detector_id="CVE-2021-41773 ",
    )
    assert key1 == key2
    assert len(key1) == 64

    # 2. Query String and URL Fragment Stripping
    key_with_query = compute_finding_dedup_key(
        program_id=prog_id,
        canonical_asset="api.target.com",
        port=443,
        normalized_path="/v1/users?page=1&sort=desc#profile",
        detector_id="apache-detect",
    )
    key_clean_path = compute_finding_dedup_key(
        program_id=prog_id,
        canonical_asset="api.target.com",
        port=443,
        normalized_path="/v1/users",
        detector_id="apache-detect",
    )
    assert key_with_query == key_clean_path

    # 3. Path Normalization: Relative . and .. Segments and Slashes
    key_relative = compute_finding_dedup_key(
        program_id=prog_id,
        canonical_asset="api.target.com",
        port=443,
        normalized_path="//v1/admin/../users/./",
        detector_id="apache-detect",
    )
    assert key_relative == key_clean_path


def test_dedup_key_collision_avoidance():
    """Different endpoints, detectors, ports, or programs must produce distinct keys."""
    prog_id = uuid.uuid4()
    base_key = compute_finding_dedup_key(
        program_id=prog_id,
        canonical_asset="api.target.com",
        port=443,
        normalized_path="/v1/users",
        detector_id="cve-2021-41773",
    )

    # Different Path
    diff_path = compute_finding_dedup_key(
        program_id=prog_id,
        canonical_asset="api.target.com",
        port=443,
        normalized_path="/v1/admin",
        detector_id="cve-2021-41773",
    )
    assert base_key != diff_path

    # Different Port
    diff_port = compute_finding_dedup_key(
        program_id=prog_id,
        canonical_asset="api.target.com",
        port=8443,
        normalized_path="/v1/users",
        detector_id="cve-2021-41773",
    )
    assert base_key != diff_port

    # Different Detector ID
    diff_detector = compute_finding_dedup_key(
        program_id=prog_id,
        canonical_asset="api.target.com",
        port=443,
        normalized_path="/v1/users",
        detector_id="cve-2021-42013",
    )
    assert base_key != diff_detector

    # Different Program ID
    diff_prog = compute_finding_dedup_key(
        program_id=uuid.uuid4(),
        canonical_asset="api.target.com",
        port=443,
        normalized_path="/v1/users",
        detector_id="cve-2021-41773",
    )
    assert base_key != diff_prog

    # Different Asset Host
    diff_asset = compute_finding_dedup_key(
        program_id=prog_id,
        canonical_asset="staging.target.com",
        port=443,
        normalized_path="/v1/users",
        detector_id="cve-2021-41773",
    )
    assert base_key != diff_asset


# ============================================================================
# 2. Finding Normalizer Upsert and Evidence Linkage Tests
# ============================================================================


@pytest.mark.asyncio
async def test_normalizer_idempotent_finding_upsert():
    """Consecutive triggers of the same vulnerability on an endpoint update last_seen without duplicating records."""
    session = InMemoryAsyncSession()
    s3_store = InMemoryS3Store()
    normalizer = FindingNormalizer(db_session=session, s3_client=s3_store)

    program_id = uuid.uuid4()
    asset_id = uuid.uuid4()

    nuclei_result_run1 = [
        {
            "template-id": "cve-2021-41773",
            "info": {
                "name": "Apache Path Traversal",
                "severity": "high",
                "classification": {"cve-id": "CVE-2021-41773"},
            },
            "host": "https://api.target.com",
            "matched-at": "https://api.target.com:443/icons/.%2e/%2e%2e/etc/passwd",
            "request": "GET /icons/.%2e/%2e%2e/etc/passwd HTTP/1.1\r\nHost: api.target.com",
            "response": "HTTP/1.1 200 OK\r\n\r\nroot:x:0:0:root:/root:/bin/bash",
        }
    ]

    # Ingestion 1: First Run
    findings_run1 = await normalizer.normalize_and_persist(
        raw_nuclei_results=nuclei_result_run1,
        program_id=program_id,
        asset_id=asset_id,
    )
    assert len(findings_run1) == 1
    f1 = findings_run1[0]
    first_seen_t1 = f1.first_seen
    last_seen_t1 = f1.last_seen
    dedup_key_t1 = f1.dedup_key

    assert len(session.findings) == 1
    assert len(session.evidence) == 1

    # Ingestion 2: Second Run with identical finding coordinates
    nuclei_result_run2 = [
        {
            "template-id": "cve-2021-41773",
            "info": {
                "name": "Apache Path Traversal",
                "severity": "high",
                "classification": {"cve-id": "CVE-2021-41773"},
            },
            "host": "https://api.target.com",
            "matched-at": "https://api.target.com:443/icons/.%2e/%2e%2e/etc/passwd?t=123",
            "request": "GET /icons/.%2e/%2e%2e/etc/passwd HTTP/1.1\r\nHost: api.target.com",
            "response": "HTTP/1.1 200 OK\r\n\r\nroot:x:0:0:root:/root:/bin/bash",
        }
    ]

    findings_run2 = await normalizer.normalize_and_persist(
        raw_nuclei_results=nuclei_result_run2,
        program_id=program_id,
        asset_id=asset_id,
    )
    assert len(findings_run2) == 1
    f2 = findings_run2[0]

    # Total findings count MUST remain 1
    assert len(session.findings) == 1
    assert f2.id == f1.id
    assert f2.dedup_key == dedup_key_t1
    assert f2.first_seen == first_seen_t1
    assert f2.last_seen >= last_seen_t1

    # Evidence count increases to 2 (one evidence artifact per scan run)
    assert len(session.evidence) == 2
    assert session.evidence[0].finding_id == f1.id
    assert session.evidence[1].finding_id == f1.id


@pytest.mark.asyncio
async def test_normalizer_distinct_endpoints_produce_distinct_findings():
    """Different endpoints produce distinct Finding records with distinct dedup keys."""
    session = InMemoryAsyncSession()
    s3_store = InMemoryS3Store()
    normalizer = FindingNormalizer(db_session=session, s3_client=s3_store)

    program_id = uuid.uuid4()
    asset_id = uuid.uuid4()

    nuclei_results = [
        {
            "template-id": "apache-detect",
            "info": {"severity": "info"},
            "matched-at": "https://api.target.com:443/users",
        },
        {
            "template-id": "apache-detect",
            "info": {"severity": "info"},
            "matched-at": "https://api.target.com:443/admin",
        },
    ]

    findings = await normalizer.normalize_and_persist(
        raw_nuclei_results=nuclei_results,
        program_id=program_id,
        asset_id=asset_id,
    )

    assert len(findings) == 2
    assert findings[0].dedup_key != findings[1].dedup_key
    assert len(session.findings) == 2


@pytest.mark.asyncio
async def test_normalizer_evidence_redaction_and_s3_upload():
    """Sensitive tokens and cookies are redacted before uploading evidence to SeaweedFS S3."""
    session = InMemoryAsyncSession()
    s3_store = InMemoryS3Store()
    redactor = Redactor()
    normalizer = FindingNormalizer(
        db_session=session,
        s3_client=s3_store,
        redactor=redactor,
    )

    program_id = uuid.uuid4()
    asset_id = uuid.uuid4()

    secret_bearer = "eyJhbGciOiJIUzI1NiJ9.secret_jwt_token_value.signature"
    secret_cookie = "session_id=12345secret; remember_me=true"

    raw_request = (
        f"GET /admin/debug HTTP/1.1\r\n"
        f"Host: secure.target.com\r\n"
        f"Authorization: Bearer {secret_bearer}\r\n"
        f"Cookie: {secret_cookie}\r\n"
        f"\r\n"
    )
    raw_response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nDebug Session Active"

    results = [
        {
            "template-id": "admin-debug-leak",
            "info": {"severity": "high"},
            "matched-at": "https://secure.target.com/admin/debug",
            "request": raw_request,
            "response": raw_response,
        }
    ]

    findings = await normalizer.normalize_and_persist(
        raw_nuclei_results=results,
        program_id=program_id,
        asset_id=asset_id,
    )

    assert len(findings) == 1
    assert len(session.evidence) == 1
    ev: Evidence = session.evidence[0]

    assert ev.finding_id == findings[0].id
    assert ev.redaction_profile == "bounty-safe-v1"
    assert ev.original_sha256 is not None
    assert ev.sanitized_sha256 is not None
    # Original and sanitized digests must differ due to redaction
    assert ev.original_sha256 != ev.sanitized_sha256

    # Verify S3 store contents
    assert s3_store.has_object("evidence", ev.seaweed_object_key)
    artifact_bytes = s3_store.get_object("evidence", ev.seaweed_object_key)
    artifact_json = json.loads(artifact_bytes.decode("utf-8"))

    # Credential assertions: Secret tokens MUST NOT appear in the saved artifact
    assert secret_bearer not in artifact_bytes.decode("utf-8")
    assert "12345secret" not in artifact_bytes.decode("utf-8")

    # Redacted values MUST appear in the saved artifact
    sanitized_req = artifact_json["request"]
    assert "Authorization: Bearer [REDACTED]" in sanitized_req
    assert "Cookie: session_id=[REDACTED]; remember_me=[REDACTED]" in sanitized_req


@pytest.mark.asyncio
async def test_normalizer_reopen_remediated_finding():
    """A finding previously marked as remediated or resolved is automatically reopened upon redetection."""
    session = InMemoryAsyncSession()
    s3_store = InMemoryS3Store()
    normalizer = FindingNormalizer(db_session=session, s3_client=s3_store)

    program_id = uuid.uuid4()
    asset_id = uuid.uuid4()

    results = [
        {
            "template-id": "xss-reflected",
            "info": {"severity": "medium"},
            "matched-at": "https://api.target.com/search",
        }
    ]

    # Ingestion 1
    findings = await normalizer.normalize_and_persist(
        raw_nuclei_results=results,
        program_id=program_id,
        asset_id=asset_id,
    )
    finding = findings[0]
    assert finding.status == FindingStatus.VALIDATED.value

    # Simulate manual analyst marking finding as REMEDIATED
    finding.status = FindingStatus.REMEDIATED.value

    # Ingestion 2: Vulnerability detected again
    re_detected = await normalizer.normalize_and_persist(
        raw_nuclei_results=results,
        program_id=program_id,
        asset_id=asset_id,
    )

    assert len(re_detected) == 1
    # Status MUST transition to REOPENED
    assert re_detected[0].status == FindingStatus.REOPENED.value


@pytest.mark.asyncio
async def test_normalizer_batch_with_identical_findings_in_same_run():
    """Handles multiple duplicate results in the same batch gracefully without integrity collision."""
    session = InMemoryAsyncSession()
    normalizer = FindingNormalizer(db_session=session)

    program_id = uuid.uuid4()
    asset_id = uuid.uuid4()

    # Raw results containing two identical entries in the exact same batch
    duplicate_results = [
        {
            "template-id": "dup-check",
            "info": {"severity": "low"},
            "matched-at": "https://api.target.com/test",
            "request": "GET /test HTTP/1.1",
        },
        {
            "template-id": "dup-check",
            "info": {"severity": "low"},
            "matched-at": "https://api.target.com/test",
            "request": "GET /test HTTP/1.1",
        },
    ]

    findings = await normalizer.normalize_and_persist(
        raw_nuclei_results=duplicate_results,
        program_id=program_id,
        asset_id=asset_id,
    )

    # Deduped to 1 finding in database session
    assert len(findings) == 1
    assert len(session.findings) == 1
    # 2 Evidence records attached to the single finding
    assert len(session.evidence) == 2
    assert session.evidence[0].finding_id == findings[0].id
    assert session.evidence[1].finding_id == findings[0].id
