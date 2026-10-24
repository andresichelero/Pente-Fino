"""Comprehensive Phase B Test Suite.

Verifies:
1. Threat Intel Integration in FindingNormalizer:
   - Enriching findings with EPSS score, percentile, CISA KEV status, priority tier
   - Automated webhook dispatch on critical or KEV findings
   - SanitizedFindingAlert generation and secret redaction
2. Threat Intel Integration in DetectionPlanner:
   - OSV package/version technology query and template correlation
   - Elevation of execution priority for CISA KEV and high EPSS templates
3. Webhook Notification Dispatcher & dispatch_finding_alert helper:
   - HMAC-SHA256 request signing
   - Slack, Discord, and Generic formatting
   - Destination URL routing
4. CLI `pentefino intel sync`:
   - Typer CliRunner invoking `pentefino intel sync --offline --json`
   - Rich table output verification
5. API `POST /api/v1/intel/sync`:
   - Endpoint invocation, status verification, synced CVE count and timestamp
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from unittest.mock import AsyncMock, MagicMock, patch
import uuid

from fastapi.testclient import TestClient
import httpx
import pytest
from typer.testing import CliRunner

from pentefino_api.main import create_app
from pentefino_cli.main import app as cli_app
from pentefino_detection.normalizer import FindingNormalizer
from pentefino_detection.planner import DetectionPlan, DetectionPlanner
from pentefino_domain.enums import ImpactClass
from pentefino_domain.models.finding import Finding
from pentefino_domain.models.template import TemplateCatalog
from pentefino_intel.enricher import (
    BASELINE_CISA_KEV_CVES,
    CveEnrichmentResult,
    OsvVulnerabilityRecord,
    ThreatIntelEnricher,
)
from pentefino_notifications.dispatcher import (
    NotificationDispatcher,
    SanitizedFindingAlert,
    dispatch_finding_alert,
)


def make_template(
    id: str,
    name: str,
    impact_class: str = ImpactClass.SAFE_READ_ONLY.value,
    severity: str = "high",
    technologies: list[str] | None = None,
    tags: list[str] | None = None,
    cve_id: str | None = None,
    file_path: str | None = None,
) -> TemplateCatalog:
    """Helper factory for creating TemplateCatalog records."""
    return TemplateCatalog(
        id=id,
        name=name,
        upstream_revision="sha256-rev-12345",
        bundle_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        protocol="http",
        http_methods=["GET"],
        impact_class=impact_class,
        severity=severity,
        technologies=technologies or [],
        tags=tags or [],
        cve_id=cve_id,
        file_path=file_path or f"http/cves/{id}.yaml",
        raw_yaml=f"id: {id}\ninfo:\n  name: {name}\n",
    )


# ==============================================================================
# 1. FindingNormalizer Threat Intel Auto-Enrichment Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_normalizer_enriches_cisa_kev_finding():
    """FindingNormalizer enriches findings matching CISA KEV with critical_kev tier."""
    mock_session = AsyncMock()
    mock_session.add = MagicMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value.first.return_value = None
    mock_session.execute.return_value = mock_result

    # Mock enricher returning CISA KEV telemetry
    mock_enricher = AsyncMock(spec=ThreatIntelEnricher)
    mock_enricher.enrich_cve.return_value = CveEnrichmentResult(
        cve_id="CVE-2021-41773",
        epss_score=0.9742,
        epss_percentile=0.9991,
        in_cisa_kev=True,
        priority_tier="critical_kev",
        source="live",
    )

    mock_dispatcher = AsyncMock(spec=NotificationDispatcher)
    mock_dispatcher.send_webhook.return_value = True

    normalizer = FindingNormalizer(
        db_session=mock_session,
        enricher=mock_enricher,
        notification_dispatcher=mock_dispatcher,
    )

    raw_results = [
        {
            "template-id": "cve-2021-41773",
            "matched-at": "https://targets.example.com/cgi-bin/.%2e/.%2e/bin/sh",
            "info": {
                "name": "Apache 2.4.49 Path Traversal",
                "severity": "critical",
                "classification": {"cve-id": ["CVE-2021-41773"]},
            },
            "type": "http",
        }
    ]

    prog_id = uuid.uuid4()
    findings = await normalizer.normalize_and_persist(
        raw_nuclei_results=raw_results,
        program_id=prog_id,
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.in_cisa_kev is True
    assert f.epss_score == pytest.approx(0.9742)
    assert f.epss_percentile == pytest.approx(0.9991)
    assert f.priority_tier == "critical_kev"
    mock_enricher.enrich_cve.assert_awaited_once_with("CVE-2021-41773")

    # Verify automated webhook dispatch was triggered
    mock_dispatcher.send_webhook.assert_awaited_once()
    call_args = mock_dispatcher.send_webhook.await_args
    assert call_args is not None
    alert = call_args[0][1]
    assert isinstance(alert, SanitizedFindingAlert)
    assert alert.detector_id == "cve-2021-41773"
    assert alert.advisory_id == "CVE-2021-41773"


@pytest.mark.asyncio
async def test_normalizer_enriches_non_kev_low_epss_finding():
    """Findings without CISA KEV or high EPSS receive 'standard' priority tier."""
    mock_session = AsyncMock()
    mock_session.add = MagicMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value.first.return_value = None
    mock_session.execute.return_value = mock_result

    mock_enricher = AsyncMock(spec=ThreatIntelEnricher)
    mock_enricher.enrich_cve.return_value = CveEnrichmentResult(
        cve_id="CVE-2020-99999",
        epss_score=0.015,
        epss_percentile=0.45,
        in_cisa_kev=False,
        priority_tier="standard",
        source="live",
    )

    mock_dispatcher = AsyncMock(spec=NotificationDispatcher)

    normalizer = FindingNormalizer(
        db_session=mock_session,
        enricher=mock_enricher,
        notification_dispatcher=mock_dispatcher,
    )

    raw_results = [
        {
            "template-id": "cve-2020-99999",
            "matched-at": "https://targets.example.com/item",
            "info": {
                "name": "Standard Flaw",
                "severity": "medium",
                "classification": {"cve-id": "CVE-2020-99999"},
            },
            "type": "http",
        }
    ]

    findings = await normalizer.normalize_and_persist(
        raw_nuclei_results=raw_results,
        program_id=uuid.uuid4(),
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.in_cisa_kev is False
    assert f.priority_tier == "standard"
    # Webhook should NOT be dispatched for standard findings
    mock_dispatcher.send_webhook.assert_not_awaited()


@pytest.mark.asyncio
async def test_normalizer_handles_finding_without_cve():
    """Findings without CVE IDs receive standard priority and no KEV flag."""
    mock_session = AsyncMock()
    mock_session.add = MagicMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value.first.return_value = None
    mock_session.execute.return_value = mock_result

    normalizer = FindingNormalizer(db_session=mock_session)

    raw_results = [
        {
            "template-id": "generic-header-leak",
            "matched-at": "https://targets.example.com/",
            "info": {
                "name": "Server Header Disclosure",
                "severity": "info",
            },
            "type": "http",
        }
    ]

    findings = await normalizer.normalize_and_persist(
        raw_nuclei_results=raw_results,
        program_id=uuid.uuid4(),
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.in_cisa_kev is False
    assert f.epss_score is None
    assert f.priority_tier == "standard"


# ==============================================================================
# 2. Automated Webhook Alert Dispatch & Secret Redaction Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_webhook_dispatch_on_high_epss_finding():
    """Findings with high EPSS score (>= 0.50) trigger automated webhook dispatch."""
    mock_session = AsyncMock()
    mock_session.add = MagicMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value.first.return_value = None
    mock_session.execute.return_value = mock_result

    mock_enricher = AsyncMock(spec=ThreatIntelEnricher)
    mock_enricher.enrich_cve.return_value = CveEnrichmentResult(
        cve_id="CVE-2023-9999",
        epss_score=0.82,
        epss_percentile=0.96,
        in_cisa_kev=False,
        priority_tier="high_epss",
    )

    mock_dispatcher = AsyncMock(spec=NotificationDispatcher)
    mock_dispatcher.send_webhook.return_value = True

    normalizer = FindingNormalizer(
        db_session=mock_session,
        enricher=mock_enricher,
        notification_dispatcher=mock_dispatcher,
        webhook_urls=["https://custom-webhook.example.com/alerts"],
    )

    raw_results = [
        {
            "template-id": "cve-2023-9999",
            "matched-at": "https://targets.example.com/admin",
            "info": {
                "name": "High EPSS Vulnerability",
                "severity": "high",
                "classification": {"cve-id": "CVE-2023-9999"},
            },
        }
    ]

    findings = await normalizer.normalize_and_persist(
        raw_nuclei_results=raw_results,
        program_id=uuid.uuid4(),
    )

    assert len(findings) == 1
    assert findings[0].priority_tier == "high_epss"
    mock_dispatcher.send_webhook.assert_awaited_once()
    assert mock_dispatcher.send_webhook.await_args[0][0] == "https://custom-webhook.example.com/alerts"


@pytest.mark.asyncio
async def test_dispatch_finding_alert_helper():
    """dispatch_finding_alert helper signs requests and redacts tokens."""
    captured: list[httpx.Request] = []

    def mock_transport(req: httpx.Request) -> httpx.Response:
        captured.append(req)
        return httpx.Response(200, json={"ok": True})

    client = httpx.AsyncClient(transport=httpx.MockTransport(mock_transport))

    f = Finding(
        id=uuid.uuid4(),
        program_id=uuid.uuid4(),
        asset_id=uuid.uuid4(),
        dedup_key="d" * 64,
        detector_id="CVE-2021-41773",
        advisory_id="CVE-2021-41773",
        status="validated",
        evidence_level="E2",
        confidence="high",
        epss_score=0.97,
        in_cisa_kev=True,
        priority_tier="critical_kev",
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
    )

    destinations = [
        "https://hooks.slack.com/services/T00/B00/X00",
        "https://generic.example.com/webhook",
    ]

    results = await dispatch_finding_alert(
        finding=f,
        destination_urls=destinations,
        webhook_secret="hmac-secret-test",
        http_client=client,
    )

    assert len(results) == 2
    assert all(results.values())
    assert len(captured) == 2

    # Check HMAC signature on both requests
    for req in captured:
        assert "X-PenteFino-Signature-256" in req.headers
        assert req.headers["X-PenteFino-Signature-256"].startswith("sha256=")

    # Slack formatted request verification
    slack_body = json.loads(captured[0].content)
    assert "blocks" in slack_body
    assert "CVE-2021-41773" in slack_body["text"]

    # Generic formatted request verification
    generic_body = json.loads(captured[1].content)
    assert generic_body["event"] == "finding.alert"
    assert generic_body["detector_id"] == "CVE-2021-41773"

    await client.aclose()


# ==============================================================================
# 3. DetectionPlanner CISA KEV & OSV Prioritization Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_planner_elevates_cisa_kev_template_execution_priority():
    """Templates covering CISA KEV receive priority rank 0 and run before standard templates."""
    mock_enricher = AsyncMock(spec=ThreatIntelEnricher)

    # Set up enricher: CVE-2021-41773 is KEV, CVE-2020-0001 is standard
    async def mock_enrich_cve(cve_id: str) -> CveEnrichmentResult:
        if cve_id == "CVE-2021-41773":
            return CveEnrichmentResult(
                cve_id="CVE-2021-41773",
                in_cisa_kev=True,
                epss_score=0.97,
                priority_tier="critical_kev",
            )
        return CveEnrichmentResult(
            cve_id=cve_id,
            in_cisa_kev=False,
            epss_score=0.02,
            priority_tier="standard",
        )

    mock_enricher.enrich_cve.side_effect = mock_enrich_cve
    mock_enricher.query_osv = AsyncMock(return_value=[])

    planner = DetectionPlanner(enricher=mock_enricher)

    # Catalog where KEV template is listed last
    catalog = [
        make_template("apache-banner", "Apache Banner Detect", technologies=["apache"]),
        make_template("cve-2020-0001", "Standard Apache Flaw", technologies=["apache"], cve_id="CVE-2020-0001"),
        make_template("cve-2021-41773", "Apache Path Traversal", technologies=["apache"], cve_id="CVE-2021-41773"),
    ]

    plan = await planner.create_plan(
        asset="target.example.com",
        detected_technologies=["apache"],
        templates=catalog,
    )

    # KEV template (CVE-2021-41773) MUST be elevated to index 0 of the execution plan
    assert len(plan.selected_template_ids) == 3
    assert plan.selected_template_ids[0] == "cve-2021-41773"
    assert "cve-2021-41773" in plan.selected_template_paths[0].lower()


@pytest.mark.asyncio
async def test_planner_osv_version_query_matches_templates():
    """Planner queries OSV for software packages with versions and correlates templates."""
    mock_enricher = AsyncMock(spec=ThreatIntelEnricher)
    mock_enricher.query_osv.return_value = [
        OsvVulnerabilityRecord(
            id="GHSA-2449-path-traversal",
            summary="Apache 2.4.49 Traversal",
            aliases=["CVE-2021-41773"],
        )
    ]
    mock_enricher.enrich_cve.return_value = CveEnrichmentResult(
        cve_id="CVE-2021-41773",
        in_cisa_kev=True,
        epss_score=0.97,
        priority_tier="critical_kev",
    )

    planner = DetectionPlanner(enricher=mock_enricher)

    tpl_kev = make_template(
        "cve-2021-41773",
        "Apache Path Traversal",
        technologies=["apache"],
        cve_id="CVE-2021-41773",
    )

    plan = await planner.create_plan(
        asset="app.example.com",
        detected_technologies=["apache 2.4.49"],
        templates=[tpl_kev],
    )

    mock_enricher.query_osv.assert_awaited_once_with("apache", "2.4.49")
    assert plan.selected_template_ids == ["cve-2021-41773"]
    assert plan.total_templates == 1


# ==============================================================================
# 4. CLI pentefino intel sync Tests
# ==============================================================================


def test_cli_intel_sync_json_offline():
    """CLI `pentefino intel sync --offline --json` produces valid JSON threat feed status."""
    runner = CliRunner()
    result = runner.invoke(cli_app, ["intel", "sync", "--offline", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["status"] == "ok"
    assert data["kev_count"] >= len(BASELINE_CISA_KEV_CVES)
    assert "CISA_KEV" in data["feeds"]
    assert "FIRST_EPSS_V4" in data["feeds"]


def test_cli_intel_sync_table_output():
    """CLI `pentefino intel sync --offline` displays formatted Rich table."""
    runner = CliRunner()
    result = runner.invoke(cli_app, ["intel", "sync", "--offline"])
    assert result.exit_code == 0
    output = result.output
    assert "PenteFino Threat Intelligence Feeds" in output
    assert "CISA KEV" in output
    assert "FIRST EPSS v4" in output
    assert "SYNCHRONIZED" in output


def test_cli_intel_status_command():
    """CLI `pentefino intel status --json` displays operational metrics."""
    runner = CliRunner()
    result = runner.invoke(cli_app, ["intel", "status", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["status"] == "ok"
    assert data["cisa_kev_baseline_count"] >= 8
    assert data["epss_version"] == "v4"


# ==============================================================================
# 5. API POST /api/v1/intel/sync Tests
# ==============================================================================


def test_api_post_intel_sync_offline():
    """API endpoint POST /api/v1/intel/sync returns 200 with synced threat telemetry."""
    test_app = create_app()
    client = TestClient(test_app)

    response = client.post("/api/v1/intel/sync?offline=true")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["kev_count"] >= len(BASELINE_CISA_KEV_CVES)
    assert payload["synced_cve_count"] >= 8
    assert "CISA_KEV" in payload["feeds"]
    assert "synced_at" in payload


def test_api_get_intel_status():
    """API endpoint GET /api/v1/intel/status returns telemetry overview."""
    test_app = create_app()
    client = TestClient(test_app)

    response = client.get("/api/v1/intel/status")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["cisa_kev_baseline_count"] >= 8
    assert payload["epss_version"] == "v4"
    assert payload["osv_enabled"] is True
