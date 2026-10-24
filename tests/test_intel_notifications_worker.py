"""Tests for Phase 1 & Phase 2 security remediations and subsystems:
- StaticTemplateClassifier active probe / OAST hardening & file_path preservation
- DetectionPlanner relative file_path resolution & HardenedNucleiRunner -irr flag
- ScopeGuard & ForwardProxyServer anti-TOCTOU DNS IP pinning
- FastAPI X-PenteFino-Key authentication enforcement
- ThreatIntelEnricher (packages/intel)
- NotificationDispatcher (packages/notifications)
- ScanTaskWorker (apps/worker) fail-closed scope enforcement
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
import uuid

import httpx
from httpx import ASGITransport
import pytest

from pentefino_api.main import create_app
from pentefino_detection import DetectionPlanner, HardenedNucleiRunner
from pentefino_domain.enums import ImpactClass
from pentefino_domain.models.asset import Asset
from pentefino_domain.models.program import Program
from pentefino_domain.models.template import TemplateCatalog
from pentefino_intel import ThreatIntelEnricher
from pentefino_notifications import NotificationDispatcher, SanitizedFindingAlert
from pentefino_proxy.scope_guard import ScopeGuard
from pentefino_runner import EphemeralRunner, RunResult
from pentefino_scope import (
    AssetType,
    AuthorizationSnapshot,
    ScopeAction,
    ScopeEngine,
    ScopeRule,
)
from pentefino_template_indexer import StaticTemplateClassifier
from pentefino_worker import ScanTaskJob, ScanTaskWorker


# ==============================================================================
# 1. Template Classifier Hardening & Relative file_path Resolution
# ==============================================================================


def test_classifier_downgrades_get_sqli_and_oast_to_active_reviewed():
    classifier = StaticTemplateClassifier()

    sqli_get_yaml = """
id: custom-get-sqli
info:
  name: Active GET SQL Injection Probe
  severity: high
  tags: cve,sqli,apache
http:
  - method: GET
    path:
      - "{{BaseURL}}/item.php?id=1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--"
"""
    meta_sqli = classifier.classify_yaml(
        sqli_get_yaml, file_path="http/cves/2024/custom-get-sqli.yaml"
    )
    assert meta_sqli.impact_class == ImpactClass.ACTIVE_REVIEWED
    assert meta_sqli.file_path == "http/cves/2024/custom-get-sqli.yaml"

    oast_get_yaml = """
id: custom-get-ssrf-oast
info:
  name: Out-of-Band SSRF Check
  severity: high
  tags: exposure,apache
http:
  - method: GET
    path:
      - "{{BaseURL}}/proxy?url=http://{{interactsh-url}}"
"""
    meta_oast = classifier.classify_yaml(oast_get_yaml)
    assert meta_oast.impact_class == ImpactClass.ACTIVE_REVIEWED


@pytest.mark.asyncio
async def test_planner_uses_template_file_path_and_runner_includes_irr():
    planner = DetectionPlanner(templates_container_dir="/templates")
    tpl = TemplateCatalog(
        id="CVE-2021-41773",
        file_path="http/cves/2021/CVE-2021-41773.yaml",
        upstream_revision="abc1234",
        bundle_hash="a" * 64,
        name="Apache 2.4.49 Path Traversal",
        protocol="http",
        http_methods=["GET"],
        impact_class=ImpactClass.SAFE_READ_ONLY.value,
        cve_id="CVE-2021-41773",
        severity="high",
        technologies=["apache"],
        tags=["cve", "apache"],
        raw_yaml="id: CVE-2021-41773",
    )

    plan = await planner.create_plan(
        asset="scanme.nmap.org",
        detected_technologies=["apache", "cloudflare"],
        templates=[tpl],
    )
    assert plan.selected_template_ids == ["CVE-2021-41773"]
    assert plan.selected_template_paths == [
        "/templates/http/cves/2021/CVE-2021-41773.yaml"
    ]

    mock_runner = MagicMock(spec=EphemeralRunner)
    nuclei = HardenedNucleiRunner(runner=mock_runner)
    run_cfg = nuclei.build_run_config(plan)
    assert "-irr" in run_cfg.command
    assert "/templates/http/cves/2021/CVE-2021-41773.yaml" in run_cfg.command


# ==============================================================================
# 2. ScopeGuard Anti-TOCTOU DNS IP Pinning
# ==============================================================================


def test_scope_guard_pins_resolved_ip_on_allowed_decision():
    prog_id = uuid.uuid4()
    now = datetime.now(timezone.utc)
    snap = AuthorizationSnapshot(
        program_id=prog_id,
        policy_hash="f" * 64,
        rules_json={},
        valid_from=now - timedelta(days=1),
        valid_until=now + timedelta(days=30),
    )
    rules = [
        ScopeRule(
            program_id=prog_id,
            asset_type=AssetType.HOSTNAME,
            pattern="scanme.nmap.org",
            action=ScopeAction.ALLOW,
        )
    ]
    engine = ScopeEngine(snapshot=snap, rules=rules)
    guard = ScopeGuard(default_engine=engine, environment_class="bounty")

    decision = guard.evaluate(
        url="https://scanme.nmap.org/",
        method="CONNECT",
        resolved_ips=["45.33.32.156"],
        check_dns=True,
    )
    assert decision.allowed is True
    assert decision.resolved_ip == "45.33.32.156"


# ==============================================================================
# 3. FastAPI X-PenteFino-Key Optional Auth Enforcement
# ==============================================================================


@pytest.mark.asyncio
async def test_api_key_authentication_when_configured(monkeypatch):
    monkeypatch.setenv("PENTEFINO_API_KEY", "super-secret-ops-key")
    test_app = create_app()
    transport = ASGITransport(app=test_app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Missing key -> 401
        r_unauth = await client.get("/api/v1/scans/history")
        assert r_unauth.status_code == 401

        # Wrong key -> 401
        r_wrong = await client.get(
            "/api/v1/scans/history", headers={"X-PenteFino-Key": "wrong-key"}
        )
        assert r_wrong.status_code == 401


# ==============================================================================
# 4. ThreatIntelEnricher (packages/intel)
# ==============================================================================


@pytest.mark.asyncio
async def test_threat_intel_enricher_kev_and_epss():
    def mock_handler(request: httpx.Request) -> httpx.Response:
        if "epss" in str(request.url):
            return httpx.Response(
                200,
                json={
                    "status": "OK",
                    "data": [
                        {
                            "cve": "CVE-2021-41773",
                            "epss": "0.9742",
                            "percentile": "0.9991",
                        }
                    ],
                },
            )
        if "osv.dev" in str(request.url):
            return httpx.Response(
                200,
                json={
                    "vulns": [
                        {
                            "id": "GHSA-xxxx-yyyy-zzzz",
                            "summary": "Apache Path Traversal",
                            "aliases": ["CVE-2021-41773"],
                        }
                    ]
                },
            )
        return httpx.Response(404)

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(mock_handler))
    enricher = ThreatIntelEnricher(http_client=mock_client)

    res = await enricher.enrich_cve("CVE-2021-41773")
    assert res.cve_id == "CVE-2021-41773"
    assert res.in_cisa_kev is True
    assert res.epss_score == pytest.approx(0.9742)
    assert res.priority_tier == "critical_kev"

    osv_list = await enricher.query_osv("apache2", "2.4.49", ecosystem="Debian")
    assert len(osv_list) == 1
    assert "CVE-2021-41773" in osv_list[0].aliases
    await mock_client.aclose()


# ==============================================================================
# 5. NotificationDispatcher (packages/notifications)
# ==============================================================================


@pytest.mark.asyncio
async def test_notification_dispatcher_redacts_secrets_and_signs_hmac():
    captured_requests: list[httpx.Request] = []

    def mock_webhook(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        return httpx.Response(200, json={"ok": True})

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(mock_webhook))
    dispatcher = NotificationDispatcher(
        signing_secret="webhook-hmac-secret",
        http_client=mock_client,
    )

    alert = SanitizedFindingAlert(
        program_slug="nmap-scanme",
        canonical_key="scanme.nmap.org",
        detector_id="CVE-2021-41773",
        severity="high",
        evidence_level="E2",
        dedup_key="a" * 64,
        advisory_id="CVE-2021-41773",
        summary="Header leaked: Bearer eyJhbGciOiJIUzI1NiJ9.secretpayload",
    )

    ok = await dispatcher.send_webhook(
        "https://hooks.example.com/pentefino", alert, provider="slack"
    )
    assert ok is True
    assert len(captured_requests) == 1
    req = captured_requests[0]
    assert req.headers.get("X-PenteFino-Signature-256", "").startswith("sha256=")
    body_text = req.content.decode("utf-8")
    assert "eyJhbGciOiJIUzI1NiJ9" not in body_text
    assert "[REDACTED]" in body_text
    await mock_client.aclose()


# ==============================================================================
# 6. ScanTaskWorker (apps/worker) Fail-Closed Scope Gate
# ==============================================================================


@pytest.mark.asyncio
async def test_scan_task_worker_rejects_out_of_scope_asset():
    prog_id = uuid.uuid4()
    prog = Program(id=prog_id, name="Test Prog", slug="test-prog", state="active")
    out_of_scope_asset = Asset(
        id=uuid.uuid4(),
        program_id=prog_id,
        canonical_key="forbidden.example.com",
        asset_type="hostname",
        scope_state="out_of_scope",
    )

    mock_session = AsyncMock()
    res_prog = MagicMock()
    res_prog.scalar_one_or_none.return_value = prog
    res_asset = MagicMock()
    res_asset.scalar_one_or_none.return_value = out_of_scope_asset
    mock_session.execute.side_effect = [res_prog, res_asset]

    mock_runner = MagicMock(spec=EphemeralRunner)
    mock_runner.run = AsyncMock(
        return_value=RunResult(exit_code=0, stdout="", stderr="")
    )

    worker = ScanTaskWorker(db_session=mock_session, runner=mock_runner)
    job = ScanTaskJob(program_slug="test-prog", target_asset="forbidden.example.com")
    outcome = await worker.process_job(job)

    assert outcome["status"] == "rejected_out_of_scope"
    assert "Hard-Gate Fail-Closed" in outcome["error"]
    mock_runner.run.assert_not_called()
