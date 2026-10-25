from __future__ import annotations

import hashlib
import uuid

import httpx
import pytest
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.testclient import TestClient

from pentefino_api.main import app
from pentefino_domain.models.asset import Asset
from pentefino_domain.models.evidence import Evidence
from pentefino_domain.models.finding import Finding
from pentefino_domain.models.program import Program
from pentefino_domain.models.template import TemplateCatalog


@pytest.mark.asyncio
async def test_findings_lifecycle_and_markdown_report(
    async_client: httpx.AsyncClient,
    db_session: AsyncSession,
    test_slug: str,
) -> None:
    """Verify GET /findings, GET /findings/{id}, PATCH /findings/{id}/status, and GET /findings/{id}/report."""
    detector_id = "pytest-http/cves/2021/CVE-2021-41773.yaml"
    existing_tpl = await db_session.execute(
        select(TemplateCatalog).where(TemplateCatalog.id == detector_id)
    )
    created_tpl = False
    if existing_tpl.scalar_one_or_none() is None:
        db_session.add(
            TemplateCatalog(
                id=detector_id,
                upstream_revision="pytest-rev-1",
                bundle_hash="c" * 64,
                name="Apache 2.4.49 Path Traversal Check",
                protocol="http",
                http_methods=["GET"],
                impact_class="safe_read_only",
                cve_id="CVE-2021-41773",
                cwe_id="CWE-22",
                severity="high",
                technologies=["apache"],
                tags=["cve", "apache"],
                raw_yaml="id: CVE-2021-41773\n",
            )
        )
        await db_session.flush()
        created_tpl = True

    prog = Program(
        slug=test_slug,
        name="Findings Triage Test Program",
        platform="hackerone",
        state="active",
        default_policy_id="bounty-safe",
    )
    db_session.add(prog)
    await db_session.flush()

    asset = Asset(
        program_id=prog.id,
        canonical_key="vuln.example.org",
        asset_type="domain",
        scope_state="in_scope_explicit",
    )
    db_session.add(asset)
    await db_session.flush()

    dedup_sha256 = hashlib.sha256(
        f"{prog.id}:{asset.id}:{detector_id}".encode("utf-8")
    ).hexdigest()
    orig_sha256 = hashlib.sha256(b"raw-http-interaction").hexdigest()
    sanitized_sha256 = hashlib.sha256(b"sanitized-http-interaction").hexdigest()

    finding = Finding(
        program_id=prog.id,
        asset_id=asset.id,
        dedup_key=dedup_sha256,
        detector_id=detector_id,
        advisory_id="CVE-2021-41773",
        status="candidate",
        evidence_level="E2",
        confidence="high",
    )
    db_session.add(finding)
    await db_session.flush()

    ev = Evidence(
        finding_id=finding.id,
        run_id=uuid.uuid4(),
        evidence_type="http_interaction",
        original_sha256=orig_sha256,
        sanitized_sha256=sanitized_sha256,
        seaweed_object_key=f"s3://evidence/{finding.id}/sanitized.json",
        redaction_profile="bounty-safe-v1",
    )
    db_session.add(ev)
    await db_session.commit()

    finding_id_str = str(finding.id)

    try:
        # 1. GET /api/v1/findings
        list_res = await async_client.get(
            f"/api/v1/findings?program_slug={test_slug}&evidence_level=E2"
        )
        assert list_res.status_code == 200
        items = list_res.json()
        assert len(items) == 1
        assert items[0]["id"] == finding_id_str
        assert items[0]["dedup_key"] == dedup_sha256
        assert items[0]["evidence_level"] == "E2"

        # 2. GET /api/v1/findings/{id}
        detail_res = await async_client.get(f"/api/v1/findings/{finding_id_str}")
        assert detail_res.status_code == 200
        detail = detail_res.json()
        assert detail["id"] == finding_id_str
        assert len(detail["evidence_items"]) == 1
        assert detail["evidence_items"][0]["sanitized_sha256"] == sanitized_sha256

        # 3. PATCH /api/v1/findings/{id}/status
        patch_res = await async_client.patch(
            f"/api/v1/findings/{finding_id_str}/status",
            json={"status": "validated"},
        )
        assert patch_res.status_code == 200
        assert patch_res.json()["status"] == "validated"

        # 4. GET /api/v1/findings/{id}/report
        report_res = await async_client.get(f"/api/v1/findings/{finding_id_str}/report")
        assert report_res.status_code == 200
        report = report_res.json()
        assert report["finding_id"] == finding_id_str
        md = report["markdown"]
        assert dedup_sha256 in md
        assert sanitized_sha256 in md
        assert "curl " in md
        assert "vuln.example.org" in md
    finally:
        await db_session.execute(delete(Finding).where(Finding.id == finding.id))
        await db_session.commit()
        if created_tpl:
            await db_session.execute(
                delete(TemplateCatalog).where(TemplateCatalog.id == detector_id)
            )
            await db_session.commit()


def test_websocket_scan_and_proxy_telemetry_streams() -> None:
    """Verify WebSocket connections to /ws/scans/{plan_id} and /ws/proxy/live using Starlette TestClient."""
    plan_id = f"plan-{uuid.uuid4().hex[:8]}"
    with TestClient(app) as client:
        # 1. Test /ws/scans/{plan_id}
        with client.websocket_connect(f"/ws/scans/{plan_id}") as ws_scan:
            connected_msg = ws_scan.receive_json()
            assert connected_msg["event"] == "connected"
            assert connected_msg["plan_id"] == plan_id

            ws_scan.send_text("ping")
            pong_msg = ws_scan.receive_json()
            assert pong_msg["event"] == "pong"
            assert pong_msg["plan_id"] == plan_id

        # 2. Test /ws/proxy/live
        with client.websocket_connect("/ws/proxy/live") as ws_proxy:
            init_msg = ws_proxy.receive_json()
            assert init_msg["event"] == "connected"
            assert init_msg["channel"] == "proxy_telemetry"

            tick_msg = ws_proxy.receive_json()
            assert tick_msg["event"] == "telemetry_tick"
            assert tick_msg["rate_limit_rps"] in (0.5, 10.0)
            assert tick_msg["mode"] == "fail-closed"

            ws_proxy.send_text("ping")
            pong_proxy = None
            for _ in range(10):
                msg = ws_proxy.receive_json()
                if msg.get("event") == "pong":
                    pong_proxy = msg
                    break
            assert pong_proxy is not None
            assert pong_proxy["event"] == "pong"
