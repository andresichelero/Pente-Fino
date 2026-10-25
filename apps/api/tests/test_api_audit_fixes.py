"""API regression tests for the review/opus-audit fixes (see REPORT.md)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from httpx import ASGITransport
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from pentefino_api import main as api_main
from pentefino_api.main import create_app
from pentefino_domain.models.asset import Asset
from pentefino_domain.models.authorization import AuthorizationSnapshot
from pentefino_domain.models.program import Program
from pentefino_domain.models.scope_rule import ScopeRule


def _planner_returning(template_ids: list[str]):
    """Planner stub: the real one depends on whatever catalog the dev database holds."""
    import uuid as _uuid
    from unittest.mock import MagicMock

    plan = MagicMock(
        plan_id=_uuid.uuid4(),
        selected_template_ids=template_ids,
        total_templates=len(template_ids),
        matched_technologies=[],
        target_url="https://lab.pentefino.test",
    )
    planner = MagicMock()
    planner.return_value.create_plan = AsyncMock(return_value=plan)
    return patch("pentefino_api.routers.scans.DetectionPlanner", planner)


async def _seed_program(db_session: AsyncSession, slug: str, *, with_auth: bool = True, allow: str | None = "lab.pentefino.test") -> Program:
    prog = Program(slug=slug, name=slug, platform="hackerone", state="active", default_policy_id="bounty-safe")
    db_session.add(prog)
    await db_session.flush()
    if with_auth:
        db_session.add(
            AuthorizationSnapshot(
                program_id=prog.id,
                source_url="https://pentefino.local/pytest",
                policy_hash="c" * 64,
                rules_json={"pytest": True},
                valid_from=datetime.now(timezone.utc) - timedelta(minutes=1),
            )
        )
    if allow:
        db_session.add(ScopeRule(program_id=prog.id, priority=10, asset_type="domain", pattern=allow, action="allow"))
    await db_session.commit()
    return prog


# ---------------------------------------------------------------------------
# Auth: fail-closed when PENTEFINO_API_KEY is unset
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_no_api_key_rejects_non_loopback_clients(monkeypatch) -> None:
    monkeypatch.delenv("PENTEFINO_API_KEY", raising=False)
    app = create_app()
    remote = ASGITransport(app=app, client=("10.20.30.40", 5555))
    async with httpx.AsyncClient(transport=remote, base_url="http://test") as client:
        res = await client.get("/api/v1/scans/circuit-breaker/status")
        assert res.status_code == 401
    local = ASGITransport(app=app, client=("127.0.0.1", 5555))
    async with httpx.AsyncClient(transport=local, base_url="http://test") as client:
        res = await client.get("/api/v1/scans/circuit-breaker/status")
        assert res.status_code == 200


def test_websocket_accepts_key_in_query_when_configured(monkeypatch) -> None:
    monkeypatch.setenv("PENTEFINO_API_KEY", "lab-test-key")
    app = create_app()
    with TestClient(app) as client:
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect("/ws/scans/abc") as ws:
                ws.receive_json()
        with client.websocket_connect("/ws/scans/abc?key=lab-test-key") as ws:
            assert ws.receive_json()["event"] == "connected"


# ---------------------------------------------------------------------------
# Standby and error mapping
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_standby_is_503_for_get_and_health_has_no_placeholder_counts(monkeypatch) -> None:
    async def db_down(*a, **k):
        return False

    monkeypatch.setattr("pentefino_api.deps.check_db_available", db_down)
    monkeypatch.setattr(api_main, "check_db_available", db_down)
    api_main._SNAPSHOT_CACHE.clear()
    app = create_app()
    async with httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/programs")
        assert res.status_code == 503
        assert res.json()["status"] == "standby"

        health = (await client.get("/api/v1/health")).json()
        assert health["database"] == "standby"
        assert health["templates_count"] is None and health["template_count"] is None
        assert health["db_latency_ms"] is None
    api_main._SNAPSHOT_CACHE.clear()


@pytest.mark.asyncio
async def test_oserror_with_db_up_is_a_real_500(monkeypatch) -> None:
    async def db_up(*a, **k):
        return True

    monkeypatch.setattr(api_main, "check_db_available", db_up)
    app = create_app()

    async def boom() -> None:
        raise ConnectionRefusedError("s3 down")

    app.add_api_route("/api/v1/_test/oserror", boom)
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/v1/_test/oserror")
    assert res.status_code == 500
    assert "standby" not in res.text


@pytest.mark.asyncio
async def test_telemetry_summary_has_no_fixed_series(async_client: httpx.AsyncClient) -> None:
    fake_live = {
        "generated_at": 1.0,
        "systems": {"valkey": {"latency_ms": 0.7}, "postgres": {"latency_ms": 1.2}},
        "scope": {"api": {}, "proxy": {"available": False}},
        "network": {"overall_latency_ms": None},
    }
    with patch.object(api_main, "get_live_status", new=AsyncMock(return_value=fake_live)):
        data = (await async_client.get("/api/v1/telemetry/summary")).json()
    for removed in ("rps_series", "planner_ms_series", "ssrf_blocks_series", "rate_limit_rps", "burst_capacity"):
        assert removed not in data
    assert data["planner_latency_ms"] is None
    assert data["valkey_latency_ms"] == 0.7
    assert data["configured_limits"]["source"] == "environment"


# ---------------------------------------------------------------------------
# Scope hard gate on scans and recon
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_scan_run_unknown_out_of_scope_asset_is_refused(
    async_client: httpx.AsyncClient, db_session: AsyncSession, test_slug: str
) -> None:
    prog = await _seed_program(db_session, test_slug)
    with patch("pentefino_api.routers.scans.run_real_nuclei", new=AsyncMock()) as nuclei:
        res = await async_client.post(
            "/api/v1/scans/run",
            json={"program_slug": test_slug, "asset_key": "not-in-scope.invalid", "mode": "auto"},
        )
    assert res.status_code == 403
    nuclei.assert_not_called()
    assets = (await db_session.execute(select(Asset).where(Asset.program_id == prog.id))).scalars().all()
    assert assets == [], "denied targets must not be persisted as in-scope assets"


@pytest.mark.asyncio
async def test_scan_run_stored_in_scope_flag_is_not_trusted(
    async_client: httpx.AsyncClient, db_session: AsyncSession, test_slug: str
) -> None:
    prog = await _seed_program(db_session, test_slug, allow=None)
    db_session.add(Asset(program_id=prog.id, canonical_key="stale.pentefino.test", asset_type="domain",
                         scope_state="in_scope_explicit"))
    await db_session.commit()
    with patch("pentefino_api.routers.scans.run_real_nuclei", new=AsyncMock()) as nuclei:
        res = await async_client.post(
            "/api/v1/scans/run",
            json={"program_slug": test_slug, "asset_key": "stale.pentefino.test", "mode": "auto"},
        )
    assert res.status_code == 403
    nuclei.assert_not_called()


@pytest.mark.asyncio
async def test_scan_run_without_matching_templates_does_not_run_nuclei(
    async_client: httpx.AsyncClient, db_session: AsyncSession, test_slug: str
) -> None:
    await _seed_program(db_session, test_slug)
    with patch("pentefino_api.routers.scans.run_real_nuclei", new=AsyncMock()) as nuclei, _planner_returning([]):
        res = await async_client.post(
            "/api/v1/scans/run",
            json={"program_slug": test_slug, "asset_key": "lab.pentefino.test", "mode": "auto"},
        )
    assert res.status_code == 200
    assert res.json()["status"] == "skipped_no_templates"
    nuclei.assert_not_called()


@pytest.mark.asyncio
async def test_batch_run_no_longer_raises_name_error(
    async_client: httpx.AsyncClient, db_session: AsyncSession, test_slug: str
) -> None:
    """`asyncio`/`logger` were undefined in scans.py: every batch-run with assets was a 500."""
    prog = await _seed_program(db_session, test_slug)
    db_session.add(Asset(program_id=prog.id, canonical_key="lab.pentefino.test", asset_type="domain",
                         scope_state="in_scope_explicit"))
    db_session.add(Asset(program_id=prog.id, canonical_key="old.pentefino.test", asset_type="domain",
                         scope_state="in_scope_explicit"))
    await db_session.commit()
    canary = AsyncMock(return_value=(True, 5.0, 200, False, "ok"))
    with patch("pentefino_api.routers.scans.probe_domain_l7_canary", new=canary), \
         patch("pentefino_api.routers.scans.run_real_nuclei", new=AsyncMock(return_value=[])), \
         _planner_returning(["tpl-a"]):
        res = await async_client.post("/api/v1/scans/batch-run", json={"program_slug": test_slug, "mode": "auto"})
    assert res.status_code == 200, res.text
    by_key = {a["asset_key"]: a["status"] for a in res.json()["assets"]}
    assert by_key["old.pentefino.test"] == "denied_by_scope"
    probed = [c.args[0] for c in canary.call_args_list]
    assert "old.pentefino.test" not in probed, "no packet may reach a target before the scope check"


@pytest.mark.asyncio
async def test_recon_out_of_scope_domain_is_refused_before_any_tool(
    async_client: httpx.AsyncClient, db_session: AsyncSession, test_slug: str
) -> None:
    await _seed_program(db_session, test_slug)
    with patch("pentefino_api.routers.recon.run_real_subfinder", new=AsyncMock()) as subfinder:
        res = await async_client.post("/api/v1/recon/run", json={"program_slug": test_slug, "domain": "example.invalid"})
    assert res.status_code == 403
    subfinder.assert_not_called()


@pytest.mark.asyncio
async def test_recon_without_authorization_snapshot_is_refused_and_none_is_fabricated(
    async_client: httpx.AsyncClient, db_session: AsyncSession, test_slug: str
) -> None:
    prog = await _seed_program(db_session, test_slug, with_auth=False, allow="*.pentefino.test")
    with patch("pentefino_api.routers.recon.run_real_subfinder", new=AsyncMock()) as subfinder:
        res = await async_client.post("/api/v1/recon/run", json={"program_slug": test_slug, "domain": "pentefino.test"})
    assert res.status_code == 403
    subfinder.assert_not_called()
    snaps = (await db_session.execute(select(AuthorizationSnapshot).where(AuthorizationSnapshot.program_id == prog.id))).scalars().all()
    assert snaps == []


@pytest.mark.asyncio
async def test_recon_skips_hosts_resolving_to_internal_ips(
    async_client: httpx.AsyncClient, db_session: AsyncSession, test_slug: str
) -> None:
    await _seed_program(db_session, test_slug, allow="*.pentefino.test")
    subs = [{"host": "a.pentefino.test", "source": "t"}, {"host": "b.pentefino.test", "source": "t"}]
    dns = [
        {"host": "a.pentefino.test", "a": ["93.184.216.34"]},
        {"host": "b.pentefino.test", "a": ["127.0.0.1"]},
    ]
    httpx_mock = AsyncMock(return_value=[])
    with patch("pentefino_api.routers.recon.run_real_subfinder", new=AsyncMock(return_value=subs)), \
         patch("pentefino_api.routers.recon.run_real_dnsx", new=AsyncMock(return_value=dns)), \
         patch("pentefino_api.routers.recon.run_real_httpx", new=httpx_mock):
        res = await async_client.post(
            "/api/v1/recon/run",
            json={"program_slug": test_slug, "domain": "pentefino.test", "task_id": "recon-pytest-0001"},
        )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["task_id"] == "recon-pytest-0001"
    assert body["resolved_count"] == 1
    assert body["live_http_count"] == 0, "no HTTP answers means 0, not the resolved count"
    assert httpx_mock.call_args.kwargs["hosts"] == ["a.pentefino.test"]


@pytest.mark.asyncio
async def test_cancel_accepts_batch_ids_and_reports_reality(async_client: httpx.AsyncClient) -> None:
    res = await async_client.post("/api/v1/scans/batch-abcd1234/cancel")
    assert res.status_code == 200
    assert res.json()["was_running_here"] is False


# ---------------------------------------------------------------------------
# Live status websocket
# ---------------------------------------------------------------------------
def test_ws_status_pushes_snapshot() -> None:
    snap = {"generated_at": 1.0, "systems": {"api": {"status": "up"}}, "scope": {}, "network": {}}
    with patch("pentefino_api.routers.ws.get_live_status", new=AsyncMock(return_value=snap)):
        with TestClient(create_app()) as client:
            with client.websocket_connect("/ws/status") as ws:
                first = ws.receive_json()
                assert first["event"] == "status" and first["data"]["systems"]["api"]["status"] == "up"
                ws.send_text("ping")
                assert ws.receive_json()["event"] == "pong"


@pytest.mark.asyncio
async def test_batch_dry_run_sends_no_canary(
    async_client: httpx.AsyncClient, db_session: AsyncSession, test_slug: str
) -> None:
    prog = await _seed_program(db_session, test_slug)
    db_session.add(Asset(program_id=prog.id, canonical_key="lab.pentefino.test", asset_type="domain",
                         scope_state="in_scope_explicit"))
    await db_session.commit()
    canary = AsyncMock(return_value=(True, 5.0, 200, False, "ok"))
    with patch("pentefino_api.routers.scans.probe_domain_l7_canary", new=canary), _planner_returning(["tpl-a"]):
        res = await async_client.post("/api/v1/scans/batch-run", json={"program_slug": test_slug, "mode": "dry_run"})
    assert res.status_code == 200
    canary.assert_not_called()


def test_intel_status_does_not_invent_a_sync_time() -> None:
    from pentefino_api.routers import intel

    intel._LAST_SYNC.clear()
    with TestClient(create_app()) as client:
        assert client.get("/api/v1/intel/status").json()["synced_at"] is None
        synced = client.post("/api/v1/intel/sync?offline=true").json()
        status = client.get("/api/v1/intel/status").json()
    assert status["synced_at"] == synced["synced_at"]
    assert status["last_sync_source"] == "baseline_cache"
