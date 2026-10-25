"""Regression tests for the fixes from the review/opus-audit branch (see REPORT.md).

Everything here is offline: scanner processes, Valkey and ping are mocked.
"""
from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pentefino_api import network_monitor, real_tools
from pentefino_api.activity import ActivityRegistry
from pentefino_api.routers.recon import _prohibited_ips
from pentefino_proxy.metrics import ProxyMetrics, redact_url
from pentefino_worker.amqp_consumer import AmqpWorkerDaemon, TrackedEphemeralRunner, WorkerTelemetryPublisher
from pentefino_worker.cancellation import ActiveContainerRegistry


# ---------------------------------------------------------------------------
# real_tools: nuclei must stay inside the planner's allowlist
# ---------------------------------------------------------------------------
class _FakeProc:
    def __init__(self) -> None:
        self.stdout = asyncio.StreamReader()
        self.stderr = asyncio.StreamReader()
        self.stdout.feed_eof()
        self.stderr.feed_eof()
        self.returncode = 0
        self.killed = False

    async def wait(self) -> int:
        return 0

    def kill(self) -> None:
        self.killed = True


@pytest.mark.asyncio
async def test_nuclei_refuses_empty_template_list() -> None:
    """Without -id, nuclei falls back to its whole catalog (intrusive templates included)."""
    with patch("asyncio.create_subprocess_exec", new=AsyncMock()) as spawn:
        with pytest.raises(real_tools.UnsafeScanRequest):
            await real_tools.run_real_nuclei("https://lab.pentefino.test", template_ids=[])
        with pytest.raises(real_tools.UnsafeScanRequest):
            await real_tools.run_real_nuclei("https://lab.pentefino.test", template_ids=None, tags="cve")
        spawn.assert_not_called()


@pytest.mark.asyncio
async def test_nuclei_args_never_auto_scan_and_only_same_host_redirects(monkeypatch) -> None:
    monkeypatch.setenv("PENTEFINO_NUCLEI_BIN", "nuclei-test-bin")
    monkeypatch.setenv("PENTEFINO_EGRESS_PROXY", "http://127.0.0.1:8080")
    captured: list[tuple] = []

    async def fake_exec(*cmd, **kwargs):
        captured.append(cmd)
        return _FakeProc()

    with patch("asyncio.create_subprocess_exec", new=fake_exec):
        await real_tools.run_real_nuclei(
            "https://lab.pentefino.test",
            template_ids=[f"tpl-{i}" for i in range(25)],
            flags={"auto_scan": True},
        )
    cmd = list(captured[0])
    assert cmd[0] == "nuclei-test-bin"
    assert "-as" not in cmd
    assert "-fr" not in cmd and "-fhr" in cmd
    assert cmd[cmd.index("-proxy") + 1] == "http://127.0.0.1:8080"
    assert cmd.count("-id") == real_tools.NUCLEI_MAX_TEMPLATES


@pytest.mark.asyncio
async def test_nuclei_require_proxy_without_proxy_is_refused(monkeypatch) -> None:
    monkeypatch.delenv("PENTEFINO_EGRESS_PROXY", raising=False)
    monkeypatch.setenv("PENTEFINO_REQUIRE_EGRESS_PROXY", "true")
    with patch("asyncio.create_subprocess_exec", new=AsyncMock()) as spawn:
        with pytest.raises(real_tools.UnsafeScanRequest):
            await real_tools.run_real_nuclei("https://lab.pentefino.test", template_ids=["a"])
        spawn.assert_not_called()


def test_tool_resolution_skips_python_httpx_cli(tmp_path: Path, monkeypatch) -> None:
    """`httpx` on PATH is often encode/httpx's Python CLI, not ProjectDiscovery httpx."""
    scripts = tmp_path / "Scripts"
    scripts.mkdir()
    (scripts / "python.exe").write_bytes(b"")
    fake_httpx = scripts / "httpx.exe"
    fake_httpx.write_bytes(b"")
    monkeypatch.delenv("PENTEFINO_HTTPX_BIN", raising=False)
    monkeypatch.setattr(real_tools.shutil, "which", lambda name: str(fake_httpx) if name == "httpx" else None)
    monkeypatch.setattr(real_tools, "is_wsl_available", lambda: True)
    cmd = real_tools.get_tool_command("httpx", ["-silent"])
    assert cmd[0] == "wsl" and "httpx" in cmd

    monkeypatch.setenv("PENTEFINO_HTTPX_BIN", "/opt/pd/httpx")
    assert real_tools.get_tool_command("httpx", ["-silent"])[0] == "/opt/pd/httpx"


# ---------------------------------------------------------------------------
# recon: is_prohibited_ip returns a tuple; `any(tuple)` was always True
# ---------------------------------------------------------------------------
def test_prohibited_ips_filters_internal_ranges_only() -> None:
    assert _prohibited_ips(["93.184.216.34", "1.1.1.1"], "bounty") == []
    assert _prohibited_ips(["127.0.0.1", "10.1.2.3", "169.254.169.254", "8.8.8.8"], "bounty") == [
        "127.0.0.1",
        "10.1.2.3",
        "169.254.169.254",
    ]


# ---------------------------------------------------------------------------
# API activity registry: cancellation reaches processes, even late ones
# ---------------------------------------------------------------------------
class _RunningProc:
    returncode = None

    def __init__(self) -> None:
        self.killed = False

    def kill(self) -> None:
        self.killed = True


def test_activity_cancel_kills_running_and_late_processes() -> None:
    reg = ActivityRegistry()
    reg.start("run-1", "scan", "prog", "lab.pentefino.test")
    early = _RunningProc()
    reg.attach_process("run-1", early)
    assert reg.cancel("run-1") is True
    assert early.killed

    late = _RunningProc()
    reg.attach_process("run-1", late)
    assert late.killed, "a process spawned after cancel must be killed on attach"
    reg.finish("run-1")
    assert reg.active() == []


def test_activity_cancel_before_start_is_tombstoned() -> None:
    reg = ActivityRegistry()
    assert reg.cancel("run-2") is False
    op = reg.start("run-2", "scan", "prog", "lab.pentefino.test")
    assert op.cancelled


def test_activity_scope_counters_classify_ssrf() -> None:
    reg = ActivityRegistry()
    reg.record_scope_decision(True, "EXPLICIT_ALLOW_MATCHED")
    reg.record_scope_decision(False, "PROHIBITED_IP_SPACE: LOOPBACK")
    reg.record_scope_decision(False, "UNKNOWN_TARGET_DEFAULT_DENY")
    win = reg.scope_window()
    assert win["evaluations"] == 3 and win["denied"] == 2 and win["ssrf_blocked"] == 1


# ---------------------------------------------------------------------------
# worker: cancellation races
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_worker_cancel_before_register_refuses_container() -> None:
    registry = ActiveContainerRegistry(valkey_url="redis://127.0.0.1:1/0")
    run_id = str(uuid.uuid4())
    assert await registry.cancel_run(run_id) is False
    assert registry.is_cancelled(run_id)

    runner = TrackedEphemeralRunner(registry=registry, run_id=run_id, container_name="pentefino_scan_x")
    with pytest.raises(asyncio.CancelledError):
        await runner.run(MagicMock(container_name=None, image="img", network="net"))
    assert registry.get(run_id) is None


@pytest.mark.asyncio
async def test_worker_operator_cancel_settles_message_without_requeue() -> None:
    """CancelledError is a BaseException: it used to skip both ack and reject."""
    registry = ActiveContainerRegistry(valkey_url="redis://127.0.0.1:1/0")
    telemetry = WorkerTelemetryPublisher()
    telemetry.emit_scan_event = AsyncMock()
    run_id = uuid.uuid4()
    registry.mark_cancelled(run_id)

    worker = AsyncMock()
    worker.process_job.side_effect = asyncio.CancelledError()
    session_factory = MagicMock()
    session_factory.return_value.__aenter__.return_value = AsyncMock()
    session_factory.return_value.__aexit__.return_value = None
    daemon = AmqpWorkerDaemon(session_factory=session_factory, container_registry=registry, telemetry=telemetry)

    msg = AsyncMock()
    msg.body = json.dumps({"run_id": str(run_id), "program_slug": "p", "target_asset": "lab.pentefino.test"}).encode()
    with patch("pentefino_worker.amqp_consumer.ScanTaskWorker", return_value=worker):
        await daemon.handle_scan_message(msg)
    msg.reject.assert_awaited_once_with(requeue=False)
    msg.ack.assert_not_called()


@pytest.mark.asyncio
async def test_worker_shutdown_cancel_requeues_message() -> None:
    registry = ActiveContainerRegistry(valkey_url="redis://127.0.0.1:1/0")
    telemetry = WorkerTelemetryPublisher()
    telemetry.emit_scan_event = AsyncMock()
    worker = AsyncMock()
    worker.process_job.side_effect = asyncio.CancelledError()
    session_factory = MagicMock()
    session_factory.return_value.__aenter__.return_value = AsyncMock()
    session_factory.return_value.__aexit__.return_value = None
    daemon = AmqpWorkerDaemon(session_factory=session_factory, container_registry=registry, telemetry=telemetry)

    msg = AsyncMock()
    msg.body = json.dumps({"run_id": str(uuid.uuid4()), "program_slug": "p", "target_asset": "a.test"}).encode()
    with patch("pentefino_worker.amqp_consumer.ScanTaskWorker", return_value=worker):
        with pytest.raises(asyncio.CancelledError):
            await daemon.handle_scan_message(msg)
    msg.reject.assert_awaited_once_with(requeue=True)


# ---------------------------------------------------------------------------
# network monitor: no fabricated fallback, never blocks the loop
# ---------------------------------------------------------------------------
def test_network_aggregate_reports_none_when_nothing_answers() -> None:
    targets = [
        {"host": "1.1.1.1", "latency_ms": None, "jitter_ms": None, "loss_pct": 100.0},
        {"host": "8.8.8.8", "latency_ms": None, "jitter_ms": None, "loss_pct": 100.0},
    ]
    agg = network_monitor._aggregate(targets)
    assert agg == {"overall_latency_ms": None, "overall_jitter_ms": None, "packet_loss_pct": None}
    assert network_monitor._build_result(targets)["status"] == "unavailable"


@pytest.mark.asyncio
async def test_network_probe_runs_in_threads(monkeypatch) -> None:
    import threading

    main_thread = threading.get_ident()
    seen: list[int] = []

    def fake_probe(host: str, name: str) -> dict:
        seen.append(threading.get_ident())
        return {"name": name, "host": host, "latency_ms": 5.0, "jitter_ms": 1.0, "loss_pct": 0.0}

    monkeypatch.setattr(network_monitor, "_probe_host", fake_probe)
    monkeypatch.setattr(network_monitor, "_CACHE_DATA", None)
    monkeypatch.setenv("PENTEFINO_NET_TARGETS", "1.1.1.1=A,8.8.8.8=B")
    res = await network_monitor.get_network_health_metrics_async()
    assert res["overall_latency_ms"] == 5.0
    assert seen and all(t != main_thread for t in seen)


def test_ping_parser_handles_sub_millisecond_and_jitter(monkeypatch) -> None:
    out = "Resposta de 127.0.0.1: bytes=32 tempo<1ms TTL=128\n" * 2 + "Resposta: tempo=3ms\n" + "(0% de perda)"
    monkeypatch.setattr(
        network_monitor.subprocess, "run", lambda *a, **k: MagicMock(stdout=out)
    )
    res = network_monitor._probe_host("127.0.0.1", "lo")
    assert res["samples"] == 3 and res["loss_pct"] == 0.0
    assert res["jitter_ms"] == 1.0  # |1-1| and |3-1| averaged


# ---------------------------------------------------------------------------
# proxy metrics: secrets stay out of events, Valkey outage is harmless
# ---------------------------------------------------------------------------
def test_redact_url_drops_query_and_userinfo() -> None:
    assert redact_url("https://user:pw@api.lab.test:8443/x?token=abc") == "https://api.lab.test:8443/x?[REDACTED]"
    assert redact_url("http://lab.test/") == "http://lab.test/"


@pytest.mark.asyncio
async def test_proxy_metrics_records_ssrf_block() -> None:
    m = ProxyMetrics("redis://unused", enabled=True)
    pipe = MagicMock()
    pipe.execute = AsyncMock(return_value=[])
    client = MagicMock()
    client.pipeline.return_value = pipe
    m._client = client
    await m.record(method="GET", url="http://169.254.169.254/latest?x=1", allowed=False,
                   reason="PROHIBITED_IP: CLOUD_METADATA", tier="explicit_deny", status_code=403)
    fields = [c.args[1] for c in pipe.hincrby.call_args_list]
    assert fields == ["requests", "denied", "ssrf_blocked"]
    published = json.loads(pipe.publish.call_args.args[1])
    assert published["verdict"] == "BLOCKED_SSRF" and "x=1" not in published["url"]


@pytest.mark.asyncio
async def test_proxy_metrics_disabled_and_outage_are_noops() -> None:
    off = ProxyMetrics("redis://unused", enabled=False)
    off._client = MagicMock()
    await off.record(method="GET", url="http://a.test/", allowed=True, reason="", tier="", status_code=200)
    off._client.pipeline.assert_not_called()

    broken = ProxyMetrics("redis://127.0.0.1:1/0", enabled=True)
    await broken.record(method="GET", url="http://a.test/", allowed=True, reason="", tier="", status_code=200)


# ---------------------------------------------------------------------------
# domain session: engine is per event loop
# ---------------------------------------------------------------------------
def test_engine_cache_is_per_event_loop() -> None:
    from pentefino_domain import session as dsession

    async def grab():
        return dsession.get_async_engine(), dsession.get_async_session_factory()

    e1, f1 = asyncio.run(grab())
    e2, f2 = asyncio.run(grab())
    assert e1 is not e2 and f1 is not f2
