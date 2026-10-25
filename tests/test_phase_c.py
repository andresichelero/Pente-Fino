"""Comprehensive test suite for Phase C (Milestone 4).

Verifies:
1. Real AMQP Queue Consumer with aio-pika:
   - Topology declaration (exchanges pentefino.tasks, pentefino.dlx, queues with DLX routing)
   - Proper ack/reject handling (unrecoverable and scope errors rejected with requeue=False to DLQ)
   - Successful processing and dispatching to worker handlers
2. Decoupled Async Publishing:
   - AmqpTaskPublisher publishing tasks with correlation IDs, headers, persistent delivery
   - Graceful fallback when broker is offline
   - CLI --async integration in recon and scan commands
3. Valkey PubSub Streaming:
   - Worker telemetry streaming to pentefino:events:scans:{run_id}
   - WebSocket subscriber forwarding distributed Valkey PubSub stream
4. Deterministic Container Cancellation:
   - ActiveContainerRegistry container tracking
   - cancel_run deterministic termination executing `docker rm -f <container_name>`
   - Valkey control channel broadcast
   - API endpoint `POST /api/v1/scans/{run_id}/cancel`
"""
from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch
import uuid

import aio_pika
from fastapi.testclient import TestClient
import pytest

from pentefino_api.main import app
from pentefino_api.routers.ws import _valkey_subscriber_loop
from pentefino_worker.amqp_consumer import (
    DLX_EXCHANGE,
    QUEUE_INTEL,
    QUEUE_RECON,
    QUEUE_SCAN,
    TASKS_EXCHANGE,
    AmqpWorkerDaemon,
    WorkerTelemetryPublisher,
    setup_amqp_topology,
)
from pentefino_worker.cancellation import (
    ActiveContainerRegistry,
    ActiveJobInfo,
    CANCEL_CONTROL_CHANNEL,
)
from pentefino_worker.publisher import (
    AmqpTaskPublisher,
)


# ============================================================================
# 1. AMQP Topology & Queue Declaration Tests
# ============================================================================


@pytest.mark.asyncio
async def test_setup_amqp_topology_declares_exchanges_and_dlq() -> None:
    """Verifies that setup_amqp_topology declares durable exchanges, DLQ, and task queues."""
    mock_channel = AsyncMock()

    mock_tasks_exchange = AsyncMock()
    mock_dlx_exchange = AsyncMock()
    mock_dlq = AsyncMock()
    mock_recon_q = AsyncMock()
    mock_scan_q = AsyncMock()
    mock_intel_q = AsyncMock()

    mock_channel.declare_exchange.side_effect = [
        mock_tasks_exchange,
        mock_dlx_exchange,
    ]
    mock_channel.declare_queue.side_effect = [
        mock_dlq,
        mock_recon_q,
        mock_scan_q,
        mock_intel_q,
    ]

    topology = await setup_amqp_topology(mock_channel)

    # 1. Assert exchanges declared
    assert mock_channel.declare_exchange.call_count == 2
    mock_channel.declare_exchange.assert_any_call(
        TASKS_EXCHANGE, aio_pika.ExchangeType.DIRECT, durable=True
    )
    mock_channel.declare_exchange.assert_any_call(
        DLX_EXCHANGE, aio_pika.ExchangeType.DIRECT, durable=True
    )

    # 2. Assert DLQ bound to DLX with routing key 'dlq'
    mock_dlq.bind.assert_awaited_once_with(mock_dlx_exchange, routing_key="dlq")

    # 3. Assert queues configured with DLX arguments
    expected_dlx_args = {
        "x-dead-letter-exchange": DLX_EXCHANGE,
        "x-dead-letter-routing-key": "dlq",
    }
    mock_channel.declare_queue.assert_any_call(
        QUEUE_RECON, durable=True, arguments=expected_dlx_args
    )
    mock_channel.declare_queue.assert_any_call(
        QUEUE_SCAN, durable=True, arguments=expected_dlx_args
    )
    mock_channel.declare_queue.assert_any_call(
        QUEUE_INTEL, durable=True, arguments=expected_dlx_args
    )

    # 4. Assert queues bound to tasks exchange with routing keys
    mock_recon_q.bind.assert_awaited_once_with(mock_tasks_exchange, routing_key="task.recon")
    mock_scan_q.bind.assert_awaited_once_with(mock_tasks_exchange, routing_key="task.scan")
    mock_intel_q.bind.assert_awaited_once_with(mock_tasks_exchange, routing_key="task.intel")

    assert topology["tasks_exchange"] is mock_tasks_exchange
    assert topology["dlx_exchange"] is mock_dlx_exchange
    assert topology["dlq"] is mock_dlq


# ============================================================================
# 2. AMQP Message Rejection to DLQ & Ack Processing Tests
# ============================================================================


@pytest.mark.asyncio
async def test_consumer_rejects_malformed_json_to_dlq() -> None:
    """Verifies that unparseable message body is rejected with requeue=False (routed to DLQ)."""
    registry = ActiveContainerRegistry()
    telemetry = WorkerTelemetryPublisher()
    telemetry.emit_scan_event = AsyncMock()

    daemon = AmqpWorkerDaemon(
        container_registry=registry,
        telemetry=telemetry,
    )

    mock_msg = AsyncMock()
    mock_msg.body = b"not a valid json payload {"

    await daemon.handle_scan_message(mock_msg)

    # Must be rejected with requeue=False so RabbitMQ drops it into DLQ
    mock_msg.reject.assert_awaited_once_with(requeue=False)
    mock_msg.ack.assert_not_called()


@pytest.mark.asyncio
async def test_consumer_rejects_out_of_scope_scan_job_to_dlq() -> None:
    """Verifies that an out-of-scope asset triggers rejection with requeue=False into DLQ."""
    registry = ActiveContainerRegistry()
    telemetry = WorkerTelemetryPublisher()
    telemetry.emit_scan_event = AsyncMock()

    mock_worker = AsyncMock()
    mock_worker.process_job.return_value = {
        "status": "rejected_out_of_scope",
        "error": "Asset scope_state is out_of_scope",
    }

    mock_session = AsyncMock()
    mock_session_factory = MagicMock()
    mock_session_factory.return_value.__aenter__.return_value = mock_session
    mock_session_factory.return_value.__aexit__.return_value = None

    daemon = AmqpWorkerDaemon(
        session_factory=mock_session_factory,
        container_registry=registry,
        telemetry=telemetry,
    )

    run_id = uuid.uuid4()
    job_payload = {
        "run_id": str(run_id),
        "program_slug": "target-corp",
        "target_asset": "forbidden.internal.corp",
    }
    mock_msg = AsyncMock()
    mock_msg.body = json.dumps(job_payload).encode("utf-8")

    with patch("pentefino_worker.amqp_consumer.ScanTaskWorker", return_value=mock_worker):
        await daemon.handle_scan_message(mock_msg)

    # Verifies policy rejection routes to DLQ without infinite requeue loop
    mock_msg.reject.assert_awaited_once_with(requeue=False)
    mock_msg.ack.assert_not_called()
    assert telemetry.emit_scan_event.await_count >= 2


@pytest.mark.asyncio
async def test_consumer_acks_successful_scan_job() -> None:
    """Verifies that a valid in-scope scan job completes and calls message.ack()."""
    registry = ActiveContainerRegistry()
    telemetry = WorkerTelemetryPublisher()
    telemetry.emit_scan_event = AsyncMock()

    mock_worker = AsyncMock()
    mock_worker.process_job.return_value = {
        "status": "completed",
        "total_templates": 5,
        "findings_count": 0,
    }

    mock_session = AsyncMock()
    mock_session_factory = MagicMock()
    mock_session_factory.return_value.__aenter__.return_value = mock_session
    mock_session_factory.return_value.__aexit__.return_value = None

    daemon = AmqpWorkerDaemon(
        session_factory=mock_session_factory,
        container_registry=registry,
        telemetry=telemetry,
    )

    run_id = uuid.uuid4()
    job_payload = {
        "run_id": str(run_id),
        "program_slug": "target-corp",
        "target_asset": "app.example.com",
    }
    mock_msg = AsyncMock()
    mock_msg.body = json.dumps(job_payload).encode("utf-8")

    with patch("pentefino_worker.amqp_consumer.ScanTaskWorker", return_value=mock_worker):
        await daemon.handle_scan_message(mock_msg)

    mock_msg.ack.assert_awaited_once()
    mock_msg.reject.assert_not_called()
    # Verified that container is unregistered after completion
    assert registry.get(str(run_id)) is None


@pytest.mark.asyncio
async def test_consumer_recon_and_intel_messages() -> None:
    """Verifies recon and intel queue consumers handle payloads and acknowledge."""
    registry = ActiveContainerRegistry()
    telemetry = WorkerTelemetryPublisher()
    telemetry.emit_scan_event = AsyncMock()

    daemon = AmqpWorkerDaemon(
        container_registry=registry,
        telemetry=telemetry,
    )

    # 1. Recon malformed
    mock_msg = AsyncMock()
    mock_msg.body = b"{malformed"
    await daemon.handle_recon_message(mock_msg)
    mock_msg.reject.assert_awaited_once_with(requeue=False)

    # 2. Intel valid
    mock_intel_msg = AsyncMock()
    mock_intel_msg.body = json.dumps({"action": "sync", "sources": ["epss"]}).encode("utf-8")
    await daemon.handle_intel_message(mock_intel_msg)
    mock_intel_msg.ack.assert_awaited_once()


# ============================================================================
# 3. Decoupled Async Publishing Tests
# ============================================================================


@pytest.mark.asyncio
async def test_publish_scan_task_with_correlation_id() -> None:
    """Verifies AmqpTaskPublisher publishes persistent task with correlation ID."""
    publisher = AmqpTaskPublisher(amqp_url="amqp://guest:guest@localhost:5672/")

    mock_exchange = AsyncMock()
    publisher._ensure_connected = AsyncMock(return_value=mock_exchange)

    run_id = uuid.uuid4()
    res = await publisher.publish_scan_task(
        program_slug="bounty-corp",
        target_asset="sub.target.com",
        severity="critical",
        tags="rce",
        run_id=run_id,
    )

    assert res["status"] == "queued"
    assert res["run_id"] == str(run_id)
    assert res["broker_published"] is True

    # Assert exchange.publish called with persistent Message
    mock_exchange.publish.assert_awaited_once()
    published_msg, kwargs = mock_exchange.publish.call_args
    message = published_msg[0]
    assert isinstance(message, aio_pika.Message)
    assert message.correlation_id == str(run_id)
    assert message.delivery_mode == aio_pika.DeliveryMode.PERSISTENT
    assert kwargs.get("routing_key") == "task.scan"

    payload_data = json.loads(message.body.decode("utf-8"))
    assert payload_data["program_slug"] == "bounty-corp"
    assert payload_data["target_asset"] == "sub.target.com"
    assert payload_data["severity"] == "critical"


@pytest.mark.asyncio
async def test_publish_recon_task() -> None:
    """Verifies AmqpTaskPublisher publishes recon task with routing_key 'task.recon'."""
    publisher = AmqpTaskPublisher()
    mock_exchange = AsyncMock()
    publisher._ensure_connected = AsyncMock(return_value=mock_exchange)

    res = await publisher.publish_recon_task(
        program_slug="test-prog",
        domain="example.org",
        bruteforce=True,
    )

    assert res["status"] == "queued"
    assert res["domain"] == "example.org"
    assert res["bruteforce"] is True
    assert res["broker_published"] is True
    _, kwargs = mock_exchange.publish.call_args
    assert kwargs.get("routing_key") == "task.recon"


@pytest.mark.asyncio
async def test_publish_fallback_when_broker_offline() -> None:
    """Verifies graceful fallback without exceptions when AMQP broker is unreachable."""
    publisher = AmqpTaskPublisher(amqp_url="amqp://unreachable-broker:9999/")
    publisher._ensure_connected = AsyncMock(side_effect=ConnectionRefusedError("Broker offline"))

    res = await publisher.publish_scan_task(
        program_slug="test-prog",
        target_asset="target.org",
    )

    assert res["status"] == "queued_offline_fallback"
    assert res["broker_published"] is False
    assert "fallback" in res["message"].lower()


# ============================================================================
# 4. Valkey PubSub Telemetry & Streaming Tests
# ============================================================================


@pytest.mark.asyncio
async def test_worker_telemetry_publisher_emits_to_channels() -> None:
    """Verifies WorkerTelemetryPublisher pushes JSON events to Valkey PubSub."""
    publisher = WorkerTelemetryPublisher(valkey_url="redis://localhost:6379/0")
    mock_client = AsyncMock()
    publisher._get_client = AsyncMock(return_value=mock_client)

    run_id = uuid.uuid4()
    ok = await publisher.emit_scan_event(
        run_id=run_id,
        event_type="container_init",
        data={"stage": "HardenedNucleiRunner", "progress": 50},
    )

    assert ok is True
    assert mock_client.publish.await_count == 2
    channel_call, _ = mock_client.publish.call_args_list[0]
    assert channel_call[0] == f"pentefino:events:scans:{run_id}"

    payload = json.loads(channel_call[1])
    assert payload["event"] == "container_init"
    assert payload["run_id"] == str(run_id)
    assert payload["progress"] == 50


@pytest.mark.asyncio
async def test_valkey_subscriber_loop_forwards_to_websocket() -> None:
    """Verifies _valkey_subscriber_loop receives message from Valkey and sends via WebSocket."""
    mock_ws = AsyncMock()
    plan_id = "test-plan-123"

    mock_pubsub = AsyncMock()
    event_data = {
        "event": "template_execution",
        "stage": "Nuclei",
        "progress": 75,
    }
    mock_pubsub.get_message.side_effect = [
        {"type": "message", "data": json.dumps(event_data)},
        asyncio.CancelledError(),
    ]

    mock_redis = AsyncMock()
    mock_redis.__aenter__.return_value = mock_redis
    mock_redis.pubsub = MagicMock(return_value=mock_pubsub)

    with patch("redis.asyncio.from_url", return_value=mock_redis):
        await _valkey_subscriber_loop(mock_ws, plan_id)


    mock_ws.send_json.assert_awaited_once_with(event_data)


# ============================================================================
# 5. Deterministic Container Cancellation Tests
# ============================================================================


@pytest.mark.asyncio
async def test_active_container_registry_lifecycle() -> None:
    """Verifies registration, retrieval, and unregistration of active containers."""
    registry = ActiveContainerRegistry()
    run_id = uuid.uuid4()
    container_name = "pentefino_run_abc123"

    job = registry.register(run_id, container_name, metadata={"tool": "nuclei"})
    assert isinstance(job, ActiveJobInfo)
    assert job.run_id == str(run_id)
    assert job.container_name == container_name
    assert job.status == "running"

    retrieved = registry.get(run_id)
    assert retrieved is job

    assert len(registry.list_active()) == 1

    removed = registry.unregister(run_id)
    assert removed is job
    assert registry.get(run_id) is None
    assert len(registry.list_active()) == 0


@pytest.mark.asyncio
async def test_deterministic_cancellation_executes_docker_rm_f() -> None:
    """Verifies cancel_run executes `docker rm -f <container_name>` and cancels in-flight task."""
    registry = ActiveContainerRegistry()
    run_id = uuid.uuid4()
    container_name = "pentefino_vuln_scan_test"

    # In-flight task
    async def _dummy_task() -> None:
        await asyncio.sleep(10.0)

    task = asyncio.create_task(_dummy_task())
    registry.register(run_id, container_name, task=task)

    # Mock subprocess for `docker rm -f`
    mock_proc = AsyncMock()
    mock_proc.returncode = 0
    mock_proc.communicate.return_value = (b"pentefino_vuln_scan_test\n", b"")

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
        with patch.object(registry, "publish_event", new=AsyncMock()) as mock_pub:
            success = await registry.cancel_run(run_id, engine_bin="mock_docker")

    assert success is True
    # Verify exact docker rm -f execution
    mock_exec.assert_awaited_once_with(
        "mock_docker",
        "rm",
        "-f",
        container_name,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    # Verify in-flight task cancelled
    try:
        await task
    except asyncio.CancelledError:
        pass
    assert task.cancelled()
    # Verify registration removed
    assert registry.get(run_id) is None
    # Verify cancellation event published
    mock_pub.assert_awaited_once()



@pytest.mark.asyncio
async def test_cancel_non_existent_run_returns_false() -> None:
    """Verifies cancel_run safely returns False if run_id is unknown."""
    registry = ActiveContainerRegistry()
    result = await registry.cancel_run(uuid.uuid4())
    assert result is False


@pytest.mark.asyncio
async def test_broadcast_cancel_publishes_to_control_channel() -> None:
    """Verifies broadcast_cancel publishes cancellation payload to pentefino:control:cancel."""
    registry = ActiveContainerRegistry(valkey_url="redis://localhost:6379/0")
    run_id = uuid.uuid4()

    mock_client = AsyncMock()
    with patch("redis.asyncio.from_url", return_value=mock_client):
        ok = await registry.broadcast_cancel(run_id)

    assert ok is True
    mock_client.publish.assert_awaited_once()
    channel, raw_payload = mock_client.publish.call_args[0]
    assert channel == CANCEL_CONTROL_CHANNEL
    payload = json.loads(raw_payload)
    assert payload["action"] == "cancel"
    assert payload["run_id"] == str(run_id)


# ============================================================================
# 6. API Endpoints Integration (Cancel & Async Execution)
# ============================================================================


def test_api_cancel_scan_endpoint() -> None:
    """Verifies POST /api/v1/scans/{run_id}/cancel dispatches cancellation."""
    from pentefino_api.deps import get_db_session

    mock_session = AsyncMock()

    async def override_get_db_session():
        yield mock_session

    app.dependency_overrides[get_db_session] = override_get_db_session
    try:
        client = TestClient(app)
        run_id = uuid.uuid4()

        with patch("pentefino_worker.cancellation.default_container_registry.broadcast_cancel", new=AsyncMock(return_value=True)):
            with patch("pentefino_api.routers.scans.record_api_audit", new=AsyncMock()):
                with patch("pentefino_api.routers.scans.scan_hub.broadcast", new=AsyncMock()):
                    response = client.post(f"/api/v1/scans/{run_id}/cancel")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "cancelled"
        assert data["run_id"] == str(run_id)
    finally:
        app.dependency_overrides.clear()


def test_api_cancel_scan_invalid_uuid() -> None:
    """Verifies POST /api/v1/scans/{run_id}/cancel returns 400 on malformed UUID."""
    from pentefino_api.deps import get_db_session

    mock_session = AsyncMock()

    async def override_get_db_session():
        yield mock_session

    app.dependency_overrides[get_db_session] = override_get_db_session
    try:
        client = TestClient(app)
        response = client.post("/api/v1/scans/invalid-uuid-string/cancel")
        assert response.status_code == 400
        assert "Invalid UUID format" in response.json()["detail"]
    finally:
        app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_api_run_scan_async_mode() -> None:
    """Verifies POST /api/v1/scans/run with mode='async' queues scan job via AmqpTaskPublisher."""
    from pentefino_api.deps import get_db_session

    mock_session = AsyncMock()

    async def override_get_db_session():
        yield mock_session

    app.dependency_overrides[get_db_session] = override_get_db_session

    try:
        client = TestClient(app)

        mock_prog = MagicMock()
        mock_prog.id = uuid.uuid4()
        mock_prog.slug = "target-program"

        mock_asset = MagicMock()
        mock_asset.id = uuid.uuid4()
        mock_asset.canonical_key = "app.target.com"
        mock_asset.scope_state = "in_scope_explicit"

        mock_plan = MagicMock()
        mock_plan.plan_id = uuid.uuid4()
        mock_plan.target_url = "https://app.target.com"
        mock_plan.matched_technologies = ["nginx"]
        mock_plan.total_templates = 3

        with patch("pentefino_api.routers.scans.get_program_or_404", new=AsyncMock(return_value=mock_prog)):
            with patch("pentefino_api.routers.scans._resolve_asset_and_techs", new=AsyncMock(return_value=(mock_asset, ["nginx"], []))):
                with patch("pentefino_api.routers.scans.DetectionPlanner.create_plan", new=AsyncMock(return_value=mock_plan)):
                    with patch("pentefino_worker.publisher.default_publisher.publish_scan_task", new=AsyncMock(return_value={"broker_published": True})) as mock_pub:
                        with patch("pentefino_api.routers.scans.record_api_audit", new=AsyncMock()):
                            with patch("pentefino_api.routers.scans.scan_hub.broadcast", new=AsyncMock()):
                                response = client.post(
                                    "/api/v1/scans/run",
                                    json={
                                        "program_slug": "target-program",
                                        "asset_key": "app.target.com",
                                        "mode": "async",
                                    },
                                )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "queued"
        assert data["mode_executed"] == "amqp_worker"
        mock_pub.assert_awaited_once()
    finally:
        app.dependency_overrides.clear()


# ============================================================================
# 7. CLI --async Task Publishing Integration Tests
# ============================================================================


def test_cli_recon_async_publishes_amqp_task() -> None:
    """Verifies that `pentefino recon run --async` dispatches task to AMQP publisher."""
    from typer.testing import CliRunner
    from pentefino_cli.commands.recon import app as recon_app

    runner = CliRunner()
    mock_prog = MagicMock()
    mock_prog.slug = "cyber-bounty"
    mock_prog.id = uuid.uuid4()

    mock_pub_res = {
        "status": "queued",
        "task_id": "test-task-123",
        "program": "cyber-bounty",
        "domain": "target.io",
        "bruteforce": False,
        "broker_published": True,
        "message": "Recon task for target.io successfully queued in AMQP.",
    }

    mock_session = AsyncMock()
    mock_session_factory = MagicMock()
    mock_session_factory.return_value.__aenter__.return_value = mock_session
    mock_session_factory.return_value.__aexit__.return_value = None

    with patch("pentefino_cli.commands.recon.get_async_session", mock_session_factory):
        with patch("pentefino_cli.commands.recon.get_program_by_slug", new=AsyncMock(return_value=mock_prog)):
            with patch("pentefino_worker.publisher.default_publisher.publish_recon_task", new=AsyncMock(return_value=mock_pub_res)) as mock_pub:
                with patch("pentefino_cli.commands.recon.record_audit_event", new=AsyncMock()):
                    result = runner.invoke(
                        recon_app,
                        ["--program", "cyber-bounty", "--domain", "target.io", "--async", "--json"],
                    )

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["status"] == "queued"
    assert data["broker_published"] is True
    mock_pub.assert_awaited_once()


def test_cli_scan_async_publishes_amqp_task() -> None:
    """Verifies that `pentefino scan run --async` dispatches task to AMQP publisher."""
    from typer.testing import CliRunner
    from pentefino_cli.commands.scan import app as scan_app

    runner = CliRunner()
    mock_prog = MagicMock()
    mock_prog.slug = "cyber-bounty"
    mock_prog.id = uuid.uuid4()

    mock_asset = MagicMock()
    mock_asset.id = uuid.uuid4()
    mock_asset.canonical_key = "api.target.io"
    mock_asset.scope_state = "in_scope_explicit"

    mock_pub_res = {
        "status": "queued",
        "run_id": "scan-run-456",
        "program": "cyber-bounty",
        "asset": "api.target.io",
        "severity": "critical",
        "tags": "cve",
        "broker_published": True,
        "message": "Scan task for api.target.io successfully queued in AMQP.",
    }

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock()
    mock_res = MagicMock()
    mock_res.scalar_one_or_none.return_value = mock_asset
    mock_session.execute.return_value = mock_res

    mock_session_factory = MagicMock()
    mock_session_factory.return_value.__aenter__.return_value = mock_session
    mock_session_factory.return_value.__aexit__.return_value = None

    with patch("pentefino_cli.commands.scan.get_async_session", mock_session_factory):
        with patch("pentefino_cli.commands.scan.get_program_by_slug", new=AsyncMock(return_value=mock_prog)):
            with patch("pentefino_worker.publisher.default_publisher.publish_scan_task", new=AsyncMock(return_value=mock_pub_res)) as mock_pub:
                with patch("pentefino_cli.commands.scan.record_audit_event", new=AsyncMock()),                      patch("pentefino_cli.commands.scan._current_scope_decision",
                           new=AsyncMock(return_value=MagicMock(allowed=True))):
                    result = runner.invoke(
                        scan_app,
                        [
                            "--program",
                            "cyber-bounty",
                            "--asset",
                            "api.target.io",
                            "--severity",
                            "critical",
                            "--tags",
                            "cve",
                            "--async",
                            "--json",
                        ],
                    )


    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["status"] == "queued"
    assert data["broker_published"] is True
    mock_pub.assert_awaited_once()


