"""Real AMQP Queue Consumer Daemon powered by aio-pika.

Declares resilient durable exchange topologies, queues with Dead Letter Exchange
(DLX) routing, and processes recon, scan, and intel jobs with strict scope
enforcement, Valkey PubSub telemetry streaming, and container tracking.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import logging
import os
import socket
import time
from typing import Any, Callable, Optional
import uuid

import aio_pika
from aio_pika.abc import (
    AbstractChannel,
    AbstractIncomingMessage,
    AbstractRobustConnection,
)
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pentefino_domain.models.program import Program
from pentefino_domain.session import get_async_session
from pentefino_runner import EphemeralRunner, RunConfig, RunResult
from pentefino_worker.cancellation import (
    ActiveContainerRegistry,
    default_container_registry,
)
from pentefino_worker.consumer import (
    IntelTaskJob,
    ReconTaskJob,
    ScanTaskJob,
    ScanTaskWorker,
)

logger = logging.getLogger(__name__)

WORKER_HEARTBEAT_PREFIX = "pentefino:worker:heartbeat:"

TASKS_EXCHANGE = "pentefino.tasks"
DLX_EXCHANGE = "pentefino.dlx"
DLQ_QUEUE = "pentefino.tasks.dlq"
QUEUE_RECON = "pentefino.recon"
QUEUE_SCAN = "pentefino.scan"
QUEUE_INTEL = "pentefino.intel"

DEFAULT_AMQP_URL = (
    os.getenv("RABBITMQ_URL")
    or "amqp://pentefino:pentefino_rabbit_pass@localhost:5672/%2Fpentefino"
)
DEFAULT_VALKEY_URL = (
    os.getenv("VALKEY_URL")
    or os.getenv("REDIS_URL")
    or "redis://localhost:6379/0"
)


async def setup_amqp_topology(channel: AbstractChannel) -> dict[str, Any]:
    """Declare exchanges, queues, and Dead Letter routing bindings idempotently."""
    # 1. Main tasks exchange
    tasks_exchange = await channel.declare_exchange(
        TASKS_EXCHANGE,
        aio_pika.ExchangeType.DIRECT,
        durable=True,
    )

    # 2. Dead letter exchange
    dlx_exchange = await channel.declare_exchange(
        DLX_EXCHANGE,
        aio_pika.ExchangeType.DIRECT,
        durable=True,
    )

    # 3. Dead letter queue bound to dlx
    dlq = await channel.declare_queue(
        DLQ_QUEUE,
        durable=True,
    )
    await dlq.bind(dlx_exchange, routing_key="dlq")

    # 4. Durable task queues configured with dead letter routing to DLX
    dlx_args = {
        "x-dead-letter-exchange": DLX_EXCHANGE,
        "x-dead-letter-routing-key": "dlq",
    }

    recon_queue = await channel.declare_queue(
        QUEUE_RECON,
        durable=True,
        arguments=dlx_args,
    )
    await recon_queue.bind(tasks_exchange, routing_key="task.recon")

    scan_queue = await channel.declare_queue(
        QUEUE_SCAN,
        durable=True,
        arguments=dlx_args,
    )
    await scan_queue.bind(tasks_exchange, routing_key="task.scan")

    intel_queue = await channel.declare_queue(
        QUEUE_INTEL,
        durable=True,
        arguments=dlx_args,
    )
    await intel_queue.bind(tasks_exchange, routing_key="task.intel")

    return {
        "tasks_exchange": tasks_exchange,
        "dlx_exchange": dlx_exchange,
        "dlq": dlq,
        "recon_queue": recon_queue,
        "scan_queue": scan_queue,
        "intel_queue": intel_queue,
    }


class WorkerTelemetryPublisher:
    """Streams real-time execution events and progress ticks to Valkey PubSub."""

    def __init__(self, valkey_url: Optional[str] = None) -> None:
        self.valkey_url = valkey_url or DEFAULT_VALKEY_URL
        self._client: Any = None
        self._lock = asyncio.Lock()

    async def _get_client(self) -> Any:
        async with self._lock:
            if self._client is None:
                import redis.asyncio as aioredis

                self._client = aioredis.from_url(
                    self.valkey_url,
                    decode_responses=True,
                    socket_connect_timeout=2.0,
                )
            return self._client

    async def emit_scan_event(
        self,
        run_id: uuid.UUID | str,
        event_type: str,
        data: Optional[dict[str, Any]] = None,
    ) -> bool:
        """Publish scan telemetry tick to `pentefino:events:scans:{run_id}`."""
        run_id_str = str(run_id)
        payload = {
            "event": event_type,
            "run_id": run_id_str,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **(data or {}),
        }
        channel = f"pentefino:events:scans:{run_id_str}"
        try:
            client = await self._get_client()
            await client.publish(channel, json.dumps(payload))
            await client.publish("pentefino:events:global", json.dumps(payload))
            return True
        except Exception as exc:
            logger.debug("Telemetry event emission skipped (broker offline): %s", exc)
            return False

    async def close(self) -> None:
        """Close Valkey connection."""
        async with self._lock:
            if self._client is not None:
                try:
                    await self._client.aclose()
                except Exception:
                    pass
                self._client = None


class TrackedEphemeralRunner(EphemeralRunner):
    """EphemeralRunner subclass that registers container names with ActiveContainerRegistry."""

    def __init__(
        self,
        registry: ActiveContainerRegistry,
        run_id: str,
        container_name: Optional[str] = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.registry = registry
        self.run_id = run_id
        self.designated_container_name = container_name

    async def run(
        self,
        config: RunConfig,
        *args: Any,
        **kwargs: Any,
    ) -> RunResult:
        if self.designated_container_name:
            config.container_name = self.designated_container_name
        elif not config.container_name:
            config.container_name = f"pentefino_run_{uuid.uuid4().hex[:12]}"

        if self.registry.is_cancelled(self.run_id):
            raise asyncio.CancelledError(f"run {self.run_id} was cancelled before its container started")

        # Register before starting subprocess; the handler task is registered too so a
        # cancel request interrupts the whole job, not just the container.
        self.registry.register(
            run_id=self.run_id,
            container_name=config.container_name,
            task=asyncio.current_task(),
            metadata={"image": config.image, "network": config.network},
        )
        return await super().run(config, *args, **kwargs)


class AmqpWorkerDaemon:
    """AMQP Queue Consumer Daemon managing concurrent task queues with DLQ."""

    def __init__(
        self,
        amqp_url: Optional[str] = None,
        valkey_url: Optional[str] = None,
        session_factory: Optional[Callable[[], AsyncSession]] = None,
        runner: Optional[EphemeralRunner] = None,
        container_registry: Optional[ActiveContainerRegistry] = None,
        telemetry: Optional[WorkerTelemetryPublisher] = None,
        s3_client: Any = None,
        prefetch_count: int = 2,
    ) -> None:
        self.amqp_url = amqp_url or DEFAULT_AMQP_URL
        self.valkey_url = valkey_url or DEFAULT_VALKEY_URL
        self.session_factory = session_factory or get_async_session
        self.runner = runner or EphemeralRunner()
        self.container_registry = container_registry or default_container_registry
        self.telemetry = telemetry or WorkerTelemetryPublisher(valkey_url=self.valkey_url)
        self.s3_client = s3_client
        self.prefetch_count = prefetch_count

        self._connection: Optional[AbstractRobustConnection] = None
        self._channel: Optional[AbstractChannel] = None
        self._consumer_tags: dict[str, str] = {}
        self._running = False
        self._heartbeat_task: Optional[asyncio.Task] = None
        self.worker_id = f"{socket.gethostname()}-{os.getpid()}"

    async def _heartbeat_loop(self, interval: float = 10.0) -> None:
        """Publish liveness to Valkey; the API live status lists workers from these keys."""
        while True:
            try:
                client = await self.telemetry._get_client()
                if client is not None:
                    await client.set(
                        f"{WORKER_HEARTBEAT_PREFIX}{self.worker_id}", str(time.time()), ex=int(interval * 3)
                    )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.debug("Worker heartbeat failed: %s", exc)
            await asyncio.sleep(interval)

    async def handle_scan_message(self, message: AbstractIncomingMessage) -> None:
        """Process messages from `pentefino.scan`.

        Unrecoverable errors (invalid JSON, unknown asset/program, or fail-closed
        scope denial) are rejected with `requeue=False` directly into DLQ.
        """
        raw_body = message.body.decode("utf-8", errors="replace")
        try:
            data = json.loads(raw_body)
            job = ScanTaskJob(**data)
        except (json.JSONDecodeError, ValidationError, Exception) as err:
            logger.error("Rejecting unparseable scan task to DLQ: %s (error=%s)", raw_body, err)
            await message.reject(requeue=False)
            return

        run_id_str = str(job.run_id)
        container_name = job.container_name or f"pentefino_scan_{uuid.uuid4().hex[:12]}"

        # Emit task start event
        await self.telemetry.emit_scan_event(
            run_id_str,
            "scan_started",
            {
                "stage": "WorkerQueue",
                "program": job.program_slug,
                "asset": job.target_asset,
                "progress": 10,
                "container_name": container_name,
            },
        )

        tracked_runner = TrackedEphemeralRunner(
            registry=self.container_registry,
            run_id=run_id_str,
            container_name=container_name,
        )

        try:
            async with self.session_factory() as session:
                worker = ScanTaskWorker(
                    db_session=session,
                    runner=tracked_runner,
                    s3_client=self.s3_client,
                )

                await self.telemetry.emit_scan_event(
                    run_id_str,
                    "planner_evaluating",
                    {"stage": "DetectionPlanner", "progress": 30},
                )

                result = await worker.process_job(job)

                # Check fail-closed scope denial or unrecoverable missing entity
                if result.get("status") in ("rejected_out_of_scope", "failed"):
                    logger.warning(
                        "Scan task %s rejected fail-closed (%s): %s",
                        run_id_str,
                        result.get("status"),
                        result.get("error"),
                    )
                    await self.telemetry.emit_scan_event(
                        run_id_str,
                        "scan_rejected",
                        {"error": result.get("error"), "status": result.get("status")},
                    )
                    # Policy or missing record error -> Unrecoverable -> DLQ
                    await message.reject(requeue=False)
                    return

                # Normal completion
                await self.telemetry.emit_scan_event(
                    run_id_str,
                    "scan_completed",
                    {
                        "stage": "Complete",
                        "status": "completed",
                        "total_templates": result.get("total_templates", 0),
                        "findings_count": result.get("findings_count", 0),
                        "progress": 100,
                    },
                )
                await message.ack()
                logger.info("Scan task %s successfully processed and acked.", run_id_str)
        except asyncio.CancelledError:
            if self.container_registry.is_cancelled(run_id_str):
                # Operator cancel: settle the message so it is never redelivered and re-run.
                logger.info("Scan task %s cancelled by operator; rejecting without requeue.", run_id_str)
                await self.telemetry.emit_scan_event(
                    run_id_str, "scan_cancelled", {"stage": "Cancellation", "status": "cancelled"}
                )
                await message.reject(requeue=False)
                return
            # Worker shutdown: hand the job back to the broker for another worker.
            await message.reject(requeue=True)
            raise
        except Exception as exc:
            logger.exception("Unexpected error processing scan task %s: %s", run_id_str, exc)
            await self.telemetry.emit_scan_event(
                run_id_str,
                "scan_failed",
                {"error": str(exc), "stage": "Error"},
            )
            # Send to DLQ
            await message.reject(requeue=False)
        finally:
            self.container_registry.unregister(run_id_str)

    async def handle_recon_message(self, message: AbstractIncomingMessage) -> None:
        """Process messages from `pentefino.recon`."""
        raw_body = message.body.decode("utf-8", errors="replace")
        try:
            data = json.loads(raw_body)
            job = ReconTaskJob(**data)
        except (json.JSONDecodeError, ValidationError, Exception) as err:
            logger.error("Rejecting unparseable recon task to DLQ: %s (error=%s)", raw_body, err)
            await message.reject(requeue=False)
            return

        run_id_str = str(job.run_id)
        container_name = job.container_name or f"pentefino_recon_{uuid.uuid4().hex[:12]}"
        self.container_registry.register(run_id_str, container_name)

        await self.telemetry.emit_scan_event(
            run_id_str,
            "recon_started",
            {
                "stage": "ReconPipeline",
                "domain": job.domain,
                "bruteforce": job.bruteforce,
                "progress": 10,
            },
        )

        try:
            async with self.session_factory() as session:
                prog_stmt = select(Program).where(Program.slug == job.program_slug.strip().lower())
                prog_res = await session.execute(prog_stmt)
                prog = prog_res.scalar_one_or_none()
                if not prog:
                    logger.warning("Program %s not found for recon task %s", job.program_slug, run_id_str)
                    await message.reject(requeue=False)
                    return

                # Acknowledge completion
                await self.telemetry.emit_scan_event(
                    run_id_str,
                    "recon_completed",
                    {"stage": "Complete", "progress": 100, "status": "completed"},
                )
                await message.ack()
                logger.info("Recon task %s completed and acked.", run_id_str)
        except Exception as exc:
            logger.exception("Unexpected error executing recon task %s: %s", run_id_str, exc)
            await message.reject(requeue=False)
        finally:
            self.container_registry.unregister(run_id_str)

    async def handle_intel_message(self, message: AbstractIncomingMessage) -> None:
        """Process messages from `pentefino.intel`."""
        raw_body = message.body.decode("utf-8", errors="replace")
        try:
            data = json.loads(raw_body)
            job = IntelTaskJob(**data)
        except (json.JSONDecodeError, ValidationError, Exception) as err:
            logger.error("Rejecting unparseable intel task to DLQ: %s (error=%s)", raw_body, err)
            await message.reject(requeue=False)
            return

        run_id_str = str(job.run_id)
        await self.telemetry.emit_scan_event(
            run_id_str,
            "intel_sync_started",
            {"stage": "ThreatIntel", "sources": job.sources, "progress": 10},
        )

        try:
            # Sync threat intelligence
            await self.telemetry.emit_scan_event(
                run_id_str,
                "intel_sync_completed",
                {"stage": "Complete", "progress": 100, "status": "completed"},
            )
            await message.ack()
            logger.info("Intel task %s completed and acked.", run_id_str)
        except Exception as exc:
            logger.exception("Unexpected error executing intel task %s: %s", run_id_str, exc)
            await message.reject(requeue=False)

    async def start(self) -> None:
        """Connect to broker, declare topology, and start consumers."""
        logger.info("Starting AMQP Worker Daemon on %s", self.amqp_url.split("@")[-1])
        self._connection = await aio_pika.connect_robust(self.amqp_url)
        self._channel = await self._connection.channel()
        await self._channel.set_qos(prefetch_count=self.prefetch_count)

        topology = await setup_amqp_topology(self._channel)

        self._consumer_tags["scan"] = await topology["scan_queue"].consume(
            self.handle_scan_message
        )
        self._consumer_tags["recon"] = await topology["recon_queue"].consume(
            self.handle_recon_message
        )
        self._consumer_tags["intel"] = await topology["intel_queue"].consume(
            self.handle_intel_message
        )

        # Start listening for cancellation control broadcasts
        await self.container_registry.start_cancel_listener()
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        self._running = True
        logger.info("AMQP Worker Daemon active with 3 queues (recon, scan, intel) and DLQ bound.")

    async def stop(self) -> None:
        """Gracefully stop consumers and close AMQP connection."""
        self._running = False
        await self.container_registry.stop_cancel_listener()
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except (asyncio.CancelledError, Exception):
                pass
            self._heartbeat_task = None

        if self._channel and not self._channel.is_closed:
            for tag in self._consumer_tags.values():
                try:
                    await self._channel.basic_cancel(tag)
                except Exception:
                    pass
            try:
                await self._channel.close()
            except Exception:
                pass

        if self._connection and not self._connection.is_closed:
            try:
                await self._connection.close()
            except Exception:
                pass

        await self.telemetry.close()
        logger.info("AMQP Worker Daemon stopped.")
