"""Deterministic ephemeral container registry and cancellation control plane.

Tracks active ephemeral scanner containers by run_id/job_id and exposes
deterministic on-demand cancellation via `docker rm -f <container_name>`,
coordinated locally and across distributed workers via Valkey PubSub.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import logging
import os
import shutil
import time
from typing import Any, Optional
import uuid

logger = logging.getLogger(__name__)

CANCEL_CONTROL_CHANNEL = "pentefino:control:cancel"
SCAN_EVENTS_CHANNEL_PREFIX = "pentefino:events:scans:"


@dataclass
class ActiveJobInfo:
    """Metadata regarding an actively running containerized scanning job."""

    run_id: str
    container_name: str
    task: Optional[asyncio.Task] = None
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "running"
    metadata: dict[str, Any] = field(default_factory=dict)


class ActiveContainerRegistry:
    """Registry maintaining active container names and providing deterministic cancellation."""

    def __init__(self, valkey_url: Optional[str] = None) -> None:
        self._jobs: dict[str, ActiveJobInfo] = {}
        # Tombstones for runs cancelled before (or while) they were registered here, so a
        # late-starting container is refused instead of running after the operator cancelled.
        self._cancelled: dict[str, float] = {}
        self._valkey_url = valkey_url or os.getenv("VALKEY_URL") or os.getenv("REDIS_URL") or "redis://localhost:6379/0"
        self._cancel_listener_task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()

    def register(
        self,
        run_id: uuid.UUID | str,
        container_name: str,
        task: Optional[asyncio.Task] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> ActiveJobInfo:
        """Register a newly spawned container for tracking."""
        key = str(run_id)
        job_info = ActiveJobInfo(
            run_id=key,
            container_name=container_name,
            task=task,
            metadata=metadata or {},
        )
        self._jobs[key] = job_info
        logger.info("Registered active container %s for run %s", container_name, key)
        return job_info

    def mark_cancelled(self, run_id: uuid.UUID | str) -> None:
        self._cancelled[str(run_id)] = time.monotonic()
        if len(self._cancelled) > 1000:
            for key in sorted(self._cancelled, key=self._cancelled.get)[:200]:
                self._cancelled.pop(key, None)

    def is_cancelled(self, run_id: uuid.UUID | str) -> bool:
        return str(run_id) in self._cancelled

    def unregister(self, run_id: uuid.UUID | str) -> Optional[ActiveJobInfo]:
        """Unregister a completed or terminated container."""
        key = str(run_id)
        job = self._jobs.pop(key, None)
        if job:
            logger.info("Unregistered active container %s for run %s", job.container_name, key)
        return job

    def get(self, run_id: uuid.UUID | str) -> Optional[ActiveJobInfo]:
        """Retrieve tracking info for a running job."""
        return self._jobs.get(str(run_id))

    def list_active(self) -> list[ActiveJobInfo]:
        """List all currently active tracked jobs."""
        return list(self._jobs.values())

    async def cancel_run(
        self,
        run_id: uuid.UUID | str,
        engine_bin: Optional[str] = None,
        timeout: float = 5.0,
    ) -> bool:
        """Deterministically terminate and remove an active container via `docker rm -f`.

        Also cancels the associated asyncio.Task if present, updates status to
        cancelled, and cleans up the registration.
        """
        key = str(run_id)
        self.mark_cancelled(key)
        job = self._jobs.get(key)
        if not job:
            logger.warning("Cancel for run %s not registered here yet; tombstoned.", key)
            return False

        job.status = "cancelled"
        container_name = job.container_name

        # 1. Terminate associated in-process task if still executing
        if job.task and not job.task.done():
            job.task.cancel()
            logger.info("Cancelled in-process task for run %s", key)

        # 2. Issue `docker rm -f <container_name>`
        bin_path = engine_bin or shutil.which("docker") or shutil.which("podman") or "docker"

        try:
            logger.info("Killing container %s via %s rm -f", container_name, bin_path)
            proc = await asyncio.create_subprocess_exec(
                bin_path,
                "rm",
                "-f",
                container_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            if proc.returncode == 0:
                logger.info("Container %s successfully removed.", container_name)

            else:
                logger.warning(
                    "Container engine returned code %d when removing %s: %s",
                    proc.returncode,
                    container_name,
                    stderr.decode(errors="replace"),
                )

        except asyncio.TimeoutError:
            logger.error("Timed out waiting for %s rm -f %s", bin_path, container_name)
        except Exception as exc:
            logger.warning("Could not execute container removal (%s): %s", bin_path, exc)

        # 3. Notify subscribers on Valkey PubSub if available
        try:
            await self.publish_event(
                key,
                {
                    "event": "scan_cancelled",
                    "run_id": key,
                    "container_name": container_name,
                    "status": "cancelled",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "message": f"Deterministic container {container_name} terminated and removed.",
                },
            )
        except Exception as err:
            logger.debug("Failed to publish cancellation event to Valkey: %s", err)

        # 4. Remove from active registry
        self._jobs.pop(key, None)
        return True

    async def publish_event(self, run_id: str, event_data: dict[str, Any]) -> bool:
        """Publish an event to Valkey PubSub for a specific run."""
        try:
            import redis.asyncio as aioredis

            client = aioredis.from_url(
                self._valkey_url,
                decode_responses=True,
                socket_connect_timeout=2.0,
            )
            async with client:
                channel = f"{SCAN_EVENTS_CHANNEL_PREFIX}{run_id}"
                await client.publish(channel, json.dumps(event_data))
                return True
        except Exception as exc:
            logger.debug("Valkey event publishing failed: %s", exc)
            return False

    async def broadcast_cancel(self, run_id: uuid.UUID | str) -> bool:
        """Broadcast a cancellation request across Valkey to all worker daemons."""
        key = str(run_id)
        self.mark_cancelled(key)
        # Cancel locally first if present
        local_cancelled = False
        if key in self._jobs:
            local_cancelled = await self.cancel_run(key)

        # Broadcast to distributed workers
        try:
            import redis.asyncio as aioredis

            client = aioredis.from_url(
                self._valkey_url,
                decode_responses=True,
                socket_connect_timeout=2.0,
            )
            async with client:
                payload = {
                    "action": "cancel",
                    "run_id": key,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                await client.publish(CANCEL_CONTROL_CHANNEL, json.dumps(payload))
                return True
        except Exception as exc:
            logger.debug("Valkey broadcast_cancel failed (local_cancelled=%s): %s", local_cancelled, exc)
            return local_cancelled

    async def start_cancel_listener(self) -> asyncio.Task:
        """Start background listener task receiving cancel control broadcasts."""
        self._stop_event.clear()
        task = asyncio.create_task(self._cancel_listener_loop())
        self._cancel_listener_task = task
        return task

    async def _cancel_listener_loop(self) -> None:
        """Subscription loop listening on `pentefino:control:cancel`."""
        while not self._stop_event.is_set():
            try:
                import redis.asyncio as aioredis

                client = aioredis.from_url(
                    self._valkey_url,
                    decode_responses=True,
                    socket_connect_timeout=3.0,
                )
                async with client:
                    pubsub = client.pubsub()
                    await pubsub.subscribe(CANCEL_CONTROL_CHANNEL)
                    logger.info("Subscribed to cancellation control channel: %s", CANCEL_CONTROL_CHANNEL)

                    while not self._stop_event.is_set():
                        try:
                            msg = await asyncio.wait_for(
                                pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0),
                                timeout=2.0,
                            )
                            if msg and msg.get("type") == "message":
                                raw_data = msg.get("data")
                                if isinstance(raw_data, str):
                                    data = json.loads(raw_data)
                                    target_run_id = data.get("run_id")
                                    if target_run_id:
                                        self.mark_cancelled(target_run_id)
                                    if target_run_id and target_run_id in self._jobs:
                                        logger.info(
                                            "Received cancel broadcast for locally managed run: %s",
                                            target_run_id,
                                        )
                                        await self.cancel_run(target_run_id)
                        except asyncio.TimeoutError:
                            continue
            except asyncio.CancelledError:
                break
            except Exception as err:
                logger.debug("Cancel listener reconnecting after error: %s", err)
                if not self._stop_event.is_set():
                    await asyncio.sleep(2.0)

    async def stop_cancel_listener(self) -> None:
        """Gracefully terminate cancel listener loop."""
        self._stop_event.set()
        if self._cancel_listener_task and not self._cancel_listener_task.done():
            self._cancel_listener_task.cancel()
            try:
                await self._cancel_listener_task
            except (asyncio.CancelledError, Exception):
                pass
        self._cancel_listener_task = None


# Module-level default registry
default_container_registry = ActiveContainerRegistry()
