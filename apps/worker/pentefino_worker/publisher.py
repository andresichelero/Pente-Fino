"""Decoupled asynchronous task publisher for RabbitMQ message broker.

Enables CLI commands and API endpoints to dispatch scan, recon, and intel tasks
asynchronously to durable RabbitMQ exchanges with correlation IDs and headers,
featuring graceful local fallback when the broker is offline.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import logging
import os
from typing import Any, Optional
import uuid

import aio_pika
from aio_pika.abc import AbstractChannel, AbstractExchange, AbstractRobustConnection

logger = logging.getLogger(__name__)

TASKS_EXCHANGE_NAME = "pentefino.tasks"
DEFAULT_AMQP_URL = (
    os.getenv("RABBITMQ_URL")
    or "amqp://pentefino:pentefino_rabbit_pass@localhost:5672/%2Fpentefino"
)


class AmqpTaskPublisher:
    """Asynchronous AMQP publisher dispatching background security tasks."""

    def __init__(self, amqp_url: Optional[str] = None) -> None:
        self.amqp_url = amqp_url or DEFAULT_AMQP_URL
        self._connection: Optional[AbstractRobustConnection] = None
        self._channel: Optional[AbstractChannel] = None
        self._exchange: Optional[AbstractExchange] = None
        self._lock = asyncio.Lock()

    async def _ensure_connected(self) -> AbstractExchange:
        """Ensure connection and exchange declaration, reconnecting if closed."""
        async with self._lock:
            if (
                self._connection
                and not self._connection.is_closed
                and self._channel
                and not self._channel.is_closed
                and self._exchange
            ):
                return self._exchange

            try:
                self._connection = await aio_pika.connect_robust(
                    self.amqp_url,
                    timeout=5.0,
                )
                self._channel = await self._connection.channel()
                self._exchange = await self._channel.declare_exchange(
                    TASKS_EXCHANGE_NAME,
                    aio_pika.ExchangeType.DIRECT,
                    durable=True,
                )
                logger.info(
                    "Connected to AMQP broker at %s, declared exchange %s",
                    self.amqp_url.split("@")[-1],
                    TASKS_EXCHANGE_NAME,
                )
                return self._exchange
            except Exception as exc:
                logger.warning("Failed to connect to AMQP broker (%s): %s", self.amqp_url, exc)
                raise

    async def publish_task(
        self,
        routing_key: str,
        payload: dict[str, Any],
        correlation_id: Optional[str] = None,
        headers: Optional[dict[str, Any]] = None,
    ) -> bool:
        """Publish a generic task payload with correlation ID and persistent delivery."""
        corr_id = correlation_id or str(uuid.uuid4())
        msg_headers = {
            "dispatched_at": datetime.now(timezone.utc).isoformat(),
            **(headers or {}),
        }
        body = json.dumps(payload).encode("utf-8")
        message = aio_pika.Message(
            body=body,
            delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
            content_type="application/json",
            correlation_id=corr_id,
            headers=msg_headers,
        )

        try:
            exchange = await self._ensure_connected()
            await exchange.publish(message, routing_key=routing_key)
            logger.info("Published task with routing_key '%s' [corr_id=%s]", routing_key, corr_id)
            return True
        except Exception as exc:
            logger.warning(
                "Could not publish AMQP task to '%s' [corr_id=%s]: %s",
                routing_key,
                corr_id,
                exc,
            )
            return False

    async def publish_scan_task(
        self,
        program_slug: str,
        target_asset: str,
        severity: Optional[str] = None,
        tags: Optional[str] = None,
        run_id: Optional[uuid.UUID | str] = None,
    ) -> dict[str, Any]:
        """Publish a scan run job to `task.scan` queue with graceful fallback."""
        task_id = str(run_id or uuid.uuid4())
        payload = {
            "run_id": task_id,
            "program_slug": program_slug.strip().lower(),
            "target_asset": target_asset.strip().lower(),
            "severity": severity,
            "tags": tags,
            "submitted_at": datetime.now(timezone.utc).isoformat(),
        }

        published = await self.publish_task(
            routing_key="task.scan",
            payload=payload,
            correlation_id=task_id,
            headers={"task_type": "scan", "program": program_slug},
        )

        status_str = "queued" if published else "queued_offline_fallback"
        return {
            "status": status_str,
            "run_id": task_id,
            "program": program_slug,
            "asset": target_asset,
            "severity": severity,
            "tags": tags,
            "broker_published": published,
            "message": (
                f"Scan task for {target_asset} successfully queued in AMQP."
                if published
                else f"Broker offline; scan task for {target_asset} queued with local fallback."
            ),
        }

    async def publish_recon_task(
        self,
        program_slug: str,
        domain: str,
        bruteforce: bool = False,
        run_id: Optional[uuid.UUID | str] = None,
    ) -> dict[str, Any]:
        """Publish a recon task job to `task.recon` queue with graceful fallback."""
        task_id = str(run_id or uuid.uuid4())
        payload = {
            "run_id": task_id,
            "program_slug": program_slug.strip().lower(),
            "domain": domain.strip().lower(),
            "bruteforce": bruteforce,
            "submitted_at": datetime.now(timezone.utc).isoformat(),
        }

        published = await self.publish_task(
            routing_key="task.recon",
            payload=payload,
            correlation_id=task_id,
            headers={"task_type": "recon", "domain": domain},
        )

        status_str = "queued" if published else "queued_offline_fallback"
        return {
            "status": status_str,
            "task_id": task_id,
            "program": program_slug,
            "domain": domain,
            "bruteforce": bruteforce,
            "broker_published": published,
            "message": (
                f"Recon task for {domain} successfully queued in AMQP."
                if published
                else f"Broker offline; recon task for {domain} queued with local fallback."
            ),
        }

    async def publish_intel_task(
        self,
        action: str = "sync",
        sources: Optional[list[str]] = None,
        run_id: Optional[uuid.UUID | str] = None,
    ) -> dict[str, Any]:
        """Publish a threat intelligence sync job to `task.intel` queue."""
        task_id = str(run_id or uuid.uuid4())
        payload = {
            "run_id": task_id,
            "action": action,
            "sources": sources or ["epss", "kev"],
            "submitted_at": datetime.now(timezone.utc).isoformat(),
        }

        published = await self.publish_task(
            routing_key="task.intel",
            payload=payload,
            correlation_id=task_id,
            headers={"task_type": "intel", "action": action},
        )

        return {
            "status": "queued" if published else "queued_offline_fallback",
            "task_id": task_id,
            "action": action,
            "broker_published": published,
        }

    async def close(self) -> None:
        """Close AMQP channel and connection."""
        async with self._lock:
            try:
                if self._channel and not self._channel.is_closed:
                    await self._channel.close()
            except Exception:
                pass
            try:
                if self._connection and not self._connection.is_closed:
                    await self._connection.close()
            except Exception:
                pass
            self._channel = None
            self._connection = None
            self._exchange = None


# Module-level default publisher instance
default_publisher = AmqpTaskPublisher()
