"""Publishes the proxy's real decisions to Valkey for the API's live status panel.

Keys (read by apps/api/pentefino_api/live_status.py):
  pentefino:metrics:proxy            HASH  requests/allowed/denied/ssrf_blocked totals
  pentefino:metrics:proxy:min:<m>    INT   requests in epoch-minute m (expires after 15 min)
  pentefino:proxy:heartbeat          STR   unix time of the last heartbeat (expires after 30 s)
  pentefino:events:proxy             PUBSUB one JSON message per request decision
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import urllib.parse
from typing import Any, Optional

logger = logging.getLogger("pentefino.proxy.metrics")

METRICS_KEY = "pentefino:metrics:proxy"
MINUTE_PREFIX = "pentefino:metrics:proxy:min:"
HEARTBEAT_KEY = "pentefino:proxy:heartbeat"
EVENTS_CHANNEL = "pentefino:events:proxy"
SSRF_REASON_PREFIXES = ("PROHIBITED_IP", "RESOLVED_IP_PROHIBITED", "DNS_REBINDING", "PROHIBITED_IP_SPACE")


def redact_url(url: str) -> str:
    """Drop query string and userinfo: tokens in URLs must not reach logs or the dashboard."""
    try:
        parts = urllib.parse.urlsplit(url)
        host = parts.hostname or ""
        if parts.port:
            host = f"{host}:{parts.port}"
        query = "?[REDACTED]" if parts.query else ""
        return urllib.parse.urlunsplit((parts.scheme, host, parts.path, "", "")) + query
    except ValueError:
        return "[unparseable-url]"


def is_ssrf_reason(reason: str) -> bool:
    return any(p in (reason or "") for p in SSRF_REASON_PREFIXES)


class ProxyMetrics:
    def __init__(self, valkey_url: str, enabled: Optional[bool] = None) -> None:
        self._valkey_url = valkey_url
        # PENTEFINO_PROXY_METRICS=0 (set by the test suite) keeps in-process test proxies
        # from writing into the live dashboard counters.
        self.enabled = (
            enabled if enabled is not None
            else os.getenv("PENTEFINO_PROXY_METRICS", "1").lower() not in ("0", "false", "no")
        )
        self._client: Any = None
        self._heartbeat_task: Optional[asyncio.Task] = None

    async def _get_client(self) -> Any:
        if self._client is None:
            import redis.asyncio as aioredis

            self._client = aioredis.from_url(
                self._valkey_url, decode_responses=True, socket_connect_timeout=1.0
            )
        return self._client

    async def record(
        self,
        *,
        method: str,
        url: str,
        allowed: bool,
        reason: str,
        tier: str,
        status_code: Optional[int],
        latency_ms: Optional[float] = None,
        rate_limit_wait_s: float = 0.0,
    ) -> None:
        """Best effort: a Valkey outage must never fail or slow the proxied request."""
        if not self.enabled:
            return
        ssrf = (not allowed) and is_ssrf_reason(reason)
        event = {
            "timestamp": time.time(),
            "method": method,
            "url": redact_url(url),
            "host": urllib.parse.urlsplit(url).hostname or "",
            "status": status_code,
            "verdict": "ALLOWED" if allowed else ("BLOCKED_SSRF" if ssrf else "BLOCKED_SCOPE"),
            "tier": tier,
            "reason": reason,
            "latency_ms": round(latency_ms, 1) if latency_ms is not None else None,
            "rate_limit_wait_s": round(rate_limit_wait_s, 3),
        }
        try:
            client = await self._get_client()
            minute_key = f"{MINUTE_PREFIX}{int(time.time() // 60)}"
            pipe = client.pipeline(transaction=False)
            pipe.hincrby(METRICS_KEY, "requests", 1)
            pipe.hincrby(METRICS_KEY, "allowed" if allowed else "denied", 1)
            if ssrf:
                pipe.hincrby(METRICS_KEY, "ssrf_blocked", 1)
            pipe.incr(minute_key)
            pipe.expire(minute_key, 900)
            pipe.publish(EVENTS_CHANNEL, json.dumps(event))
            await asyncio.wait_for(pipe.execute(), timeout=1.0)
        except Exception as exc:
            logger.debug("Proxy metrics publish failed: %s", exc)

    async def _heartbeat_loop(self, interval: float) -> None:
        while True:
            try:
                client = await self._get_client()
                await client.set(HEARTBEAT_KEY, str(time.time()), ex=int(interval * 3))
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.debug("Proxy heartbeat failed: %s", exc)
            await asyncio.sleep(interval)

    def start_heartbeat(self, interval: float = 10.0) -> None:
        if not self.enabled:
            return
        if self._heartbeat_task is None or self._heartbeat_task.done():
            self._heartbeat_task = asyncio.create_task(self._heartbeat_loop(interval))

    async def close(self) -> None:
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except (asyncio.CancelledError, Exception):
                pass
            self._heartbeat_task = None
        if self._client is not None:
            try:
                await self._client.delete(HEARTBEAT_KEY)
                await self._client.aclose()
            except Exception:
                pass
            self._client = None
