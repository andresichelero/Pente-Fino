from __future__ import annotations

import asyncio
from collections import defaultdict
from datetime import datetime, timezone
import json
import os
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from pentefino_api.live_status import collect_proxy_traffic, get_live_status, valkey_client
from pentefino_api.telemetry_series import record_sample

PROXY_EVENTS_CHANNEL = "pentefino:events:proxy"
STATUS_PUSH_INTERVAL_S = float(os.getenv("PENTEFINO_STATUS_PUSH_INTERVAL", "5"))

router = APIRouter(tags=["websockets"])


class ScanTelemetryHub:
    """In-memory pub/sub and event buffer for real-time scan telemetry streams."""

    def __init__(self) -> None:
        self._subscribers: dict[str, set[WebSocket]] = defaultdict(set)
        self._history: dict[str, list[dict[str, Any]]] = defaultdict(list)

    def record_and_get_subscribers(
        self, plan_id: str, event: dict[str, Any]
    ) -> list[WebSocket]:
        payload = {
            "plan_id": plan_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **event,
        }
        buf = self._history[plan_id]
        buf.append(payload)
        if len(buf) > 200:
            del buf[:-200]
        return list(self._subscribers.get(plan_id, set()))

    async def broadcast(self, plan_id: str, event: dict[str, Any]) -> None:
        subscribers = set(self.record_and_get_subscribers(plan_id, event))
        if plan_id != "live":
            subscribers.update(self.record_and_get_subscribers("live", event))

        latest = self._history[plan_id][-1]
        dead: list[WebSocket] = []
        for ws in subscribers:
            try:
                await ws.send_json(latest)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._subscribers[plan_id].discard(ws)
            if "live" in self._subscribers:
                self._subscribers["live"].discard(ws)

    def subscribe(self, plan_id: str, ws: WebSocket) -> list[dict[str, Any]]:
        self._subscribers[plan_id].add(ws)
        return list(self._history.get(plan_id, []))

    def unsubscribe(self, plan_id: str, ws: WebSocket) -> None:
        if plan_id in self._subscribers:
            self._subscribers[plan_id].discard(ws)


scan_hub = ScanTelemetryHub()


async def _valkey_subscriber_loop(websocket: WebSocket, plan_id: str) -> None:
    """Stream real-time Valkey PubSub scan events to connected WebSocket client."""
    valkey_url = (
        os.getenv("VALKEY_URL")
        or os.getenv("REDIS_URL")
        or "redis://localhost:6379/0"
    )
    try:
        import redis.asyncio as aioredis

        client = aioredis.from_url(
            valkey_url,
            decode_responses=True,
            socket_connect_timeout=2.0,
        )
        async with client:
            pubsub = client.pubsub()
            channel = f"pentefino:events:scans:{plan_id}"
            await pubsub.subscribe(channel)
            while True:
                msg = await pubsub.get_message(
                    ignore_subscribe_messages=True,
                    timeout=1.0,
                )
                if msg and msg.get("type") == "message":
                    raw_data = msg.get("data")
                    if isinstance(raw_data, str):
                        try:
                            payload = json.loads(raw_data)
                            await websocket.send_json(payload)
                        except Exception:
                            pass
                await asyncio.sleep(0.02)
    except asyncio.CancelledError:
        pass
    except Exception:
        pass


@router.websocket("/ws/scans/{plan_id}")
async def ws_scan_telemetry(websocket: WebSocket, plan_id: str) -> None:
    """Stream real-time scan execution telemetry for a given plan_id."""
    await websocket.accept()
    buffered = scan_hub.subscribe(plan_id, websocket)

    valkey_task = asyncio.create_task(_valkey_subscriber_loop(websocket, plan_id))

    try:
        await websocket.send_json(
            {
                "event": "connected",
                "plan_id": plan_id,
                "buffered_events": len(buffered),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
        for item in buffered:
            await websocket.send_json(item)

        while True:
            raw_msg = await websocket.receive_text()
            cmd = raw_msg.strip().lower()
            try:
                parsed = json.loads(raw_msg)
                if isinstance(parsed, dict):
                    cmd = str(parsed.get("action") or parsed.get("cmd") or cmd).lower()
            except Exception:
                pass

            if cmd == "ping":
                await websocket.send_json(
                    {
                        "event": "pong",
                        "plan_id": plan_id,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )
            else:
                await websocket.send_json(
                    {
                        "event": "ack",
                        "plan_id": plan_id,
                        "received": raw_msg,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )
    except WebSocketDisconnect:
        pass
    finally:
        valkey_task.cancel()
        try:
            await valkey_task
        except (asyncio.CancelledError, Exception):
            pass
        scan_hub.unsubscribe(plan_id, websocket)



def _configured_limits() -> dict[str, Any]:
    return {
        "source": "environment",
        "rate_limit_host_rps": float(os.getenv("RATE_LIMIT_HOST_RPS", "0.5")),
        "rate_limit_program_rps": float(os.getenv("RATE_LIMIT_PROGRAM_RPS", "2.0")),
    }


async def _proxy_tick() -> dict[str, Any]:
    client = valkey_client()
    try:
        traffic = await collect_proxy_traffic(client)
    finally:
        try:
            await client.aclose()
        except Exception:
            pass
    return {
        "event": "telemetry_tick",
        "channel": "proxy_telemetry",
        "configured_limits": _configured_limits(),
        "traffic": traffic,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


async def _proxy_event_relay(websocket: WebSocket) -> None:
    """Relay real proxy decisions published by pentefino_proxy on Valkey."""
    try:
        import redis.asyncio as aioredis

        valkey_url = os.getenv("VALKEY_URL") or os.getenv("REDIS_URL") or "redis://127.0.0.1:6379/0"
        client = aioredis.from_url(valkey_url, decode_responses=True, socket_connect_timeout=2.0)
        async with client:
            pubsub = client.pubsub()
            await pubsub.subscribe(PROXY_EVENTS_CHANNEL)
            while True:
                msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if msg and msg.get("type") == "message" and isinstance(msg.get("data"), str):
                    try:
                        await websocket.send_json({"event": "http_egress", **json.loads(msg["data"])})
                    except json.JSONDecodeError:
                        pass
                await asyncio.sleep(0.02)
    except asyncio.CancelledError:
        pass
    except Exception:
        pass


@router.websocket("/ws/proxy/live")
async def ws_proxy_telemetry(websocket: WebSocket) -> None:
    """Stream egress-proxy decisions and counters. Only events the proxy actually published."""
    await websocket.accept()
    relay = asyncio.create_task(_proxy_event_relay(websocket))
    try:
        await websocket.send_json(
            {
                "event": "connected",
                "channel": "proxy_telemetry",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
        await websocket.send_json(await _proxy_tick())

        while True:
            try:
                msg = await asyncio.wait_for(websocket.receive_text(), timeout=5.0)
                if msg.strip().lower() == "ping":
                    await websocket.send_json(
                        {
                            "event": "pong",
                            "channel": "proxy_telemetry",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        }
                    )
                else:
                    await websocket.send_json(await _proxy_tick())
            except asyncio.TimeoutError:
                await websocket.send_json(await _proxy_tick())
    except WebSocketDisconnect:
        pass
    finally:
        relay.cancel()
        try:
            await relay
        except (asyncio.CancelledError, Exception):
            pass


@router.websocket("/ws/status")
async def ws_live_status(websocket: WebSocket) -> None:
    """Push a live status snapshot every STATUS_PUSH_INTERVAL_S seconds.

    Clients may send "refresh" to get an immediate snapshot or "ping" for a pong.
    """
    await websocket.accept()

    async def _push(force: bool = False) -> None:
        snap = await get_live_status(force=force)
        record_sample(snap)
        await websocket.send_json({"event": "status", "interval_s": STATUS_PUSH_INTERVAL_S, "data": snap})

    try:
        await _push()
        while True:
            try:
                msg = await asyncio.wait_for(websocket.receive_text(), timeout=STATUS_PUSH_INTERVAL_S)
                cmd = msg.strip().lower()
                if cmd == "ping":
                    await websocket.send_json({"event": "pong", "timestamp": datetime.now(timezone.utc).isoformat()})
                elif cmd == "refresh":
                    await _push(force=True)
            except asyncio.TimeoutError:
                await _push()
    except WebSocketDisconnect:
        pass
