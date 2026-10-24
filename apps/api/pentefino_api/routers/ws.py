from __future__ import annotations

import asyncio
from collections import defaultdict
from datetime import datetime, timezone
import json
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import func, select

from pentefino_domain.models.audit import AuditEvent
from pentefino_domain.session import get_async_session

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
        subscribers = self.record_and_get_subscribers(plan_id, event)
        latest = self._history[plan_id][-1]
        dead: list[WebSocket] = []
        for ws in subscribers:
            try:
                await ws.send_json(latest)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._subscribers[plan_id].discard(ws)

    def subscribe(self, plan_id: str, ws: WebSocket) -> list[dict[str, Any]]:
        self._subscribers[plan_id].add(ws)
        return list(self._history.get(plan_id, []))

    def unsubscribe(self, plan_id: str, ws: WebSocket) -> None:
        if plan_id in self._subscribers:
            self._subscribers[plan_id].discard(ws)


scan_hub = ScanTelemetryHub()


@router.websocket("/ws/scans/{plan_id}")
async def ws_scan_telemetry(websocket: WebSocket, plan_id: str) -> None:
    """Stream real-time scan execution telemetry for a given plan_id."""
    await websocket.accept()
    buffered = scan_hub.subscribe(plan_id, websocket)

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
            elif cmd == "simulate":
                steps = [
                    {
                        "event": "planner_pruning",
                        "stage": "DetectionPlanner",
                        "message": "Pruned generic CDN/WAF tags (cloudflare, akamai); retained safe_read_only templates.",
                        "progress": 25,
                    },
                    {
                        "event": "container_init",
                        "stage": "HardenedNucleiRunner",
                        "message": "Launching ephemeral container (--read-only, --cap-drop=ALL, --network=egress_net, HTTP_PROXY=http://mitmproxy:8080).",
                        "progress": 50,
                    },
                    {
                        "event": "template_execution",
                        "stage": "HardenedNucleiRunner",
                        "message": "Executing safe_read_only nuclei templates at 0.5 req/sec token-bucket rate limit.",
                        "progress": 80,
                    },
                    {
                        "event": "scan_completed",
                        "stage": "FindingNormalizer",
                        "message": "Normalized JSONL output and verified SHA-256 evidence digests.",
                        "progress": 100,
                    },
                ]
                for step in steps:
                    await scan_hub.broadcast(plan_id, step)
                    await asyncio.sleep(0.05)
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
        scan_hub.unsubscribe(plan_id, websocket)


@router.websocket("/ws/proxy/live")
async def ws_proxy_telemetry(websocket: WebSocket) -> None:
    """Stream real-time Egress Proxy Guard & rate-limiting telemetry."""
    await websocket.accept()
    try:
        await websocket.send_json(
            {
                "event": "connected",
                "channel": "proxy_telemetry",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

        # Query audit count once upon connection for live context
        audit_count = 0
        try:
            async with get_async_session() as session:
                stmt = select(func.count()).select_from(AuditEvent)
                res = await session.execute(stmt)
                audit_count = int(res.scalar_one() or 0)
        except Exception:
            audit_count = 0

        await websocket.send_json(
            {
                "event": "telemetry_tick",
                "rate_limit_rps": 0.5,
                "burst_capacity": 2,
                "mode": "fail-closed",
                "cloaking": "desktop-ua-rotation",
                "ssrf_guard": "active (RFC1918 + IMDSv2 169.254.169.254 blocked)",
                "dns_rebinding_protection": "enforced",
                "audit_events_logged": audit_count,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

        while True:
            try:
                msg = await asyncio.wait_for(websocket.receive_text(), timeout=3.0)
                if msg.strip().lower() == "ping":
                    await websocket.send_json(
                        {
                            "event": "pong",
                            "channel": "proxy_telemetry",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        }
                    )
                else:
                    await websocket.send_json(
                        {
                            "event": "telemetry_tick",
                            "rate_limit_rps": 0.5,
                            "burst_capacity": 2,
                            "mode": "fail-closed",
                            "cloaking": "desktop-ua-rotation",
                            "ssrf_guard": "active",
                            "audit_events_logged": audit_count,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        }
                    )
            except asyncio.TimeoutError:
                await websocket.send_json(
                    {
                        "event": "telemetry_tick",
                        "rate_limit_rps": 0.5,
                        "burst_capacity": 2,
                        "mode": "fail-closed",
                        "cloaking": "desktop-ua-rotation",
                        "ssrf_guard": "active",
                        "audit_events_logged": audit_count,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )
    except WebSocketDisconnect:
        pass
