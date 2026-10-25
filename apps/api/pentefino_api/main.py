from __future__ import annotations

import asyncio
import logging
import os
import secrets
import sys
import time
from typing import Any

if sys.platform == "win32":
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    except Exception:
        pass

from dotenv import load_dotenv

load_dotenv()

from fastapi import Depends, FastAPI, Header, HTTPException, Request, WebSocketException, status
from fastapi.requests import HTTPConnection
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.exc import InterfaceError, OperationalError

from pentefino_api.deps import DatabaseStandbyError
from pentefino_api.live_status import get_live_status
from pentefino_api.network_monitor import get_network_health_metrics_async
from pentefino_api.telemetry_series import record_sample, sample_series
from pentefino_api.routers import (
    assets,
    evidence,
    findings,
    intel,
    programs,
    recon,
    scans,
    scope,
    templates,
    ws,
)
from pentefino_domain.models.asset import Asset
from pentefino_domain.models.audit import AuditEvent
from pentefino_domain.models.finding import Finding
from pentefino_domain.models.program import Program
from pentefino_domain.models.template import TemplateCatalog
from pentefino_domain.session import check_db_available, get_async_session, mark_db_offline

_SNAPSHOT_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_SNAPSHOT_TTL_SECONDS = 2.5


def _standby_snapshot() -> dict[str, Any]:
    """Counts are unknown while the database is down: report None, never placeholders."""
    return {
        "db_connected": False,
        "db_latency_ms": None,
        "templates_count": None,
        "active_programs_count": None,
        "programs_count": None,
        "assets_count": None,
        "findings_count": None,
        "validated_e2_count": None,
        "audit_count": None,
        "recent_audit_events": [],
    }


async def _fetch_db_counts_snapshot() -> tuple[bool, float | None, dict[str, Any]]:
    """Fetch combined counts in a single SQL roundtrip with a 2.5s in-memory TTL cache."""
    now = time.monotonic()
    cached = _SNAPSHOT_CACHE.get("counts")
    if cached and now < cached[0]:
        data = cached[1]
        return bool(data["db_connected"]), data["db_latency_ms"], data

    if not await check_db_available():
        standby_data = _standby_snapshot()
        _SNAPSHOT_CACHE["counts"] = (now + _SNAPSHOT_TTL_SECONDS, standby_data)
        return False, None, standby_data

    t0 = time.perf_counter()
    try:
        async with get_async_session() as session:
            combined_stmt = select(
                select(func.count()).select_from(TemplateCatalog).scalar_subquery().label("templates"),
                select(func.count())
                .select_from(Program)
                .where(Program.state == "active")
                .scalar_subquery()
                .label("active_programs"),
                select(func.count()).select_from(Program).scalar_subquery().label("programs"),
                select(func.count()).select_from(Asset).scalar_subquery().label("assets"),
                select(func.count()).select_from(Finding).scalar_subquery().label("findings"),
                select(func.count())
                .select_from(Finding)
                .where(Finding.evidence_level.in_(["E2", "E3"]))
                .scalar_subquery()
                .label("validated_e2"),
                select(func.count()).select_from(AuditEvent).scalar_subquery().label("audits"),
            )
            row = (await session.execute(combined_stmt)).one()

            audit_res = await session.execute(
                select(AuditEvent)
                .order_by(AuditEvent.occurred_at.desc(), AuditEvent.sequence.desc())
                .limit(10)
            )
            recent_audit_events = [
                {
                    "sequence": ev.sequence,
                    "actor": ev.actor,
                    "event_type": ev.event_type,
                    "object_type": ev.object_type,
                    "object_id": ev.object_id,
                    "payload": ev.payload if isinstance(ev.payload, dict) else {},
                    "occurred_at": ev.occurred_at.isoformat() if ev.occurred_at else "",
                }
                for ev in audit_res.scalars().all()
            ]

        db_latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        live_data = {
            "db_connected": True,
            "db_latency_ms": db_latency_ms,
            "templates_count": int(row.templates or 0),
            "active_programs_count": int(row.active_programs or 0),
            "programs_count": int(row.programs or 0),
            "assets_count": int(row.assets or 0),
            "findings_count": int(row.findings or 0),
            "validated_e2_count": int(row.validated_e2 or 0),
            "audit_count": int(row.audits or 0),
            "recent_audit_events": recent_audit_events,
        }
        _SNAPSHOT_CACHE["counts"] = (now + _SNAPSHOT_TTL_SECONDS, live_data)
        return True, live_data["db_latency_ms"], live_data
    except Exception as exc:
        logging.getLogger("pentefino.api").warning("DB counts snapshot failed: %r", exc)
        mark_db_offline()
        standby_data = _standby_snapshot()
        _SNAPSHOT_CACHE["counts"] = (now + _SNAPSHOT_TTL_SECONDS, standby_data)
        return False, None, standby_data


_LOOPBACK_DEFAULT = "127.0.0.1,::1,localhost"


def _trusted_clients() -> set[str]:
    raw = os.getenv("PENTEFINO_TRUSTED_CLIENTS", _LOOPBACK_DEFAULT)
    return {c.strip() for c in raw.split(",") if c.strip()}


async def verify_api_key(
    conn: HTTPConnection,
    x_pentefino_key: str | None = Header(default=None, alias="X-PenteFino-Key"),
) -> None:
    """Authenticate every HTTP and WebSocket request, failing closed.

    - PENTEFINO_API_KEY set: require it in the X-PenteFino-Key header (HTTP) or, because
      browsers cannot set headers on a WebSocket handshake, in the `key` query parameter
      (WebSocket only).
    - PENTEFINO_API_KEY unset: only clients in PENTEFINO_TRUSTED_CLIENTS (loopback by
      default) are served; everyone else gets 401 instead of an open API.
    """
    is_ws = conn.scope.get("type") == "websocket"
    expected_key = os.getenv("PENTEFINO_API_KEY", "").strip()
    if expected_key:
        supplied = x_pentefino_key or (conn.query_params.get("key") if is_ws else None)
        if supplied and secrets.compare_digest(supplied.strip(), expected_key):
            return
        reason = "Invalid or missing X-PenteFino-Key header."
    else:
        client_host = conn.client.host if conn.client else ""
        if client_host in _trusted_clients():
            return
        reason = (
            "PENTEFINO_API_KEY is not configured; only loopback clients are allowed. "
            "Set PENTEFINO_API_KEY to serve remote clients."
        )
    if is_ws:
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION, reason=reason)
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=reason)


def create_app() -> FastAPI:
    """Create and configure the PenteFino FastAPI application."""
    app = FastAPI(
        title="PenteFino Security Governance & Recon API",
        version="0.5.0",
        description=(
            "Hard-gate fail-closed scope governance, CDN-pruned Nuclei detection planner, "
            "and forensic bug bounty triage API."
        ),
        dependencies=[Depends(verify_api_key)],
    )

    raw_origins = os.getenv(
        "PENTEFINO_CORS_ORIGINS",
        "http://localhost:4321,http://127.0.0.1:4321,http://localhost:3000,http://127.0.0.1:3000",
    )
    allowed_origins = [o.strip() for o in raw_origins.split(",") if o.strip()]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    def _build_standby_response(request: Request, exc: Exception) -> JSONResponse:
        # 503 for every method: a 200 with empty lists is indistinguishable from "no data".
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            headers={"Retry-After": "5"},
            content={
                "status": "standby",
                "db_connected": False,
                "detail": f"Database standby ({type(exc).__name__})",
                "items": [],
                "findings": [],
                "programs": [],
                "assets": [],
                "rules": [],
                "history": [],
                "nodes": [],
                "edges": [],
                "total": 0,
                "page": 1,
                "page_size": 25,
                "total_pages": 0,
                "by_impact_class": {},
                "by_severity": {},
            },
        )

    @app.exception_handler(DatabaseStandbyError)
    async def standby_circuit_handler(
        request: Request, exc: DatabaseStandbyError
    ) -> JSONResponse:
        """Fast-fail handler when PostgreSQL circuit breaker is open."""
        return _build_standby_response(request, exc)

    @app.exception_handler(Exception)
    async def standby_db_exception_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        """Map DB connectivity errors to standby; surface every other failure as a real 500."""
        if isinstance(exc, HTTPException):
            return JSONResponse(
                status_code=exc.status_code,
                content={"detail": exc.detail},
                headers=getattr(exc, "headers", None),
            )
        if isinstance(exc, (OperationalError, InterfaceError)):
            mark_db_offline()
            return _build_standby_response(request, exc)
        if isinstance(exc, (OSError, TimeoutError)) and not await check_db_available():
            # Socket-level errors are only "standby" when PostgreSQL really is unreachable;
            # otherwise (S3, docker, a scanner binary...) they are genuine 500s.
            mark_db_offline()
            return _build_standby_response(request, exc)
        logging.getLogger("pentefino.api").exception("Unhandled error on %s", request.url.path)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": f"Internal error ({type(exc).__name__})"},
        )

    @app.get("/api/v1/health", tags=["health"])
    async def health_check() -> dict[str, Any]:
        """Check database connectivity, template catalog count, and active programs count."""
        db_connected, db_latency_ms, snap = await _fetch_db_counts_snapshot()
        return {
            "status": "ok" if db_connected else "degraded",
            "service": "pentefino-api",
            "version": "0.5.0",
            "database": "connected" if db_connected else "standby",
            "db_connected": db_connected,
            "db_latency_ms": db_latency_ms,
            "templates_count": snap["templates_count"],
            "template_count": snap["templates_count"],
            "active_programs_count": snap["active_programs_count"],
            "programs_count": snap["programs_count"],
            "assets_count": snap["assets_count"],
            "findings_count": snap["findings_count"],
            "validated_e2_count": snap["validated_e2_count"],
            "recent_audit_events": snap["recent_audit_events"],
        }

    @app.get("/api/v1/telemetry/summary", tags=["telemetry"])
    async def telemetry_summary() -> dict[str, Any]:
        """Measured counters and latencies; configured limits are labelled as configuration.

        Series are samples of the live status taken by this process, so they stay empty
        until the live status has been polled at least twice.
        """
        db_connected, db_latency_ms, snap = await _fetch_db_counts_snapshot()
        live = await get_live_status()
        record_sample(live)
        return {
            "status": "ok" if db_connected else "degraded",
            "db_connected": db_connected,
            "configured_limits": {
                "source": "environment",
                "rate_limit_host_rps": float(os.getenv("RATE_LIMIT_HOST_RPS", "0.5")),
                "rate_limit_program_rps": float(os.getenv("RATE_LIMIT_PROGRAM_RPS", "2.0")),
                "max_concurrency_per_host": int(os.getenv("RATE_LIMIT_MAX_CONCURRENCY_PER_HOST", "1")),
            },
            "templates_indexed": snap["templates_count"],
            "programs_count": snap["programs_count"],
            "assets_count": snap["assets_count"],
            "findings_count": snap["findings_count"],
            "validated_e2_count": snap["validated_e2_count"],
            "audit_events_count": snap["audit_count"],
            "planner_latency_ms": None,
            "db_latency_ms": db_latency_ms,
            "valkey_latency_ms": live["systems"]["valkey"]["latency_ms"],
            "network": live["network"],
            "series": sample_series(),
            "unavailable": {
                "planner_latency_ms": "DetectionPlanner does not record timings",
            },
        }

    @app.get("/api/v1/telemetry/network-health", tags=["telemetry"])
    async def get_network_health() -> dict[str, Any]:
        """Return real network monitor stats: ping, jitter, loss, packets, throughput, and target health."""
        return await get_network_health_metrics_async()

    @app.get("/api/v1/status/live", tags=["telemetry"])
    async def live_status() -> dict[str, Any]:
        """One-shot live snapshot of every subsystem (same payload as /ws/status)."""
        snap = await get_live_status()
        record_sample(snap)
        return snap

    app.include_router(programs.router)
    app.include_router(scope.router)
    app.include_router(assets.router)
    app.include_router(recon.router)
    app.include_router(templates.router)
    app.include_router(scans.router)
    app.include_router(findings.router)
    app.include_router(evidence.router)
    app.include_router(intel.router)
    app.include_router(ws.router)

    return app


app = create_app()
