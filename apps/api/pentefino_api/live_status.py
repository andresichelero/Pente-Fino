"""Live operational status, measured on demand from each subsystem.

Contract: every value is either measured now (with `checked_at` and `source`) or is
`None` with a `detail` explaining why it is unavailable. Nothing here is a constant
dressed up as a measurement.
"""
from __future__ import annotations

import asyncio
import os
import socket
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Optional
from urllib.parse import quote

import httpx
from sqlalchemy import func, select, text

from pentefino_api.activity import activity
from pentefino_api.network_monitor import get_network_health_metrics_async
from pentefino_domain.models.asset import Asset
from pentefino_domain.models.finding import Finding
from pentefino_domain.models.template import TemplateCatalog
from pentefino_domain.session import check_db_available, get_async_session

PROXY_METRICS_KEY = "pentefino:metrics:proxy"
PROXY_MINUTE_PREFIX = "pentefino:metrics:proxy:min:"
PROXY_HEARTBEAT_KEY = "pentefino:proxy:heartbeat"
WORKER_HEARTBEAT_PREFIX = "pentefino:worker:heartbeat:"
STATUS_TTL_SECONDS = float(os.getenv("PENTEFINO_STATUS_CACHE_TTL", "4"))
PROBE_TIMEOUT = 2.0

_started_monotonic = time.monotonic()
_cache: tuple[float, dict[str, Any]] | None = None
_cache_lock: Optional[asyncio.Lock] = None


def _now() -> float:
    return time.time()


def _check(
    status: str,
    *,
    latency_ms: Optional[float] = None,
    source: str,
    detail: str = "",
    **extra: Any,
) -> dict[str, Any]:
    return {
        "status": status,  # "up" | "down" | "degraded" | "unknown"
        "latency_ms": round(latency_ms, 2) if latency_ms is not None else None,
        "checked_at": _now(),
        "source": source,
        "detail": detail,
        **extra,
    }


async def _timed(coro_fn: Callable[[], Awaitable[Any]]) -> tuple[Any, float]:
    t0 = time.perf_counter()
    result = await asyncio.wait_for(coro_fn(), timeout=PROBE_TIMEOUT)
    return result, (time.perf_counter() - t0) * 1000.0


def _valkey_url() -> str:
    return os.getenv("VALKEY_URL") or os.getenv("REDIS_URL") or "redis://127.0.0.1:6379/0"


def valkey_client():
    import redis.asyncio as aioredis

    url = _valkey_url().replace("@localhost", "@127.0.0.1").replace("//localhost", "//127.0.0.1")
    return aioredis.from_url(url, decode_responses=True, socket_connect_timeout=PROBE_TIMEOUT)


# ---------------------------------------------------------------------------
# Subsystem probes
# ---------------------------------------------------------------------------
async def probe_postgres() -> dict[str, Any]:
    if not await check_db_available():
        return _check("down", source="tcp probe", detail="PostgreSQL port unreachable")
    try:
        async def _q():
            async with get_async_session() as session:
                await session.execute(text("SELECT 1"))

        _, ms = await _timed(_q)
        return _check("up", latency_ms=ms, source="SELECT 1")
    except Exception as exc:
        return _check("down", source="SELECT 1", detail=f"{type(exc).__name__}: {exc}"[:200])


async def probe_valkey(client) -> dict[str, Any]:
    try:
        _, ms = await _timed(client.ping)
        return _check("up", latency_ms=ms, source="PING")
    except Exception as exc:
        return _check("down", source="PING", detail=type(exc).__name__)


async def probe_seaweedfs(http: httpx.AsyncClient) -> dict[str, Any]:
    port = os.getenv("SEAWEEDFS_MASTER_PORT", "9333")
    url = f"http://127.0.0.1:{port}/cluster/status"
    try:
        resp, ms = await _timed(lambda: http.get(url))
        ok = resp.status_code == 200
        return _check("up" if ok else "degraded", latency_ms=ms, source=f"GET {url}",
                      detail="" if ok else f"HTTP {resp.status_code}")
    except Exception as exc:
        return _check("down", source=f"GET {url}", detail=type(exc).__name__)


def _rabbit_params() -> tuple[str, str, str, str]:
    port = os.getenv("RABBITMQ_MGMT_PORT", "15672")
    user = os.getenv("RABBITMQ_USER") or os.getenv("RABBITMQ_DEFAULT_USER") or "guest"
    password = os.getenv("RABBITMQ_PASSWORD") or os.getenv("RABBITMQ_DEFAULT_PASS") or "guest"
    vhost = os.getenv("RABBITMQ_VHOST") or os.getenv("RABBITMQ_DEFAULT_VHOST") or "/"
    return f"http://127.0.0.1:{port}", user, password, vhost


async def probe_rabbitmq(http: httpx.AsyncClient) -> tuple[dict[str, Any], dict[str, Any]]:
    """Returns (health, queues). Queue depth comes from the management API."""
    base, user, password, vhost = _rabbit_params()
    url = f"{base}/api/queues/{quote(vhost, safe='')}"
    try:
        resp, ms = await _timed(lambda: http.get(url, auth=(user, password)))
        if resp.status_code != 200:
            health = _check("degraded", latency_ms=ms, source="management API",
                            detail=f"HTTP {resp.status_code}")
            return health, {"available": False, "detail": health["detail"], "queues": []}
        queues = [
            {
                "name": q.get("name"),
                "messages_ready": q.get("messages_ready"),
                "messages_unacked": q.get("messages_unacknowledged"),
                "consumers": q.get("consumers"),
            }
            for q in resp.json()
        ]
        return (
            _check("up", latency_ms=ms, source="management API"),
            {
                "available": True,
                "source": f"GET {base}/api/queues",
                "checked_at": _now(),
                "total_ready": sum(q["messages_ready"] or 0 for q in queues),
                "total_unacked": sum(q["messages_unacked"] or 0 for q in queues),
                "queues": queues,
            },
        )
    except Exception as exc:
        health = _check("down", source="management API", detail=type(exc).__name__)
        return health, {"available": False, "detail": health["detail"], "queues": []}


async def _tcp_probe(host: str, port: int) -> float:
    def _connect() -> float:
        t0 = time.perf_counter()
        with socket.create_connection((host, port), timeout=PROBE_TIMEOUT):
            return (time.perf_counter() - t0) * 1000.0

    return await asyncio.to_thread(_connect)


async def probe_proxy(client) -> dict[str, Any]:
    host = os.getenv("PROXY_HOST", "127.0.0.1")
    port = int(os.getenv("PROXY_PORT", "8080"))
    heartbeat = None
    try:
        heartbeat = await client.get(PROXY_HEARTBEAT_KEY)
    except Exception:
        pass
    try:
        ms = await _tcp_probe(host, port)
    except Exception as exc:
        return _check("down", source=f"tcp {host}:{port}", detail=f"{type(exc).__name__}; proxy not running",
                      heartbeat_at=float(heartbeat) if heartbeat else None)
    if not heartbeat:
        return _check("degraded", latency_ms=ms, source=f"tcp {host}:{port}",
                      detail="port open but no PenteFino proxy heartbeat in Valkey", heartbeat_at=None)
    return _check("up", latency_ms=ms, source=f"tcp {host}:{port} + heartbeat", heartbeat_at=float(heartbeat))


async def probe_workers(client) -> dict[str, Any]:
    try:
        keys = [k async for k in client.scan_iter(match=f"{WORKER_HEARTBEAT_PREFIX}*", count=100)]
        beats = []
        for k in keys:
            v = await client.get(k)
            if v:
                beats.append({"id": k.removeprefix(WORKER_HEARTBEAT_PREFIX), "heartbeat_at": float(v)})
    except Exception as exc:
        return _check("unknown", source="valkey heartbeat keys", detail=f"Valkey unavailable ({type(exc).__name__})",
                      workers=[])
    if not beats:
        return _check("down", source="valkey heartbeat keys", detail="no worker heartbeat (worker not running)",
                      workers=[])
    return _check("up", source="valkey heartbeat keys", workers=beats, detail=f"{len(beats)} worker(s)")


async def probe_runners() -> dict[str, Any]:
    """Count ephemeral scanner containers via the docker CLI."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "ps", "--filter", "name=pentefino_scan", "--format", "{{.Names}}\t{{.Status}}",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        t0 = time.perf_counter()
        out, err = await asyncio.wait_for(proc.communicate(), timeout=4.0)
        ms = (time.perf_counter() - t0) * 1000.0
    except FileNotFoundError:
        return _check("unknown", source="docker ps", detail="docker CLI not found", containers=[])
    except asyncio.TimeoutError:
        return _check("down", source="docker ps", detail="docker engine timeout", containers=[])
    if proc.returncode != 0:
        return _check("down", source="docker ps", detail=err.decode(errors="replace").strip()[:160], containers=[])
    containers = [line.split("\t", 1)[0] for line in out.decode().splitlines() if line.strip()]
    return _check("up", latency_ms=ms, source="docker ps", containers=containers,
                  detail=f"{len(containers)} scanner container(s) running")


# ---------------------------------------------------------------------------
# Domain data
# ---------------------------------------------------------------------------
async def collect_findings() -> dict[str, Any]:
    if not await check_db_available():
        return {"available": False, "detail": "PostgreSQL unreachable"}
    try:
        async with get_async_session() as session:
            sev = func.coalesce(TemplateCatalog.severity, "unknown")
            by_sev = (
                await session.execute(
                    select(sev, func.count())
                    .select_from(Finding)
                    .join(TemplateCatalog, TemplateCatalog.id == Finding.detector_id, isouter=True)
                    .where(Finding.status.in_(["candidate", "reopened", "validated"]))
                    .group_by(sev)
                )
            ).all()
            by_ev = (
                await session.execute(
                    select(Finding.evidence_level, func.count())
                    .where(Finding.status.in_(["candidate", "reopened", "validated"]))
                    .group_by(Finding.evidence_level)
                )
            ).all()
            by_status = (await session.execute(select(Finding.status, func.count()).group_by(Finding.status))).all()
            since = datetime.now(timezone.utc) - timedelta(hours=24)
            new_24h = (
                await session.execute(select(func.count()).select_from(Finding).where(Finding.first_seen >= since))
            ).scalar_one()
            recent = (
                await session.execute(
                    select(Finding, Asset.canonical_key, sev)
                    .join(Asset, Asset.id == Finding.asset_id, isouter=True)
                    .join(TemplateCatalog, TemplateCatalog.id == Finding.detector_id, isouter=True)
                    .where(Finding.status.in_(["candidate", "reopened", "validated"]))
                    .order_by(Finding.first_seen.desc())
                    .limit(8)
                )
            ).all()
        status_counts = {s: c for s, c in by_status}
        return {
            "available": True,
            "source": "PostgreSQL findings",
            "checked_at": _now(),
            "needs_triage": sum(status_counts.get(s, 0) for s in ("candidate", "reopened", "validated")),
            "new_24h": int(new_24h),
            "by_status": status_counts,
            "open_by_severity": {s: c for s, c in by_sev},
            "open_by_evidence_level": {e: c for e, c in by_ev},
            "recent": [
                {
                    "id": str(f.id),
                    "detector_id": f.detector_id,
                    "asset": key,
                    "severity": s,
                    "status": f.status,
                    "evidence_level": f.evidence_level,
                    "first_seen": f.first_seen.isoformat() if f.first_seen else None,
                }
                for f, key, s in recent
            ],
        }
    except Exception as exc:
        return {"available": False, "detail": f"{type(exc).__name__}"}


async def collect_proxy_traffic(client) -> dict[str, Any]:
    try:
        totals = await client.hgetall(PROXY_METRICS_KEY)
        minute = int(_now() // 60)
        keys = [f"{PROXY_MINUTE_PREFIX}{m}" for m in range(minute - 4, minute + 1)]
        window_vals = await client.mget(keys)
    except Exception as exc:
        return {"available": False, "detail": f"Valkey unavailable ({type(exc).__name__})"}
    if not totals:
        return {"available": False, "detail": "proxy has not published metrics (not running or no traffic yet)"}
    return {
        "available": True,
        "source": f"Valkey {PROXY_METRICS_KEY}",
        "checked_at": _now(),
        "totals": {k: int(float(v)) for k, v in totals.items()},
        "requests_last_5m": sum(int(v) for v in window_vals if v),
    }


# ---------------------------------------------------------------------------
# Snapshot
# ---------------------------------------------------------------------------
async def _collect() -> dict[str, Any]:
    client = valkey_client()
    async with httpx.AsyncClient(timeout=PROBE_TIMEOUT) as http:
        try:
            results = await asyncio.gather(
                probe_postgres(),
                probe_valkey(client),
                probe_seaweedfs(http),
                probe_rabbitmq(http),
                probe_proxy(client),
                probe_workers(client),
                probe_runners(),
                collect_findings(),
                collect_proxy_traffic(client),
                get_network_health_metrics_async(),
                return_exceptions=True,
            )
        finally:
            try:
                await client.aclose()
            except Exception:
                pass

    def _ok(r: Any, fallback: dict[str, Any]) -> Any:
        return fallback if isinstance(r, BaseException) else r

    def err(name: str) -> dict[str, Any]:
        return _check("unknown", source=name, detail="probe raised")

    pg, vk, sw, rabbit, proxy, workers, runners, findings, proxy_traffic, network = results
    rabbit_health, queues = _ok(rabbit, (err("rabbitmq"), {"available": False, "queues": []}))
    api_check = _check("up", latency_ms=0.0, source="this process",
                       uptime_s=round(time.monotonic() - _started_monotonic, 1), pid=os.getpid())
    active = activity.active()
    return {
        "generated_at": _now(),
        "systems": {
            "api": api_check,
            "postgres": _ok(pg, err("postgres")),
            "valkey": _ok(vk, err("valkey")),
            "seaweedfs": _ok(sw, err("seaweedfs")),
            "rabbitmq": rabbit_health,
            "proxy": _ok(proxy, err("proxy")),
            "worker": _ok(workers, err("worker")),
            "runners": _ok(runners, err("runners")),
        },
        "execution": {
            "source": "API activity registry",
            "checked_at": _now(),
            "active_scans": [o for o in active if o["kind"] in ("scan", "batch_scan")],
            "active_recon": [o for o in active if o["kind"] == "recon"],
            "amqp": queues,
        },
        "scope": {
            "api": {**activity.scope_window(), "source": "API scope engine decisions", "checked_at": _now()},
            "proxy": _ok(proxy_traffic, {"available": False, "detail": "probe raised"}),
        },
        "findings": _ok(findings, {"available": False, "detail": "probe raised"}),
        "network": _ok(network, {"status": "unavailable", "targets": []}),
    }


async def get_live_status(force: bool = False) -> dict[str, Any]:
    """Shared, briefly cached snapshot so many dashboard tabs do not multiply probes."""
    global _cache, _cache_lock
    if _cache_lock is None:
        _cache_lock = asyncio.Lock()
    async with _cache_lock:
        if not force and _cache and time.monotonic() - _cache[0] < STATUS_TTL_SECONDS:
            return _cache[1]
        snap = await _collect()
        _cache = (time.monotonic(), snap)
        return snap

