from __future__ import annotations

import asyncio
import logging
import os
import re
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import psutil

logger = logging.getLogger(__name__)

_LAST_NET_TIME: float = time.monotonic()
_LAST_NET_COUNTERS: Any = psutil.net_io_counters()

_CACHE_TIME: float = 0.0
_CACHE_DATA: Optional[Dict[str, Any]] = None
_CACHE_TTL: float = float(os.getenv("PENTEFINO_NET_CACHE_TTL", "10"))
_LOCK: Optional[asyncio.Lock] = None

# "host=Label,host=Label". Only ICMP echo is sent to these hosts.
_DEFAULT_TARGETS = "127.0.0.1=Loopback,1.1.1.1=DNS Cloudflare,8.8.8.8=DNS Google,192.168.18.1=Gateway local"
_WAN_HOSTS = {"1.1.1.1", "8.8.8.8"}


def _configured_targets() -> List[Tuple[str, str]]:
    raw = os.getenv("PENTEFINO_NET_TARGETS", _DEFAULT_TARGETS)
    targets: List[Tuple[str, str]] = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        host, _, label = item.partition("=")
        targets.append((host.strip(), (label or host).strip()))
    return targets


def _ping_command(host: str) -> List[str]:
    if sys.platform == "win32":
        return ["ping", "-n", "3", "-w", "1000", host]
    return ["ping", "-c", "3", "-W", "1", host]


def _probe_host(host: str, name: str) -> Dict[str, Any]:
    """Run the OS ping (3 echoes) and parse latency, jitter and loss from its output."""
    checked_at = time.time()
    try:
        res = subprocess.run(
            _ping_command(host),
            capture_output=True,
            text=True,
            timeout=5.0,
            errors="replace",
        )
        times = [
            float(x)
            for x in re.findall(r"(?:tempo|time)[=<]\s*([\d.]+)\s*ms", res.stdout, re.IGNORECASE)
        ]
        loss_match = re.search(r"(\d+)%\s*(?:de perda|packet loss|loss|perda)", res.stdout, re.IGNORECASE)
        loss_pct = float(loss_match.group(1)) if loss_match else (0.0 if times else 100.0)

        if times:
            avg_lat: Optional[float] = sum(times) / len(times)
            diffs = [abs(b - a) for a, b in zip(times, times[1:])]
            jitter: Optional[float] = sum(diffs) / len(diffs) if diffs else 0.0
            status_val = "online" if loss_pct == 0 else "degraded"
        else:
            avg_lat = None
            jitter = None
            status_val = "offline"

        return {
            "name": name,
            "host": host,
            "latency_ms": round(avg_lat, 1) if avg_lat is not None else None,
            "jitter_ms": round(jitter, 1) if jitter is not None else None,
            "loss_pct": loss_pct,
            "samples": len(times),
            "status": status_val,
            "checked_at": checked_at,
        }
    except Exception as exc:
        return {
            "name": name,
            "host": host,
            "latency_ms": None,
            "jitter_ms": None,
            "loss_pct": None,
            "samples": 0,
            "status": "error",
            "error": type(exc).__name__,
            "checked_at": checked_at,
        }


def _aggregate(targets: List[Dict[str, Any]]) -> Dict[str, Any]:
    online = [t for t in targets if t["latency_ms"] is not None]
    wan = [t for t in online if t["host"] in _WAN_HOSTS]
    chosen = wan or online
    if not chosen:
        # No echo came back: there is nothing to average, so report no value.
        return {"overall_latency_ms": None, "overall_jitter_ms": None, "packet_loss_pct": None}
    return {
        "overall_latency_ms": round(sum(t["latency_ms"] for t in chosen) / len(chosen), 1),
        "overall_jitter_ms": round(sum((t["jitter_ms"] or 0.0) for t in chosen) / len(chosen), 1),
        "packet_loss_pct": round(sum((t["loss_pct"] or 0.0) for t in chosen) / len(chosen), 1),
    }


def _throughput() -> Dict[str, Any]:
    global _LAST_NET_TIME, _LAST_NET_COUNTERS
    now = time.monotonic()
    current = psutil.net_io_counters()
    time_delta = max(0.5, now - _LAST_NET_TIME)
    recv = max(0, current.bytes_recv - _LAST_NET_COUNTERS.bytes_recv)
    sent = max(0, current.bytes_sent - _LAST_NET_COUNTERS.bytes_sent)
    _LAST_NET_TIME = now
    _LAST_NET_COUNTERS = current
    return {
        "packets_sent": current.packets_sent,
        "packets_recv": current.packets_recv,
        "bytes_sent": current.bytes_sent,
        "bytes_recv": current.bytes_recv,
        "download_kbps": round((recv / 1024.0) / time_delta, 1),
        "upload_kbps": round((sent / 1024.0) / time_delta, 1),
        "throughput_window_s": round(time_delta, 1),
    }


def _build_result(targets: List[Dict[str, Any]]) -> Dict[str, Any]:
    agg = _aggregate(targets)
    loss = agg["packet_loss_pct"]
    if loss is None:
        status = "unavailable"
    else:
        status = "healthy" if loss < 20 else "degraded"
    return {
        "status": status,
        **agg,
        **_throughput(),
        "targets": targets,
        "source": "os ping (ICMP) + psutil.net_io_counters",
        "timestamp": time.time(),
    }


async def get_network_health_metrics_async() -> Dict[str, Any]:
    """Probe all targets in parallel worker threads; never blocks the event loop."""
    global _CACHE_TIME, _CACHE_DATA, _LOCK
    if _LOCK is None:
        _LOCK = asyncio.Lock()
    async with _LOCK:
        now = time.monotonic()
        if _CACHE_DATA is not None and (now - _CACHE_TIME) < _CACHE_TTL:
            return _CACHE_DATA
        targets = await asyncio.gather(
            *(asyncio.to_thread(_probe_host, host, name) for host, name in _configured_targets())
        )
        result = _build_result(list(targets))
        _CACHE_TIME = time.monotonic()
        _CACHE_DATA = result
        return result


def get_network_health_metrics() -> Dict[str, Any]:
    """Synchronous variant for CLI/scripts. Do not call from the API event loop."""
    global _CACHE_TIME, _CACHE_DATA
    now = time.monotonic()
    if _CACHE_DATA is not None and (now - _CACHE_TIME) < _CACHE_TTL:
        return _CACHE_DATA
    result = _build_result([_probe_host(host, name) for host, name in _configured_targets()])
    _CACHE_TIME = time.monotonic()
    _CACHE_DATA = result
    return result
