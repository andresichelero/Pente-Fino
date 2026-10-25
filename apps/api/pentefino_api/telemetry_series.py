"""Ring buffer of live-status samples, the only source for telemetry time series."""
from __future__ import annotations

from collections import deque
from typing import Any, Deque

MAX_SAMPLES = 60
_MIN_INTERVAL_S = 3.0

_samples: Deque[dict[str, Any]] = deque(maxlen=MAX_SAMPLES)


def record_sample(snapshot: dict[str, Any]) -> None:
    ts = snapshot.get("generated_at")
    if ts is None or (_samples and ts - _samples[-1]["t"] < _MIN_INTERVAL_S):
        return
    systems = snapshot.get("systems", {})
    scope_api = snapshot.get("scope", {}).get("api", {})
    proxy = snapshot.get("scope", {}).get("proxy", {})
    net = snapshot.get("network", {})
    _samples.append(
        {
            "t": ts,
            "db_latency_ms": systems.get("postgres", {}).get("latency_ms"),
            "valkey_latency_ms": systems.get("valkey", {}).get("latency_ms"),
            "scope_evaluations": scope_api.get("since_start", {}).get("allowed", 0)
            + scope_api.get("since_start", {}).get("denied", 0),
            "ssrf_blocked": scope_api.get("since_start", {}).get("ssrf_blocked", 0),
            "proxy_requests_5m": proxy.get("requests_last_5m") if proxy.get("available") else None,
            "net_latency_ms": net.get("overall_latency_ms"),
            "net_loss_pct": net.get("packet_loss_pct"),
        }
    )


def sample_series() -> dict[str, Any]:
    """Column-oriented view; None marks a sample where the metric was unavailable."""
    keys = [k for k in (_samples[0].keys() if _samples else []) if k != "t"]
    return {
        "t": [s["t"] for s in _samples],
        **{k: [s[k] for s in _samples] for k in keys},
    }


def reset() -> None:
    _samples.clear()
