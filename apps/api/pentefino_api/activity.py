"""In-process registry of running operations and scope-decision counters.

Everything here is measured inside this API process: the live status panel reads
it directly, so a value is only reported if something actually happened here.
"""
from __future__ import annotations

import asyncio
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Deque


@dataclass
class ActiveOperation:
    run_id: str
    kind: str  # "scan" | "batch_scan" | "recon"
    program_slug: str
    target: str
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    processes: list[asyncio.subprocess.Process] = field(default_factory=list)
    cancelled: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "kind": self.kind,
            "program_slug": self.program_slug,
            "target": self.target,
            "started_at": self.started_at.isoformat(),
            "elapsed_s": round((datetime.now(timezone.utc) - self.started_at).total_seconds(), 1),
            "cancelled": self.cancelled,
        }


class ActivityRegistry:
    """Tracks running scans/recon and counts scope-engine decisions made by this API."""

    WINDOW_SECONDS = 300.0

    def __init__(self) -> None:
        self._ops: dict[str, ActiveOperation] = {}
        self._cancelled: set[str] = set()
        self.scope_decisions: Counter[str] = Counter()
        self._decision_times: Deque[tuple[float, bool, bool]] = deque(maxlen=5000)
        self.started_at = time.time()

    # -- operations ---------------------------------------------------------
    def start(self, run_id: str, kind: str, program_slug: str, target: str) -> ActiveOperation:
        op = ActiveOperation(run_id=run_id, kind=kind, program_slug=program_slug, target=target)
        if run_id in self._cancelled:
            op.cancelled = True
        self._ops[run_id] = op
        return op

    def finish(self, run_id: str) -> None:
        self._ops.pop(run_id, None)
        self._cancelled.discard(run_id)

    def is_cancelled(self, run_id: str) -> bool:
        return run_id in self._cancelled

    def attach_process(self, run_id: str, proc: asyncio.subprocess.Process) -> None:
        op = self._ops.get(run_id)
        if op is None:
            return
        op.processes.append(proc)
        if op.cancelled:
            _kill(proc)

    def cancel(self, run_id: str) -> bool:
        """Mark a run cancelled and kill its child processes. Returns True if it was running here.

        The tombstone is kept even when the run is unknown, so a scan whose process
        is spawned after the cancel request is killed on attach instead of running.
        """
        self._cancelled.add(run_id)
        op = self._ops.get(run_id)
        if op is None:
            return False
        op.cancelled = True
        for proc in op.processes:
            _kill(proc)
        return True

    def active(self) -> list[dict[str, Any]]:
        return [op.to_dict() for op in self._ops.values()]

    # -- scope decisions ----------------------------------------------------
    def record_scope_decision(self, allowed: bool, reason: str) -> None:
        ssrf = reason.startswith(("PROHIBITED_IP", "RESOLVED_IP_PROHIBITED", "DNS_REBINDING"))
        self.scope_decisions["allowed" if allowed else "denied"] += 1
        if ssrf:
            self.scope_decisions["ssrf_blocked"] += 1
        self._decision_times.append((time.time(), allowed, ssrf))

    def scope_window(self) -> dict[str, Any]:
        cutoff = time.time() - self.WINDOW_SECONDS
        recent = [d for d in self._decision_times if d[0] >= cutoff]
        return {
            "window_s": int(self.WINDOW_SECONDS),
            "evaluations": len(recent),
            "denied": sum(1 for d in recent if not d[1]),
            "ssrf_blocked": sum(1 for d in recent if d[2]),
            "since_start": dict(self.scope_decisions),
            "counting_since": datetime.fromtimestamp(self.started_at, timezone.utc).isoformat(),
        }


def _kill(proc: asyncio.subprocess.Process) -> None:
    if proc.returncode is None:
        try:
            proc.kill()
        except ProcessLookupError:
            pass


activity = ActivityRegistry()


def get_activity() -> ActivityRegistry:
    return activity


__all__ = ["ActiveOperation", "ActivityRegistry", "activity", "get_activity"]
