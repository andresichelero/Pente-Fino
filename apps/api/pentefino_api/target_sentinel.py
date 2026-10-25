from __future__ import annotations

import asyncio
import logging
import socket
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

import httpx

logger = logging.getLogger(__name__)

CLOUDFLARE_CHALLENGE_SIGNATURES = [
    "challenge-error-text",
    "just a moment...",
    "attention required! | cloudflare",
    "cf-browser-verification",
    "cloudflare ray id",
]

CLOUDFLARE_HEADERS = [
    "cf-mitigated",
    "cf-ray",
    "cf-cache-status",
]


class DomainHealthState:
    """Represents real-time health and WAF status for a specific domain."""

    def __init__(self, domain: str) -> None:
        self.domain = domain
        self.status = "healthy"  # "healthy", "waf_cooldown", "high_latency", "offline"
        self.cooldown_until: float = 0.0
        self.last_checked: float = 0.0
        self.last_latency_ms: float = 0.0
        self.last_status_code: Optional[int] = None
        self.waf_detected: bool = False
        self.waf_provider: Optional[str] = None
        self.reason: str = "Aguardando verificação"
        self.consecutive_timeouts: int = 0

    def to_dict(self) -> Dict[str, Any]:
        now = time.monotonic()
        remaining_cooldown = max(0.0, self.cooldown_until - now)
        return {
            "domain": self.domain,
            "status": self.status,
            "is_blocked": self.status == "waf_cooldown" and remaining_cooldown > 0,
            "remaining_cooldown_sec": round(remaining_cooldown, 1),
            "last_latency_ms": round(self.last_latency_ms, 1),
            "last_status_code": self.last_status_code,
            "waf_detected": self.waf_detected,
            "waf_provider": self.waf_provider,
            "reason": self.reason,
            "last_checked_iso": datetime.fromtimestamp(
                self.last_checked or time.time(), tz=timezone.utc
            ).isoformat(),
        }


class CircuitBreakerManager:
    """Manages per-domain Circuit Breaker states, preventing scanner IP burn while keeping other targets running."""

    def __init__(self) -> None:
        self._domains: Dict[str, DomainHealthState] = {}
        self._lock = asyncio.Lock()

    def get_or_create(self, domain: str) -> DomainHealthState:
        clean = self._clean_domain(domain)
        if clean not in self._domains:
            self._domains[clean] = DomainHealthState(clean)
        return self._domains[clean]

    @staticmethod
    def _clean_domain(raw: str) -> str:
        clean = raw.strip().lower()
        if "://" in clean:
            clean = urllib.parse.urlsplit(clean).netloc or clean
        return clean.split(":")[0]

    def is_domain_blocked(self, domain: str) -> bool:
        clean = self._clean_domain(domain)
        state = self._domains.get(clean)
        if not state:
            return False
        if state.status == "waf_cooldown":
            if time.monotonic() < state.cooldown_until:
                return True
            # Cooldown expired, auto-promote to retest
            state.status = "healthy"
            state.reason = "Cooldown do WAF expirado; pronto para re-teste."
            return False
        return False

    def trip_domain(
        self,
        domain: str,
        reason: str,
        waf_provider: str = "Cloudflare",
        cooldown_seconds: float = 60.0,
    ) -> DomainHealthState:
        """Trip circuit breaker for THIS domain only, initiating cooldown."""
        clean = self._clean_domain(domain)
        state = self.get_or_create(clean)
        state.status = "waf_cooldown"
        state.cooldown_until = time.monotonic() + cooldown_seconds
        state.waf_detected = True
        state.waf_provider = waf_provider
        state.reason = reason
        state.last_checked = time.time()
        logger.warning(
            "Circuit Breaker TRIPPED for %s: %s (cooldown=%ss)",
            clean,
            reason,
            cooldown_seconds,
        )
        return state

    def record_healthy(
        self, domain: str, latency_ms: float, status_code: int
    ) -> DomainHealthState:
        clean = self._clean_domain(domain)
        state = self.get_or_create(clean)
        state.status = "healthy"
        state.last_latency_ms = latency_ms
        state.last_status_code = status_code
        state.waf_detected = False
        state.consecutive_timeouts = 0
        state.last_checked = time.time()
        state.reason = f"HTTP {status_code} ({latency_ms:.0f}ms) · Serviço acessível"
        return state

    def record_timeout_or_error(
        self, domain: str, error_msg: str
    ) -> DomainHealthState:
        clean = self._clean_domain(domain)
        state = self.get_or_create(clean)
        state.consecutive_timeouts += 1
        state.last_checked = time.time()
        if state.consecutive_timeouts >= 2:
            state.status = "waf_cooldown"
            state.cooldown_until = time.monotonic() + 45.0
            state.reason = f"Conexão descartada / Timeout repetido ({error_msg})"
            logger.warning(
                "Circuit Breaker tripped on timeout for %s: %s", clean, error_msg
            )
        else:
            state.status = "high_latency"
            state.reason = f"Timeout na tentativa #{state.consecutive_timeouts}: {error_msg}"
        return state

    def reset_domain(self, domain: str) -> DomainHealthState:
        clean = self._clean_domain(domain)
        state = self.get_or_create(clean)
        state.status = "healthy"
        state.cooldown_until = 0.0
        state.waf_detected = False
        state.consecutive_timeouts = 0
        state.reason = "Circuit Breaker redefinido manualmente pelo usuário."
        return state

    def get_all_statuses(self) -> Dict[str, Dict[str, Any]]:
        return {d: s.to_dict() for d, s in self._domains.items()}


circuit_breaker = CircuitBreakerManager()


async def probe_domain_l4_tcp(
    host: str, port: int = 443, timeout: float = 1.5
) -> Tuple[bool, float, str]:
    """Layer 4 TCP connect probe. Verifies if server socket responds to SYN-ACK without ICMP ping."""
    start = time.monotonic()
    clean_host = CircuitBreakerManager._clean_domain(host)

    try:
        loop = asyncio.get_running_loop()
        conn = loop.create_connection(
            asyncio.Protocol, host=clean_host, port=port
        )
        transport, _ = await asyncio.wait_for(conn, timeout=timeout)
        duration_ms = (time.monotonic() - start) * 1000.0
        transport.close()
        return True, duration_ms, "TCP Open (SYN-ACK)"
    except asyncio.TimeoutError:
        return False, timeout * 1000.0, "TCP Connect Timeout"
    except (ConnectionRefusedError, OSError) as exc:
        duration_ms = (time.monotonic() - start) * 1000.0
        return False, duration_ms, f"TCP Error: {exc}"


async def probe_domain_l7_canary(
    host: str, timeout: float = 2.5
) -> Tuple[bool, float, Optional[int], bool, str]:
    """
    Layer 7 HTTP canary probe.
    Returns: (is_accessible, latency_ms, status_code, is_waf_blocked, reason)
    """
    clean_host = CircuitBreakerManager._clean_domain(host)
    url = f"https://{clean_host}"
    start = time.monotonic()

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

    try:
        async with httpx.AsyncClient(
            verify=False,
            timeout=timeout,
            follow_redirects=True,
        ) as client:
            resp = await client.get(url, headers=headers)
            duration_ms = (time.monotonic() - start) * 1000.0
            status_code = resp.status_code
            server_header = resp.headers.get("server", "").lower()
            resp_text_lower = resp.text[:2000].lower()

            # Inspect WAF signatures
            has_cf_headers = any(h in resp.headers for h in CLOUDFLARE_HEADERS) or "cloudflare" in server_header
            has_cf_body = any(sig in resp_text_lower for sig in CLOUDFLARE_CHALLENGE_SIGNATURES)

            if status_code in (403, 429) and (has_cf_headers or has_cf_body):
                return False, duration_ms, status_code, True, f"WAF Cloudflare {status_code} Detectado"

            if status_code == 503 and has_cf_body:
                return False, duration_ms, status_code, True, "Cloudflare Challenge / JS Screen (503)"

            # Legitimate application responses (even 404 or 401 proves the web server is alive and functioning)
            if status_code in (200, 204, 301, 302, 307, 308, 401, 404):
                return True, duration_ms, status_code, False, f"HTTP {status_code} OK"

            return True, duration_ms, status_code, False, f"HTTP {status_code}"

    except httpx.ConnectTimeout:
        return False, timeout * 1000.0, None, False, "HTTP Connect Timeout"
    except httpx.ReadTimeout:
        return False, timeout * 1000.0, None, False, "HTTP Read Timeout"
    except Exception as exc:
        duration_ms = (time.monotonic() - start) * 1000.0
        return False, duration_ms, None, False, f"Erro de conexão HTTP: {type(exc).__name__}"
