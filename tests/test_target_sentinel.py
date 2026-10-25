from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pentefino_api.target_sentinel import (
    CircuitBreakerManager,
    DomainHealthState,
    probe_domain_l4_tcp,
    probe_domain_l7_canary,
)


def test_domain_health_state_serialization():
    state = DomainHealthState("api.docq.app")
    data = state.to_dict()
    assert data["domain"] == "api.docq.app"
    assert data["status"] == "healthy"
    assert data["is_blocked"] is False
    assert data["remaining_cooldown_sec"] == 0.0
    assert data["waf_detected"] is False


def test_circuit_breaker_domain_cleaning():
    manager = CircuitBreakerManager()
    assert manager._clean_domain("https://sub.docq.app:8443/api/v1") == "sub.docq.app"
    assert manager._clean_domain("http://DOCQ.APP:80/") == "docq.app"
    assert manager._clean_domain("admin.docq.app") == "admin.docq.app"


def test_circuit_breaker_per_domain_isolation():
    manager = CircuitBreakerManager()
    
    # Trip domain A
    manager.trip_domain("blocked.docq.app", reason="403 Cloudflare challenge", cooldown_seconds=30.0)
    
    # Verify domain A is blocked
    assert manager.is_domain_blocked("blocked.docq.app") is True
    
    # Verify other domains are NOT blocked (Strict Per-Domain Isolation)
    assert manager.is_domain_blocked("healthy.docq.app") is False
    assert manager.is_domain_blocked("sr-connector.docq.app") is False
    
    # State check
    all_statuses = manager.get_all_statuses()
    assert "blocked.docq.app" in all_statuses
    assert all_statuses["blocked.docq.app"]["is_blocked"] is True
    assert all_statuses["blocked.docq.app"]["waf_detected"] is True


def test_circuit_breaker_cooldown_expiration():
    manager = CircuitBreakerManager()
    
    # Trip domain with 0.1s cooldown
    manager.trip_domain("fast-expire.docq.app", reason="WAF test", cooldown_seconds=0.05)
    assert manager.is_domain_blocked("fast-expire.docq.app") is True
    
    # Wait for cooldown to expire
    time.sleep(0.06)
    
    # Should now unblock automatically
    assert manager.is_domain_blocked("fast-expire.docq.app") is False
    state = manager.get_or_create("fast-expire.docq.app")
    assert state.status == "healthy"


def test_circuit_breaker_consecutive_timeouts():
    manager = CircuitBreakerManager()
    
    # First timeout -> high_latency, not blocked yet
    s1 = manager.record_timeout_or_error("slow.docq.app", "Connect timeout")
    assert s1.status == "high_latency"
    assert s1.consecutive_timeouts == 1
    assert manager.is_domain_blocked("slow.docq.app") is False
    
    # Second timeout -> triggers waf_cooldown
    s2 = manager.record_timeout_or_error("slow.docq.app", "Connect timeout again")
    assert s2.status == "waf_cooldown"
    assert s2.consecutive_timeouts == 2
    assert manager.is_domain_blocked("slow.docq.app") is True
    
    # A subsequent healthy response resets consecutive timeouts
    s3 = manager.record_healthy("slow.docq.app", latency_ms=45.0, status_code=200)
    assert s3.status == "healthy"
    assert s3.consecutive_timeouts == 0
    assert manager.is_domain_blocked("slow.docq.app") is False


def test_circuit_breaker_manual_reset():
    manager = CircuitBreakerManager()
    manager.trip_domain("reset-me.docq.app", reason="WAF Block", cooldown_seconds=120.0)
    assert manager.is_domain_blocked("reset-me.docq.app") is True
    
    manager.reset_domain("reset-me.docq.app")
    assert manager.is_domain_blocked("reset-me.docq.app") is False


@pytest.mark.asyncio
async def test_probe_domain_l4_tcp_success():
    mock_transport = MagicMock()
    
    async def fake_create_connection(*args, **kwargs):
        return mock_transport, None

    with patch("asyncio.get_running_loop") as mock_get_loop:
        mock_get_loop.return_value.create_connection = fake_create_connection
        is_open, latency_ms, reason = await probe_domain_l4_tcp("alive.docq.app", port=443, timeout=1.0)
        assert is_open is True
        assert "TCP Open" in reason
        mock_transport.close.assert_called_once()


@pytest.mark.asyncio
async def test_probe_domain_l4_tcp_timeout():
    with patch("asyncio.get_running_loop") as mock_get_loop:
        async def fake_timeout(*args, **kwargs):
            await asyncio.sleep(0.5)
            raise asyncio.TimeoutError()

        mock_get_loop.return_value.create_connection = fake_timeout
        is_open, latency_ms, reason = await probe_domain_l4_tcp("drop.docq.app", port=443, timeout=0.05)
        assert is_open is False
        assert "Timeout" in reason


@pytest.mark.asyncio
async def test_probe_domain_l7_canary_healthy():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"server": "nginx"}
    mock_resp.text = "Welcome to DocQ"

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        is_accessible, latency, status, is_waf, reason = await probe_domain_l7_canary("app.docq.app")
        assert is_accessible is True
        assert is_waf is False
        assert status == 200
        assert "200 OK" in reason


@pytest.mark.asyncio
async def test_probe_domain_l7_canary_404_proves_alive():
    # Crucial test: 404 does NOT mean dead; it proves the HTTP web server is active and reachable
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.headers = {"server": "nginx"}
    mock_resp.text = "Not Found"

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        is_accessible, latency, status, is_waf, reason = await probe_domain_l7_canary("sr-connector.docq.app")
        assert is_accessible is True
        assert is_waf is False
        assert status == 404


@pytest.mark.asyncio
async def test_probe_domain_l7_canary_cloudflare_block_detected():
    # 403 with Cloudflare ray or headers
    mock_resp = MagicMock()
    mock_resp.status_code = 403
    mock_resp.headers = {"server": "cloudflare", "cf-ray": "1234567890abcdef-GRU"}
    mock_resp.text = "<html><body>Error 403 Forbidden</body></html>"

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        is_accessible, latency, status, is_waf, reason = await probe_domain_l7_canary("protected.docq.app")
        assert is_accessible is False
        assert is_waf is True
        assert status == 403
        assert "Cloudflare" in reason


@pytest.mark.asyncio
async def test_probe_domain_l7_canary_cloudflare_503_challenge():
    # 503 with Just a moment... / challenge screen
    mock_resp = MagicMock()
    mock_resp.status_code = 503
    mock_resp.headers = {"server": "cloudflare"}
    mock_resp.text = "<html><title>Just a moment...</title><div class='challenge-error-text'>Verify you are human</div></html>"

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        is_accessible, latency, status, is_waf, reason = await probe_domain_l7_canary("challenge.docq.app")
        assert is_accessible is False
        assert is_waf is True
        assert status == 503
        assert "Challenge" in reason
