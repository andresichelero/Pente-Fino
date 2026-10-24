from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4
from unittest.mock import patch

import pytest
from aiohttp import web

from pentefino_scope import (
    AssetType,
    AuthorizationSnapshot,
    PrecedenceTier,
    ScopeAction,
    ScopeEngine,
    ScopeRule,
)

from pentefino_proxy import (
    CloakingEngine,
    ForwardProxyServer,
    MODERN_USER_AGENTS,
    ScopeGuard,
    ScopeGuardError,
    ValkeyRateLimiter,
)


@pytest.fixture
def program_id() -> UUID:
    return uuid4()


@pytest.fixture
def active_snapshot(program_id: UUID) -> AuthorizationSnapshot:
    now = datetime.now(timezone.utc)
    return AuthorizationSnapshot(
        program_id=program_id,
        policy_hash="b" * 64,
        rules_json={},
        valid_from=now - timedelta(days=1),
        valid_until=now + timedelta(days=30),
    )


@pytest.fixture
def sample_scope_rules(program_id: UUID) -> list[ScopeRule]:
    return [
        # Tier 1: Explicit Deny
        ScopeRule(
            program_id=program_id,
            priority=10,
            asset_type=AssetType.DOMAIN,
            pattern="forbidden.example.com",
            action=ScopeAction.DENY,
        ),
        # Tier 3: Path Deny on allowed wildcard
        ScopeRule(
            program_id=program_id,
            priority=20,
            asset_type=AssetType.WILDCARD_DOMAIN,
            pattern="*.example.com",
            action=ScopeAction.ALLOW,
            denied_paths=["/admin*", "/private/*"],
            allowed_ports=[80, 443, 8080],
        ),
        # Tier 4: Explicit Allow
        ScopeRule(
            program_id=program_id,
            priority=30,
            asset_type=AssetType.DOMAIN,
            pattern="app.example.com",
            action=ScopeAction.ALLOW,
        ),
    ]


@pytest.fixture
def scope_engine(active_snapshot: AuthorizationSnapshot, sample_scope_rules: list[ScopeRule]) -> ScopeEngine:
    return ScopeEngine(
        snapshot=active_snapshot,
        rules=sample_scope_rules,
        environment_class="bounty",
    )


@pytest.fixture
def scope_guard(scope_engine: ScopeEngine, program_id: UUID) -> ScopeGuard:
    guard = ScopeGuard(default_engine=scope_engine, environment_class="bounty")
    guard.register_engine(program_id, scope_engine)
    return guard


# ==============================================================================
# 1. Scope Guard & HTTP 403 Rejection Tests
# ==============================================================================

class TestScopeGuardEnforcement:

    def test_in_scope_request_allowed(self, scope_guard: ScopeGuard, program_id: UUID):
        url = "https://app.example.com/api/v1/users"
        decision = scope_guard.evaluate(url, method="GET", program_id=program_id, check_dns=False)
        assert decision.allowed is True
        assert decision.matched_tier == PrecedenceTier.EXPLICIT_ALLOW

    def test_explicit_deny_target_returns_403_decision(self, scope_guard: ScopeGuard, program_id: UUID):
        url = "https://forbidden.example.com/resource"
        decision = scope_guard.evaluate(url, method="GET", program_id=program_id, check_dns=False)
        assert decision.allowed is False
        assert decision.matched_tier == PrecedenceTier.EXPLICIT_DENY

        resp = ScopeGuard.build_403_response(decision, url)
        assert resp["status_code"] == 403
        assert resp["headers"]["X-PenteFino-Proxy"] == "Egress-Traffic-Controller"
        assert resp["headers"]["X-PenteFino-Decision"] == "DENY"
        assert resp["body"]["error"] == "out_of_scope_violation"
        assert resp["body"]["code"] == 403

    def test_unknown_target_blocked_fail_closed(self, scope_guard: ScopeGuard, program_id: UUID):
        url = "https://unauthorized-external-site.com/test"
        decision = scope_guard.evaluate(url, method="GET", program_id=program_id, check_dns=False)
        assert decision.allowed is False
        assert decision.matched_tier == PrecedenceTier.UNKNOWN_DENY

        with pytest.raises(ScopeGuardError) as exc_info:
            scope_guard.enforce(url, method="GET", program_id=program_id, check_dns=False)
        assert exc_info.value.status_code == 403

    def test_denied_path_returns_403_forbidden(self, scope_guard: ScopeGuard, program_id: UUID):
        # api.example.com is allowed by *.example.com wildcard, but /admin is denied
        url = "https://api.example.com/admin/settings"
        decision = scope_guard.evaluate(url, method="GET", program_id=program_id, check_dns=False)
        assert decision.allowed is False
        assert decision.matched_tier == PrecedenceTier.PATH_PORT_DENY

    def test_anti_ssrf_blocks_private_and_loopback_ips(self, scope_guard: ScopeGuard, program_id: UUID):
        # Loopback
        decision_loopback = scope_guard.evaluate("http://127.0.0.1:8080/metrics", program_id=program_id)
        assert decision_loopback.allowed is False
        assert "PROHIBITED_IP" in decision_loopback.reason

        # Cloud metadata
        decision_metadata = scope_guard.evaluate("http://169.254.169.254/latest/meta-data/", program_id=program_id)
        assert decision_metadata.allowed is False
        assert "PROHIBITED_IP" in decision_metadata.reason

        # RFC 1918 Private ranges
        decision_rfc1918 = scope_guard.evaluate("http://10.0.0.1/internal", program_id=program_id)
        assert decision_rfc1918.allowed is False
        assert "PROHIBITED_IP" in decision_rfc1918.reason

    def test_bounty_mode_public_domain_allowed(self, scope_guard: ScopeGuard, program_id: UUID):
        """Validates that public domain with public IP resolution is allowed in bounty mode."""
        url = "https://app.example.com/api/v1/users"
        decision = scope_guard.evaluate(
            url,
            method="GET",
            program_id=program_id,
            check_dns=True,
            resolved_ips=["93.184.215.14"],
        )
        assert decision.allowed is True
        assert decision.matched_tier == PrecedenceTier.EXPLICIT_ALLOW

    def test_bounty_mode_rebound_private_ip_blocked(self, scope_guard: ScopeGuard, program_id: UUID):
        """Validates that domain resolving to private IP (DNS rebinding) is blocked in bounty mode."""
        url = "https://app.example.com/api/v1/users"
        decision = scope_guard.evaluate(
            url,
            method="GET",
            program_id=program_id,
            check_dns=True,
            resolved_ips=["127.0.0.1"],
        )
        assert decision.allowed is False
        assert decision.matched_tier == PrecedenceTier.EXPLICIT_DENY
        assert "DNS_REBINDING_BLOCK" in decision.reason

    def test_bounty_mode_rebound_cloud_metadata_blocked(self, scope_guard: ScopeGuard, program_id: UUID):
        """Validates that domain resolving to cloud metadata IP is blocked in bounty mode."""
        url = "https://app.example.com/api/v1/users"
        decision = scope_guard.evaluate(
            url,
            method="GET",
            program_id=program_id,
            check_dns=True,
            resolved_ips=["169.254.169.254"],
        )
        assert decision.allowed is False
        assert decision.matched_tier == PrecedenceTier.EXPLICIT_DENY
        assert "DNS_REBINDING_BLOCK" in decision.reason


# ==============================================================================
# 2. Valkey Hierarchical Rate Limiting Tests
# ==============================================================================

class TestValkeyRateLimiter:

    @pytest.mark.asyncio
    async def test_single_request_acquires_immediately(self):
        limiter = ValkeyRateLimiter(host_rate=0.5, prog_rate=2.0)
        wait_sec = await limiter.acquire_lease("target.example.com", program_id="prog1", cost=1.0, sleep=False)
        assert wait_sec == 0.0
        await limiter.close()

    @pytest.mark.asyncio
    async def test_concurrent_requests_micro_spaced_smoothly(self):
        """
        Validates acceptance criteria:
        10 concurrent requests to the same host are spaced out at 0.5 req/s (every 2.0 seconds).
        """
        host_rate = 0.5  # 1 req every 2.0s
        host_capacity = 1.0
        limiter = ValkeyRateLimiter(
            host_rate=host_rate,
            host_capacity=host_capacity,
            prog_rate=10.0,
            prog_capacity=20.0,
        )
        await limiter.reset(host="concurrency.target.com", program_id="test_smooth")

        delays = []
        # Simulate 10 simultaneous requests arriving at the exact same instant
        for i in range(10):
            wait = await limiter.acquire_lease(
                host="concurrency.target.com",
                program_id="test_smooth",
                cost=1.0,
                sleep=False,  # Measure calculated wait without sleeping
            )
            delays.append(wait)

        # Request 1 has 0s delay (burst 1)
        assert delays[0] == 0.0

        # Each subsequent request is spaced by exactly 2.0 seconds (1 / 0.5 req/s)
        for i in range(1, 10):
            expected_wait = i * 2.0
            assert delays[i] == pytest.approx(expected_wait, abs=0.1), (
                f"Request {i+1} expected wait ~{expected_wait}s, got {delays[i]}s"
            )

        await limiter.close()

    @pytest.mark.asyncio
    async def test_program_level_rate_limiting(self):
        """
        Validates hierarchical rate limit: program quota (2.0 req/s = 0.5s per request)
        throttles even across different hosts when program burst is exhausted.
        """
        limiter = ValkeyRateLimiter(
            host_rate=10.0,  # Host limit high
            host_capacity=10.0,
            prog_rate=2.0,   # Program limit 2.0 req/s (0.5s spacing)
            prog_capacity=1.0, # Capacity 1 to test immediate throttling
        )
        await limiter.reset(program_id="test_prog_limit")

        # Req 1 for host A: immediate
        w1 = await limiter.acquire_lease("hostA.example.com", program_id="test_prog_limit", sleep=False)
        assert w1 == 0.0

        # Req 2 for host B (different host, same program): throttled by program rate (0.5s)
        w2 = await limiter.acquire_lease("hostB.example.com", program_id="test_prog_limit", sleep=False)
        assert w2 == pytest.approx(0.5, abs=0.1)

        # Req 3 for host C: throttled to 1.0s
        w3 = await limiter.acquire_lease("hostC.example.com", program_id="test_prog_limit", sleep=False)
        assert w3 == pytest.approx(1.0, abs=0.1)

        await limiter.close()

    @pytest.mark.asyncio
    async def test_reactive_circuit_breaker_backoff(self):
        limiter = ValkeyRateLimiter()
        target_host = "rate-limited-host.com"

        # Initially no backoff
        assert await limiter.get_backoff(target_host) == 0.0

        # Set 429 backoff for 3 seconds
        await limiter.set_backoff(target_host, 3.0)
        backoff_val = await limiter.get_backoff(target_host)
        assert 1.0 <= backoff_val <= 3.0

        await limiter.close()


# ==============================================================================
# 3. Scanner Signature Scrubbing & User-Agent Cloaking Tests
# ==============================================================================

class TestCloakingEngine:

    def test_scanner_user_agent_detection(self):
        engine = CloakingEngine()
        assert engine.is_scanner_user_agent("Nuclei - Open-source projectdiscovery scanner") is True
        assert engine.is_scanner_user_agent("httpx/1.3.0 (projectdiscovery.io)") is True
        assert engine.is_scanner_user_agent("sqlmap/1.7#stable") is True
        assert engine.is_scanner_user_agent("curl/7.88.1") is True
        assert engine.is_scanner_user_agent("Go-http-client/1.1") is True
        assert engine.is_scanner_user_agent("python-requests/2.31.0") is True
        assert engine.is_scanner_user_agent("") is True
        assert engine.is_scanner_user_agent(None) is True

        # Realistic browser UA is not a scanner
        chrome_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36"
        assert engine.is_scanner_user_agent(chrome_ua) is False

    def test_scanner_headers_stripped(self):
        engine = CloakingEngine()
        raw_headers = {
            "User-Agent": "Nuclei v3.1.0",
            "X-Nuclei-Version": "3.1.0",
            "X-Nuclei-Template": "cve-2024-1234",
            "X-Httpx-Title": "target",
            "X-Scanner-Run": "run-42",
            "X-Forwarded-For": "10.0.0.1",
            "Via": "1.1 proxy",
            "Proxy-Connection": "keep-alive",
            "Accept": "text/html",
            "Host": "api.example.com",
        }

        cloaked = engine.cloak_headers(raw_headers, host="api.example.com", program_id="prog1")

        # Signature headers must be completely removed
        assert "X-Nuclei-Version" not in cloaked
        assert "X-Nuclei-Template" not in cloaked
        assert "X-Httpx-Title" not in cloaked
        assert "X-Scanner-Run" not in cloaked
        assert "X-Forwarded-For" not in cloaked
        assert "Via" not in cloaked
        assert "Proxy-Connection" not in cloaked

        # User-Agent must be cloaked to a realistic browser UA
        assert "Nuclei" not in cloaked["User-Agent"]
        assert cloaked["User-Agent"] in MODERN_USER_AGENTS

        # Legitimate headers preserved
        assert cloaked["Host"] == "api.example.com"
        assert "Accept" in cloaked

    def test_session_pinning_consistency(self):
        """
        Validates ADR-02 / Survey 3:
        Same (program_id + host) MUST produce identical User-Agent across multiple invocations.
        """
        engine = CloakingEngine()
        prog_id = "bounty-prog-123"
        host = "app.example.com"

        ua1 = engine.get_pinned_user_agent(host, prog_id)
        ua2 = engine.get_pinned_user_agent(host, prog_id)
        ua3 = engine.get_pinned_user_agent(host, prog_id)

        assert ua1 == ua2 == ua3

        # Different host or program may produce different pinned UA
        other_host_ua = engine.get_pinned_user_agent("other.org", prog_id)
        assert isinstance(other_host_ua, str)
        assert other_host_ua in MODERN_USER_AGENTS


# ==============================================================================
# 4. End-to-End Forward Proxy Pipeline & Socket Server Tests
# ==============================================================================

class TestForwardProxyPipeline:

    @pytest.mark.asyncio
    async def test_process_request_blocks_out_of_scope(self, scope_guard: ScopeGuard, program_id: UUID):
        server = ForwardProxyServer(
            scope_guard=scope_guard,
            rate_limiter=ValkeyRateLimiter(use_in_memory=True),
            default_program_id=program_id,
        )

        result = await server.process_request(
            method="GET",
            url="https://forbidden.example.com/secret",
            headers={"User-Agent": "Nuclei v3"},
            program_id=program_id,
        )

        assert result.status_code == 403
        assert result.headers["X-PenteFino-Decision"] == "DENY"
        assert result.json()["error"] == "out_of_scope_violation"

    @pytest.mark.asyncio
    async def test_process_request_cloaks_and_forwards_in_scope(
        self,
        scope_guard: ScopeGuard,
        active_snapshot: AuthorizationSnapshot,
        program_id: UUID,
    ):
        # Setup a local mock target server to receive the proxied request
        received_headers = {}

        async def mock_handler(request: web.Request) -> web.Response:
            nonlocal received_headers
            received_headers = dict(request.headers)
            return web.json_response({"status": "upstream_ok", "client_ip": request.remote})

        app = web.Application()
        app.router.add_get("/api/v1/test", mock_handler)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        # Setup dedicated lab engine and guard for local test endpoint
        lab_engine = ScopeEngine(
            snapshot=active_snapshot,
            rules=[
                ScopeRule(
                    program_id=program_id,
                    priority=1,
                    asset_type=AssetType.IP,
                    pattern="127.0.0.1",
                    action=ScopeAction.ALLOW,
                    allowed_ports=[port, 80, 443],
                )
            ],
            environment_class="lab",
        )
        lab_guard = ScopeGuard(default_engine=lab_engine, environment_class="lab")
        lab_guard.register_engine(program_id, lab_engine)

        proxy = ForwardProxyServer(
            scope_guard=lab_guard,
            rate_limiter=ValkeyRateLimiter(use_in_memory=True),
            default_program_id=program_id,
            environment_class="lab",  # Permit local testing
        )

        local_target_url = f"http://127.0.0.1:{port}/api/v1/test"

        result = await proxy.process_request(
            method="GET",
            url=local_target_url,
            headers={
                "Host": "app.example.com",
                "User-Agent": "Nuclei/3.0.0 (scanner)",
                "X-Nuclei-Scan": "active",
                "X-Forwarded-For": "1.2.3.4",
            },
            program_id=program_id,
            upload_evidence=False,
        )

        assert result.status_code == 200
        assert result.json()["status"] == "upstream_ok"

        # Verify upstream received cloaked headers
        assert "Nuclei" not in received_headers.get("User-Agent", "")
        assert received_headers.get("User-Agent") in MODERN_USER_AGENTS
        assert "X-Nuclei-Scan" not in received_headers
        assert "X-Forwarded-For" not in received_headers

        await runner.cleanup()
        await proxy.stop()

    @pytest.mark.asyncio
    async def test_socket_server_connect_rejects_out_of_scope(
        self,
        scope_guard: ScopeGuard,
        program_id: UUID,
    ):
        """
        Validates HTTPS CONNECT tunneling via real TCP socket.
        Out-of-scope destination receives HTTP/1.1 403 Forbidden.
        """
        proxy = ForwardProxyServer(
            host="127.0.0.1",
            port=0,
            scope_guard=scope_guard,
            rate_limiter=ValkeyRateLimiter(use_in_memory=True),
            default_program_id=program_id,
        )
        await proxy.start()

        # Connect directly to proxy via raw TCP socket and issue CONNECT
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.port)
        connect_req = (
            f"CONNECT forbidden.example.com:443 HTTP/1.1\r\n"
            f"Host: forbidden.example.com:443\r\n"
            f"X-PenteFino-Program: {program_id}\r\n"
            f"\r\n"
        ).encode("utf-8")
        writer.write(connect_req)
        await writer.drain()

        # Read response line
        response_line = await reader.readline()
        status_line = response_line.decode("utf-8")
        assert "403 Forbidden" in status_line

        # Read remainder of 403 response
        raw_resp = await reader.read(4096)
        resp_text = raw_resp.decode("utf-8", errors="replace")
        assert "out_of_scope_violation" in resp_text

        writer.close()
        await writer.wait_closed()
        await proxy.stop()

    @pytest.mark.asyncio
    async def test_process_request_bounty_mode_blocks_dns_rebinding(
        self,
        scope_guard: ScopeGuard,
        program_id: UUID,
    ):
        """
        Validates ForwardProxyServer.process_request in bounty mode blocks DNS rebinding.
        """
        proxy = ForwardProxyServer(
            scope_guard=scope_guard,
            rate_limiter=ValkeyRateLimiter(use_in_memory=True),
            default_program_id=program_id,
            environment_class="bounty",
        )
        with patch(
            "pentefino_proxy.scope_guard.check_dns_rebinding",
            return_value=(False, ["127.0.0.1"], "DNS_REBINDING_OR_PROHIBITED_IP: 127.0.0.1 is LOOPBACK_OR_SPECIAL_USE"),
        ):
            result = await proxy.process_request(
                method="GET",
                url="https://app.example.com/sensitive-data",
                program_id=program_id,
                upload_evidence=False,
            )
            assert result.status_code == 403
            assert "DNS_REBINDING_BLOCK" in result.headers.get("X-PenteFino-Reason", "")

        await proxy.stop()

    @pytest.mark.asyncio
    async def test_socket_server_connect_bracketed_ipv6_loopback_rejected(
        self,
        scope_guard: ScopeGuard,
        program_id: UUID,
    ):
        """
        Validates HTTPS CONNECT with bracketed IPv6 loopback [::1]:8443 is blocked.
        """
        proxy = ForwardProxyServer(
            host="127.0.0.1",
            port=0,
            scope_guard=scope_guard,
            rate_limiter=ValkeyRateLimiter(use_in_memory=True),
            default_program_id=program_id,
        )
        await proxy.start()

        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.port)
        connect_req = (
            f"CONNECT [::1]:8443 HTTP/1.1\r\n"
            f"Host: [::1]:8443\r\n"
            f"X-PenteFino-Program: {program_id}\r\n"
            f"\r\n"
        ).encode("utf-8")
        writer.write(connect_req)
        await writer.drain()

        response_line = await reader.readline()
        status_line = response_line.decode("utf-8")
        assert "403 Forbidden" in status_line

        raw_resp = await reader.read(4096)
        resp_text = raw_resp.decode("utf-8", errors="replace")
        assert "PROHIBITED_IP" in resp_text or "out_of_scope_violation" in resp_text

        writer.close()
        await writer.wait_closed()
        await proxy.stop()

    @pytest.mark.asyncio
    async def test_socket_server_connect_bracketed_ipv6_public_out_of_scope(
        self,
        scope_guard: ScopeGuard,
        program_id: UUID,
    ):
        """
        Validates HTTPS CONNECT with bracketed public IPv6 [2606:4700::1]:443 parses correctly
        and rejects unknown IP without raising parsing errors.
        """
        proxy = ForwardProxyServer(
            host="127.0.0.1",
            port=0,
            scope_guard=scope_guard,
            rate_limiter=ValkeyRateLimiter(use_in_memory=True),
            default_program_id=program_id,
        )
        await proxy.start()

        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.port)
        connect_req = (
            f"CONNECT [2606:4700::1]:443 HTTP/1.1\r\n"
            f"Host: [2606:4700::1]:443\r\n"
            f"X-PenteFino-Program: {program_id}\r\n"
            f"\r\n"
        ).encode("utf-8")
        writer.write(connect_req)
        await writer.drain()

        response_line = await reader.readline()
        status_line = response_line.decode("utf-8")
        assert "403 Forbidden" in status_line

        raw_resp = await reader.read(4096)
        resp_text = raw_resp.decode("utf-8", errors="replace")
        assert "out_of_scope_violation" in resp_text

        writer.close()
        await writer.wait_closed()
        await proxy.stop()
