from __future__ import annotations

import asyncio
import json
import logging
import time
import urllib.parse
from typing import Any, Callable, Dict, List, Optional, Union
from uuid import UUID

import aiohttp
from pentefino_scope import PrecedenceTier, ScopeDecision

from .cloaking import CloakingEngine
from .evidence_tap import EvidenceRecord, EvidenceTap
from .metrics import ProxyMetrics, redact_url
from .passive_analyzer import PassiveFinding, PassiveResponseAnalyzer
from .rate_limiter import ValkeyRateLimiter
from .s3_client import S3EvidenceClient
from .scope_guard import ScopeGuard

logger = logging.getLogger("pentefino.proxy.server")


class ProxyResult:
    """Represents the outcome of a proxied HTTP request."""

    def __init__(
        self,
        status_code: int,
        headers: Dict[str, str],
        body: bytes,
        decision: ScopeDecision,
        evidence: Optional[EvidenceRecord] = None,
        cloaked_headers: Optional[Dict[str, str]] = None,
        rate_limit_wait: float = 0.0,
        passive_findings: Optional[List[PassiveFinding]] = None,
    ):
        self.status_code = status_code
        self.headers = headers
        self.body = body
        self.decision = decision
        self.evidence = evidence
        self.cloaked_headers = cloaked_headers or {}
        self.rate_limit_wait = rate_limit_wait
        self.passive_findings = passive_findings or []

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return json.loads(self.text)


class ForwardProxyServer:
    """
    PenteFino Intercepting HTTP/HTTPS Forward Proxy & Traffic Control Plane.
    
    Capabilities:
    1. Intercepts outbound requests and queries ScopeGuard (hard-gate fail-closed).
       Out-of-scope requests dropped with HTTP 403 Forbidden.
    2. Hierarchical rate limiting via Valkey atomic Lua token bucket.
    3. Cloaks scanner headers (Nuclei, httpx, etc.) and rotates session-pinned browser UAs.
    4. Transparent evidence tapping with dual SHA-256 hashing and S3 SeaweedFS upload.
    5. Native support for HTTP_PROXY and HTTPS_PROXY (CONNECT method).
    6. Dynamic ScopeGuard <-> PostgreSQL database synchronization.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        scope_guard: Optional[ScopeGuard] = None,
        rate_limiter: Optional[ValkeyRateLimiter] = None,
        cloaking_engine: Optional[CloakingEngine] = None,
        evidence_tap: Optional[EvidenceTap] = None,
        default_program_id: Union[str, UUID] = "default",
        valkey_url: str = "redis://127.0.0.1:6379/0",
        s3_client: Optional[S3EvidenceClient] = None,
        environment_class: str = "bounty",
        async_session_factory: Optional[Callable[[], Any]] = None,
        passive_analyzer: Optional[PassiveResponseAnalyzer] = None,
        metrics: Optional[ProxyMetrics] = None,
        max_body_bytes: int = 10 * 1024 * 1024,
    ):
        self.host = host
        self.port = port
        self.default_program_id = str(default_program_id)
        self.environment_class = environment_class
        self.async_session_factory = async_session_factory

        self.scope_guard = scope_guard or ScopeGuard(environment_class=environment_class)
        self.rate_limiter = rate_limiter or ValkeyRateLimiter(valkey_url=valkey_url)
        self.cloaking_engine = cloaking_engine or CloakingEngine()
        self.evidence_tap = evidence_tap or EvidenceTap(s3_client=s3_client)
        self.passive_analyzer = passive_analyzer if passive_analyzer is not None else PassiveResponseAnalyzer()
        self.metrics = metrics if metrics is not None else ProxyMetrics(valkey_url)
        self.max_body_bytes = max_body_bytes

        self._server: Optional[asyncio.AbstractServer] = None
        self._is_running = False
        self._http_session: Optional[aiohttp.ClientSession] = None

    async def sync_scope(self, program_id: Optional[UUID] = None) -> None:
        """Dynamically sync scope rules and auth snapshots from PostgreSQL into ScopeGuard."""
        if not self.async_session_factory:
            return
        async with self.async_session_factory() as session:
            await self.scope_guard.sync_from_db(session, program_id=program_id)

    async def _ensure_program_synced(self, program_id: Optional[UUID]) -> None:
        """Lazy-sync program rules from DB if program_id not yet loaded in ScopeGuard."""
        if not program_id or not self.async_session_factory:
            return
        if program_id not in self.scope_guard._programs:
            try:
                await self.sync_scope(program_id=program_id)
            except Exception as e:
                logger.warning("Dynamic scope sync failed for program %s: %s", program_id, e)

    async def _get_http_session(self) -> aiohttp.ClientSession:
        if self._http_session is None or self._http_session.closed:
            timeout = aiohttp.ClientTimeout(total=30, connect=10)
            self._http_session = aiohttp.ClientSession(timeout=timeout)
        return self._http_session

    async def process_request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[Union[str, bytes]] = None,
        program_id: Optional[Union[str, UUID]] = None,
        upload_evidence: bool = True,
        enforce_rate_limit: bool = True,
    ) -> ProxyResult:
        """
        Core traffic processing pipeline for an HTTP request:
        1. Scope Engine check -> Drop with 403 if out of scope.
        2. Valkey rate limiting check -> Micro-space if needed.
        3. Cloak headers & pin browser User-Agent.
        4. Upstream execution.
        5. Evidence capture & S3 upload.
        """
        prog_id = str(program_id or self.default_program_id)
        req_headers = dict(headers or {})
        method_upper = method.upper()

        parsed_prog_uuid: Optional[UUID] = None
        if len(prog_id) == 36:
            try:
                parsed_prog_uuid = UUID(prog_id)
            except ValueError:
                parsed_prog_uuid = None

        if parsed_prog_uuid:
            await self._ensure_program_synced(parsed_prog_uuid)

        # Parse host from URL
        parsed = urllib.parse.urlsplit(url)
        target_host = parsed.hostname or req_headers.get("Host", "localhost")

        # -----------------------------------------------------------------
        # 1. Scope Guard Evaluation (Hard-Gate Fail-Closed)
        # -----------------------------------------------------------------
        try:
            decision = self.scope_guard.evaluate(
                url=url,
                method=method_upper,
                program_id=parsed_prog_uuid,
                check_dns=(self.environment_class != "lab"),
            )
        except Exception as e:
            logger.error("Scope evaluation error: %s", e)
            decision = ScopeDecision(
                allowed=False,
                matched_tier=PrecedenceTier.UNKNOWN_DENY,
                reason=f"SCOPE_EVAL_ERROR: {str(e)}",
                target_canonical=url,
            )

        if not decision.allowed:
            logger.warning("Request rejected by Scope Guard: %s -> %s", redact_url(url), decision.reason)
            await self.metrics.record(
                method=method_upper, url=url, allowed=False, reason=decision.reason,
                tier=(decision.matched_tier.value if hasattr(decision.matched_tier, "value") else str(decision.matched_tier)), status_code=403,
            )
            resp_payload = ScopeGuard.build_403_response(decision, url)
            body_bytes = json.dumps(resp_payload["body"], indent=2).encode("utf-8")
            return ProxyResult(
                status_code=403,
                headers=resp_payload["headers"],
                body=body_bytes,
                decision=decision,
                evidence=None,
                cloaked_headers=req_headers,
                rate_limit_wait=0.0,
            )

        # -----------------------------------------------------------------
        # 2. Hierarchical Rate Limiting (Valkey Token-Bucket)
        # -----------------------------------------------------------------
        wait_seconds = 0.0
        if enforce_rate_limit:
            wait_seconds = await self.rate_limiter.acquire_lease(
                host=target_host,
                program_id=prog_id,
                cost=1.0,
                sleep=True,
            )

        # -----------------------------------------------------------------
        # 3. Stealth Header Scrubbing & User-Agent Cloaking
        # -----------------------------------------------------------------
        cloaked_headers = self.cloaking_engine.cloak_headers(
            headers=req_headers,
            host=target_host,
            program_id=prog_id,
        )

        # -----------------------------------------------------------------
        # 4. Forward Request Upstream
        # -----------------------------------------------------------------
        start_time = time.monotonic()
        status_code = 502
        resp_headers: Dict[str, str] = {}
        resp_body = b""

        # Prepare request body
        req_data = body.encode("utf-8") if isinstance(body, str) else body

        session = await self._get_http_session()
        try:
            async with session.request(
                method=method_upper,
                url=url,
                headers=cloaked_headers,
                data=req_data,
                allow_redirects=False,
            ) as upstream_resp:
                status_code = upstream_resp.status
                resp_headers = dict(upstream_resp.headers)
                resp_body = await upstream_resp.read()

                # Reactive circuit breaker for HTTP 429 Too Many Requests
                if status_code == 429:
                    retry_after = resp_headers.get("Retry-After", "60")
                    try:
                        backoff_val = float(retry_after)
                    except ValueError:
                        backoff_val = 60.0
                    await self.rate_limiter.set_backoff(target_host, backoff_val)

        except Exception as ex:
            logger.error("Upstream request to %s failed: %s", redact_url(url), ex)
            status_code = 502
            resp_body = json.dumps({"error": "Bad Gateway", "detail": str(ex)}).encode("utf-8")
            resp_headers = {"Content-Type": "application/json"}

        latency_ms = (time.monotonic() - start_time) * 1000.0
        await self.metrics.record(
            method=method_upper, url=url, allowed=True, reason=decision.reason,
            tier=(decision.matched_tier.value if hasattr(decision.matched_tier, "value") else str(decision.matched_tier)), status_code=status_code,
            latency_ms=latency_ms, rate_limit_wait_s=wait_seconds,
        )

        # -----------------------------------------------------------------
        # 5. Evidence Tapping (Sanitization & Dual Hash)
        # -----------------------------------------------------------------
        evidence_record = self.evidence_tap.tap_interaction(
            method=method_upper,
            url=url,
            request_headers=cloaked_headers,
            request_body=req_data,
            status_code=status_code,
            response_headers=resp_headers,
            response_body=resp_body,
            latency_ms=latency_ms,
            program_id=prog_id,
            upload_to_s3=upload_evidence,
        )

        # -----------------------------------------------------------------
        # 6. Passive Response Analysis (Zero-Outbound-Request Inspection)
        # -----------------------------------------------------------------
        passive_findings: List[PassiveFinding] = []
        if self.passive_analyzer:
            try:
                passive_findings = self.passive_analyzer.analyze(
                    url=url,
                    status_code=status_code,
                    headers=resp_headers,
                    body=resp_body,
                    program_id=prog_id,
                )
            except Exception as e:
                logger.warning("Passive response analysis failed for %s: %s", redact_url(url), e)

        return ProxyResult(
            status_code=status_code,
            headers=resp_headers,
            body=resp_body,
            decision=decision,
            evidence=evidence_record,
            cloaked_headers=cloaked_headers,
            rate_limit_wait=wait_seconds,
            passive_findings=passive_findings,
        )

    async def _handle_client_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handles a single client socket connection (HTTP or HTTPS CONNECT)."""
        try:
            line = await reader.readline()
            if not line:
                writer.close()
                await writer.wait_closed()
                return

            req_line = line.decode("utf-8", errors="replace").strip()
            parts = req_line.split(" ")
            if len(parts) < 2:
                writer.close()
                await writer.wait_closed()
                return

            method, raw_target = parts[0].upper(), parts[1]

            # Read headers
            headers: Dict[str, str] = {}
            content_length = 0
            while True:
                header_line = await reader.readline()
                if not header_line or header_line in (b"\r\n", b"\n"):
                    break
                decoded = header_line.decode("utf-8", errors="replace").strip()
                if ":" in decoded:
                    k, v = decoded.split(":", 1)
                    k_clean = k.strip()
                    v_clean = v.strip()
                    headers[k_clean] = v_clean
                    if k_clean.lower() == "content-length":
                        try:
                            content_length = int(v_clean)
                        except ValueError:
                            content_length = 0

            # -------------------------------------------------------------
            # Case A: HTTPS CONNECT Tunneling
            # -------------------------------------------------------------
            if method == "CONNECT":
                await self._handle_connect(raw_target, headers, reader, writer)
                return

            # -------------------------------------------------------------
            # Case B: Standard Forward HTTP Request
            # -------------------------------------------------------------
            body_bytes = b""
            if content_length > self.max_body_bytes:
                writer.write(b"HTTP/1.1 413 Payload Too Large\r\nConnection: close\r\n\r\n")
                await writer.drain()
                return
            if content_length > 0:
                body_bytes = await reader.readexactly(content_length)

            # Resolve full target URL
            if raw_target.startswith(("http://", "https://")):
                url = raw_target
            else:
                host_hdr = headers.get("Host", "localhost")
                url = f"http://{host_hdr}{raw_target}"

            result = await self.process_request(
                method=method,
                url=url,
                headers=headers,
                body=body_bytes,
                program_id=headers.get("X-PenteFino-Program", self.default_program_id),
            )

            # Send HTTP response back to client
            status_line = f"HTTP/1.1 {result.status_code} OK\r\n"
            writer.write(status_line.encode("utf-8"))
            for hk, hv in result.headers.items():
                if hk.lower() in ("transfer-encoding", "connection"):
                    continue
                writer.write(f"{hk}: {hv}\r\n".encode("utf-8"))
            writer.write(f"Content-Length: {len(result.body)}\r\n".encode("utf-8"))
            writer.write(b"Connection: close\r\n\r\n")
            writer.write(result.body)
            await writer.drain()

        except Exception as e:
            logger.error("Client connection error: %s", e)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _handle_connect(
        self,
        target_hostport: str,
        headers: Dict[str, str],
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        """
        Handles HTTPS CONNECT tunneling requests.
        Evaluates destination scope before establishing upstream TCP tunnel.
        """
        prog_id = headers.get("X-PenteFino-Program", self.default_program_id)
        parsed_prog_uuid: Optional[UUID] = None
        if len(prog_id) == 36:
            try:
                parsed_prog_uuid = UUID(prog_id)
            except ValueError:
                parsed_prog_uuid = None

        if parsed_prog_uuid:
            await self._ensure_program_synced(parsed_prog_uuid)

        if target_hostport.startswith("[") and "]" in target_hostport:
            bracket_end = target_hostport.index("]")
            target_host = target_hostport[1:bracket_end]
            rest = target_hostport[bracket_end + 1:]
            try:
                target_port = int(rest.lstrip(":")) if rest.startswith(":") else 443
            except ValueError:
                target_port = 443
        elif ":" in target_hostport:
            target_host, port_str = target_hostport.rsplit(":", 1)
            try:
                target_port = int(port_str)
            except ValueError:
                target_port = 443
        else:
            target_host = target_hostport
            target_port = 443

        host_for_url = f"[{target_host}]" if ":" in target_host else target_host
        url = f"https://{host_for_url}:{target_port}/"

        # 1. Scope Guard Check
        decision = self.scope_guard.evaluate(
            url=url,
            method="CONNECT",
            program_id=parsed_prog_uuid,
            check_dns=(self.environment_class != "lab"),
        )

        if not decision.allowed:
            logger.warning("CONNECT tunnel to %s rejected: %s", target_hostport, decision.reason)
            await self.metrics.record(
                method="CONNECT", url=url, allowed=False, reason=decision.reason,
                tier=(decision.matched_tier.value if hasattr(decision.matched_tier, "value") else str(decision.matched_tier)), status_code=403,
            )
            resp = ScopeGuard.build_403_response(decision, url)
            body_bytes = json.dumps(resp["body"]).encode("utf-8")
            payload = (
                f"HTTP/1.1 403 Forbidden\r\n"
                f"Content-Type: application/json\r\n"
                f"X-PenteFino-Proxy: Egress-Traffic-Controller\r\n"
                f"X-PenteFino-Decision: DENY\r\n"
                f"X-PenteFino-Reason: {decision.reason}\r\n"
                f"Content-Length: {len(body_bytes)}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("utf-8") + body_bytes
            client_writer.write(payload)
            await client_writer.drain()
            client_writer.close()
            await client_writer.wait_closed()
            return

        await self.metrics.record(
            method="CONNECT", url=url, allowed=True, reason=decision.reason,
            tier=(decision.matched_tier.value if hasattr(decision.matched_tier, "value") else str(decision.matched_tier)), status_code=200,
        )

        # 2. Rate Limiting Check
        await self.rate_limiter.acquire_lease(
            host=target_host,
            program_id=prog_id,
            cost=1.0,
            sleep=True,
        )

        # 3. Establish upstream connection using pinned IP (anti-TOCTOU DNS rebinding)
        connect_host = decision.resolved_ip or target_host
        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(
                connect_host,
                target_port,
            )
        except Exception as e:
            logger.error("Failed to connect upstream to %s:%d: %s", target_host, target_port, e)
            client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            await client_writer.drain()
            client_writer.close()
            await client_writer.wait_closed()
            return

        # 4. Respond 200 Connection Established
        client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await client_writer.drain()

        # 5. Bidirectional TCP piping
        async def pipe(r: asyncio.StreamReader, w: asyncio.StreamWriter):
            try:
                while True:
                    data = await r.read(65536)
                    if not data:
                        break
                    w.write(data)
                    await w.drain()
            except Exception:
                pass
            finally:
                try:
                    w.close()
                    await w.wait_closed()
                except Exception:
                    pass

        await asyncio.gather(
            pipe(client_reader, upstream_writer),
            pipe(upstream_reader, client_writer),
            return_exceptions=True,
        )

    async def start(self) -> None:
        """Starts the forward proxy server asynchronously."""
        if self._is_running:
            return

        self._server = await asyncio.start_server(
            self._handle_client_connection,
            self.host,
            self.port,
        )
        self._is_running = True
        # In case port was 0, retrieve assigned port
        if self._server.sockets:
            self.port = self._server.sockets[0].getsockname()[1]
        self.metrics.start_heartbeat()
        logger.info("PenteFino Forward Proxy listening on %s:%d", self.host, self.port)

    async def stop(self) -> None:
        """Gracefully shuts down the forward proxy server and cleans up resources."""
        self._is_running = False
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

        if self._http_session is not None and not self._http_session.closed:
            await self._http_session.close()
            self._http_session = None

        await self.rate_limiter.close()
        await self.metrics.close()
        logger.info("PenteFino Forward Proxy stopped")
