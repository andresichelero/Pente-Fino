from __future__ import annotations

import datetime
import hashlib
import json
import ssl
import unittest.mock as mock
import uuid
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pentefino_adapters.katana import KatanaAdapter
from pentefino_adapters.models import (
    KatanaEndpointRecord,
    PassiveFindingRecord,
    TlsAuditResult,
    TlsCertificateInfo,
    TlsSecurityAnomaly,
)
from pentefino_adapters.tls_audit import TlsAuditAdapter
from pentefino_domain.enums import ScopeState
from pentefino_domain.models import Asset, Observation
from pentefino_proxy.passive_analyzer import PassiveFinding, PassiveResponseAnalyzer
from pentefino_proxy.rate_limiter import ValkeyRateLimiter
from pentefino_proxy.server import ForwardProxyServer, ProxyResult
from pentefino_runner import EphemeralRunner, RunConfig, RunResult
from pentefino_scope import ScopeEngine
from pentefino_scope.enums import AssetType, PrecedenceTier, ScopeAction
from pentefino_scope.models import ScopeDecision, ScopeRule, ScopeTarget


# =============================================================================
# Helper: Generate In-Memory X.509 Certificates for TLS Tests
# =============================================================================


def _create_test_certificate(
    common_name: str,
    san_names: List[str],
    days_valid: int = 30,
    self_signed: bool = True,
    issuer_name: Optional[str] = None,
    hash_algorithm: Any = hashes.SHA256(),
) -> x509.Certificate:
    """Generates a genuine in-memory X.509 certificate for TLS audit tests."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    issuer = (
        subject
        if self_signed
        else x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name or "Trusted Root CA")])
    )

    now = datetime.datetime.now(datetime.timezone.utc)
    if days_valid < 0:
        not_before = now - datetime.timedelta(days=abs(days_valid) + 10)
        not_after = now - datetime.timedelta(days=abs(days_valid))
    else:
        not_before = now - datetime.timedelta(days=1)
        not_after = now + datetime.timedelta(days=days_valid)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    if san_names:
        sans = [x509.DNSName(name) for name in san_names]
        builder = builder.add_extension(
            x509.SubjectAlternativeName(sans),
            critical=False,
        )

    cert = builder.sign(private_key, hash_algorithm, default_backend())
    return cert


# =============================================================================
# 1. KatanaAdapter Tests
# =============================================================================


class TestKatanaAdapter:
    @pytest.fixture
    def mock_runner(self) -> EphemeralRunner:
        runner = MagicMock(spec=EphemeralRunner)
        return runner

    @pytest.fixture
    def sample_scope_engine(self) -> ScopeEngine:
        engine = MagicMock(spec=ScopeEngine)

        def mock_eval(target: ScopeTarget) -> ScopeDecision:
            host = target.host.lower() if target.host else ""
            path = target.path.lower() if target.path else ""
            if "forbidden.com" in host or "out-of-scope" in host or "/admin" in path:
                return ScopeDecision(
                    allowed=False,
                    matched_tier=PrecedenceTier.PATH_PORT_DENY if "/admin" in path else PrecedenceTier.EXPLICIT_DENY,
                    reason="DENIED_BY_POLICY",
                    target_canonical=target.canonical_url,
                )
            return ScopeDecision(
                allowed=True,
                matched_tier=PrecedenceTier.EXPLICIT_ALLOW,
                reason="EXPLICIT_ALLOW",
                target_canonical=target.canonical_url,
            )

        engine.evaluate_target.side_effect = mock_eval
        prog_id = uuid.uuid4()
        engine.rules = [
            ScopeRule(
                program_id=prog_id,
                asset_type=AssetType.DOMAIN,
                pattern="forbidden.com",
                action=ScopeAction.DENY,
            ),
            ScopeRule(
                program_id=prog_id,
                asset_type=AssetType.URL,
                pattern="/admin",
                action=ScopeAction.DENY,
            ),
        ]
        return engine

    def test_katana_build_run_config_default(self, mock_runner: EphemeralRunner):
        adapter = KatanaAdapter(runner=mock_runner, proxy_url="http://pentefino_proxy:8080")
        config = adapter.build_run_config(target_url="https://app.example.com")

        assert config.image == "projectdiscovery/katana:v1.1.0"
        assert config.http_proxy == "http://pentefino_proxy:8080"
        assert config.https_proxy == "http://pentefino_proxy:8080"
        assert "-u" in config.command
        assert "https://app.example.com" in config.command
        assert "-proxy" in config.command
        assert "http://pentefino_proxy:8080" in config.command
        assert "-d" in config.command
        assert "2" in config.command
        assert "-jc" in config.command
        assert "-kf" in config.command
        assert "all" in config.command
        assert "-silent" in config.command
        assert "-json" in config.command

    def test_katana_build_run_config_scoped_and_headless(self, mock_runner: EphemeralRunner):
        adapter = KatanaAdapter(runner=mock_runner, proxy_url="http://proxy:8080")
        config = adapter.build_run_config(
            target_url="https://example.com",
            crawl_scope_regex=r"^https?://([a-z0-9-]+\.)*example\.com",
            crawl_out_scope_regex=r"logout|signout",
            depth=3,
            headless=True,
            rate_limit=25,
            concurrency=20,
            extra_args=["-retry", "3"],
        )

        assert "-cs" in config.command
        assert r"^https?://([a-z0-9-]+\.)*example\.com" in config.command
        assert "-cos" in config.command
        assert "logout|signout" in config.command
        assert "-headless" in config.command
        assert "-rl" in config.command
        assert "25" in config.command
        assert "-c" in config.command
        assert "20" in config.command
        assert "-retry" in config.command
        assert "3" in config.command

    def test_katana_derive_scope_regexes(self, mock_runner: EphemeralRunner, sample_scope_engine: ScopeEngine):
        adapter = KatanaAdapter(
            runner=mock_runner,
            scope_engine=sample_scope_engine,
        )
        cs, cos = adapter.derive_scope_regexes("https://api.test.example.com/v1")

        assert cs is not None
        assert "api\\.test\\.example\\.com" in cs
        assert cos is not None
        assert "forbidden\\.com" in cos

    def test_katana_parse_ndjson_and_scope_confinement(
        self, mock_runner: EphemeralRunner, sample_scope_engine: ScopeEngine
    ):
        adapter = KatanaAdapter(runner=mock_runner, scope_engine=sample_scope_engine)

        ndjson_output = "\n".join(
            [
                json.dumps(
                    {
                        "timestamp": "2026-10-24T12:00:00Z",
                        "request": {
                            "method": "GET",
                            "endpoint": "https://api.example.com/users",
                        },
                        "response": {
                            "status_code": 200,
                            "technologies": ["express", "node.js"],
                        },
                    }
                ),
                json.dumps(
                    {
                        "timestamp": "2026-10-24T12:00:01Z",
                        "request": {
                            "method": "POST",
                            "endpoint": "https://api.example.com/login",
                            "form": {"username": "test", "password": "123"},
                        },
                        "response": {
                            "status_code": 200,
                        },
                    }
                ),
                json.dumps(
                    {
                        "timestamp": "2026-10-24T12:00:02Z",
                        "request": {
                            "method": "GET",
                            "endpoint": "https://forbidden.com/leak",
                        },
                        "response": {
                            "status_code": 200,
                        },
                    }
                ),
                json.dumps(
                    {
                        "timestamp": "2026-10-24T12:00:03Z",
                        "request": {
                            "method": "GET",
                            "endpoint": "https://api.example.com/admin/keys",
                        },
                        "response": {
                            "status_code": 403,
                        },
                    }
                ),
                "   malformed json line to ignore   ",
            ]
        )

        records = adapter.parse_ndjson(ndjson_output)
        assert len(records) == 4

        # Record 1: in-scope GET
        assert records[0].endpoint == "https://api.example.com/users"
        assert records[0].method == "GET"
        assert records[0].path == "/users"
        assert records[0].status_code == 200
        assert "express" in records[0].technologies
        assert records[0].is_in_scope is True
        assert records[0].scope_tier == PrecedenceTier.EXPLICIT_ALLOW

        # Record 2: in-scope POST with form
        assert records[1].endpoint == "https://api.example.com/login"
        assert records[1].method == "POST"
        assert records[1].form_data == {"username": "test", "password": "123"}
        assert records[1].is_in_scope is True

        # Record 3: out-of-scope domain (forbidden.com)
        assert records[2].endpoint == "https://forbidden.com/leak"
        assert records[2].is_in_scope is False
        assert records[2].scope_tier == PrecedenceTier.EXPLICIT_DENY

        # Record 4: denied path (/admin/keys)
        assert records[3].endpoint == "https://api.example.com/admin/keys"
        assert records[3].is_in_scope is False
        assert records[3].scope_tier == PrecedenceTier.PATH_PORT_DENY

    @pytest.mark.asyncio
    async def test_katana_crawl_filters_out_of_scope(
        self, mock_runner: EphemeralRunner, sample_scope_engine: ScopeEngine
    ):
        adapter = KatanaAdapter(runner=mock_runner, scope_engine=sample_scope_engine)

        mock_runner.run = AsyncMock(
            return_value=RunResult(
                exit_code=0,
                stdout="\n".join(
                    [
                        json.dumps({"request": {"endpoint": "https://api.example.com/home"}}),
                        json.dumps({"request": {"endpoint": "https://forbidden.com/evil"}}),
                    ]
                ),
                stderr="",
                container_name="test_katana",
            )
        )

        records = await adapter.crawl("https://api.example.com", filter_out_of_scope=True)
        assert len(records) == 1
        assert records[0].endpoint == "https://api.example.com/home"
        assert records[0].is_in_scope is True

    @pytest.mark.asyncio
    async def test_katana_crawl_rejects_denied_target_url(
        self, mock_runner: EphemeralRunner, sample_scope_engine: ScopeEngine
    ):
        adapter = KatanaAdapter(runner=mock_runner, scope_engine=sample_scope_engine)
        mock_runner.run = AsyncMock()

        records = await adapter.crawl("https://forbidden.com/target")
        assert len(records) == 0
        mock_runner.run.assert_not_called()

    @pytest.mark.asyncio
    async def test_katana_persist_observations(self, mock_runner: EphemeralRunner):
        adapter = KatanaAdapter(runner=mock_runner)
        prog_id = uuid.uuid4()
        asset_id = uuid.uuid4()

        mock_asset = MagicMock(spec=Asset)
        mock_asset.id = asset_id
        mock_asset.canonical_key = "api.example.com"

        session = AsyncMock()
        session.add = MagicMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_asset
        session.execute.return_value = mock_result

        records = [
            KatanaEndpointRecord(
                endpoint="https://api.example.com/v1/profile",
                url="https://api.example.com/v1/profile",
                path="/v1/profile",
                method="GET",
                status_code=200,
                technologies=["react"],
                is_in_scope=True,
            )
        ]

        saved = await adapter.persist(session, prog_id, records)
        assert len(saved) == 1
        assert saved[0].asset_id == asset_id
        assert saved[0].observation_type == "crawled_endpoint"
        session.commit.assert_awaited_once()


# =============================================================================
# 2. TlsAuditAdapter Tests
# =============================================================================


class TestTlsAuditAdapter:
    @pytest.mark.asyncio
    async def test_tls_audit_detects_deprecated_protocols(self):
        adapter = TlsAuditAdapter(timeout=2.0)

        # Mock handshake to report TLS 1.0, 1.1, and 1.2 supported
        async def mock_handshake(host, port, context, server_hostname=None):
            min_v = getattr(context, "minimum_version", None)
            if min_v in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_2):
                mock_ssl = MagicMock()
                mock_ssl.cipher.return_value = ("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2", 128)
                return True, mock_ssl, None
            return False, None, "Unsupported version"

        with patch.object(adapter, "_test_handshake", side_effect=mock_handshake), patch.object(
            adapter, "inspect_certificate", return_value=(None, [])
        ):
            result = await adapter.audit("example.com", 443)

            assert "TLSv1.0" in result.supported_protocols
            assert "TLSv1.1" in result.supported_protocols
            assert "TLSv1.2" in result.supported_protocols
            assert "TLSv1.0" in result.deprecated_protocols
            assert "TLSv1.1" in result.deprecated_protocols

            anomaly_ids = [a.id for a in result.anomalies]
            assert "TLS-DEP-10" in anomaly_ids
            assert "TLS-DEP-11" in anomaly_ids

    @pytest.mark.asyncio
    async def test_tls_audit_detects_weak_ciphers(self):
        adapter = TlsAuditAdapter(timeout=2.0)

        async def mock_handshake(host, port, context, server_hostname=None):
            mock_ssl = MagicMock()
            # Default handshake negotiates a CBC cipher
            mock_ssl.cipher.return_value = ("ECDHE-RSA-AES128-SHA", "TLSv1.2", 128)
            return True, mock_ssl, None

        with patch.object(adapter, "_test_handshake", side_effect=mock_handshake), patch.object(
            adapter, "inspect_certificate", return_value=(None, [])
        ):
            weak_ciphers, default_cipher = await adapter.probe_weak_ciphers("example.com", 443)
            assert len(weak_ciphers) > 0

            result = await adapter.audit("example.com", 443)
            anomaly_ids = [a.id for a in result.anomalies]
            assert "TLS-WEAK-CIPHER" in anomaly_ids

    @pytest.mark.asyncio
    async def test_tls_audit_detects_expired_certificate(self):
        adapter = TlsAuditAdapter(timeout=2.0)
        expired_cert = _create_test_certificate(
            common_name="test.example.com",
            san_names=["test.example.com"],
            days_valid=-5,  # Expired 5 days ago
            self_signed=True,
        )
        der_bytes = expired_cert.public_bytes(serialization.Encoding.DER)

        mock_ssl = MagicMock()
        mock_ssl.getpeercert.return_value = der_bytes

        with patch.object(adapter, "_test_handshake", return_value=(True, mock_ssl, None)):
            cert_info, anomalies = await adapter.inspect_certificate("test.example.com", 443)

            assert cert_info is not None
            assert cert_info.is_expired is True
            assert cert_info.days_to_expire < 0
            anomaly_ids = [a.id for a in anomalies]
            assert "TLS-CERT-EXPIRED" in anomaly_ids
            assert "TLS-CERT-SELF-SIGNED" in anomaly_ids

    @pytest.mark.asyncio
    async def test_tls_audit_detects_hostname_san_mismatch(self):
        adapter = TlsAuditAdapter(timeout=2.0)
        cert = _create_test_certificate(
            common_name="api.internal.com",
            san_names=["api.internal.com", "*.internal.com"],
            days_valid=30,
            self_signed=False,
            issuer_name="GlobalSign CA",
        )
        der_bytes = cert.public_bytes(serialization.Encoding.DER)

        mock_ssl = MagicMock()
        mock_ssl.getpeercert.return_value = der_bytes

        with patch.object(adapter, "_test_handshake", return_value=(True, mock_ssl, None)):
            cert_info, anomalies = await adapter.inspect_certificate("app.public.com", 443)

            assert cert_info is not None
            assert cert_info.hostname_matches_san is False
            anomaly_ids = [a.id for a in anomalies]
            assert "TLS-CERT-SAN-MISMATCH" in anomaly_ids

    @pytest.mark.asyncio
    async def test_tls_audit_san_wildcard_matching(self):
        adapter = TlsAuditAdapter(timeout=2.0)
        cert = _create_test_certificate(
            common_name="*.example.com",
            san_names=["*.example.com"],
            days_valid=90,
            self_signed=False,
        )
        der_bytes = cert.public_bytes(serialization.Encoding.DER)

        mock_ssl = MagicMock()
        mock_ssl.getpeercert.return_value = der_bytes

        with patch.object(adapter, "_test_handshake", return_value=(True, mock_ssl, None)):
            cert_info, anomalies = await adapter.inspect_certificate("sub.example.com", 443)
            assert cert_info is not None
            assert cert_info.hostname_matches_san is True
            anomaly_ids = [a.id for a in anomalies]
            assert "TLS-CERT-SAN-MISMATCH" not in anomaly_ids

    @pytest.mark.asyncio
    async def test_tls_audit_detects_weak_sha1_signature(self):
        adapter = TlsAuditAdapter(timeout=2.0)
        cert = _create_test_certificate(
            common_name="weak.example.com",
            san_names=["weak.example.com"],
            days_valid=30,
        )
        der_bytes = cert.public_bytes(serialization.Encoding.DER)

        mock_ssl = MagicMock()
        mock_ssl.getpeercert.return_value = der_bytes

        real_cert = x509.load_der_x509_certificate(der_bytes, default_backend())
        mock_sha1 = MagicMock()
        mock_sha1.name = "sha1"
        wrapped_cert = MagicMock(wraps=real_cert)
        wrapped_cert.signature_hash_algorithm = mock_sha1
        wrapped_cert.subject = real_cert.subject
        wrapped_cert.issuer = real_cert.issuer
        wrapped_cert.serial_number = real_cert.serial_number
        wrapped_cert.not_valid_before_utc = real_cert.not_valid_before_utc
        wrapped_cert.not_valid_after_utc = real_cert.not_valid_after_utc
        wrapped_cert.extensions = real_cert.extensions

        with patch.object(adapter, "_test_handshake", return_value=(True, mock_ssl, None)), patch(
            "cryptography.x509.load_der_x509_certificate", return_value=wrapped_cert
        ):
            cert_info, anomalies = await adapter.inspect_certificate("weak.example.com", 443)
            assert cert_info is not None
            assert cert_info.signature_algorithm == "sha1"
            anomaly_ids = [a.id for a in anomalies]
            assert "TLS-CERT-WEAK-SIG" in anomaly_ids

    def test_tls_audit_generate_candidate_findings(self):
        adapter = TlsAuditAdapter()
        prog_id = uuid.uuid4()
        result = TlsAuditResult(
            host="app.example.com",
            port=443,
            supported_protocols=["TLSv1.0", "TLSv1.2"],
            deprecated_protocols=["TLSv1.0"],
            anomalies=[
                TlsSecurityAnomaly(
                    id="TLS-DEP-10",
                    title="Deprecated TLS 1.0",
                    severity="medium",
                    description="TLS 1.0 is enabled",
                )
            ],
        )

        findings = adapter.generate_candidate_findings(result, prog_id)
        assert len(findings) == 1
        f = findings[0]
        assert f["detector_id"] == "TLS-DEP-10"
        expected_dedup = hashlib.sha256(f"{prog_id}:app.example.com:443:/:TLS-DEP-10".encode("utf-8")).hexdigest()
        assert f["dedup_key"] == expected_dedup

    @pytest.mark.asyncio
    async def test_tls_audit_persist(self):
        adapter = TlsAuditAdapter()
        prog_id = uuid.uuid4()
        asset_id = uuid.uuid4()

        mock_asset = MagicMock(spec=Asset)
        mock_asset.id = asset_id
        mock_asset.canonical_key = "secure.example.com"

        session = AsyncMock()
        session.add = MagicMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_asset
        session.execute.return_value = mock_result

        audit_res = TlsAuditResult(
            host="secure.example.com",
            port=443,
            supported_protocols=["TLSv1.3"],
        )

        obs = await adapter.persist(session, prog_id, audit_res)
        assert obs is not None
        assert obs.asset_id == asset_id
        assert obs.observation_type == "tls_audit"
        session.commit.assert_awaited_once()


# =============================================================================
# 3. PassiveResponseAnalyzer Tests
# =============================================================================


class TestPassiveResponseAnalyzer:
    @pytest.fixture
    def analyzer(self) -> PassiveResponseAnalyzer:
        return PassiveResponseAnalyzer()

    def test_zero_outbound_requests_invariant(self, analyzer: PassiveResponseAnalyzer):
        """Verifies analyzer executes 100% in-memory with zero network or subprocess calls."""
        with patch("socket.socket") as mock_sock, patch("asyncio.open_connection") as mock_conn:
            findings = analyzer.analyze(
                url="https://app.example.com/login",
                status_code=200,
                headers={"Content-Type": "text/html"},
                body=b"<html>Hello</html>",
            )
            mock_sock.assert_not_called()
            mock_conn.assert_not_called()
            assert isinstance(findings, list)

    def test_missing_security_headers_flagged(self, analyzer: PassiveResponseAnalyzer):
        findings = analyzer.analyze(
            url="https://app.example.com/test",
            status_code=200,
            headers={"Content-Type": "text/html; charset=utf-8"},
            body=b"<html><body>test</body></html>",
        )
        rule_ids = {f.rule_id for f in findings}

        assert "PASSIVE-SEC-HSTS-MISSING" in rule_ids
        assert "PASSIVE-SEC-CSP-MISSING" in rule_ids
        assert "PASSIVE-SEC-NOSNIFF" in rule_ids
        assert "PASSIVE-SEC-XFO-MISSING" in rule_ids

    def test_hsts_short_max_age_flagged(self, analyzer: PassiveResponseAnalyzer):
        findings = analyzer.analyze(
            url="https://app.example.com/api",
            status_code=200,
            headers={
                "Strict-Transport-Security": "max-age=86400",  # Only 1 day
                "X-Content-Type-Options": "nosniff",
            },
            body=b"{}",
        )
        rule_ids = {f.rule_id for f in findings}
        assert "PASSIVE-SEC-HSTS-SHORT" in rule_ids
        assert "PASSIVE-SEC-HSTS-MISSING" not in rule_ids

    def test_permissive_csp_directives_flagged(self, analyzer: PassiveResponseAnalyzer):
        findings = analyzer.analyze(
            url="https://app.example.com/dashboard",
            status_code=200,
            headers={
                "Content-Type": "text/html",
                "Content-Security-Policy": "default-src 'self' 'unsafe-inline' 'unsafe-eval'",
                "X-Content-Type-Options": "nosniff",
                "Strict-Transport-Security": "max-age=31536000",
                "X-Frame-Options": "DENY",
            },
            body=b"<html>dashboard</html>",
        )
        rule_ids = {f.rule_id for f in findings}
        assert "PASSIVE-SEC-CSP-UNSAFE-INLINE" in rule_ids
        assert "PASSIVE-SEC-CSP-UNSAFE-EVAL" in rule_ids
        assert "PASSIVE-SEC-CSP-MISSING" not in rule_ids

    def test_insecure_cookies_flagged(self, analyzer: PassiveResponseAnalyzer):
        findings = analyzer.analyze(
            url="https://app.example.com/login",
            status_code=200,
            headers={
                "Set-Cookie": "auth_token=abc123xyz; Path=/",  # Missing Secure, HttpOnly, SameSite
                "Content-Type": "application/json",
            },
            body=b"{}",
        )
        rule_ids = {f.rule_id for f in findings}
        assert "PASSIVE-COOKIE-NO-SECURE" in rule_ids
        assert "PASSIVE-COOKIE-NO-HTTPONLY" in rule_ids
        assert "PASSIVE-COOKIE-NO-SAMESITE" in rule_ids

    def test_cookie_samesite_none_without_secure_flagged(self, analyzer: PassiveResponseAnalyzer):
        findings = analyzer.analyze(
            url="https://app.example.com/auth",
            status_code=200,
            headers={
                "Set-Cookie": "pref=dark; SameSite=None; Path=/",  # Missing Secure
            },
            body=b"{}",
        )
        rule_ids = {f.rule_id for f in findings}
        assert "PASSIVE-COOKIE-SAMESITE-NONE-INSECURE" in rule_ids

    def test_information_leak_headers_flagged(self, analyzer: PassiveResponseAnalyzer):
        findings = analyzer.analyze(
            url="https://app.example.com/",
            status_code=200,
            headers={
                "Server": "Apache/2.4.49 (Ubuntu)",
                "X-Powered-By": "PHP/7.4.28",
                "X-Debug-Token": "d3b07384d113edec49eaa6238ad5ff00",
                "X-Content-Type-Options": "nosniff",
                "Strict-Transport-Security": "max-age=31536000",
            },
            body=b"OK",
        )
        rule_ids = {f.rule_id for f in findings}
        assert "PASSIVE-LEAK-SERVER-BANNER" in rule_ids
        assert "PASSIVE-LEAK-POWERED-BY" in rule_ids
        assert "PASSIVE-LEAK-DEBUG-HEADER" in rule_ids

    def test_body_aws_key_leak_sanitized(self, analyzer: PassiveResponseAnalyzer):
        body = b'{"status": "error", "aws_access_key": "AKIAIOSFODNN7EXAMPLE", "region": "us-east-1"}'
        findings = analyzer.analyze(
            url="https://api.example.com/config",
            status_code=200,
            headers={"Content-Type": "application/json"},
            body=body,
        )
        aws_findings = [f for f in findings if f.rule_id == "PASSIVE-LEAK-AWS-KEY"]
        assert len(aws_findings) == 1
        assert aws_findings[0].severity == "high"
        # Secret must be masked and NOT stored raw
        assert "AKIAIOSFODNN7EXAMPLE" not in aws_findings[0].matched_text
        assert aws_findings[0].matched_text == "AKIA************MPLE"

    def test_body_private_key_leak_sanitized(self, analyzer: PassiveResponseAnalyzer):
        body = (
            b"-----BEGIN RSA PRIVATE KEY-----\n"
            b"MIIEowIBAAKCAQEA0Y1o0z7Vp1vG...\n"
            b"-----END RSA PRIVATE KEY-----"
        )
        findings = analyzer.analyze(
            url="https://api.example.com/backup.key",
            status_code=200,
            headers={"Content-Type": "text/plain"},
            body=body,
        )
        pk_findings = [f for f in findings if f.rule_id == "PASSIVE-LEAK-PRIVATE-KEY"]
        assert len(pk_findings) == 1
        assert pk_findings[0].severity == "critical"
        assert "[REDACTED]" in pk_findings[0].matched_text

    def test_body_slack_and_github_token_leaks(self, analyzer: PassiveResponseAnalyzer):
        body = b"slack_webhook = 'xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx'\ngh_token = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz'"
        findings = analyzer.analyze(
            url="https://api.example.com/code",
            status_code=200,
            headers={"Content-Type": "text/plain"},
            body=body,
        )
        rule_ids = {f.rule_id for f in findings}
        assert "PASSIVE-LEAK-SLACK-TOKEN" in rule_ids
        assert "PASSIVE-LEAK-GITHUB-TOKEN" in rule_ids

    def test_body_stack_trace_leak(self, analyzer: PassiveResponseAnalyzer):
        body = (
            b"Traceback (most recent call last):\n"
            b'  File "/var/app/server.py", line 42, in get_user\n'
            b"ZeroDivisionError: division by zero"
        )
        findings = analyzer.analyze(
            url="https://api.example.com/error",
            status_code=500,
            headers={"Content-Type": "text/html"},
            body=body,
        )
        st_findings = [f for f in findings if f.rule_id == "PASSIVE-LEAK-STACK-TRACE"]
        assert len(st_findings) == 1
        assert "Python Traceback" in st_findings[0].title

    def test_deduplication_keys_consistency(self, analyzer: PassiveResponseAnalyzer):
        f1 = analyzer.analyze(
            url="https://api.example.com/v1/users",
            status_code=200,
            headers={"Content-Type": "application/json"},
            body=b"{}",
            program_id="prog-123",
        )
        f2 = analyzer.analyze(
            url="https://api.example.com/v1/users",
            status_code=200,
            headers={"Content-Type": "application/json"},
            body=b"{}",
            program_id="prog-123",
        )

        assert len(f1) > 0
        assert len(f1) == len(f2)
        for a, b in zip(f1, f2):
            assert a.rule_id == b.rule_id
            assert a.dedup_key == b.dedup_key

        # Changing path must change dedup key
        f3 = analyzer.analyze(
            url="https://api.example.com/v2/other",
            status_code=200,
            headers={"Content-Type": "application/json"},
            body=b"{}",
            program_id="prog-123",
        )
        assert f1[0].dedup_key != f3[0].dedup_key

    def test_to_observation(self, analyzer: PassiveResponseAnalyzer):
        findings = analyzer.analyze(
            url="https://app.example.com/",
            status_code=200,
            headers={"Server": "nginx/1.24.0"},
            body=b"",
        )
        assert len(findings) > 0
        asset_id = uuid.uuid4()
        obs = analyzer.to_observation(findings[0], asset_id)
        assert obs.asset_id == asset_id
        assert obs.observation_type == "passive_finding"
        assert obs.metadata_json["rule_id"] == findings[0].rule_id


# =============================================================================
# 4. ForwardProxyServer Integration with PassiveResponseAnalyzer
# =============================================================================


class TestProxyPassiveAnalyzerIntegration:
    @pytest.mark.asyncio
    async def test_process_request_triggers_passive_analysis(self):
        # Create a proxy server with passive analyzer and mock upstream response
        proxy = ForwardProxyServer(
            rate_limiter=ValkeyRateLimiter(use_in_memory=True),
            environment_class="lab",
        )

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {
            "Content-Type": "text/html",
            "Server": "Apache/2.4.52 (Ubuntu)",
            # Missing HSTS, CSP, nosniff, XFO
        }
        mock_resp.read = AsyncMock(return_value=b"<html>Hello</html>")

        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_ctx.__aexit__ = AsyncMock(return_value=None)

        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.request = MagicMock(return_value=mock_ctx)
        proxy._http_session = mock_session

        with patch.object(
            proxy.scope_guard,
            "evaluate",
            return_value=ScopeDecision(
                allowed=True,
                matched_tier=PrecedenceTier.EXPLICIT_ALLOW,
                reason="ALLOW",
                target_canonical="https://lab.example.com/app",
            ),
        ):
            result = await proxy.process_request(
                method="GET",
                url="https://lab.example.com/app",
                headers={"Host": "lab.example.com"},
                upload_evidence=False,
            )

            assert isinstance(result, ProxyResult)
            assert result.status_code == 200
            assert len(result.passive_findings) > 0

            rule_ids = {f.rule_id for f in result.passive_findings}
            assert "PASSIVE-SEC-HSTS-MISSING" in rule_ids
            assert "PASSIVE-LEAK-SERVER-BANNER" in rule_ids
            assert "PASSIVE-SEC-NOSNIFF" in rule_ids
