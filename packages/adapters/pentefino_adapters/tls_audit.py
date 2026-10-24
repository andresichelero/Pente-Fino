from __future__ import annotations

import asyncio
import fnmatch
import hashlib
import logging
import ssl
import uuid
import warnings
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pentefino_adapters.models import (
    TlsAuditResult,
    TlsCertificateInfo,
    TlsSecurityAnomaly,
)
from pentefino_domain.models import Asset, Observation

logger = logging.getLogger(__name__)


class TlsAuditAdapter:
    """
    Safe, non-destructive SSL/TLS configuration and cipher suite audit adapter.
    Performs standard cryptographic handshakes without sending exploit payloads.
    """

    TLS_VERSIONS: List[Tuple[str, ssl.TLSVersion]] = [
        ("TLSv1.0", ssl.TLSVersion.TLSv1),
        ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
        ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
        ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
    ]

    WEAK_CIPHER_PROBES: List[Tuple[str, str]] = [
        ("RC4", "RC4:@SECLEVEL=0"),
        ("3DES", "3DES:DES-CBC3-SHA:@SECLEVEL=0"),
        ("CBC_CIPHERS", "AES128-SHA:AES256-SHA:@SECLEVEL=0"),
        ("EXPORT_OR_NULL", "EXPORT:NULL:@SECLEVEL=0"),
    ]

    def __init__(self, timeout: float = 5.0, expiry_warning_days: int = 14):
        self.timeout = timeout
        self.expiry_warning_days = expiry_warning_days

    async def _test_handshake(
        self,
        host: str,
        port: int,
        context: ssl.SSLContext,
        server_hostname: Optional[str] = None,
    ) -> Tuple[bool, Optional[Any], Optional[str]]:
        """
        Executes a single non-destructive TLS handshake with a specific SSLContext.
        Returns (success, ssl_object, error_message).
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host,
                    port,
                    ssl=context,
                    server_hostname=server_hostname or host,
                ),
                timeout=self.timeout,
            )
            ssl_obj = writer.get_extra_info("ssl_object")
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True, ssl_obj, None
        except (ssl.SSLError, asyncio.TimeoutError, OSError) as e:
            return False, None, str(e)
        except Exception as e:
            return False, None, str(e)

    async def probe_tls_versions(self, host: str, port: int) -> Tuple[List[str], List[str]]:
        """
        Probes support for TLS 1.0, 1.1, 1.2, and 1.3.
        Returns (supported_protocols, deprecated_protocols).
        """
        supported: List[str] = []
        deprecated: List[str] = []

        for name, version in self.TLS_VERSIONS:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                try:
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore", DeprecationWarning)
                        ctx.minimum_version = version
                        ctx.maximum_version = version
                except (ValueError, ssl.SSLError):
                    continue

                success, _, _ = await self._test_handshake(host, port, ctx, server_hostname=host)
                if success:
                    supported.append(name)
                    if name in ("TLSv1.0", "TLSv1.1"):
                        deprecated.append(name)
            except Exception as e:
                logger.debug("TLS version check failed for %s on %s:%d: %s", name, host, port, e)

        return supported, deprecated

    async def probe_weak_ciphers(self, host: str, port: int) -> Tuple[List[str], Optional[str]]:
        """
        Probes for deprecated or weak cipher suites (RC4, 3DES, CBC, Export/Null).
        Returns (weak_ciphers, default_cipher_name).
        """
        detected_weak: List[str] = []
        default_cipher: Optional[str] = None

        # 1. Standard handshake to inspect negotiated default cipher
        try:
            default_ctx = ssl.create_default_context()
            default_ctx.check_hostname = False
            default_ctx.verify_mode = ssl.CERT_NONE
            success, ssl_obj, _ = await self._test_handshake(host, port, default_ctx, server_hostname=host)
            if success and ssl_obj:
                cipher_tuple = ssl_obj.cipher()
                if cipher_tuple:
                    default_cipher = cipher_tuple[0]
                    cipher_upper = default_cipher.upper()
                    if any(bad in cipher_upper for bad in ("RC4", "3DES", "DES-CBC", "CBC", "NULL", "EXP")):
                        detected_weak.append(default_cipher)
        except Exception as e:
            logger.debug("Default handshake cipher inspection failed for %s:%d: %s", host, port, e)

        # 2. Probe weak cipher suites specifically
        for label, cipher_str in self.WEAK_CIPHER_PROBES:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.set_ciphers(cipher_str)
                success, ssl_obj, _ = await self._test_handshake(host, port, ctx, server_hostname=host)
                if success:
                    if label not in detected_weak:
                        detected_weak.append(label)
            except Exception as e:
                logger.debug("Weak cipher probe for %s on %s:%d failed: %s", label, host, port, e)

        return detected_weak, default_cipher

    def _matches_san(self, hostname: str, san: str) -> bool:
        """Matches target hostname against Subject Alternative Name (supporting wildcards)."""
        host_clean = hostname.strip().lower()
        san_clean = san.strip().lower()
        if host_clean == san_clean:
            return True
        if san_clean.startswith("*."):
            base_domain = san_clean[2:]
            if host_clean.endswith(f".{base_domain}") and "." not in host_clean[: -len(base_domain) - 1]:
                return True
        return fnmatch.fnmatch(host_clean, san_clean)

    async def inspect_certificate(
        self, host: str, port: int
    ) -> Tuple[Optional[TlsCertificateInfo], List[TlsSecurityAnomaly]]:
        """
        Inspects the peer certificate: validity dates, expiration, SAN matching, self-signed status.
        """
        anomalies: List[TlsSecurityAnomaly] = []
        cert_info: Optional[TlsCertificateInfo] = None

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        success, ssl_obj, err = await self._test_handshake(host, port, ctx, server_hostname=host)
        if not success or not ssl_obj:
            logger.debug("Failed to obtain certificate for %s:%d: %s", host, port, err)
            return None, anomalies

        der_cert = ssl_obj.getpeercert(binary_form=True)
        if not der_cert:
            return None, anomalies

        try:
            cert = x509.load_der_x509_certificate(der_cert, default_backend())
            now_utc = datetime.now(timezone.utc)

            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc

            days_to_expire = (not_after - now_utc).total_seconds() / 86400.0
            is_expired = days_to_expire <= 0

            is_self_signed = cert.subject == cert.issuer

            # Extract Subject Alternative Names (SANs)
            san_names: List[str] = []
            try:
                san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                for name in san_ext.value:
                    san_names.append(str(name.value))
            except Exception:
                # If SAN extension is missing, fallback to Common Name
                for attr in cert.subject:
                    if attr.oid == x509.NameOID.COMMON_NAME:
                        san_names.append(str(attr.value))

            hostname_matches = any(self._matches_san(host, s) for s in san_names) if san_names else False

            sig_algo = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"
            try:
                fingerprint = cert.fingerprint(hashes.SHA256()).hex()
            except Exception:
                fingerprint = None

            cert_info = TlsCertificateInfo(
                subject=cert.subject.rfc4514_string(),
                issuer=cert.issuer.rfc4514_string(),
                serial_number=hex(cert.serial_number),
                not_before=not_before.isoformat(),
                not_after=not_after.isoformat(),
                days_to_expire=round(days_to_expire, 2),
                is_expired=is_expired,
                is_self_signed=is_self_signed,
                san_names=san_names,
                hostname_matches_san=hostname_matches,
                signature_algorithm=sig_algo,
                fingerprint_sha256=fingerprint,
            )

            # Anomaly Checks on Certificate
            if is_expired:
                anomalies.append(
                    TlsSecurityAnomaly(
                        id="TLS-CERT-EXPIRED",
                        title="SSL/TLS Certificate Expired",
                        severity="high",
                        description=f"Target certificate expired {abs(days_to_expire):.1f} days ago on {not_after.isoformat()}.",
                        recommendation="Renew the SSL/TLS certificate immediately.",
                    )
                )
            elif days_to_expire <= self.expiry_warning_days:
                anomalies.append(
                    TlsSecurityAnomaly(
                        id="TLS-CERT-EXPIRING",
                        title="SSL/TLS Certificate Expiring Soon",
                        severity="low",
                        description=f"Target certificate will expire in {days_to_expire:.1f} days on {not_after.isoformat()}.",
                        recommendation="Schedule renewal for the SSL/TLS certificate.",
                    )
                )

            if san_names and not hostname_matches:
                anomalies.append(
                    TlsSecurityAnomaly(
                        id="TLS-CERT-SAN-MISMATCH",
                        title="SSL/TLS Certificate Hostname Mismatch",
                        severity="medium",
                        description=f"Hostname '{host}' does not match any certificate SANs: {san_names}.",
                        recommendation="Ensure the certificate contains the target hostname in Subject Alternative Names.",
                    )
                )

            if is_self_signed:
                anomalies.append(
                    TlsSecurityAnomaly(
                        id="TLS-CERT-SELF-SIGNED",
                        title="Self-Signed SSL/TLS Certificate",
                        severity="low",
                        description="Certificate is self-signed and untrusted by default public PKI trust stores.",
                        recommendation="Replace self-signed certificate with one issued by a trusted public CA.",
                    )
                )

            if sig_algo.lower() in ("sha1", "md5"):
                anomalies.append(
                    TlsSecurityAnomaly(
                        id="TLS-CERT-WEAK-SIG",
                        title="Weak Certificate Signature Algorithm",
                        severity="medium",
                        description=f"Certificate uses deprecated cryptographic hash algorithm: {sig_algo}.",
                        recommendation="Reissue the certificate using SHA-256 or stronger signature algorithm.",
                    )
                )

        except Exception as e:
            logger.warning("Error parsing X.509 certificate for %s:%d: %s", host, port, e)

        return cert_info, anomalies

    async def audit(
        self,
        host: str,
        port: int = 443,
        program_id: Optional[uuid.UUID] = None,
        session: Optional[AsyncSession] = None,
    ) -> TlsAuditResult:
        """
        Executes a comprehensive, non-destructive TLS security audit on host:port.
        """
        supported_proto, deprecated_proto = await self.probe_tls_versions(host, port)
        weak_ciphers, default_cipher = await self.probe_weak_ciphers(host, port)
        cert_info, cert_anomalies = await self.inspect_certificate(host, port)

        anomalies: List[TlsSecurityAnomaly] = list(cert_anomalies)

        # Protocol anomalies
        if "TLSv1.0" in supported_proto:
            anomalies.append(
                TlsSecurityAnomaly(
                    id="TLS-DEP-10",
                    title="Deprecated TLS 1.0 Protocol Enabled",
                    severity="medium",
                    description="Server negotiates or supports TLS 1.0, which was formally deprecated by RFC 8996.",
                    recommendation="Disable TLS 1.0 on the web server or load balancer.",
                )
            )
        if "TLSv1.1" in supported_proto:
            anomalies.append(
                TlsSecurityAnomaly(
                    id="TLS-DEP-11",
                    title="Deprecated TLS 1.1 Protocol Enabled",
                    severity="medium",
                    description="Server negotiates or supports TLS 1.1, which was formally deprecated by RFC 8996.",
                    recommendation="Disable TLS 1.1 on the web server or load balancer.",
                )
            )

        # Cipher anomalies
        if weak_ciphers:
            anomalies.append(
                TlsSecurityAnomaly(
                    id="TLS-WEAK-CIPHER",
                    title="Weak or Deprecated Cipher Suite Supported",
                    severity="medium",
                    description=f"Server supports weak or legacy cipher suites: {', '.join(weak_ciphers)}.",
                    recommendation="Configure cipher suites to only allow modern AEAD ciphers (e.g. AES-GCM, CHACHA20-POLY1305).",
                )
            )

        success = bool(supported_proto or cert_info)

        result = TlsAuditResult(
            host=host,
            port=port,
            supported_protocols=supported_proto,
            deprecated_protocols=deprecated_proto,
            weak_ciphers=weak_ciphers,
            selected_cipher=default_cipher,
            certificate_info=cert_info,
            anomalies=anomalies,
            error=None if success else "Failed to establish TLS handshake with host",
            success=success,
        )

        if session is not None and program_id is not None and success:
            await self.persist(session, program_id, result)

        return result

    def generate_candidate_findings(
        self,
        result: TlsAuditResult,
        program_id: uuid.UUID,
    ) -> List[Dict[str, Any]]:
        """
        Generates candidate finding payloads with deduplication keys:
        sha256(program_id + host + port + path + detector_id).
        """
        findings: List[Dict[str, Any]] = []
        for anomaly in result.anomalies:
            dedup_input = f"{program_id}:{result.host.lower()}:{result.port}:/:{anomaly.id}"
            dedup_key = hashlib.sha256(dedup_input.encode("utf-8")).hexdigest()
            findings.append(
                {
                    "program_id": program_id,
                    "host": result.host.lower(),
                    "port": result.port,
                    "dedup_key": dedup_key,
                    "detector_id": anomaly.id,
                    "title": anomaly.title,
                    "severity": anomaly.severity,
                    "description": anomaly.description,
                    "recommendation": anomaly.recommendation,
                }
            )
        return findings

    async def persist(
        self,
        session: AsyncSession,
        program_id: uuid.UUID,
        result: TlsAuditResult,
    ) -> Optional[Observation]:
        """Persists TLS audit result as an observation attached to the host asset."""
        stmt = select(Asset).where(
            Asset.program_id == program_id,
            Asset.canonical_key == result.host.lower(),
        )
        res = await session.execute(stmt)
        asset = res.scalar_one_or_none()
        if not asset:
            return None

        obs = Observation(
            asset_id=asset.id,
            observation_type="tls_audit",
            raw_data=result.model_dump_json(),
            metadata_json=result.model_dump(),
        )
        session.add(obs)
        await session.commit()
        return obs
