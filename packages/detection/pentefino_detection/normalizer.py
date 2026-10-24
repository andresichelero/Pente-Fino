"""Finding Normalizer and Forensics Evidence Linker.

Ingests raw Nuclei findings, normalizes target coordinates, computes deterministic
SHA-256 deduplication keys via pentefino_domain.dedup, performs idempotent database
upserts, sanitizes sensitive credentials, and links immutable SeaweedFS S3 evidence records.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Sequence
import urllib.parse
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pentefino_domain.dedup import compute_finding_dedup_key
from pentefino_domain.enums import (
    EvidenceLevel,
    EvidenceType,
    FindingConfidence,
    FindingStatus,
)
from pentefino_domain.models.evidence import Evidence
from pentefino_domain.models.finding import Finding

# Fallback regexes for sanitizing raw HTTP strings
RE_BEARER = re.compile(r"(?im)^(Authorization:\s*Bearer\s+)[^\r\n]+", re.MULTILINE)
RE_BASIC = re.compile(r"(?im)^(Authorization:\s*Basic\s+)[^\r\n]+", re.MULTILINE)
RE_TOKEN = re.compile(r"(?im)^(Authorization:\s*Token\s+)[^\r\n]+", re.MULTILINE)
RE_COOKIE = re.compile(r"(?im)^(Cookie:\s*)([^\r\n]+)", re.MULTILINE)
RE_SET_COOKIE = re.compile(r"(?im)^(Set-Cookie:\s*)([^\r\n]+)", re.MULTILINE)


class FindingNormalizer:
    """Normalizes raw Nuclei findings and links sanitized forensic evidence in S3."""

    def __init__(
        self,
        db_session: AsyncSession,
        s3_client: Any | None = None,
        redactor: Any | None = None,
    ):
        self.db_session = db_session
        self.s3_client = s3_client if s3_client is not None else self._resolve_default_s3_client()
        self.redactor = redactor or self._resolve_default_redactor()

    @staticmethod
    def _resolve_default_s3_client() -> Any:
        try:
            from pentefino_proxy.s3_client import S3EvidenceClient
            return S3EvidenceClient()
        except Exception:
            return None

    @staticmethod
    def _resolve_default_redactor() -> Any:
        try:
            from pentefino_proxy.redactor import Redactor
            return Redactor()
        except ImportError:
            return None

    @staticmethod
    def _determine_evidence_level(raw_item: dict[str, Any]) -> str:
        explicit = raw_item.get("evidence_level")
        if explicit and str(explicit).upper() in ("E0", "E1", "E2", "E3"):
            return str(explicit).upper()
        proto_type = str(raw_item.get("type") or "").strip().lower()
        if proto_type == "passive":
            return EvidenceLevel.E0.value
        if proto_type in ("dns", "ssl", "whois") and not raw_item.get("request"):
            return EvidenceLevel.E1.value
        return EvidenceLevel.E2.value

    async def normalize_and_persist(
        self,
        raw_nuclei_results: Sequence[dict[str, Any]],
        program_id: uuid.UUID | str,
        asset_id: uuid.UUID | str | None = None,
        run_id: uuid.UUID | str | None = None,
    ) -> list[Finding]:
        """Normalize Nuclei output into deduplicated Finding and Evidence records.

        Args:
            raw_nuclei_results: List of raw Nuclei JSON finding dictionaries.
            program_id: Program ID UUID.
            asset_id: Optional Asset ID UUID (generated if not provided).
            run_id: Optional Run ID UUID for forensic correlation.

        Returns:
            List of persisted or updated Finding domain instances.
        """
        # Normalize UUIDs
        prog_uuid = (
            program_id
            if isinstance(program_id, uuid.UUID)
            else uuid.UUID(str(program_id).strip())
        )
        as_uuid = (
            asset_id
            if isinstance(asset_id, uuid.UUID) or asset_id is None
            else uuid.UUID(str(asset_id).strip())
        )
        if as_uuid is None:
            as_uuid = uuid.uuid4()

        r_uuid = (
            run_id
            if isinstance(run_id, uuid.UUID) or run_id is None
            else uuid.UUID(str(run_id).strip())
        )
        if r_uuid is None:
            r_uuid = uuid.uuid4()

        session_findings: dict[str, Finding] = {}
        persisted_findings: list[Finding] = []

        now = datetime.now(timezone.utc)

        for raw_item in raw_nuclei_results:
            if not isinstance(raw_item, dict):
                continue

            # 1. Extract detector ID
            detector_id = (
                raw_item.get("template-id")
                or raw_item.get("template_id")
                or raw_item.get("templateID")
                or "unknown"
            )
            detector_id = str(detector_id).strip().lower()

            # 2. Extract and parse matched target
            matched_at = str(
                raw_item.get("matched-at")
                or raw_item.get("matched_at")
                or raw_item.get("host")
                or ""
            ).strip()

            canonical_asset, port, normalized_path = self._parse_target_coordinates(
                matched_at
            )

            # 3. Compute Deterministic SHA-256 Deduplication Key
            dedup_key = compute_finding_dedup_key(
                program_id=prog_uuid,
                canonical_asset=canonical_asset,
                port=port,
                normalized_path=normalized_path,
                detector_id=detector_id,
            )

            # 4. Extract Metadata
            info = raw_item.get("info", {})
            if not isinstance(info, dict):
                info = {}

            severity = str(info.get("severity") or "info").strip().lower()
            classification = info.get("classification", {})
            if not isinstance(classification, dict):
                classification = {}

            cve_id = classification.get("cve-id")
            if isinstance(cve_id, list) and cve_id:
                advisory_id = str(cve_id[0])
            elif cve_id:
                advisory_id = str(cve_id)
            else:
                advisory_id = None

            # 5. Determine or Update Finding Entity
            finding: Finding | None = session_findings.get(dedup_key)

            if finding is None:
                # Query database for existing finding with (program_id, dedup_key)
                stmt = select(Finding).where(
                    Finding.program_id == prog_uuid,
                    Finding.dedup_key == dedup_key,
                )
                res = await self.db_session.execute(stmt)
                existing = res.scalars().first()

                if existing is not None:
                    finding = existing
                    finding.last_seen = now
                    # Reopen finding if it was previously marked remediated or resolved
                    if finding.status in (
                        FindingStatus.REMEDIATED.value,
                        FindingStatus.RESOLVED.value,
                        "remediated",
                        "resolved",
                    ):
                        finding.status = FindingStatus.REOPENED.value
                else:
                    # New Finding
                    initial_status = (
                        FindingStatus.CANDIDATE.value
                        if severity == "info"
                        else FindingStatus.VALIDATED.value
                    )
                    confidence = (
                        FindingConfidence.HIGH.value
                        if severity in ("high", "critical", "medium")
                        else FindingConfidence.MEDIUM.value
                    )

                    # Resolve exact template ID casing from template_catalog for FK integrity
                    resolved_detector_id = detector_id
                    try:
                        from pentefino_domain.models.template import TemplateCatalog
                        from sqlalchemy import func
                        cat_stmt = select(TemplateCatalog.id).where(
                            (TemplateCatalog.id == detector_id)
                            | (func.lower(TemplateCatalog.id) == detector_id)
                        )
                        cat_res = await self.db_session.execute(cat_stmt)
                        cat_id = cat_res.scalars().first()
                        if cat_id:
                            resolved_detector_id = cat_id
                    except Exception:
                        pass

                    finding = Finding(
                        id=uuid.uuid4(),
                        program_id=prog_uuid,
                        asset_id=as_uuid,
                        dedup_key=dedup_key,
                        detector_id=resolved_detector_id,
                        advisory_id=advisory_id,
                        status=initial_status,
                        evidence_level=self._determine_evidence_level(raw_item),
                        confidence=confidence,
                        first_seen=now,
                        last_seen=now,
                    )
                    self.db_session.add(finding)

                session_findings[dedup_key] = finding
                persisted_findings.append(finding)
            else:
                finding.last_seen = now
                if finding.status in (
                    FindingStatus.REMEDIATED.value,
                    FindingStatus.RESOLVED.value,
                    "remediated",
                    "resolved",
                ):
                    finding.status = FindingStatus.REOPENED.value

            # 6. Sanitize and Store Forensic Evidence in SeaweedFS
            evidence_record = await self._create_and_store_evidence(
                finding=finding,
                raw_item=raw_item,
                program_id=prog_uuid,
                run_id=r_uuid,
                timestamp=now,
            )
            self.db_session.add(evidence_record)

        # Commit transaction
        await self.db_session.commit()
        return persisted_findings

    def _parse_target_coordinates(self, matched_at: str) -> tuple[str, int, str]:
        """Parses canonical asset, port, and normalized path from target URL or host string."""
        raw = matched_at.strip()
        if "://" not in raw:
            raw = f"http://{raw}"

        parsed = urllib.parse.urlsplit(raw)
        host = parsed.hostname or parsed.netloc or "unknown"
        if ":" in host:
            host = host.split(":", 1)[0]
        canonical_asset = host.rstrip(".").lower()

        if parsed.port is not None:
            port = parsed.port
        elif parsed.scheme.lower() == "https":
            port = 443
        else:
            port = 80

        path = parsed.path or "/"
        return canonical_asset, port, path

    async def _create_and_store_evidence(
        self,
        finding: Finding,
        raw_item: dict[str, Any],
        program_id: uuid.UUID,
        run_id: uuid.UUID,
        timestamp: datetime,
    ) -> Evidence:
        """Sanitizes raw HTTP interaction artifact and uploads to S3 store."""
        raw_evidence = {
            "template_id": finding.detector_id,
            "finding_id": str(finding.id),
            "matched_at": raw_item.get("matched-at") or raw_item.get("host"),
            "request": raw_item.get("request", ""),
            "response": raw_item.get("response", ""),
            "extracted_results": raw_item.get("extracted-results", []),
            "curl_command": raw_item.get("curl-command"),
            "timestamp": timestamp.isoformat(),
        }

        raw_bytes = json.dumps(raw_evidence, sort_keys=True, ensure_ascii=False).encode("utf-8")
        original_sha256 = hashlib.sha256(raw_bytes).hexdigest()

        # Sanitize evidence
        sanitized_evidence = self._sanitize_evidence_dict(raw_evidence)
        sanitized_bytes = json.dumps(
            sanitized_evidence, sort_keys=True, ensure_ascii=False
        ).encode("utf-8")
        sanitized_sha256 = hashlib.sha256(sanitized_bytes).hexdigest()

        date_str = timestamp.strftime("%Y-%m-%d")
        seaweed_object_key = (
            f"evidence/{program_id}/{date_str}/{sanitized_sha256}.json"
        )

        # Upload to S3 if client is available
        if self.s3_client is not None:
            self._upload_to_s3(seaweed_object_key, sanitized_bytes)

        return Evidence(
            id=uuid.uuid4(),
            finding_id=finding.id,
            run_id=run_id,
            evidence_type=EvidenceType.HTTP_INTERACTION.value,
            original_sha256=original_sha256,
            sanitized_sha256=sanitized_sha256,
            seaweed_object_key=seaweed_object_key,
            redaction_profile="bounty-safe-v1",
        )

    def _sanitize_evidence_dict(self, data: dict[str, Any]) -> dict[str, Any]:
        """Applies credential and cookie sanitization to the evidence structure."""
        sanitized = dict(data)

        # 1. If Redactor instance is present, try full interaction redaction
        if self.redactor is not None and hasattr(self.redactor, "redact_interaction"):
            try:
                sanitized = self.redactor.redact_interaction(sanitized)
            except Exception:
                pass

        # 2. String-level header and pattern scrubbing for request/response
        if isinstance(sanitized.get("request"), str):
            sanitized["request"] = self._sanitize_http_text(sanitized["request"])
        if isinstance(sanitized.get("response"), str):
            sanitized["response"] = self._sanitize_http_text(sanitized["response"])

        return sanitized

    def _sanitize_http_text(self, text: str) -> str:
        """Sanitizes sensitive headers and values in raw HTTP text."""
        if not text:
            return text

        scrubbed = RE_BEARER.sub(r"\1[REDACTED]", text)
        scrubbed = RE_BASIC.sub(r"\1[REDACTED]", scrubbed)
        scrubbed = RE_TOKEN.sub(r"\1[REDACTED]", scrubbed)

        def _cookie_repl(match: re.Match) -> str:
            prefix = match.group(1)
            raw_cookies = match.group(2)
            parts = [c.strip() for c in raw_cookies.split(";") if c.strip()]
            redacted = []
            for part in parts:
                if "=" in part:
                    name, _ = part.split("=", 1)
                    redacted.append(f"{name.strip()}=[REDACTED]")
                else:
                    redacted.append(f"{part}=[REDACTED]")
            return f"{prefix}{'; '.join(redacted)}"

        scrubbed = RE_COOKIE.sub(_cookie_repl, scrubbed)
        scrubbed = RE_SET_COOKIE.sub(_cookie_repl, scrubbed)
        return scrubbed

    def _upload_to_s3(self, object_key: str, data: bytes) -> None:
        """Uploads sanitized evidence bytes to SeaweedFS / S3 store."""
        try:
            if hasattr(self.s3_client, "upload_evidence"):
                self.s3_client.upload_evidence(
                    artifact_data=data,
                    object_key=object_key,
                    content_type="application/json",
                )
            elif hasattr(self.s3_client, "put_object"):
                try:
                    # InMemoryS3Store style: put_object(bucket_name, key, data)
                    self.s3_client.put_object("evidence", object_key, data)
                except TypeError:
                    # Boto3 style: put_object(Bucket=..., Key=..., Body=...)
                    self.s3_client.put_object(Bucket="evidence", Key=object_key, Body=data)
        except Exception:
            # S3 client errors must not crash the normalizer
            pass
