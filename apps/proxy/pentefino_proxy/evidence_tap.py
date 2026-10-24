from __future__ import annotations

import gzip
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Union
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from .redactor import Redactor
from .s3_client import S3EvidenceClient


class EvidenceRecord(BaseModel):
    """Forensic evidence metadata record."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    id: UUID = Field(default_factory=uuid4)
    program_id: str
    run_id: str
    finding_id: Optional[str] = None
    evidence_type: str = "http_interaction"
    original_sha256: str
    sanitized_sha256: str
    seaweed_object_key: str
    redaction_profile: str = "bounty-safe-v1"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_redacted: bool = False
    sanitized_payload: Dict[str, Any] = Field(default_factory=dict)


def compute_canonical_hash(data: Dict[str, Any]) -> str:
    """
    Computes a deterministic SHA-256 hex digest of a Python dictionary
    using sorted keys and compact JSON formatting.
    """
    serialized = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


class EvidenceTap:
    """
    Transparent Evidence Tapper.
    Captures raw HTTP requests and responses, enforces credentials redaction,
    computes dual SHA-256 cryptographic hashes, and persists artifacts in SeaweedFS S3.
    """

    def __init__(
        self,
        s3_client: Optional[S3EvidenceClient] = None,
        redactor: Optional[Redactor] = None,
        redaction_profile: str = "bounty-safe-v1",
    ):
        self.s3_client = s3_client or S3EvidenceClient()
        self.redactor = redactor or Redactor()
        self.redaction_profile = redaction_profile

    def tap_interaction(
        self,
        method: str,
        url: str,
        request_headers: Dict[str, str],
        request_body: Optional[Union[str, bytes]] = None,
        status_code: int = 200,
        response_headers: Optional[Dict[str, str]] = None,
        response_body: Optional[Union[str, bytes]] = None,
        latency_ms: float = 0.0,
        program_id: Union[str, UUID] = "default",
        run_id: Optional[Union[str, UUID]] = None,
        finding_id: Optional[Union[str, UUID]] = None,
        upload_to_s3: bool = True,
        compress: bool = True,
    ) -> EvidenceRecord:
        """
        Processes an observed HTTP interaction:
        1. Assembles raw interaction dict.
        2. Computes original_sha256.
        3. Sanitizes headers and body via Redactor.
        4. Computes sanitized_sha256.
        5. Uploads to S3 bucket 'evidence'.
        6. Returns EvidenceRecord.
        """
        now = datetime.now(timezone.utc)
        prog_str = str(program_id)
        run_str = str(run_id or uuid4())
        date_str = now.strftime("%Y-%m-%d")

        # Encode bodies cleanly for JSON
        def body_to_str(b: Optional[Union[str, bytes]]) -> Optional[str]:
            if b is None:
                return None
            if isinstance(b, bytes):
                return b.decode("utf-8", errors="replace")
            return b

        raw_interaction: Dict[str, Any] = {
            "version": "1.0",
            "evidence_type": "http_interaction",
            "captured_at": now.isoformat(),
            "program_id": prog_str,
            "run_id": run_str,
            "latency_ms": latency_ms,
            "request": {
                "method": method.upper(),
                "url": url,
                "headers": dict(request_headers),
                "body": body_to_str(request_body),
            },
            "response": {
                "status_code": status_code,
                "headers": dict(response_headers or {}),
                "body": body_to_str(response_body),
            },
        }

        # 1. Compute original hash
        original_sha256 = compute_canonical_hash(raw_interaction)

        # 2. Sanitize interaction
        sanitized_interaction = self.redactor.redact_interaction(raw_interaction)

        # 3. Compute sanitized hash
        sanitized_sha256 = compute_canonical_hash(sanitized_interaction)
        is_redacted = (original_sha256 != sanitized_sha256)

        # 4. Construct S3 object key
        ext = ".json.gz" if compress else ".json"
        object_key = f"artifacts/{prog_str}/{date_str}/{sanitized_sha256}{ext}"

        # 5. Upload to S3
        if upload_to_s3:
            json_bytes = json.dumps(sanitized_interaction, ensure_ascii=False, indent=2).encode("utf-8")
            if compress:
                payload_to_upload = gzip.compress(json_bytes)
                content_encoding = "gzip"
            else:
                payload_to_upload = json_bytes
                content_encoding = None

            self.s3_client.upload_evidence(
                artifact_data=payload_to_upload,
                object_key=object_key,
                content_type="application/json",
                content_encoding=content_encoding,
                metadata={
                    "original-sha256": original_sha256,
                    "sanitized-sha256": sanitized_sha256,
                    "program-id": prog_str,
                    "run-id": run_str,
                    "redaction-profile": self.redaction_profile,
                },
            )

        return EvidenceRecord(
            program_id=prog_str,
            run_id=run_str,
            finding_id=str(finding_id) if finding_id else None,
            evidence_type="http_interaction",
            original_sha256=original_sha256,
            sanitized_sha256=sanitized_sha256,
            seaweed_object_key=object_key,
            redaction_profile=self.redaction_profile,
            created_at=now,
            is_redacted=is_redacted,
            sanitized_payload=sanitized_interaction,
        )
