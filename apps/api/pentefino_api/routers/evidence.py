from __future__ import annotations

import io
import logging
import uuid

from botocore.exceptions import ClientError
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pentefino_api.deps import get_db_session
from pentefino_api.schemas import EvidenceItemSchema
from pentefino_domain.models.evidence import Evidence
from pentefino_proxy.s3_client import S3EvidenceClient

logger = logging.getLogger("pentefino.api.evidence")

router = APIRouter(prefix="/api/v1/evidence", tags=["evidence"])


@router.get("/{evidence_id}", response_model=EvidenceItemSchema)
async def get_evidence_metadata(
    evidence_id: str,
    session: AsyncSession = Depends(get_db_session),
) -> EvidenceItemSchema:
    """Retrieve metadata record for a forensic evidence artifact."""
    try:
        eid = uuid.UUID(evidence_id.strip())
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid evidence UUID '{evidence_id}'.",
        ) from exc

    stmt = select(Evidence).where(Evidence.id == eid)
    res = await session.execute(stmt)
    evidence = res.scalar_one_or_none()
    if not evidence:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence artifact '{evidence_id}' not found.",
        )

    return EvidenceItemSchema(
        id=str(evidence.id),
        finding_id=str(evidence.finding_id),
        run_id=str(evidence.run_id),
        evidence_type=evidence.evidence_type,
        original_sha256=evidence.original_sha256.strip() if evidence.original_sha256 else None,
        sanitized_sha256=evidence.sanitized_sha256.strip(),
        seaweed_object_key=evidence.seaweed_object_key,
        redaction_profile=evidence.redaction_profile,
        created_at=evidence.created_at.isoformat() if evidence.created_at else "",
    )


@router.get("/{evidence_id}/blob")
async def get_evidence_blob(
    evidence_id: str,
    session: AsyncSession = Depends(get_db_session),
) -> StreamingResponse:
    """
    Stream raw forensic evidence artifact blob from SeaweedFS S3 storage.
    Validates existence in PostgreSQL and provides SHA-256 verification headers.
    """
    try:
        eid = uuid.UUID(evidence_id.strip())
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid evidence UUID '{evidence_id}'.",
        ) from exc

    stmt = select(Evidence).where(Evidence.id == eid)
    res = await session.execute(stmt)
    evidence = res.scalar_one_or_none()
    if not evidence:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence artifact '{evidence_id}' not found.",
        )

    s3_client = S3EvidenceClient()
    try:
        blob_bytes = s3_client.get_evidence(evidence.seaweed_object_key)
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence artifact blob '{evidence.seaweed_object_key}' not found in storage.",
        )
    except ClientError as ce:
        err_code = ce.response.get("Error", {}).get("Code", "")
        if err_code in ("404", "NoSuchKey"):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Evidence artifact blob '{evidence.seaweed_object_key}' not found in S3 storage.",
            ) from ce
        logger.error("S3 storage ClientError retrieving evidence %s: %s", evidence.id, ce)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Storage service error while retrieving evidence artifact: {str(ce)}",
        ) from ce
    except Exception as exc:
        logger.error("Failed to retrieve evidence blob %s: %s", evidence.id, exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to retrieve evidence blob from storage: {str(exc)}",
        ) from exc

    sanitized_sha = evidence.sanitized_sha256.strip()
    ext = "bin"
    content_type = "application/octet-stream"

    if evidence.evidence_type in ("http_interaction", "fingerprint", "dns") or evidence.seaweed_object_key.endswith(".json"):
        content_type = "application/json"
        ext = "json"
    elif evidence.seaweed_object_key.endswith(".txt"):
        content_type = "text/plain; charset=utf-8"
        ext = "txt"

    filename = f"evidence_{sanitized_sha[:12]}.{ext}"
    headers = {
        "Content-Disposition": f'inline; filename="{filename}"',
        "Content-Type": content_type,
        "X-Content-SHA256": sanitized_sha,
        "X-PenteFino-Sanitized-SHA256": sanitized_sha,
        "X-PenteFino-Evidence-Type": evidence.evidence_type,
        "ETag": f'"{sanitized_sha}"',
    }
    if evidence.original_sha256:
        headers["X-PenteFino-Original-SHA256"] = evidence.original_sha256.strip()

    return StreamingResponse(
        io.BytesIO(blob_bytes),
        media_type=content_type,
        headers=headers,
    )
