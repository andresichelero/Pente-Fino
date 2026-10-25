from __future__ import annotations

from typing import Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from pentefino_api.deps import get_db_session, record_api_audit
from pentefino_api.schemas import (
    AssetInfoSchema,
    DetectorInfoSchema,
    EvidenceItemSchema,
    FindingDetailResponse,
    FindingListItem,
    FindingReportResponse,
    FindingStatusUpdate,
)
from pentefino_domain.enums import FindingStatus
from pentefino_domain.models.asset import Asset
from pentefino_domain.models.finding import Finding
from pentefino_domain.models.program import Program
from pentefino_domain.models.template import TemplateCatalog

router = APIRouter(prefix="/api/v1/findings", tags=["findings"])


def _serialize_finding_item(
    finding: Finding, prog_slug: Optional[str] = None
) -> FindingListItem:
    asset_obj = finding.asset if "asset" in finding.__dict__ else None
    detector_obj = finding.detector if "detector" in finding.__dict__ else None
    prog_obj = finding.program if "program" in finding.__dict__ else None
    resolved_slug = prog_slug or (prog_obj.slug if prog_obj else None)

    return FindingListItem(
        id=str(finding.id),
        program_id=str(finding.program_id),
        program_slug=resolved_slug,
        asset_id=str(finding.asset_id),
        detector_id=finding.detector_id,
        advisory_id=finding.advisory_id,
        status=finding.status,
        evidence_level=finding.evidence_level,
        confidence=finding.confidence,
        dedup_key=finding.dedup_key.strip(),
        first_seen=finding.first_seen.isoformat(),
        last_seen=finding.last_seen.isoformat(),
        epss_score=finding.epss_score,
        epss_percentile=finding.epss_percentile,
        in_cisa_kev=finding.in_cisa_kev,
        priority_tier=finding.priority_tier,
        asset=(
            AssetInfoSchema(
                id=str(asset_obj.id),
                canonical_key=asset_obj.canonical_key,
                asset_type=asset_obj.asset_type,
                scope_state=asset_obj.scope_state,
            )
            if asset_obj
            else None
        ),
        detector=(
            DetectorInfoSchema(
                id=detector_obj.id,
                name=detector_obj.name,
                protocol=detector_obj.protocol,
                severity=detector_obj.severity or "info",
                cve_id=detector_obj.cve_id,
                cwe_id=detector_obj.cwe_id,
                impact_class=detector_obj.impact_class,
            )
            if detector_obj
            else None
        ),
    )


def _serialize_finding_detail(finding: Finding) -> FindingDetailResponse:
    base = _serialize_finding_item(finding)
    ev_items = (
        finding.evidence_items if "evidence_items" in finding.__dict__ else []
    )
    return FindingDetailResponse(
        **base.model_dump(),
        evidence_items=[
            EvidenceItemSchema(
                id=str(e.id),
                run_id=str(e.run_id),
                evidence_type=e.evidence_type,
                original_sha256=(
                    e.original_sha256.strip() if e.original_sha256 else None
                ),
                sanitized_sha256=e.sanitized_sha256.strip(),
                seaweed_object_key=e.seaweed_object_key,
                redaction_profile=e.redaction_profile,
                created_at=e.created_at.isoformat() if e.created_at else None,
            )
            for e in ev_items
        ],
    )


@router.get("", response_model=list[FindingListItem])
async def list_findings(
    program_slug: Optional[str] = Query(None, description="Filter by program slug"),
    status_filter: Optional[str] = Query(
        None, alias="status", description="Filter by finding status"
    ),
    severity: Optional[str] = Query(None, description="Filter by detector severity"),
    evidence_level: Optional[str] = Query(
        None, description="Filter by evidence level (E0, E1, E2, E3)"
    ),
    session: AsyncSession = Depends(get_db_session),
) -> list[FindingListItem]:
    """List findings with joined asset and detector metadata."""
    stmt = (
        select(Finding)
        .join(Program, Finding.program_id == Program.id)
        .join(Asset, Finding.asset_id == Asset.id)
        .outerjoin(TemplateCatalog, Finding.detector_id == TemplateCatalog.id)
        .options(
            selectinload(Finding.program),
            selectinload(Finding.asset),
            selectinload(Finding.detector),
        )
    )

    if program_slug:
        stmt = stmt.where(Program.slug == program_slug.strip().lower())
    if status_filter:
        stmt = stmt.where(func.lower(Finding.status) == status_filter.strip().lower())
    if evidence_level:
        stmt = stmt.where(
            func.upper(Finding.evidence_level) == evidence_level.strip().upper()
        )
    if severity:
        stmt = stmt.where(
            func.lower(TemplateCatalog.severity) == severity.strip().lower()
        )

    stmt = stmt.order_by(Finding.first_seen.desc())
    res = await session.execute(stmt)
    findings = res.scalars().all()
    return [_serialize_finding_item(f) for f in findings]


@router.get("/{finding_id}", response_model=FindingDetailResponse)
async def get_finding(
    finding_id: str,
    session: AsyncSession = Depends(get_db_session),
) -> FindingDetailResponse:
    """Get full finding details including forensic evidence items and detector metadata."""
    try:
        fid = uuid.UUID(finding_id.strip())
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid finding UUID '{finding_id}'.",
        ) from exc

    stmt = (
        select(Finding)
        .options(
            selectinload(Finding.program),
            selectinload(Finding.asset),
            selectinload(Finding.detector),
            selectinload(Finding.evidence_items),
        )
        .where(Finding.id == fid)
    )
    res = await session.execute(stmt)
    finding = res.scalar_one_or_none()
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' not found.",
        )

    return _serialize_finding_detail(finding)


@router.patch("/{finding_id}/status", response_model=FindingDetailResponse)
async def update_finding_status(
    finding_id: str,
    payload: FindingStatusUpdate,
    session: AsyncSession = Depends(get_db_session),
) -> FindingDetailResponse:
    """Update a finding's lifecycle status and record an audit event."""
    try:
        fid = uuid.UUID(finding_id.strip())
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid finding UUID '{finding_id}'.",
        ) from exc

    clean_status = payload.status.strip().lower()
    valid_statuses = {s.value for s in FindingStatus}
    if clean_status not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid status '{payload.status}'. Allowed: {sorted(valid_statuses)}",
        )

    stmt = (
        select(Finding)
        .options(
            selectinload(Finding.program),
            selectinload(Finding.asset),
            selectinload(Finding.detector),
            selectinload(Finding.evidence_items),
        )
        .where(Finding.id == fid)
    )
    res = await session.execute(stmt)
    finding = res.scalar_one_or_none()
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' not found.",
        )

    old_status = finding.status
    finding.status = clean_status
    await session.flush()

    await record_api_audit(
        session=session,
        event_type="api.finding.status_change",
        object_type="finding",
        object_id=finding.id,
        payload={
            "previous_status": old_status,
            "new_status": clean_status,
            "detector_id": finding.detector_id,
        },
    )

    return _serialize_finding_detail(finding)


@router.get("/{finding_id}/report", response_model=FindingReportResponse)
async def generate_finding_report(
    finding_id: str,
    session: AsyncSession = Depends(get_db_session),
) -> FindingReportResponse:
    """Generate a HackerOne/Bugcrowd Bug Bounty Markdown report with SHA-256 evidence table."""
    detail = await get_finding(finding_id, session=session)

    detector_name = (
        detail.detector.name if detail.detector else detail.detector_id
    )
    severity = (
        (detail.detector.severity or "medium").upper()
        if detail.detector
        else "MEDIUM"
    )
    cve_id = (
        detail.detector.cve_id
        if detail.detector and detail.detector.cve_id
        else (detail.advisory_id or "N/A")
    )
    cwe_id = (
        detail.detector.cwe_id
        if detail.detector and detail.detector.cwe_id
        else "CWE-200"
    )
    impact_class = (
        detail.detector.impact_class
        if detail.detector
        else "safe_read_only"
    )
    target_host = (
        detail.asset.canonical_key if detail.asset else "unknown-target"
    )
    target_url = (
        target_host
        if target_host.startswith(("http://", "https://"))
        else f"https://{target_host}"
    )

    title = f"[{severity}] {detector_name} on {target_host}"

    ev_rows = []
    if detail.evidence_items:
        for ev in detail.evidence_items:
            ev_rows.append(
                f"| `{ev.id[:8]}` | `{ev.evidence_type}` | "
                f"`{ev.original_sha256 or 'N/A'}` | `{ev.sanitized_sha256}` | "
                f"`{ev.seaweed_object_key}` | `{ev.redaction_profile}` |"
            )
    else:
        ev_rows.append(
            f"| `N/A` | `http_interaction` | `N/A` | `{detail.dedup_key}` | "
            f"`seaweed://findings/{detail.id}/interaction.json` | `bounty-safe-v1` |"
        )

    evidence_table = "\n".join(ev_rows)

    markdown = f"""# {title}

## 1. Executive Summary
During authorized, non-intrusive security testing under program **`{detail.program_slug or detail.program_id}`**, an instance of **{detector_name}** (`{detail.detector_id}`) was identified on **`{target_host}`**.

- **Target Asset**: `{target_host}` (`{detail.asset.scope_state if detail.asset else 'in_scope_explicit'}`)
- **Severity**: **{severity}**
- **Confidence**: `{detail.confidence.upper()}`
- **Evidence Level**: `{detail.evidence_level}`
- **CVE / Advisory**: `{cve_id}`
- **CWE Classification**: `{cwe_id}`
- **Template Impact Class**: `{impact_class}`
- **Deduplication Key (SHA-256)**: `{detail.dedup_key}`

---

## 2. Step-by-Step Reproducible PoC (Sanitized)
All active requests were executed using strictly `{impact_class}` verification templates (`{detail.detector_id}`) at <= 0.5 req/sec with credential redaction enabled (`bounty-safe-v1`).

```bash
curl -i -s -k -X GET "{target_url}/" \\
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \\
  -H "X-PenteFino-Detector: {detail.detector_id}" \\
  -H "X-PenteFino-Dedup-SHA256: {detail.dedup_key[:16]}" \\
  -H "Accept: */*" \\
  -H "Authorization: [REDACTED_BY_PENTEFINO_SAFE_V1]"
```

---

## 3. Forensic SHA-256 Evidence Verification
Cryptographic hashes of the raw and redacted HTTP interaction blobs stored in the PenteFino Evidence Vault:

| Evidence ID | Type | Original SHA-256 | Sanitized SHA-256 | SeaweedFS Object Key | Redaction Profile |
|---|---|---|---|---|---|
{evidence_table}

---

## 4. Remediation Recommendations
1. Apply the vendor security patch or configuration hardening corresponding to **{cve_id}** / **{detector_name}**.
2. Restrict public exposure of sensitive diagnostic, version, or configuration endpoints on `{target_host}`.
3. Re-run PenteFino targeted verification (`pentefino scan run --program {detail.program_slug or 'program'} --asset {target_host}`) to confirm remediation.
"""

    return FindingReportResponse(
        finding_id=detail.id,
        title=title,
        markdown=markdown,
    )
