from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import any_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from pentefino_api.deps import get_db_session
from pentefino_api.schemas import (
    TemplateDetailResponse,
    TemplateListResponse,
    TemplateStatsResponse,
    TemplateSummaryItem,
)
from pentefino_domain.models.template import TemplateCatalog

router = APIRouter(prefix="/api/v1/templates", tags=["templates"])


@router.get("/stats", response_model=TemplateStatsResponse)
async def get_template_stats(
    session: AsyncSession = Depends(get_db_session),
) -> TemplateStatsResponse:
    """Return total template count, counts grouped by impact_class, and counts grouped by severity."""
    total_stmt = select(func.count()).select_from(TemplateCatalog)
    total_res = await session.execute(total_stmt)
    total = int(total_res.scalar_one() or 0)

    impact_stmt = select(
        TemplateCatalog.impact_class, func.count()
    ).group_by(TemplateCatalog.impact_class)
    impact_res = await session.execute(impact_stmt)
    by_impact_class = {
        str(row[0] or "unknown"): int(row[1]) for row in impact_res.all()
    }

    sev_stmt = select(
        TemplateCatalog.severity, func.count()
    ).group_by(TemplateCatalog.severity)
    sev_res = await session.execute(sev_stmt)
    by_severity = {
        str(row[0] or "info").lower(): int(row[1]) for row in sev_res.all()
    }

    return TemplateStatsResponse(
        total=total,
        by_impact_class=by_impact_class,
        by_severity=by_severity,
    )


@router.get("", response_model=TemplateListResponse)
async def list_templates(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    page: Optional[int] = Query(None, ge=1, description="1-based page index"),
    page_size: Optional[int] = Query(None, ge=1, le=500, description="Page size"),
    impact_class: Optional[str] = Query(None, description="Filter by impact_class"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    tech: Optional[str] = Query(None, description="Filter by technology or tag"),
    protocol: Optional[str] = Query(None, description="Filter by protocol"),
    q: Optional[str] = Query(None, description="Search query across ID, name, CVE"),
    session: AsyncSession = Depends(get_db_session),
) -> TemplateListResponse:
    """Paginated template catalog query using native SQL filtering."""
    effective_limit = page_size if page_size is not None else limit
    effective_page = page if page is not None else (offset // max(1, effective_limit)) + 1
    effective_offset = (page - 1) * effective_limit if page is not None else offset

    filters = []

    if impact_class:
        clean_impact = impact_class.strip().lower()
        filters.append(func.lower(TemplateCatalog.impact_class) == clean_impact)

    if severity:
        clean_sev = severity.strip().lower()
        filters.append(func.lower(TemplateCatalog.severity) == clean_sev)

    if protocol:
        clean_proto = protocol.strip().lower()
        filters.append(func.lower(TemplateCatalog.protocol) == clean_proto)

    if tech:
        clean_tech = tech.strip().lower()
        filters.append(
            (clean_tech == any_(TemplateCatalog.technologies))
            | (clean_tech == any_(TemplateCatalog.tags))
            | TemplateCatalog.id.ilike(f"%{clean_tech}%")
            | TemplateCatalog.name.ilike(f"%{clean_tech}%")
        )

    if q:
        clean_q = q.strip()
        filters.append(
            TemplateCatalog.id.ilike(f"%{clean_q}%")
            | TemplateCatalog.name.ilike(f"%{clean_q}%")
            | TemplateCatalog.cve_id.ilike(f"%{clean_q}%")
            | (clean_q.lower() == any_(TemplateCatalog.tags))
            | (clean_q.lower() == any_(TemplateCatalog.technologies))
        )

    count_stmt = select(func.count()).select_from(TemplateCatalog)
    if filters:
        count_stmt = count_stmt.where(*filters)
    count_res = await session.execute(count_stmt)
    total = int(count_res.scalar_one() or 0)

    stmt = select(TemplateCatalog)
    if filters:
        stmt = stmt.where(*filters)
    stmt = stmt.order_by(TemplateCatalog.id.asc()).offset(effective_offset).limit(effective_limit)

    res = await session.execute(stmt)
    templates = res.scalars().all()

    items = [
        TemplateSummaryItem(
            id=t.id,
            name=t.name,
            protocol=t.protocol,
            http_methods=list(t.http_methods) if t.http_methods else None,
            impact_class=t.impact_class,
            severity=t.severity or "info",
            cve_id=t.cve_id,
            cwe_id=t.cwe_id,
            technologies=list(t.technologies or []),
            tags=list(t.tags or []),
            upstream_revision=t.upstream_revision,
            bundle_hash=t.bundle_hash.strip(),
            raw_yaml=t.raw_yaml,
            updated_at=t.updated_at.isoformat() if t.updated_at else None,
        )
        for t in templates
    ]

    total_pages = max(1, (total + effective_limit - 1) // effective_limit)
    return TemplateListResponse(
        total=total,
        page=effective_page,
        page_size=effective_limit,
        total_pages=total_pages,
        items=items,
    )


@router.get("/{template_id:path}", response_model=TemplateDetailResponse)
async def get_template_detail(
    template_id: str,
    session: AsyncSession = Depends(get_db_session),
) -> TemplateDetailResponse:
    """Return full template metadata including raw_yaml and bundle_hash."""
    clean_id = template_id.strip()
    stmt = select(TemplateCatalog).where(TemplateCatalog.id == clean_id)
    res = await session.execute(stmt)
    template = res.scalar_one_or_none()

    if template is None:
        fallback_stmt = select(TemplateCatalog).where(
            func.lower(TemplateCatalog.id) == clean_id.lower()
        )
        fallback_res = await session.execute(fallback_stmt)
        template = fallback_res.scalar_one_or_none()

    if template is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Template '{clean_id}' not found.",
        )

    return TemplateDetailResponse(
        id=template.id,
        name=template.name,
        protocol=template.protocol,
        http_methods=list(template.http_methods) if template.http_methods else None,
        impact_class=template.impact_class,
        severity=template.severity or "info",
        cve_id=template.cve_id,
        cwe_id=template.cwe_id,
        technologies=list(template.technologies or []),
        tags=list(template.tags or []),
        upstream_revision=template.upstream_revision,
        bundle_hash=template.bundle_hash.strip(),
        raw_yaml=template.raw_yaml,
        updated_at=template.updated_at.isoformat() if template.updated_at else None,
    )
