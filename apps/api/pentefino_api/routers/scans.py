from __future__ import annotations

import urllib.parse

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pentefino_api.deps import get_db_session, get_program_or_404, record_api_audit
from pentefino_api.routers.ws import scan_hub
from pentefino_api.schemas import (
    ScanHistoryItem,
    ScanPlanRequest,
    ScanPlanResponse,
    ScanRunRequest,
    ScanRunResponse,
    SelectedTemplateItem,
)
from pentefino_detection import (
    DetectionPlan,
    DetectionPlanner,
    FindingNormalizer,
    HardenedNucleiRunner,
)
from pentefino_detection.planner import EDGE_CDN_WAF_TAGS
from pentefino_domain.enums import ImpactClass
from pentefino_domain.models.asset import Asset
from pentefino_domain.models.audit import AuditEvent
from pentefino_domain.models.observation import Observation
from pentefino_domain.models.template import TemplateCatalog
from pentefino_runner import EphemeralRunner

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])


def _clean_asset_key(raw_key: str) -> str:
    clean = raw_key.strip().lower()
    if "://" in clean:
        clean = urllib.parse.urlsplit(clean).netloc or clean
    return clean


async def _resolve_asset_and_techs(
    session: AsyncSession, program_id: object, asset_key: str
) -> tuple[Asset, list[str], list[str]]:
    clean_key = _clean_asset_key(asset_key)
    stmt = select(Asset).where(
        Asset.program_id == program_id,
        Asset.canonical_key == clean_key,
    )
    res = await session.execute(stmt)
    target_asset = res.scalar_one_or_none()
    if not target_asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset '{clean_key}' not found in program.",
        )

    obs_stmt = select(Observation).where(
        Observation.asset_id == target_asset.id,
        Observation.observation_type.in_(["http_probe", "http"]),
    )
    obs_res = await session.execute(obs_stmt)
    observations = obs_res.scalars().all()

    raw_techs: set[str] = set()
    for obs in observations:
        if isinstance(obs.metadata_json, dict):
            for t in obs.metadata_json.get("technologies") or []:
                if t and str(t).strip():
                    raw_techs.add(str(t).strip().lower())

    sorted_raw = sorted(raw_techs)
    pruned = sorted([t for t in sorted_raw if t in EDGE_CDN_WAF_TAGS])
    return target_asset, sorted_raw, pruned


@router.post("/plan", response_model=ScanPlanResponse)
async def create_scan_plan(
    payload: ScanPlanRequest,
    session: AsyncSession = Depends(get_db_session),
) -> ScanPlanResponse:
    """Generate a dry-run DetectionPlan showing CDN tag pruning and safe template selection."""
    prog = await get_program_or_404(session, payload.program_slug)
    target_asset, raw_techs, pruned_tags = await _resolve_asset_and_techs(
        session, prog.id, payload.asset_key
    )

    planner = DetectionPlanner(db_session=session)
    plan: DetectionPlan = await planner.create_plan(
        asset=target_asset,
        detected_technologies=raw_techs,
        severity_filter=payload.severity,
        tag_filter=payload.tags,
        max_impact_class=ImpactClass.SAFE_READ_ONLY,
    )

    selected_items: list[SelectedTemplateItem] = []
    if plan.selected_template_ids:
        tpl_stmt = (
            select(TemplateCatalog)
            .where(TemplateCatalog.id.in_(plan.selected_template_ids))
            .order_by(TemplateCatalog.id.asc())
        )
        tpl_res = await session.execute(tpl_stmt)
        for t in tpl_res.scalars().all():
            selected_items.append(
                SelectedTemplateItem(
                    id=t.id,
                    name=t.name,
                    severity=t.severity or "info",
                    impact_class=t.impact_class,
                    cve_id=t.cve_id,
                    technologies=list(t.technologies or []),
                )
            )

    return ScanPlanResponse(
        plan_id=str(plan.plan_id),
        program_slug=prog.slug,
        asset_key=target_asset.canonical_key,
        target_url=plan.target_url,
        raw_detected_technologies=raw_techs,
        pruned_edge_tags=pruned_tags,
        matched_technologies=plan.matched_technologies,
        total_templates=plan.total_templates,
        selected_templates=selected_items,
    )


@router.post("/run", response_model=ScanRunResponse)
async def run_scan(
    payload: ScanRunRequest,
    session: AsyncSession = Depends(get_db_session),
) -> ScanRunResponse:
    """Plan and execute a hardened scan with WebSocket progress telemetry and graceful Docker fallback."""
    prog = await get_program_or_404(session, payload.program_slug)
    target_asset, raw_techs, pruned_tags = await _resolve_asset_and_techs(
        session, prog.id, payload.asset_key
    )

    planner = DetectionPlanner(db_session=session)
    plan: DetectionPlan = await planner.create_plan(
        asset=target_asset,
        detected_technologies=raw_techs,
        severity_filter=payload.severity,
        tag_filter=payload.tags,
        max_impact_class=ImpactClass.SAFE_READ_ONLY,
    )
    plan_id_str = str(plan.plan_id)

    await scan_hub.broadcast(
        plan_id_str,
        {
            "event": "plan_created",
            "stage": "DetectionPlanner",
            "asset_key": target_asset.canonical_key,
            "raw_detected_technologies": raw_techs,
            "pruned_edge_tags": pruned_tags,
            "matched_technologies": plan.matched_technologies,
            "total_templates": plan.total_templates,
            "progress": 25,
        },
    )

    requested_mode = (payload.mode or "auto").strip().lower()
    persisted_findings_data: list[dict[str, object]] = []
    status_str = "dry_run_completed"
    mode_executed = "dry_run"
    msg = (
        f"Dry-run scan plan completed with {plan.total_templates} safe_read_only templates."
    )

    if requested_mode == "auto":
        await scan_hub.broadcast(
            plan_id_str,
            {
                "event": "runner_starting",
                "stage": "HardenedNucleiRunner",
                "message": "Dispatching ephemeral hardened Nuclei container via egress proxy guard.",
                "progress": 50,
            },
        )
        try:
            runner = EphemeralRunner()
            nuclei_runner = HardenedNucleiRunner(runner=runner)
            raw_findings = await nuclei_runner.execute_scan(plan=plan)

            normalizer = FindingNormalizer(db_session=session)
            persisted = await normalizer.normalize_and_persist(
                raw_nuclei_results=raw_findings,
                program_id=prog.id,
                asset_id=target_asset.id,
                run_id=plan.plan_id,
            )
            persisted_findings_data = [
                {
                    "id": str(f.id),
                    "dedup_key": f.dedup_key,
                    "detector_id": f.detector_id,
                    "advisory_id": f.advisory_id,
                    "status": f.status,
                    "evidence_level": f.evidence_level,
                    "confidence": f.confidence,
                }
                for f in persisted
            ]
            status_str = "completed"
            mode_executed = "container"
            msg = (
                f"Executed {plan.total_templates} templates in isolated container; "
                f"{len(persisted_findings_data)} finding(s) persisted."
            )
        except Exception as exc:
            status_str = "dry_run_completed"
            mode_executed = "dry_run_fallback"
            msg = (
                f"Docker runtime unavailable or restricted ({type(exc).__name__}); "
                f"gracefully completed in dry-run mode with {plan.total_templates} planned templates."
            )

    await scan_hub.broadcast(
        plan_id_str,
        {
            "event": "scan_finished",
            "stage": "Complete",
            "status": status_str,
            "mode_executed": mode_executed,
            "total_templates": plan.total_templates,
            "findings_count": len(persisted_findings_data),
            "message": msg,
            "progress": 100,
        },
    )

    await record_api_audit(
        session=session,
        event_type="api.scan.run",
        object_type="scan_run",
        object_id=plan.plan_id,
        payload={
            "program_slug": prog.slug,
            "asset_key": target_asset.canonical_key,
            "status": status_str,
            "mode_executed": mode_executed,
            "total_templates": plan.total_templates,
            "pruned_edge_tags": pruned_tags,
            "matched_technologies": plan.matched_technologies,
            "findings_count": len(persisted_findings_data),
        },
    )

    return ScanRunResponse(
        plan_id=plan_id_str,
        program_slug=prog.slug,
        asset_key=target_asset.canonical_key,
        target_url=plan.target_url,
        status=status_str,
        mode_executed=mode_executed,
        raw_detected_technologies=raw_techs,
        pruned_edge_tags=pruned_tags,
        matched_technologies=plan.matched_technologies,
        total_templates=plan.total_templates,
        findings_count=len(persisted_findings_data),
        findings=persisted_findings_data,
        message=msg,
    )


@router.get("/history", response_model=list[ScanHistoryItem])
async def get_scan_history(
    limit: int = Query(50, ge=1, le=200),
    session: AsyncSession = Depends(get_db_session),
) -> list[ScanHistoryItem]:
    """Return recent scan, recon, and governance audit events ordered by timestamp DESC."""
    stmt = (
        select(AuditEvent)
        .order_by(AuditEvent.occurred_at.desc(), AuditEvent.sequence.desc())
        .limit(limit)
    )
    res = await session.execute(stmt)
    events = res.scalars().all()

    return [
        ScanHistoryItem(
            sequence=ev.sequence,
            actor=ev.actor,
            event_type=ev.event_type,
            object_type=ev.object_type,
            object_id=ev.object_id,
            payload=ev.payload if isinstance(ev.payload, dict) else {},
            occurred_at=ev.occurred_at.isoformat(),
            timestamp=ev.occurred_at.isoformat(),
        )
        for ev in events
    ]
