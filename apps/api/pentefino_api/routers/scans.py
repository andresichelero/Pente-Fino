from __future__ import annotations

import urllib.parse
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pentefino_api.deps import get_db_session, get_program_or_404, record_api_audit
from pentefino_api.real_tools import run_real_nuclei
from pentefino_api.routers.ws import scan_hub
from pentefino_api.schemas import (
    BatchScanAssetSummary,
    BatchScanRequest,
    BatchScanResponse,
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
        import ipaddress
        raw_val = clean_key.split(":")[0]
        try:
            ipaddress.ip_address(raw_val)
            atype = "ip"
        except ValueError:
            atype = "domain" if "." in raw_val else "hostname"

        target_asset = Asset(
            program_id=program_id,
            canonical_key=clean_key,
            asset_type=atype,
            scope_state="in_scope_explicit",
        )
        session.add(target_asset)
        await session.flush()
        await session.refresh(target_asset)

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

    if target_asset.scope_state not in ("in_scope_explicit", "in_scope_derived"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Hard-Gate Fail-Closed: Asset '{target_asset.canonical_key}' has scope_state="
                f"'{target_asset.scope_state}' and cannot be actively scanned."
            ),
        )

    planner = DetectionPlanner(db_session=session)
    plan: DetectionPlan = await planner.create_plan(
        asset=target_asset,
        detected_technologies=raw_techs,
        severity_filter=payload.severity,
        tag_filter=payload.tags,
        max_impact_class=ImpactClass.SAFE_READ_ONLY,
    )
    if payload.plan_id:
        try:
            import uuid as _uuid
            plan.plan_id = _uuid.UUID(str(payload.plan_id).strip())
        except Exception:
            pass
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
        async def _live_nuclei_cb(tool: str, line: str):
            try:
                await scan_hub.broadcast(
                    plan_id_str,
                    {
                        "event": "tool_output",
                        "tool": "NUCLEI",
                        "line": line,
                        "message": line,
                    },
                )
            except Exception:
                pass

        try:
            target_url = (
                target_asset.canonical_key
                if "://" in target_asset.canonical_key
                else f"https://{target_asset.canonical_key}"
            )
            raw_findings = await run_real_nuclei(
                target_url=target_url,
                template_ids=plan.selected_template_ids,
                rate_limit=10,
                broadcast_cb=_live_nuclei_cb,
            )

            if not raw_findings:
                # Fallback to ephemeral runner if real nuclei found nothing
                try:
                    runner = EphemeralRunner()
                    nuclei_runner = HardenedNucleiRunner(runner=runner, rate_limit=10)
                    raw_findings = await nuclei_runner.execute_scan(plan=plan)
                except Exception:
                    pass

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
            mode_executed = "real_cli"
            msg = (
                f"Executados {plan.total_templates} templates de detecção cirúrgica; "
                f"{len(persisted_findings_data)} falha(s) identificada(s)."
            )
        except Exception as exc:
            status_str = "dry_run_completed"
            mode_executed = "dry_run_fallback"
            msg = (
                f"Runtime de varredura indisponível ({type(exc).__name__}); "
                f"concluído em modo de simulação com {plan.total_templates} templates."
            )
    elif requested_mode in ("async", "queue", "queued"):
        from pentefino_worker.publisher import default_publisher

        pub_res = await default_publisher.publish_scan_task(
            program_slug=prog.slug,
            target_asset=target_asset.canonical_key,
            severity=payload.severity,
            tags=payload.tags,
            run_id=plan.plan_id,
        )
        status_str = "queued"
        mode_executed = "amqp_worker"
        msg = (
            f"Scan job queued in AMQP broker (run_id={plan_id_str})."
            if pub_res.get("broker_published")
            else f"Scan job queued with fallback (run_id={plan_id_str})."
        )
        await scan_hub.broadcast(
            plan_id_str,
            {
                "event": "scan_queued",
                "stage": "AmqpBroker",
                "status": "queued",
                "run_id": plan_id_str,
                "message": msg,
                "progress": 10,
            },
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


@router.post("/batch-run", response_model=BatchScanResponse)
async def run_batch_scans(
    payload: BatchScanRequest,
    session: AsyncSession = Depends(get_db_session),
) -> BatchScanResponse:
    """Executes surgical technology-matched Nuclei scans across all in-scope assets discovered in a program."""
    prog = await get_program_or_404(session, payload.program_slug)

    # 1. Fetch all in-scope assets for program
    stmt = (
        select(Asset)
        .where(
            Asset.program_id == prog.id,
            Asset.scope_state.in_(["in_scope_explicit", "in_scope_derived"]),
        )
        .limit(payload.max_assets)
    )
    in_scope_assets = (await session.execute(stmt)).scalars().all()

    if not in_scope_assets:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"No authorized in-scope assets found for program '{payload.program_slug}'. Run reconnaissance first.",
        )

    batch_run_id = f"batch-{uuid.uuid4().hex[:8]}"
    planner = DetectionPlanner(db_session=session)
    runner = EphemeralRunner()
    nuclei_runner = HardenedNucleiRunner(runner=runner, rate_limit=payload.rate_limit)
    normalizer = FindingNormalizer(db_session=session)

    asset_summaries: list[BatchScanAssetSummary] = []
    total_templates_executed = 0
    total_findings_discovered = 0

    await scan_hub.broadcast(
        batch_run_id,
        {
            "event": "batch_scan_started",
            "message": f"Iniciando varredura cirúrgica em lote para {len(in_scope_assets)} ativos em escopo (rate_limit: {payload.rate_limit} req/s)...",
            "total_assets": len(in_scope_assets),
            "progress": 5,
        },
    )

    for idx, asset in enumerate(in_scope_assets):
        target_asset, raw_techs, pruned_tags = await _resolve_asset_and_techs(
            session, prog.id, asset.canonical_key
        )
        plan = await planner.create_plan(
            asset=target_asset,
            detected_technologies=raw_techs,
            severity_filter=payload.severity,
            tag_filter=payload.tags,
            max_impact_class=ImpactClass.SAFE_READ_ONLY,
        )

        progress_pct = int(5 + ((idx + 1) / len(in_scope_assets)) * 90)

        # Surgical skip if no matching templates for this endpoint
        if plan.total_templates == 0:
            asset_summaries.append(
                BatchScanAssetSummary(
                    asset_key=asset.canonical_key,
                    matched_technologies=[],
                    total_templates=0,
                    findings_count=0,
                    status="skipped_no_matching_tech",
                )
            )
            continue

        total_templates_executed += plan.total_templates
        findings_count = 0
        status_val = "completed"

        if payload.mode == "auto":
            async def _live_batch_nuclei_cb(tool: str, line: str):
                try:
                    await scan_hub.broadcast(
                        batch_run_id,
                        {
                            "event": "tool_output",
                            "tool": "NUCLEI",
                            "line": line,
                            "message": line,
                        },
                    )
                except Exception:
                    pass

            try:
                target_url = (
                    asset.canonical_key
                    if "://" in asset.canonical_key
                    else f"https://{asset.canonical_key}"
                )
                raw_findings = await run_real_nuclei(
                    target_url=target_url,
                    template_ids=plan.selected_template_ids,
                    rate_limit=payload.rate_limit,
                    broadcast_cb=_live_batch_nuclei_cb,
                )
                if not raw_findings:
                    try:
                        raw_findings = await nuclei_runner.execute_scan(
                            plan=plan, rate_limit=payload.rate_limit
                        )
                    except Exception:
                        pass

                if raw_findings:
                    persisted = await normalizer.normalize_and_persist(
                        raw_nuclei_results=raw_findings,
                        program_id=prog.id,
                        asset_id=target_asset.id,
                        run_id=plan.plan_id,
                    )
                    findings_count = len(persisted)
                    total_findings_discovered += findings_count
            except Exception:
                status_val = "dry_run_fallback"

        asset_summaries.append(
            BatchScanAssetSummary(
                asset_key=asset.canonical_key,
                matched_technologies=plan.matched_technologies,
                total_templates=plan.total_templates,
                findings_count=findings_count,
                status=status_val,
            )
        )

        await scan_hub.broadcast(
            batch_run_id,
            {
                "event": "batch_asset_scanned",
                "asset_key": asset.canonical_key,
                "matched_technologies": plan.matched_technologies,
                "templates_count": plan.total_templates,
                "findings_count": findings_count,
                "progress": progress_pct,
            },
        )

    await record_api_audit(
        session=session,
        event_type="api.scan.batch_run",
        object_type="batch_scan",
        object_id=batch_run_id,
        payload={
            "program_slug": prog.slug,
            "assets_count": len(in_scope_assets),
            "templates_executed": total_templates_executed,
            "findings_discovered": total_findings_discovered,
            "rate_limit": payload.rate_limit,
        },
    )

    msg = (
        f"Varredura cirúrgica concluída para {len(in_scope_assets)} ativos em escopo: "
        f"{total_templates_executed} templates executadas, {total_findings_discovered} falha(s) identificada(s)."
    )

    await scan_hub.broadcast(
        batch_run_id,
        {
            "event": "batch_scan_completed",
            "message": msg,
            "progress": 100,
        },
    )

    return BatchScanResponse(
        program_slug=prog.slug,
        total_assets_scanned=len(in_scope_assets),
        total_templates_executed=total_templates_executed,
        total_findings_discovered=total_findings_discovered,
        rate_limit_enforced=f"{payload.rate_limit} req/s",
        assets=asset_summaries,
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


@router.post("/{run_id}/cancel", status_code=status.HTTP_200_OK)
async def cancel_scan(
    run_id: str,
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """Deterministically terminate and cancel an ephemeral scan run on-demand."""
    from pentefino_worker.cancellation import default_container_registry

    clean_run_id = str(run_id).strip()
    try:
        parsed_uuid = uuid.UUID(clean_run_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid UUID format: '{clean_run_id}'",
        )

    # 1. Trigger cancellation locally and broadcast via Valkey
    await default_container_registry.broadcast_cancel(clean_run_id)

    # 2. Record API audit event
    await record_api_audit(
        session=session,
        event_type="api.scan.cancel",
        object_type="scan_run",
        object_id=parsed_uuid,
        payload={"status": "cancelled", "run_id": clean_run_id},
    )

    # 3. Broadcast to WebSocket telemetry hub
    await scan_hub.broadcast(
        clean_run_id,
        {
            "event": "scan_cancelled",
            "stage": "Cancellation",
            "status": "cancelled",
            "run_id": clean_run_id,
            "message": f"Scan run {clean_run_id} was cancelled by operator request.",
            "progress": 100,
        },
    )

    return {
        "status": "cancelled",
        "run_id": clean_run_id,
        "message": f"Cancellation signal dispatched for scan run {clean_run_id}.",
    }

