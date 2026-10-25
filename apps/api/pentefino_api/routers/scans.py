from __future__ import annotations

import asyncio
import logging
import re
import urllib.parse
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pentefino_api.activity import activity
from pentefino_api.deps import get_db_session, get_program_or_404, record_api_audit
from pentefino_api.real_tools import UnsafeScanRequest, run_real_nuclei
from pentefino_api.scope_loader import evaluate_and_count, load_program_scope_engine
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
    SentinelDomainResetRequest,
    SentinelStatusResponse,
)
from pentefino_api.target_sentinel import (
    circuit_breaker,
    probe_domain_l7_canary,
)
from pentefino_domain.session import get_async_session
from pentefino_detection import (
    DetectionPlan,
    DetectionPlanner,
    FindingNormalizer,
    HardenedNucleiRunner,
)
from pentefino_detection.planner import EDGE_CDN_WAF_TAGS
from pentefino_domain.enums import ImpactClass, ScopeState
from pentefino_domain.models.asset import Asset
from pentefino_domain.models.audit import AuditEvent
from pentefino_domain.models.observation import Observation
from pentefino_domain.models.program import Program
from pentefino_domain.models.template import TemplateCatalog
from pentefino_runner import EphemeralRunner
from pentefino_scope.enums import PrecedenceTier

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])


def _clean_asset_key(raw_key: str) -> str:
    clean = raw_key.strip().lower()
    if "://" in clean:
        clean = urllib.parse.urlsplit(clean).netloc or clean
    return clean


async def _resolve_asset_and_techs(
    session: AsyncSession, prog: Program, asset_key: str
) -> tuple[Asset, list[str], list[str]]:
    """Look up (or register) the asset, re-checking scope with the program's engine every time.

    The scope decision is never taken from the stored `scope_state` alone: rules or the
    authorization snapshot may have changed since the asset was recorded.
    """
    clean_key = _clean_asset_key(asset_key)
    engine = await load_program_scope_engine(session, prog)
    decision = evaluate_and_count(engine, clean_key)
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Hard-Gate Fail-Closed: '{clean_key}' denied by scope engine "
                f"({decision.matched_tier.value}: {decision.reason})."
            ),
        )
    scope_state = (
        ScopeState.IN_SCOPE_EXPLICIT.value
        if decision.matched_tier == PrecedenceTier.EXPLICIT_ALLOW
        else ScopeState.IN_SCOPE_DERIVED.value
    )

    stmt = select(Asset).where(
        Asset.program_id == prog.id,
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
            program_id=prog.id,
            canonical_key=clean_key,
            asset_type=atype,
            scope_state=scope_state,
        )
        session.add(target_asset)
        await session.flush()
        await session.refresh(target_asset)
    elif target_asset.scope_state != scope_state:
        target_asset.scope_state = scope_state

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
        session, prog, payload.asset_key
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
        session, prog, payload.asset_key
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

    if requested_mode == "auto" and not plan.selected_template_ids:
        status_str = "skipped_no_templates"
        mode_executed = "not_executed"
        msg = (
            "Nenhum template safe_read_only corresponde às tecnologias do ativo; "
            "nuclei não foi executado."
        )
    elif requested_mode == "auto":
        await scan_hub.broadcast(
            plan_id_str,
            {
                "event": "runner_starting",
                "stage": "NucleiCLI",
                "message": "Dispatching nuclei with the planner's safe_read_only allowlist.",
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

        activity.start(plan_id_str, "scan", prog.slug, target_asset.canonical_key)
        try:
            target_url = (
                target_asset.canonical_key
                if "://" in target_asset.canonical_key
                else f"https://{target_asset.canonical_key}"
            )
            try:
                raw_findings = await run_real_nuclei(
                    target_url=target_url,
                    template_ids=plan.selected_template_ids,
                    rate_limit=10,
                    broadcast_cb=_live_nuclei_cb,
                    run_id=plan_id_str,
                )
            except FileNotFoundError:
                # nuclei CLI missing on host/WSL: use the hardened container runner instead.
                runner = EphemeralRunner()
                nuclei_runner = HardenedNucleiRunner(runner=runner, rate_limit=10)
                raw_findings = await nuclei_runner.execute_scan(plan=plan)

            if activity.is_cancelled(plan_id_str):
                raise asyncio.CancelledError()

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
                f"Executados {min(plan.total_templates, 20)} templates de detecção cirúrgica; "
                f"{len(persisted_findings_data)} falha(s) identificada(s)."
            )
        except asyncio.CancelledError:
            status_str = "cancelled"
            mode_executed = "real_cli"
            msg = "Varredura cancelada pelo operador."
        except UnsafeScanRequest as exc:
            status_str = "refused"
            mode_executed = "not_executed"
            msg = f"Varredura recusada: {exc}"
        except Exception as exc:
            logger.exception("Scan %s failed", plan_id_str)
            status_str = "failed"
            mode_executed = "not_executed"
            msg = (
                f"Runtime de varredura indisponível ({type(exc).__name__}: {exc}); "
                "nenhum template foi executado."
            )
        finally:
            activity.finish(plan_id_str)
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

    # Re-check every stored asset against the current rules before any packet is sent
    # (the L7 canary below already talks to the target).
    engine = await load_program_scope_engine(session, prog)
    denied_summaries: list[BatchScanAssetSummary] = []
    allowed_assets: list[Asset] = []
    for a in in_scope_assets:
        if evaluate_and_count(engine, a.canonical_key).allowed:
            allowed_assets.append(a)
        else:
            denied_summaries.append(
                BatchScanAssetSummary(
                    asset_key=a.canonical_key,
                    matched_technologies=[],
                    total_templates=0,
                    findings_count=0,
                    status="denied_by_scope",
                )
            )
    in_scope_assets = allowed_assets

    if not in_scope_assets:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"No authorized in-scope assets found for program '{payload.program_slug}'. Run reconnaissance first.",
        )

    batch_run_id = f"batch-{uuid.uuid4().hex[:8]}"
    concurrency_limit = min(5, max(1, getattr(payload, "concurrency", 5)))
    worker_rate_limit = min(15, max(10, payload.rate_limit))

    await scan_hub.broadcast(
        batch_run_id,
        {
            "event": "batch_scan_started",
            "message": (
                f"Iniciando varredura concorrente em lote para {len(in_scope_assets)} ativos em escopo "
                f"({concurrency_limit} workers simultâneos, rl: {worker_rate_limit} req/s por worker, circuit-breaker per-domain ativo)..."
            ),
            "total_assets": len(in_scope_assets),
            "concurrency": concurrency_limit,
            "rate_limit_per_worker": worker_rate_limit,
            "progress": 5,
        },
    )

    sem = asyncio.Semaphore(concurrency_limit)
    total_templates_executed = 0
    total_findings_discovered = 0
    asset_summaries: list[BatchScanAssetSummary] = list(denied_summaries)
    lock = asyncio.Lock()

    async def _scan_single_asset(idx: int, asset: Asset) -> BatchScanAssetSummary:
        nonlocal total_templates_executed, total_findings_discovered
        domain_key = asset.canonical_key

        async with sem:
            # 1. Circuit Breaker check
            if circuit_breaker.is_domain_blocked(domain_key):
                summary = BatchScanAssetSummary(
                    asset_key=domain_key,
                    matched_technologies=[],
                    total_templates=0,
                    findings_count=0,
                    status="skipped_waf_cooldown",
                )
                async with lock:
                    asset_summaries.append(summary)
                return summary

            # 2. Canary Probe L7 (sends a real request, so only for live runs, never dry_run)
            if payload.mode == "auto":
                is_acc, lat, status_code, is_waf, reason = await probe_domain_l7_canary(domain_key)
            else:
                is_acc, lat, status_code, is_waf, reason = False, 0.0, None, False, "dry_run"
            if is_waf:
                circuit_breaker.trip_domain(domain_key, reason=reason, cooldown_seconds=60.0)
                await scan_hub.broadcast(
                    batch_run_id,
                    {
                        "event": "circuit_breaker_tripped",
                        "domain": domain_key,
                        "reason": reason,
                        "cooldown_sec": 60,
                        "message": (
                            f"[CIRCUIT BREAKER] WAF Detectado em '{domain_key}' ({reason}). "
                            f"Alvo em cooldown de 60s; liberando slot para o próximo domínio."
                        ),
                    },
                )
                summary = BatchScanAssetSummary(
                    asset_key=domain_key,
                    matched_technologies=[],
                    total_templates=0,
                    findings_count=0,
                    status="waf_cooldown_tripped",
                )
                async with lock:
                    asset_summaries.append(summary)
                return summary

            if is_acc:
                circuit_breaker.record_healthy(domain_key, lat, status_code or 200)

            # 3. Detection Planner & Nuclei execution with dedicated session
            findings_count = 0
            status_val = "completed"
            matched_techs: list[str] = []
            planned_templates_count = 0

            try:
                async with get_async_session() as worker_session:
                    worker_target_asset, raw_techs, _ = await _resolve_asset_and_techs(
                        worker_session, prog, domain_key
                    )
                    worker_planner = DetectionPlanner(db_session=worker_session)
                    plan = await worker_planner.create_plan(
                        asset=worker_target_asset,
                        detected_technologies=raw_techs,
                        severity_filter=payload.severity,
                        tag_filter=payload.tags,
                        max_impact_class=ImpactClass.SAFE_READ_ONLY,
                    )
                    matched_techs = plan.matched_technologies
                    planned_templates_count = plan.total_templates

                    if planned_templates_count == 0:
                        summary = BatchScanAssetSummary(
                            asset_key=domain_key,
                            matched_technologies=[],
                            total_templates=0,
                            findings_count=0,
                            status="skipped_no_matching_tech",
                        )
                        async with lock:
                            asset_summaries.append(summary)
                        return summary

                    async with lock:
                        total_templates_executed += planned_templates_count

                    if payload.mode == "auto":
                        async def _live_batch_nuclei_cb(tool: str, line: str):
                            try:
                                await scan_hub.broadcast(
                                    batch_run_id,
                                    {
                                        "event": "tool_output",
                                        "tool": "NUCLEI",
                                        "domain": domain_key,
                                        "line": line,
                                        "message": f"[{domain_key}] {line}",
                                    },
                                )
                            except Exception:
                                pass

                        target_url = (
                            domain_key
                            if "://" in domain_key
                            else f"https://{domain_key}"
                        )
                        raw_findings = await run_real_nuclei(
                            target_url=target_url,
                            template_ids=plan.selected_template_ids,
                            rate_limit=worker_rate_limit,
                            flags=payload.nuclei_flags,
                            broadcast_cb=_live_batch_nuclei_cb,
                            run_id=batch_run_id,
                        )

                        if raw_findings:
                            worker_normalizer = FindingNormalizer(db_session=worker_session)
                            persisted = await worker_normalizer.normalize_and_persist(
                                raw_nuclei_results=raw_findings,
                                program_id=prog.id,
                                asset_id=worker_target_asset.id,
                                run_id=plan.plan_id,
                            )
                            findings_count = len(persisted)
                            async with lock:
                                total_findings_discovered += findings_count

            except Exception as exc:
                logger.warning("Error scanning asset %s: %s", domain_key, exc)
                status_val = "error_fallback"

            summary = BatchScanAssetSummary(
                asset_key=domain_key,
                matched_technologies=matched_techs,
                total_templates=planned_templates_count,
                findings_count=findings_count,
                status=status_val,
            )
            async with lock:
                asset_summaries.append(summary)

            progress_pct = int(5 + ((idx + 1) / len(in_scope_assets)) * 90)
            await scan_hub.broadcast(
                batch_run_id,
                {
                    "event": "batch_asset_scanned",
                    "asset_key": domain_key,
                    "matched_technologies": matched_techs,
                    "templates_count": planned_templates_count,
                    "findings_count": findings_count,
                    "progress": progress_pct,
                },
            )
            return summary

    # Execute up to 5 concurrent domain tasks
    tasks = [_scan_single_asset(i, a) for i, a in enumerate(in_scope_assets)]
    activity.start(batch_run_id, "batch_scan", prog.slug, f"{len(in_scope_assets)} assets")
    try:
        await asyncio.gather(*tasks)
    finally:
        activity.finish(batch_run_id)

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
            "rate_limit_per_worker": worker_rate_limit,
            "concurrency": concurrency_limit,
        },
    )

    msg = (
        f"Varredura cirúrgica concorrente concluída ({concurrency_limit} workers simultâneos, rl: {worker_rate_limit} req/s): "
        f"{len(in_scope_assets)} ativos processados, {total_templates_executed} templates executadas, "
        f"{total_findings_discovered} falha(s) identificada(s)."
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
        rate_limit_enforced=f"{worker_rate_limit} req/s per worker",
        concurrency_enforced=concurrency_limit,
        assets=asset_summaries,
        message=msg,
    )


@router.get("/circuit-breaker/status", response_model=SentinelStatusResponse)
async def get_circuit_breaker_status() -> SentinelStatusResponse:
    """Return real-time Circuit Breaker & Canary health states for all monitored domains."""
    statuses = circuit_breaker.get_all_statuses()
    blocked = len([s for s in statuses.values() if s.get("is_blocked")])
    return SentinelStatusResponse(
        total_monitored=len(statuses),
        blocked_count=blocked,
        domains=statuses,
    )


@router.post("/circuit-breaker/reset")
async def reset_circuit_breaker_domain(payload: SentinelDomainResetRequest) -> dict[str, Any]:
    """Manually reset Circuit Breaker cooldown for a specific domain or all."""
    state = circuit_breaker.reset_domain(payload.domain)
    return {
        "message": f"Circuit breaker para '{payload.domain}' resetado com sucesso.",
        "state": state.to_dict(),
    }


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
        object_id: uuid.UUID | str = uuid.UUID(clean_run_id)
    except ValueError:
        if not re.fullmatch(r"(batch|recon)-[a-z0-9-]{4,40}", clean_run_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid UUID format (or batch-/recon- id): '{clean_run_id}'",
            )
        object_id = clean_run_id

    # 1. Kill processes this API spawned for the run (tombstoned if not started yet),
    #    then broadcast to worker daemons via Valkey.
    was_running_here = activity.cancel(clean_run_id)
    await default_container_registry.broadcast_cancel(clean_run_id)

    # 2. Record API audit event
    await record_api_audit(
        session=session,
        event_type="api.scan.cancel",
        object_type="scan_run",
        object_id=object_id,
        payload={"status": "cancelled", "run_id": clean_run_id, "was_running_here": was_running_here},
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
        "was_running_here": was_running_here,
        "message": f"Cancellation signal dispatched for scan run {clean_run_id}.",
    }

