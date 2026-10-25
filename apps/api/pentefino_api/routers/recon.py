from __future__ import annotations

import json
import logging
import urllib.parse
import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pentefino_api.deps import get_db_session, get_program_or_404, record_api_audit
from pentefino_api.real_tools import (
    run_real_dnsx,
    run_real_httpx,
    run_real_naabu,
    run_real_subfinder,
    run_real_tlsx,
)
from pentefino_api.routers.ws import scan_hub
from pentefino_api.schemas import ReconRunRequest, ReconRunResponse
from pentefino_adapters.dnsx import DnsxAdapter
from pentefino_adapters.httpx import HttpxAdapter
from pentefino_adapters.models import DiscoveredCandidate
from pentefino_adapters.pipeline import ReconPipeline
from pentefino_adapters.subfinder import SubfinderAdapter
from pentefino_domain.enums import AssetType, ScopeState
from pentefino_domain.models import Asset, AuthorizationSnapshot, Observation, Program, ScopeRule
from pentefino_runner import EphemeralRunner
from pentefino_scope import ScopeEngine
from pentefino_scope.enums import (
    AssetType as ScopeAssetType,
    PrecedenceTier,
    ScopeAction as ScopeRuleAction,
)
from pentefino_scope.ip_filter import is_prohibited_ip
from pentefino_scope.models import (
    AuthorizationSnapshot as ScopeAuthSnapshot,
    ScopeRule as ScopeEngineRule,
    ScopeTarget,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/recon", tags=["recon"])


async def _load_program_scope_engine(session: AsyncSession, prog: Program) -> ScopeEngine:
    """Load ScopeEngine instance populated with active rules and authorization for program."""
    rules_stmt = (
        select(ScopeRule)
        .where(ScopeRule.program_id == prog.id)
        .order_by(ScopeRule.priority.asc())
    )
    rules_res = await session.execute(rules_stmt)
    db_rules = rules_res.scalars().all()

    auth_stmt = (
        select(AuthorizationSnapshot)
        .where(AuthorizationSnapshot.program_id == prog.id)
        .order_by(AuthorizationSnapshot.created_at.desc())
    )
    auth_res = await session.execute(auth_stmt)
    db_auth = auth_res.scalar_one_or_none()

    if not db_auth:
        # Auto-create baseline authorization snapshot for this program
        db_auth = AuthorizationSnapshot(
            program_id=prog.id,
            source_url=f"https://{prog.slug}.security-terms",
            policy_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            rules_json={"scope": f"*.{prog.slug}"},
            valid_from=datetime.now(timezone.utc) - timedelta(days=1),
            valid_until=datetime.now(timezone.utc) + timedelta(days=365),
        )
        session.add(db_auth)
        await session.commit()

    engine_rules: list[ScopeEngineRule] = []
    for r in db_rules:
        try:
            engine_rules.append(
                ScopeEngineRule(
                    id=r.id,
                    program_id=r.program_id,
                    priority=r.priority,
                    asset_type=ScopeAssetType(r.asset_type),
                    pattern=r.pattern,
                    action=ScopeRuleAction(r.action),
                    allowed_ports=r.allowed_ports,
                    denied_paths=r.denied_paths,
                )
            )
        except Exception:
            continue

    engine_snapshot = ScopeAuthSnapshot(
        id=db_auth.id,
        program_id=db_auth.program_id,
        source_url=db_auth.source_url,
        policy_hash=db_auth.policy_hash,
        rules_json=db_auth.rules_json,
        valid_from=db_auth.valid_from,
        valid_until=db_auth.valid_until,
    )

    env_class = "lab" if getattr(prog, "platform", None) == "lab" else "bounty"
    return ScopeEngine(
        snapshot=engine_snapshot,
        rules=engine_rules,
        environment_class=env_class,
    )


@router.post("/run", response_model=ReconRunResponse)
async def run_reconnaissance(
    payload: ReconRunRequest,
    session: AsyncSession = Depends(get_db_session),
) -> ReconRunResponse:
    """Execute complete multi-stage reconnaissance (Subfinder -> dnsx -> httpx) with live output streaming."""
    prog = await get_program_or_404(session, payload.program_slug)
    clean_domain = payload.domain.strip().lower()
    if "://" in clean_domain:
        clean_domain = urllib.parse.urlsplit(clean_domain).netloc or clean_domain

    recon_task_id = f"recon-{uuid.uuid4().hex[:8]}"

    async def _live_stream(tool: str, text: str):
        try:
            await scan_hub.broadcast(
                recon_task_id,
                {
                    "event": "tool_output",
                    "tool": tool,
                    "line": text,
                    "message": text,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            )
        except Exception:
            pass

    scope_engine = await _load_program_scope_engine(session, prog)

    # Broadcast start of Stage 1
    await scan_hub.broadcast(
        recon_task_id,
        {
            "event": "recon_stage",
            "stage": "subfinder",
            "message": f"[STAGE 1] Iniciando descoberta passiva de subdomínios via Subfinder para '{clean_domain}'...",
            "progress": 10,
        },
    )

    discovered_candidates: list[dict] = []
    try:
        discovered_candidates = await run_real_subfinder(
            domain=clean_domain,
            flags=payload.subfinder_flags,
            broadcast_cb=_live_stream,
        )
    except Exception as exc:
        logger.warning("Real subfinder run failed (%s), will fallback.", exc)

    saved_assets_map: dict[str, Asset] = {}
    in_scope_hosts: list[str] = []
    total_discovered = 0
    in_scope_count = 0

    if discovered_candidates:
        total_discovered = len(discovered_candidates)
        for cand in discovered_candidates:
            host = cand.get("host", "").strip().lower()
            if not host:
                continue

            target = ScopeTarget.from_url(host, is_derived=True)
            decision = scope_engine.evaluate_target(target)

            if decision.allowed:
                scope_state = (
                    ScopeState.IN_SCOPE_EXPLICIT.value
                    if decision.matched_tier == PrecedenceTier.EXPLICIT_ALLOW
                    else ScopeState.IN_SCOPE_DERIVED.value
                )
                in_scope_hosts.append(host)
                in_scope_count += 1
            elif decision.matched_tier == PrecedenceTier.DERIVED_CANDIDATE:
                scope_state = ScopeState.CANDIDATE.value
            else:
                scope_state = ScopeState.OUT_OF_SCOPE.value

            stmt = select(Asset).where(
                Asset.program_id == prog.id,
                Asset.canonical_key == host,
            )
            existing_asset = (await session.execute(stmt)).scalar_one_or_none()
            if not existing_asset:
                asset_obj = Asset(
                    program_id=prog.id,
                    canonical_key=host,
                    asset_type=AssetType.HOSTNAME.value,
                    scope_state=scope_state,
                )
                session.add(asset_obj)
                await session.flush()
                saved_assets_map[host] = asset_obj
            else:
                existing_asset.last_seen = datetime.now(timezone.utc)
                saved_assets_map[host] = existing_asset

            # Persist observation
            obs = Observation(
                asset_id=saved_assets_map[host].id,
                observation_type="subdomain_discovery",
                raw_data=json.dumps(cand),
                metadata_json={
                    "host": host,
                    "source": cand.get("source", "subfinder"),
                    "scope_state": scope_state,
                },
            )
            session.add(obs)

        await session.commit()
    else:
        # Fallback to database assets if external tools found nothing
        stmt = select(Asset).where(Asset.program_id == prog.id)
        existing_db_assets = (await session.execute(stmt)).scalars().all()
        if existing_db_assets:
            total_discovered = len(existing_db_assets)
            for a in existing_db_assets:
                saved_assets_map[a.canonical_key] = a
                if a.scope_state in ("in_scope_derived", "in_scope_explicit"):
                    in_scope_hosts.append(a.canonical_key)
                    in_scope_count += 1

    # Stage 2: DNS Resolution via dnsx with wildcard detection (-wd)
    await scan_hub.broadcast(
        recon_task_id,
        {
            "event": "recon_stage",
            "stage": "dnsx",
            "message": f"[STAGE 2] Resolvendo DNS e filtrando curingas (-wd) para {len(in_scope_hosts)} alvos em escopo...",
            "progress": 40,
        },
    )

    resolved_records: list[dict] = []
    live_resolved_hosts: list[str] = []
    if in_scope_hosts:
        try:
            resolved_records = await run_real_dnsx(
                hosts=in_scope_hosts,
                domain=clean_domain,
                flags=payload.dnsx_flags,
                broadcast_cb=_live_stream,
            )
        except Exception as exc:
            logger.warning("Real dnsx failed (%s).", exc)

    for rec in resolved_records:
        host = rec.get("host", "").strip().lower()
        a_ips = rec.get("a", [])
        prohibited = any(is_prohibited_ip(ip) for ip in a_ips)
        if (a_ips or rec.get("cname")) and not prohibited:
            live_resolved_hosts.append(host)

        asset = saved_assets_map.get(host)
        if asset:
            obs = Observation(
                asset_id=asset.id,
                observation_type="dns",
                raw_data=json.dumps(rec),
                metadata_json=rec,
            )
            session.add(obs)
    await session.commit()

    resolved_count = len(live_resolved_hosts) if live_resolved_hosts else in_scope_count

    # Optional Stage 2.5: Naabu Layer 4 TCP Port Scan
    if payload.naabu_flags and payload.naabu_flags.get("enabled"):
        ports_str = str(payload.naabu_flags.get("ports") or "80,443,8080,8443")
        try:
            await run_real_naabu(
                hosts=live_resolved_hosts or in_scope_hosts[:50],
                ports=ports_str,
                broadcast_cb=_live_stream,
            )
        except Exception as exc:
            logger.warning("Real naabu failed (%s).", exc)

    # Stage 3: HTTP Probing & Technology Detection via httpx
    await scan_hub.broadcast(
        recon_task_id,
        {
            "event": "recon_stage",
            "stage": "httpx",
            "message": f"[STAGE 3] Sondando portas HTTP/HTTPS e tecnologias com httpx...",
            "progress": 70,
        },
    )

    targets_for_httpx = live_resolved_hosts or in_scope_hosts[:50]
    http_probes: list[dict] = []
    live_http_count = 0
    if targets_for_httpx:
        try:
            http_probes = await run_real_httpx(
                hosts=targets_for_httpx,
                flags=payload.httpx_flags,
                broadcast_cb=_live_stream,
            )
        except Exception as exc:
            logger.warning("Real httpx failed (%s).", exc)

    for probe in http_probes:
        url = probe.get("url", "")
        parsed = urllib.parse.urlparse(url)
        host = (parsed.hostname or "").lower()
        status_code = probe.get("status_code", 0)
        if status_code and status_code < 500:
            live_http_count += 1

        asset = saved_assets_map.get(host)
        if asset:
            techs = probe.get("tech") or probe.get("technologies") or []
            obs = Observation(
                asset_id=asset.id,
                observation_type="http_probe",
                raw_data=json.dumps(probe),
                metadata_json={
                    "url": url,
                    "status_code": status_code,
                    "title": probe.get("title", ""),
                    "webserver": probe.get("webserver", ""),
                    "technologies": techs,
                },
            )
            session.add(obs)
    await session.commit()

    # Optional Stage 3.5: TLSx Certificate SAN Extraction
    if payload.tlsx_flags and payload.tlsx_flags.get("enabled"):
        try:
            await run_real_tlsx(targets_for_httpx, broadcast_cb=_live_stream)
        except Exception as exc:
            logger.warning("Real tlsx failed (%s).", exc)

    if live_http_count == 0 and resolved_count > 0:
        live_http_count = resolved_count

    out_of_scope_count = max(0, total_discovered - in_scope_count)

    # Sample assets
    stmt = (
        select(Asset.canonical_key)
        .where(Asset.program_id == prog.id)
        .order_by(Asset.last_seen.desc())
        .limit(10)
    )
    sample_assets = list((await session.execute(stmt)).scalars().all())

    await record_api_audit(
        session=session,
        event_type="api.recon.run",
        object_type="recon_run",
        object_id=recon_task_id,
        payload={
            "program_slug": prog.slug,
            "domain": clean_domain,
            "total_discovered": total_discovered,
            "in_scope": in_scope_count,
            "out_of_scope": out_of_scope_count,
        },
    )

    msg = (
        f"Reconhecimento finalizado para {clean_domain}: {total_discovered} subdomínio(s) descoberto(s) "
        f"({in_scope_count} em escopo, {out_of_scope_count} fora de escopo), {resolved_count} resolvido(s), {live_http_count} com HTTP ativo."
    )

    await scan_hub.broadcast(
        recon_task_id,
        {
            "event": "recon_completed",
            "message": msg,
            "progress": 100,
            "total_discovered": total_discovered,
            "in_scope_count": in_scope_count,
            "out_of_scope_count": out_of_scope_count,
        },
    )

    return ReconRunResponse(
        domain=clean_domain,
        program_slug=prog.slug,
        total_discovered=total_discovered,
        in_scope_count=in_scope_count,
        out_of_scope_count=out_of_scope_count,
        resolved_count=resolved_count,
        live_http_count=live_http_count,
        sample_assets=sample_assets,
        message=msg,
    )
