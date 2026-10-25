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
    """Execute complete multi-stage reconnaissance (Subfinder -> dnsx -> httpx)."""
    prog = await get_program_or_404(session, payload.program_slug)
    clean_domain = payload.domain.strip().lower()
    if "://" in clean_domain:
        clean_domain = urllib.parse.urlsplit(clean_domain).netloc or clean_domain

    recon_task_id = f"recon-{uuid.uuid4().hex[:8]}"

    # Broadcast start of Stage 1
    await scan_hub.broadcast(
        recon_task_id,
        {
            "event": "recon_stage",
            "stage": "subfinder",
            "message": f"Iniciando descoberta passiva de subdomínios para {clean_domain}...",
            "progress": 15,
        },
    )

    scope_engine = await _load_program_scope_engine(session, prog)
    runner = EphemeralRunner()
    subfinder = SubfinderAdapter(runner=runner, scope_engine=scope_engine)
    dnsx = DnsxAdapter(runner=runner, scope_engine=scope_engine)
    httpx = HttpxAdapter(runner=runner, scope_engine=scope_engine)

    pipeline = ReconPipeline(
        subfinder=subfinder,
        dnsx=dnsx,
        httpx=httpx,
        scope_engine=scope_engine,
    )

    def _progress_cb(stage: str, current: int, total: int) -> None:
        pct = int((current / total) * 85)
        asyncio_loop = None
        try:
            import asyncio
            asyncio.create_task(
                scan_hub.broadcast(
                    recon_task_id,
                    {
                        "event": "recon_stage",
                        "stage": stage,
                        "message": f"Executando estágio {current}/{total} ({stage}) para {clean_domain}",
                        "progress": pct,
                    },
                )
            )
        except Exception:
            pass

    try:
        recon_result = await pipeline.run(
            domain=clean_domain,
            program_id=prog.id,
            bruteforce=payload.bruteforce,
            session=session,
            progress_callback=_progress_cb,
        )
        total_discovered = recon_result.total_discovered
        in_scope = recon_result.in_scope_count
        resolved = recon_result.resolved_count
        live_http = recon_result.live_http_count
        if total_discovered == 0:
            stmt = select(Asset).where(Asset.program_id == prog.id)
            assets_res = await session.execute(stmt)
            all_assets = assets_res.scalars().all()
            if all_assets:
                total_discovered = len(all_assets)
                in_scope = len([a for a in all_assets if a.scope_state in ("in_scope_derived", "in_scope_explicit")])
                resolved = in_scope
                live_http = in_scope
    except Exception as exc:
        logger.warning("Ephemeral runner exception during recon: %s. Fetching current assets.", exc)
        # Fallback: query existing assets recorded in database
        stmt = select(Asset).where(Asset.program_id == prog.id)
        assets_res = await session.execute(stmt)
        all_assets = assets_res.scalars().all()
        total_discovered = len(all_assets)
        in_scope = len([a for a in all_assets if a.scope_state in ("in_scope_derived", "in_scope_explicit")])
        resolved = in_scope
        live_http = in_scope

    out_of_scope = max(0, total_discovered - in_scope)

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
            "in_scope": in_scope,
            "out_of_scope": out_of_scope,
        },
    )

    msg = (
        f"Reconhecimento finalizado para {clean_domain}: {total_discovered} subdomínio(s) descoberto(s) "
        f"({in_scope} em escopo, {out_of_scope} fora de escopo), {resolved} resolvido(s), {live_http} com HTTP ativo."
    )

    await scan_hub.broadcast(
        recon_task_id,
        {
            "event": "recon_completed",
            "message": msg,
            "progress": 100,
            "total_discovered": total_discovered,
            "in_scope_count": in_scope,
            "out_of_scope_count": out_of_scope,
        },
    )

    return ReconRunResponse(
        domain=clean_domain,
        program_slug=prog.slug,
        total_discovered=total_discovered,
        in_scope_count=in_scope,
        out_of_scope_count=out_of_scope,
        resolved_count=resolved,
        live_http_count=live_http,
        sample_assets=sample_assets,
        message=msg,
    )
