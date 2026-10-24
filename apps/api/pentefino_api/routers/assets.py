from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from pentefino_api.deps import get_db_session, get_program_or_404
from pentefino_api.schemas import (
    AssetGraphResponse,
    AssetResponse,
    GraphEdge,
    GraphNode,
    ObservationItem,
)
from pentefino_domain.models.asset import Asset
from pentefino_domain.models.observation import Observation

router = APIRouter(prefix="/api/v1/programs/{slug}/assets", tags=["assets"])

PRUNED_CDN_TAGS = {"cloudflare", "akamai", "fastly", "incapsula", "sucuri"}


@router.get("", response_model=list[AssetResponse])
async def list_assets(
    slug: str,
    scope_state: Optional[str] = Query(None, description="Filter by scope_state"),
    q: Optional[str] = Query(None, description="Search canonical_key substring"),
    session: AsyncSession = Depends(get_db_session),
) -> list[AssetResponse]:
    """List assets for a program including observations and findings count."""
    prog = await get_program_or_404(session, slug)

    stmt = (
        select(Asset)
        .options(
            selectinload(Asset.findings),
            selectinload(Asset.observations),  # type: ignore[arg-type]
        )
        .where(Asset.program_id == prog.id)
    )
    if scope_state:
        stmt = stmt.where(Asset.scope_state == scope_state.strip().lower())
    if q:
        stmt = stmt.where(Asset.canonical_key.ilike(f"%{q.strip()}%"))

    stmt = stmt.order_by(Asset.canonical_key.asc())
    res = await session.execute(stmt)
    assets = res.scalars().all()

    items: list[AssetResponse] = []
    for asset in assets:
        obs_list: list[Observation] = getattr(asset, "observations", []) or []
        techs: set[str] = set()
        serialized_obs: list[ObservationItem] = []

        for obs in obs_list:
            meta = obs.metadata_json if isinstance(obs.metadata_json, dict) else {}
            for t in meta.get("technologies") or []:
                if t and str(t).strip():
                    techs.add(str(t).strip().lower())
            serialized_obs.append(
                ObservationItem(
                    id=str(obs.id),
                    observation_type=obs.observation_type,
                    metadata_json=meta,
                    created_at=obs.created_at.isoformat() if obs.created_at else None,
                )
            )

        items.append(
            AssetResponse(
                id=str(asset.id),
                program_id=str(asset.program_id),
                canonical_key=asset.canonical_key,
                asset_type=asset.asset_type,
                scope_state=asset.scope_state,
                first_seen=asset.first_seen.isoformat() if asset.first_seen else None,
                last_seen=asset.last_seen.isoformat() if asset.last_seen else None,
                observations=serialized_obs,
                findings_count=len(asset.findings) if "findings" in asset.__dict__ else 0,
                technologies=sorted(techs),
            )
        )
    return items


@router.get("/graph", response_model=AssetGraphResponse)
async def get_asset_graph(
    slug: str,
    session: AsyncSession = Depends(get_db_session),
) -> AssetGraphResponse:
    """Build the topological graph while strictly enforcing the Critical IP Invariant."""
    prog = await get_program_or_404(session, slug)

    stmt = (
        select(Asset)
        .options(
            selectinload(Asset.observations),  # type: ignore[arg-type]
            selectinload(Asset.findings),
        )
        .where(Asset.program_id == prog.id)
        .order_by(Asset.canonical_key.asc())
    )
    res = await session.execute(stmt)
    assets = res.scalars().all()

    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    seen_nodes: set[str] = set()

    program_node_id = f"program:{prog.slug}"
    nodes.append(
        GraphNode(
            id=program_node_id,
            label=prog.name,
            node_type="program",
            scope_state=None,
            asset_type=None,
            metadata={"slug": prog.slug, "platform": prog.platform, "state": prog.state},
        )
    )
    seen_nodes.add(program_node_id)

    for asset in assets:
        asset_node_id = f"asset:{asset.canonical_key}"
        if asset_node_id not in seen_nodes:
            nodes.append(
                GraphNode(
                    id=asset_node_id,
                    label=asset.canonical_key,
                    node_type="asset",
                    scope_state=asset.scope_state,
                    asset_type=asset.asset_type,
                    metadata={
                        "asset_id": str(asset.id),
                        "findings_count": len(asset.findings) if "findings" in asset.__dict__ else 0,
                    },
                )
            )
            seen_nodes.add(asset_node_id)

        edges.append(
            GraphEdge(
                source=program_node_id,
                target=asset_node_id,
                relation="HAS_ASSET",
            )
        )

        obs_list: list[Observation] = getattr(asset, "observations", []) or []
        for obs in obs_list:
            meta = obs.metadata_json if isinstance(obs.metadata_json, dict) else {}

            # DNS Observations -> Strictly metadata-only observed_ip nodes (NEVER scoped assets)
            if obs.observation_type == "dns":
                raw_ips: list[str] = []
                for key in ("a", "aaaa", "a_records", "aaaa_records", "ips", "resolved_ips"):
                    val = meta.get(key)
                    if isinstance(val, list):
                        raw_ips.extend(str(ip).strip() for ip in val if ip)
                    elif isinstance(val, str) and val.strip():
                        raw_ips.append(val.strip())

                for ip_str in raw_ips:
                    if not ip_str:
                        continue
                    ip_node_id = f"ip:{ip_str}"
                    if ip_node_id not in seen_nodes:
                        nodes.append(
                            GraphNode(
                                id=ip_node_id,
                                label=ip_str,
                                node_type="observed_ip",
                                scope_state=None,
                                asset_type=None,
                                metadata={
                                    "dns_metadata_only": True,
                                    "scopable": False,
                                },
                            )
                        )
                        seen_nodes.add(ip_node_id)

                    edges.append(
                        GraphEdge(
                            source=asset_node_id,
                            target=ip_node_id,
                            relation="RESOLVES_TO",
                        )
                    )

            # HTTP Observations -> Technology nodes with CDN pruning flag
            if obs.observation_type in ("http_probe", "http"):
                tech_list = meta.get("technologies") or []
                if isinstance(tech_list, list):
                    for raw_tech in tech_list:
                        tech = str(raw_tech).strip()
                        if not tech:
                            continue
                        tech_lower = tech.lower()
                        tech_node_id = f"tech:{tech_lower}"
                        if tech_node_id not in seen_nodes:
                            nodes.append(
                                GraphNode(
                                    id=tech_node_id,
                                    label=tech,
                                    node_type="technology",
                                    scope_state=None,
                                    asset_type=None,
                                    metadata={
                                        "is_pruned_cdn": tech_lower in PRUNED_CDN_TAGS,
                                    },
                                )
                            )
                            seen_nodes.add(tech_node_id)

                        edges.append(
                            GraphEdge(
                                source=asset_node_id,
                                target=tech_node_id,
                                relation="RUNS_TECH",
                            )
                        )

    return AssetGraphResponse(
        program_slug=prog.slug,
        nodes=nodes,
        edges=edges,
    )
