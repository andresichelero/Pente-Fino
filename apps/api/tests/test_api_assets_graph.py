from __future__ import annotations

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pentefino_domain.models.asset import Asset
from pentefino_domain.models.observation import Observation
from pentefino_domain.models.program import Program


@pytest.mark.asyncio
async def test_assets_list_and_topological_graph_critical_ip_invariant(
    async_client: httpx.AsyncClient,
    db_session: AsyncSession,
    test_slug: str,
) -> None:
    """Verify GET /assets and GET /assets/graph enforce the Critical IP Invariant and CDN pruning."""
    # 1. Seed Program, Scoped Asset, DNS Observation, and HTTP Probe Observation
    prog = Program(
        slug=test_slug,
        name="Graph Invariant Program",
        platform="hackerone",
        state="active",
        default_policy_id="bounty-safe",
    )
    db_session.add(prog)
    await db_session.flush()

    asset = Asset(
        program_id=prog.id,
        canonical_key="portal.example.com",
        asset_type="domain",
        scope_state="in_scope_explicit",
    )
    db_session.add(asset)
    await db_session.flush()

    dns_obs = Observation(
        asset_id=asset.id,
        observation_type="dns",
        metadata_json={
            "a_records": ["93.184.216.34"],
            "cname": ["edge.example.net"],
        },
    )
    http_obs = Observation(
        asset_id=asset.id,
        observation_type="http_probe",
        metadata_json={
            "status_code": 200,
            "title": "Example Portal",
            "technologies": ["Apache", "Cloudflare"],
        },
    )
    db_session.add_all([dns_obs, http_obs])
    await db_session.commit()

    # 2. Test GET /api/v1/programs/{slug}/assets
    assets_res = await async_client.get(f"/api/v1/programs/{test_slug}/assets")
    assert assets_res.status_code == 200
    assets_data = assets_res.json()
    assert len(assets_data) == 1
    assert assets_data[0]["canonical_key"] == "portal.example.com"
    assert assets_data[0]["scope_state"] == "in_scope_explicit"
    assert "apache" in assets_data[0]["technologies"]
    assert "cloudflare" in assets_data[0]["technologies"]

    # Critical IP Invariant Check #1: 93.184.216.34 is NEVER in the `assets` table
    ip_asset_stmt = select(Asset).where(
        Asset.program_id == prog.id,
        Asset.canonical_key == "93.184.216.34",
    )
    ip_asset_res = await db_session.execute(ip_asset_stmt)
    assert ip_asset_res.scalar_one_or_none() is None
    assert all(a["canonical_key"] != "93.184.216.34" for a in assets_data)

    # 3. Test GET /api/v1/programs/{slug}/assets/graph
    graph_res = await async_client.get(f"/api/v1/programs/{test_slug}/assets/graph")
    assert graph_res.status_code == 200
    graph = graph_res.json()
    assert graph["program_slug"] == test_slug

    nodes_by_id = {n["id"]: n for n in graph["nodes"]}

    # Verify Asset node
    assert "asset:portal.example.com" in nodes_by_id
    asset_node = nodes_by_id["asset:portal.example.com"]
    assert asset_node["node_type"] == "asset"
    assert asset_node["scope_state"] == "in_scope_explicit"

    # Critical IP Invariant Check #2: 93.184.216.34 appears ONLY as node_type == "observed_ip" with scopable == False
    assert "ip:93.184.216.34" in nodes_by_id
    ip_node = nodes_by_id["ip:93.184.216.34"]
    assert ip_node["node_type"] == "observed_ip"
    assert ip_node["scope_state"] is None
    assert ip_node["metadata"]["dns_metadata_only"] is True
    assert ip_node["metadata"]["scopable"] is False
    assert "asset:93.184.216.34" not in nodes_by_id

    # Verify Technology nodes and CDN pruning flag
    assert "tech:apache" in nodes_by_id
    assert nodes_by_id["tech:apache"]["node_type"] == "technology"
    assert nodes_by_id["tech:apache"]["metadata"]["is_pruned_cdn"] is False

    assert "tech:cloudflare" in nodes_by_id
    assert nodes_by_id["tech:cloudflare"]["node_type"] == "technology"
    assert nodes_by_id["tech:cloudflare"]["metadata"]["is_pruned_cdn"] is True
