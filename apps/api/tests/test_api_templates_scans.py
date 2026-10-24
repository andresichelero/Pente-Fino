from __future__ import annotations

import httpx
import pytest
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from pentefino_domain.models.asset import Asset
from pentefino_domain.models.observation import Observation
from pentefino_domain.models.program import Program
from pentefino_domain.models.template import TemplateCatalog


@pytest.mark.asyncio
async def test_templates_stats_and_filtering(
    async_client: httpx.AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Verify GET /api/v1/templates/stats and GET /api/v1/templates?impact_class=safe_read_only&tech=apache."""
    seeded_id = "pytest-http/technologies/apache/apache-safe-probe.yaml"
    existing = await db_session.execute(
        select(TemplateCatalog).where(TemplateCatalog.id == seeded_id)
    )
    created_seed = False
    if existing.scalar_one_or_none() is None:
        tpl = TemplateCatalog(
            id=seeded_id,
            upstream_revision="pytest-rev-1",
            bundle_hash="a" * 64,
            name="Apache Safe Read-Only Version Probe",
            protocol="http",
            http_methods=["GET"],
            impact_class="safe_read_only",
            cve_id=None,
            cwe_id="CWE-200",
            severity="info",
            technologies=["apache"],
            tags=["tech", "apache"],
            raw_yaml="id: apache-safe-probe\ninfo:\n  name: Apache Safe Read-Only Version Probe\n",
        )
        db_session.add(tpl)
        await db_session.commit()
        created_seed = True

    try:
        # 1. Template Stats
        stats_res = await async_client.get("/api/v1/templates/stats")
        assert stats_res.status_code == 200
        stats = stats_res.json()
        assert stats["total"] >= 1
        assert "safe_read_only" in stats["by_impact_class"]
        assert isinstance(stats["by_severity"], dict)

        # 2. Filtered Template List
        list_res = await async_client.get(
            "/api/v1/templates?impact_class=safe_read_only&tech=apache&limit=25"
        )
        assert list_res.status_code == 200
        listing = list_res.json()
        assert listing["total"] >= 1
        assert len(listing["items"]) >= 1
        for item in listing["items"]:
            assert item["impact_class"] == "safe_read_only"

        # 3. Template Detail
        detail_res = await async_client.get(f"/api/v1/templates/{seeded_id}")
        assert detail_res.status_code == 200
        detail = detail_res.json()
        assert detail["id"] == seeded_id
        assert detail["impact_class"] == "safe_read_only"
        assert "raw_yaml" in detail
    finally:
        if created_seed:
            await db_session.execute(
                delete(TemplateCatalog).where(TemplateCatalog.id == seeded_id)
            )
            await db_session.commit()


@pytest.mark.asyncio
async def test_scan_plan_cdn_pruning_and_dry_run_execution(
    async_client: httpx.AsyncClient,
    db_session: AsyncSession,
    test_slug: str,
) -> None:
    """Verify POST /api/v1/scans/plan prunes CDN tags, selects only safe templates, and POST /scans/run + /scans/history work."""
    seeded_apache_id = "pytest-http/apache-config-check.yaml"
    seeded_cdn_id = "pytest-http/cloudflare-waf-detect.yaml"
    seeded_intrusive_id = "pytest-http/apache-intrusive-rce.yaml"

    for tid, name, impact, techs, tags in [
        (
            seeded_apache_id,
            "Apache Safe Config Check",
            "safe_read_only",
            ["apache"],
            ["apache", "config"],
        ),
        (
            seeded_cdn_id,
            "Cloudflare Edge WAF Detect",
            "safe_read_only",
            ["cloudflare"],
            ["cloudflare", "waf"],
        ),
        (
            seeded_intrusive_id,
            "Apache Intrusive Exploit",
            "intrusive",
            ["apache"],
            ["apache", "rce"],
        ),
    ]:
        res = await db_session.execute(
            select(TemplateCatalog).where(TemplateCatalog.id == tid)
        )
        if res.scalar_one_or_none() is None:
            db_session.add(
                TemplateCatalog(
                    id=tid,
                    upstream_revision="pytest-rev-1",
                    bundle_hash="b" * 64,
                    name=name,
                    protocol="http",
                    http_methods=["GET"],
                    impact_class=impact,
                    severity="medium",
                    technologies=techs,
                    tags=tags,
                    raw_yaml=f"id: {tid}\n",
                )
            )

    prog = Program(
        slug=test_slug,
        name="Scan Planner Test Program",
        platform="hackerone",
        state="active",
        default_policy_id="bounty-safe",
    )
    db_session.add(prog)
    await db_session.flush()

    asset = Asset(
        program_id=prog.id,
        canonical_key="scanme.nmap.org",
        asset_type="domain",
        scope_state="in_scope_explicit",
    )
    db_session.add(asset)
    await db_session.flush()

    obs = Observation(
        asset_id=asset.id,
        observation_type="http_probe",
        metadata_json={"technologies": ["Apache", "Cloudflare"]},
    )
    db_session.add(obs)
    await db_session.commit()

    try:
        # 1. Test POST /api/v1/scans/plan
        plan_res = await async_client.post(
            "/api/v1/scans/plan",
            json={
                "program_slug": test_slug,
                "asset_key": "scanme.nmap.org",
            },
        )
        assert plan_res.status_code == 200
        plan = plan_res.json()
        assert plan["program_slug"] == test_slug
        assert plan["asset_key"] == "scanme.nmap.org"
        assert "cloudflare" in plan["pruned_edge_tags"]
        assert "apache" in plan["matched_technologies"]
        assert "cloudflare" not in plan["matched_technologies"]
        assert plan["total_templates"] >= 1

        # Verify only safe_read_only / passive templates are selected and never cloudflare or intrusive
        selected_ids = {t["id"] for t in plan["selected_templates"]}
        assert seeded_apache_id in selected_ids
        assert seeded_cdn_id not in selected_ids
        assert seeded_intrusive_id not in selected_ids
        for tpl in plan["selected_templates"]:
            assert tpl["impact_class"] in ("safe_read_only", "passive")

        # 2. Test POST /api/v1/scans/run in dry_run mode
        run_res = await async_client.post(
            "/api/v1/scans/run",
            json={
                "program_slug": test_slug,
                "asset_key": "scanme.nmap.org",
                "mode": "dry_run",
            },
        )
        assert run_res.status_code == 200
        run_data = run_res.json()
        assert run_data["program_slug"] == test_slug
        assert run_data["mode_executed"] == "dry_run"
        assert "cloudflare" in run_data["pruned_edge_tags"]
        assert run_data["total_templates"] >= 1

        # 3. Test GET /api/v1/scans/history
        hist_res = await async_client.get("/api/v1/scans/history")
        assert hist_res.status_code == 200
        history = hist_res.json()
        assert len(history) >= 1
        assert any(h["event_type"] == "api.scan.run" for h in history)
    finally:
        await db_session.execute(
            delete(TemplateCatalog).where(
                TemplateCatalog.id.in_(
                    [seeded_apache_id, seeded_cdn_id, seeded_intrusive_id]
                )
            )
        )
        await db_session.commit()
