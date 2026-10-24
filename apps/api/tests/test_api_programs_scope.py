from __future__ import annotations

import httpx
import pytest


@pytest.mark.asyncio
async def test_health_endpoint(async_client: httpx.AsyncClient) -> None:
    """Verify GET /api/v1/health reports database connected and service ok."""
    res = await async_client.get("/api/v1/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["service"] == "pentefino-api"
    assert data["database"] == "connected"
    assert isinstance(data["templates_count"], int)
    assert isinstance(data["active_programs_count"], int)


@pytest.mark.asyncio
async def test_create_and_list_programs(
    async_client: httpx.AsyncClient,
    test_slug: str,
) -> None:
    """Verify POST /api/v1/programs, GET /api/v1/programs, GET /api/v1/programs/{slug}, and PATCH."""
    create_res = await async_client.post(
        "/api/v1/programs",
        json={
            "slug": test_slug,
            "name": "Pytest Bug Bounty Program",
            "platform": "hackerone",
            "default_policy_id": "bounty-safe",
        },
    )
    assert create_res.status_code == 201
    created = create_res.json()
    assert created["slug"] == test_slug
    assert created["name"] == "Pytest Bug Bounty Program"
    assert created["platform"] == "hackerone"
    assert created["state"] == "active"
    assert created["snapshots_count"] == 1

    # Duplicate slug should return 409 Conflict
    dup_res = await async_client.post(
        "/api/v1/programs",
        json={
            "slug": test_slug,
            "name": "Duplicate",
            "platform": "hackerone",
        },
    )
    assert dup_res.status_code == 409

    # List programs and confirm presence
    list_res = await async_client.get("/api/v1/programs")
    assert list_res.status_code == 200
    programs = list_res.json()
    assert any(p["slug"] == test_slug for p in programs)

    # Get by slug
    get_res = await async_client.get(f"/api/v1/programs/{test_slug}")
    assert get_res.status_code == 200
    assert get_res.json()["slug"] == test_slug

    # Update program name
    patch_res = await async_client.patch(
        f"/api/v1/programs/{test_slug}",
        json={"name": "Updated Pytest Program"},
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["name"] == "Updated Pytest Program"


@pytest.mark.asyncio
async def test_scope_rules_and_7_tier_evaluation_with_ssrf_guard(
    async_client: httpx.AsyncClient,
    test_slug: str,
) -> None:
    """Verify scope rule CRUD and 7-tier fail-closed ScopeEngine evaluation including SSRF protection."""
    # 1. Create program
    prog_res = await async_client.post(
        "/api/v1/programs",
        json={
            "slug": test_slug,
            "name": "Scope Evaluation Test Program",
            "platform": "bugcrowd",
        },
    )
    assert prog_res.status_code == 201

    # 2. Add wildcard allow rule with denied_paths and allowed_ports
    allow_rule_res = await async_client.post(
        f"/api/v1/programs/{test_slug}/scope",
        json={
            "action": "allow",
            "pattern": "*.example.org",
            "asset_type": "wildcard_domain",
            "priority": 100,
            "allowed_ports": [80, 443],
            "denied_paths": ["/admin", "/logout"],
        },
    )
    assert allow_rule_res.status_code == 201
    allow_rule = allow_rule_res.json()
    assert allow_rule["action"] == "allow"
    assert allow_rule["pattern"] == "*.example.org"

    # 3. Add explicit domain allow rule for example.org
    root_allow_res = await async_client.post(
        f"/api/v1/programs/{test_slug}/scope",
        json={
            "action": "allow",
            "pattern": "example.org",
            "asset_type": "domain",
            "priority": 90,
            "allowed_ports": [80, 443],
            "denied_paths": ["/admin"],
        },
    )
    assert root_allow_res.status_code == 201

    # 4. Add explicit deny rule for payments.example.org
    deny_rule_res = await async_client.post(
        f"/api/v1/programs/{test_slug}/scope",
        json={
            "action": "deny",
            "pattern": "payments.example.org",
            "asset_type": "hostname",
            "priority": 10,
        },
    )
    assert deny_rule_res.status_code == 201
    deny_rule_id = deny_rule_res.json()["id"]

    # 5. List scope rules
    list_rules_res = await async_client.get(f"/api/v1/programs/{test_slug}/scope")
    assert list_rules_res.status_code == 200
    rules = list_rules_res.json()
    assert len(rules) == 3

    # 6. Evaluate ALLOWED explicit domain
    eval_allow = await async_client.post(
        f"/api/v1/programs/{test_slug}/scope/evaluate",
        json={"target": "https://example.org/api/v1/status"},
    )
    assert eval_allow.status_code == 200
    verdict_allow = eval_allow.json()
    assert verdict_allow["allowed"] is True
    assert verdict_allow["scope_state"] == "in_scope_explicit"
    assert verdict_allow["precedence_tier"] == "EXPLICIT_ALLOW"

    # 7. Evaluate ALLOWED wildcard subdomain
    eval_wildcard = await async_client.post(
        f"/api/v1/programs/{test_slug}/scope/evaluate",
        json={"target": "https://app.example.org/login"},
    )
    assert eval_wildcard.status_code == 200
    verdict_wildcard = eval_wildcard.json()
    assert verdict_wildcard["allowed"] is True
    assert verdict_wildcard["scope_state"] == "in_scope_derived"
    assert verdict_wildcard["precedence_tier"] == "WILDCARD_ALLOW"

    # 8. Evaluate DENIED subdomain (Tier 1: EXPLICIT_DENY)
    eval_deny_sub = await async_client.post(
        f"/api/v1/programs/{test_slug}/scope/evaluate",
        json={"target": "https://payments.example.org/checkout"},
    )
    assert eval_deny_sub.status_code == 200
    verdict_deny_sub = eval_deny_sub.json()
    assert verdict_deny_sub["allowed"] is False
    assert verdict_deny_sub["scope_state"] == "out_of_scope"
    assert verdict_deny_sub["precedence_tier"] == "EXPLICIT_DENY"

    # 9. Evaluate DENIED path (Tier 3: PATH_PORT_DENY)
    eval_deny_path = await async_client.post(
        f"/api/v1/programs/{test_slug}/scope/evaluate",
        json={"target": "https://app.example.org/admin/settings"},
    )
    assert eval_deny_path.status_code == 200
    verdict_deny_path = eval_deny_path.json()
    assert verdict_deny_path["allowed"] is False
    assert verdict_deny_path["precedence_tier"] == "PATH_PORT_DENY"

    # 10. Evaluate Cloud Metadata IP 169.254.169.254 & Loopback 127.0.0.1 -> Blocked by SSRF Guard
    for ssrf_target in (
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:8080/private",
    ):
        eval_ssrf = await async_client.post(
            f"/api/v1/programs/{test_slug}/scope/evaluate",
            json={"target": ssrf_target},
        )
        assert eval_ssrf.status_code == 200
        verdict_ssrf = eval_ssrf.json()
        assert verdict_ssrf["allowed"] is False
        assert verdict_ssrf["scope_state"] == "out_of_scope"

    # 11. Delete rule and verify removal
    del_res = await async_client.delete(
        f"/api/v1/programs/{test_slug}/scope/{deny_rule_id}"
    )
    assert del_res.status_code == 200
    assert del_res.json()["status"] == "deleted"
