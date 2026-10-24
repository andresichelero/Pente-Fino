"""Unit and integration test suite for Detection Planner and Hardened Nuclei Runner.

Verifies:
1. Technology-to-template matching against detected asset technologies.
2. SAFE_READ_ONLY impact class hard-gate enforcement.
3. Explicit pruning and exclusion of generic Edge CDN/WAF tags (Cloudflare, Akamai, etc.).
4. Optional severity and custom tag constraints.
5. Fallback baseline selection when no technologies are discovered.
6. DetectionPlan data contract and container path resolution.
7. Hardened Nuclei runner command construction, proxy routing, and surgical template passing.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock
import uuid

import pytest

from pentefino_detection.planner import (
    DetectionPlan,
    DetectionPlanner,
)
from pentefino_detection.runner import HardenedNucleiRunner
from pentefino_domain.enums import ImpactClass
from pentefino_domain.models.asset import Asset
from pentefino_domain.models.template import TemplateCatalog
from pentefino_runner import EphemeralRunner, RunConfig, RunResult


def make_template(
    id: str,
    name: str,
    impact_class: str = ImpactClass.SAFE_READ_ONLY.value,
    severity: str = "info",
    technologies: list[str] | None = None,
    tags: list[str] | None = None,
    protocol: str = "http",
) -> TemplateCatalog:
    """Helper factory for creating mock TemplateCatalog records."""
    return TemplateCatalog(
        id=id,
        name=name,
        upstream_revision="sha256-test-revision-12345",
        bundle_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        protocol=protocol,
        http_methods=["GET"],
        impact_class=impact_class,
        severity=severity,
        technologies=technologies or [],
        tags=tags or [],
        raw_yaml=f"id: {id}\ninfo:\n  name: {name}\n",
    )


# ============================================================================
# 1. Technology Matching & Filtering Tests
# ============================================================================


@pytest.mark.asyncio
async def test_planner_technology_matching():
    """Matches detected asset technologies strictly against catalog templates."""
    catalog = [
        make_template(
            "httpd-detect",
            "Apache HTTP Server Detection",
            technologies=["apache"],
            tags=["apache", "detect"],
        ),
        make_template(
            "nginx-version",
            "Nginx Version Disclosure",
            technologies=["nginx"],
            tags=["nginx", "version"],
        ),
        make_template(
            "wp-cve-1",
            "WordPress Core Vulnerability",
            technologies=["wordpress"],
            tags=["wordpress", "cve"],
        ),
        make_template(
            "jenkins-cli",
            "Jenkins CLI Deserialization",
            technologies=["jenkins"],
            tags=["jenkins", "rce"],
        ),
    ]

    planner = DetectionPlanner()
    plan = await planner.create_plan(
        asset="api.target.com",
        detected_technologies=["apache", "php"],
        templates=catalog,
    )

    # Only Apache template should be selected
    assert plan.selected_template_ids == ["httpd-detect"]
    assert plan.matched_technologies == ["apache"]
    assert plan.total_templates == 1
    assert "nginx-version" not in plan.selected_template_ids
    assert "wp-cve-1" not in plan.selected_template_ids
    assert "jenkins-cli" not in plan.selected_template_ids


@pytest.mark.asyncio
async def test_planner_impact_class_hard_gate():
    """Enforces SAFE_READ_ONLY impact class gate, excluding stateful, intrusive, or lab-only templates."""
    catalog = [
        make_template(
            "apache-safe-get",
            "Apache Safe Version Check",
            impact_class="safe_read_only",
            technologies=["apache"],
        ),
        make_template(
            "apache-stateful-post",
            "Apache Stateful Configuration Modifier",
            impact_class="stateful",
            technologies=["apache"],
        ),
        make_template(
            "apache-intrusive-dos",
            "Apache Slowloris DoS Intrusive",
            impact_class="intrusive",
            technologies=["apache"],
        ),
        make_template(
            "apache-lab-only-code",
            "Apache Local Lab Code Execution",
            impact_class="lab_only",
            technologies=["apache"],
        ),
    ]

    planner = DetectionPlanner()
    plan = await planner.create_plan(
        asset="target.com",
        detected_technologies=["apache"],
        max_impact_class=ImpactClass.SAFE_READ_ONLY,
        templates=catalog,
    )

    # Strictly only safe_read_only is permitted
    assert plan.selected_template_ids == ["apache-safe-get"]
    assert "apache-stateful-post" not in plan.selected_template_ids
    assert "apache-intrusive-dos" not in plan.selected_template_ids
    assert "apache-lab-only-code" not in plan.selected_template_ids


@pytest.mark.asyncio
async def test_planner_edge_cdn_waf_exclusion():
    """Explicitly prunes generic edge CDN/WAF tags (Cloudflare, Akamai, etc.) from detection plans."""
    catalog = [
        make_template(
            "cloudflare-bypass",
            "Cloudflare Origin IP Bypass",
            technologies=["cloudflare"],
            tags=["cloudflare", "bypass"],
        ),
        make_template(
            "akamai-waf-probe",
            "Akamai WAF Rule Probe",
            technologies=["akamai"],
            tags=["akamai", "waf"],
        ),
        make_template(
            "fastly-cache-poison",
            "Fastly Cache Header Probe",
            technologies=["fastly"],
            tags=["fastly"],
        ),
        make_template(
            "nginx-safe-cve",
            "Nginx Read-Only Traversal",
            technologies=["nginx"],
            tags=["nginx", "cve"],
        ),
    ]

    planner = DetectionPlanner()
    # Asset is behind Cloudflare and running Nginx
    plan = await planner.create_plan(
        asset="cloaked.bounty.target",
        detected_technologies=["cloudflare", "nginx", "akamai"],
        templates=catalog,
    )

    # Cloudflare, Akamai, and Fastly templates MUST be pruned
    assert "cloudflare-bypass" not in plan.selected_template_ids
    assert "akamai-waf-probe" not in plan.selected_template_ids
    assert "fastly-cache-poison" not in plan.selected_template_ids

    # Nginx template must be retained
    assert plan.selected_template_ids == ["nginx-safe-cve"]
    assert "cloudflare" not in plan.matched_technologies
    assert "akamai" not in plan.matched_technologies
    assert plan.matched_technologies == ["nginx"]


@pytest.mark.asyncio
async def test_planner_tag_and_severity_filters():
    """Filters matched templates by user-specified severity and custom tags."""
    catalog = [
        make_template(
            "apache-info-headers",
            "Apache Info Headers",
            severity="info",
            technologies=["apache"],
            tags=["apache", "headers"],
        ),
        make_template(
            "apache-medium-misconfig",
            "Apache Medium Misconfiguration",
            severity="medium",
            technologies=["apache"],
            tags=["apache", "misconfig"],
        ),
        make_template(
            "apache-high-cve",
            "Apache High CVE Path Traversal",
            severity="high",
            technologies=["apache"],
            tags=["apache", "cve"],
        ),
        make_template(
            "apache-critical-cve",
            "Apache Critical CVE Exploit",
            severity="critical",
            technologies=["apache"],
            tags=["apache", "cve"],
        ),
    ]

    planner = DetectionPlanner()

    # Filter 1: Only high or critical CVEs
    plan_cve = await planner.create_plan(
        asset="web.target.com",
        detected_technologies=["apache"],
        severity_filter=["high", "critical"],
        tag_filter=["cve"],
        templates=catalog,
    )
    assert set(plan_cve.selected_template_ids) == {
        "apache-high-cve",
        "apache-critical-cve",
    }

    # Filter 2: Comma-separated string filters
    plan_string_filters = await planner.create_plan(
        asset="web.target.com",
        detected_technologies=["apache"],
        severity_filter="critical",
        tag_filter="cve",
        templates=catalog,
    )
    assert plan_string_filters.selected_template_ids == ["apache-critical-cve"]


@pytest.mark.asyncio
async def test_planner_empty_technologies_fallback():
    """When no specific technologies are detected, selects generic baseline exposure templates."""
    catalog = [
        make_template(
            "ssl-weak-cipher",
            "Weak SSL Ciphers",
            technologies=[],
            tags=["ssl", "exposure"],
        ),
        make_template(
            "missing-csp-header",
            "Missing CSP Header",
            technologies=[],
            tags=["headers", "misconfig"],
        ),
        make_template(
            "wordpress-plugin-sqli",
            "WordPress Specific SQLi",
            technologies=["wordpress"],
            tags=["wordpress", "sqli"],
        ),
        make_template(
            "jenkins-admin-panel",
            "Jenkins Admin Panel",
            technologies=["jenkins"],
            tags=["jenkins"],
        ),
    ]

    planner = DetectionPlanner()

    # Case A: Empty list
    plan_empty = await planner.create_plan(
        asset="unknown-host.com",
        detected_technologies=[],
        templates=catalog,
    )
    assert set(plan_empty.selected_template_ids) == {
        "ssl-weak-cipher",
        "missing-csp-header",
    }
    assert "wordpress-plugin-sqli" not in plan_empty.selected_template_ids
    assert "jenkins-admin-panel" not in plan_empty.selected_template_ids

    # Case B: Only CDN tag detected (which is pruned to empty)
    plan_cdn_only = await planner.create_plan(
        asset="unknown-host.com",
        detected_technologies=["cloudflare"],
        templates=catalog,
    )
    assert set(plan_cdn_only.selected_template_ids) == {
        "ssl-weak-cipher",
        "missing-csp-header",
    }


@pytest.mark.asyncio
async def test_planner_plan_structure_and_asset_domain_object():
    """Validates DetectionPlan attributes when passed an Asset domain model."""
    prog_id = uuid.uuid4()
    asset_id = uuid.uuid4()

    asset_obj = Asset(
        id=asset_id,
        program_id=prog_id,
        canonical_key="api.example.com",
        asset_type="host",
        scope_state="in_scope_explicit",
    )

    catalog = [
        make_template(
            "apache-test",
            "Apache Test",
            technologies=["apache"],
            tags=["apache"],
        )
    ]

    planner = DetectionPlanner(templates_container_dir="/templates")
    plan = await planner.create_plan(
        asset=asset_obj,
        detected_technologies=["apache"],
        templates=catalog,
    )

    assert plan.program_id == prog_id
    assert plan.asset_id == asset_id
    assert plan.asset_canonical_key == "api.example.com"
    assert plan.target_url == "https://api.example.com"
    assert plan.selected_template_ids == ["apache-test"]
    assert plan.selected_template_paths == ["/templates/apache-test.yaml"]
    assert plan.total_templates == 1
    assert plan.estimated_requests == 2


@pytest.mark.asyncio
async def test_planner_database_session_integration():
    """Validates DetectionPlanner querying database through AsyncSession."""
    catalog = [
        make_template(
            "apache-db-test",
            "Apache DB Test",
            technologies=["apache"],
            tags=["apache"],
        )
    ]

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = catalog

    mock_session = AsyncMock()
    mock_session.execute.return_value = mock_result

    planner = DetectionPlanner(db_session=mock_session)
    plan = await planner.create_plan(
        asset="db.target.com",
        detected_technologies=["apache"],
    )

    assert mock_session.execute.called
    assert plan.selected_template_ids == ["apache-db-test"]


# ============================================================================
# 2. Hardened Nuclei Runner Tests
# ============================================================================


def test_hardened_nuclei_runner_flags_and_templates():
    """Verifies that HardenedNucleiRunner constructs strict sandboxed Docker invocation with surgical -t flags."""
    plan = DetectionPlan(
        program_id=uuid.uuid4(),
        asset_canonical_key="sub.target.com",
        target_url="https://sub.target.com",
        selected_template_ids=["apache-cve-1", "apache-cve-2"],
        selected_template_paths=[
            "/templates/cves/apache-cve-1.yaml",
            "/templates/cves/apache-cve-2.yaml",
        ],
        total_templates=2,
    )

    mock_runner = MagicMock(spec=EphemeralRunner)
    nuclei_runner = HardenedNucleiRunner(
        runner=mock_runner,
        templates_host_dir="D:/PenteFino/storage/templates",
        templates_container_dir="/templates",
        proxy_url="http://pentefino_proxy:8080",
    )

    config: RunConfig = nuclei_runner.build_run_config(plan)

    # 1. Hardening & Sandboxing
    assert config.read_only is True
    assert config.cap_drop == ["ALL"]
    assert config.security_opt == ["no-new-privileges:true"]
    assert config.tmpfs == {"/tmp": "rw,noexec,nosuid,size=64m"}
    assert config.cpus == 1.0
    assert config.memory == "512m"
    assert config.pids_limit == 128

    # 2. Network & Proxy Routing
    assert config.network == "pentefino_pentefino-net"
    assert config.http_proxy == "http://pentefino_proxy:8080"
    assert config.https_proxy == "http://pentefino_proxy:8080"

    # 3. Read-Only Volume Mount
    assert len(config.volumes) == 1
    assert config.volumes[0].container_path == "/templates"
    assert config.volumes[0].mode == "ro"

    # 4. Surgical Command Line: ONLY selected templates passed via -t
    cmd = config.command
    assert "-u" in cmd and cmd[cmd.index("-u") + 1] == "https://sub.target.com"
    assert "-jsonl" in cmd
    assert "-no-interactsh" in cmd
    assert "-rate-limit" in cmd and cmd[cmd.index("-rate-limit") + 1] == "1"

    # Extract all -t occurrences
    t_flags = [cmd[i + 1] for i, arg in enumerate(cmd) if arg == "-t"]
    assert t_flags == [
        "/templates/cves/apache-cve-1.yaml",
        "/templates/cves/apache-cve-2.yaml",
    ]
    # Invariant: Directory /templates itself is NEVER passed as a bulk scan argument
    assert "/templates" not in t_flags


@pytest.mark.asyncio
async def test_hardened_nuclei_runner_execution_and_parsing():
    """Verifies async execution and parsing of Nuclei NDJSON findings from stdout."""
    plan = DetectionPlan(
        program_id=uuid.uuid4(),
        asset_canonical_key="api.target.com",
        target_url="https://api.target.com",
        selected_template_ids=["apache-cve-1"],
        selected_template_paths=["/templates/apache-cve-1.yaml"],
        total_templates=1,
    )

    mock_runner = AsyncMock(spec=EphemeralRunner)
    mock_runner.run.return_value = RunResult(
        exit_code=0,
        stdout=(
            '{"template-id": "apache-cve-1", "matched-at": "https://api.target.com/icons", '
            '"info": {"severity": "high", "classification": {"cve-id": "CVE-2021-41773"}}}\n'
        ),
        stderr="",
    )

    nuclei_runner = HardenedNucleiRunner(runner=mock_runner)
    findings = await nuclei_runner.execute_scan(plan)

    assert len(findings) == 1
    assert findings[0]["template-id"] == "apache-cve-1"
    assert findings[0]["matched-at"] == "https://api.target.com/icons"
    assert findings[0]["info"]["severity"] == "high"


@pytest.mark.asyncio
async def test_hardened_nuclei_runner_empty_plan_short_circuit():
    """Short-circuits without spawning a container if plan has zero templates."""
    plan = DetectionPlan(
        program_id=uuid.uuid4(),
        asset_canonical_key="no-templates.target.com",
        target_url="https://no-templates.target.com",
        selected_template_ids=[],
        selected_template_paths=[],
        total_templates=0,
    )

    mock_runner = AsyncMock(spec=EphemeralRunner)
    nuclei_runner = HardenedNucleiRunner(runner=mock_runner)

    findings = await nuclei_runner.execute_scan(plan)
    assert findings == []
    # EphemeralRunner must not have been called
    assert not mock_runner.run.called
