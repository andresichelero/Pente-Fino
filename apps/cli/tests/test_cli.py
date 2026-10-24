from __future__ import annotations

import json
import uuid
from typer.testing import CliRunner

from pentefino_cli.db import run_async
from pentefino_cli.main import app
from pentefino_domain.enums import FindingConfidence, FindingStatus, ImpactClass
from sqlalchemy import select
from pentefino_domain.models import Asset, Finding, Program, TemplateCatalog
from pentefino_domain.session import get_async_session


def test_cli_help(runner: CliRunner) -> None:
    """Verify top-level CLI help command displays all subcommands."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "program" in result.output
    assert "scope" in result.output
    assert "auth" in result.output
    assert "asset" in result.output
    assert "run" in result.output
    assert "finding" in result.output


def test_cli_version(runner: CliRunner) -> None:
    """Verify version command output in text and JSON."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "pentefino version" in result.output

    json_result = runner.invoke(app, ["--version", "--json"])
    assert json_result.exit_code == 0
    parsed = json.loads(json_result.output)
    assert parsed["name"] == "pentefino"
    assert "version" in parsed


def test_program_lifecycle(runner: CliRunner) -> None:
    """Verify program creation, duplication detection, and listing in Rich and JSON."""
    slug = f"test-bounty-{uuid.uuid4().hex[:8]}"
    name = "Automated Test Bounty"

    # Create program
    create_res = runner.invoke(app, ["program", "create", "--slug", slug, "--name", name])
    assert create_res.exit_code == 0
    assert "Program Created" in create_res.output
    assert slug in create_res.output

    # Duplicate creation must fail
    dup_res = runner.invoke(app, ["program", "create", "--slug", slug, "--name", name])
    assert dup_res.exit_code == 1
    assert "already exists" in dup_res.output

    # List programs (JSON)
    list_json_res = runner.invoke(app, ["program", "list", "--json"])
    assert list_json_res.exit_code == 0
    programs = json.loads(list_json_res.output)
    assert any(p["slug"] == slug for p in programs)

    # Show program
    show_res = runner.invoke(app, ["program", "show", "--slug", slug])
    assert show_res.exit_code == 0
    assert slug in show_res.output


def test_program_validation(runner: CliRunner) -> None:
    """Verify invalid platform or state arguments are rejected."""
    slug = f"invalid-val-{uuid.uuid4().hex[:8]}"

    res_plat = runner.invoke(
        app, ["program", "create", "--slug", slug, "--name", "Val Test", "--platform", "invalid_plat"]
    )
    assert res_plat.exit_code == 1
    assert "Invalid platform" in res_plat.output

    res_state = runner.invoke(
        app, ["program", "create", "--slug", slug, "--name", "Val Test", "--state", "invalid_state"]
    )
    assert res_state.exit_code == 1
    assert "Invalid state" in res_state.output


def test_scope_and_auth_workflow(runner: CliRunner, tmp_path) -> None:
    """Verify scope rules addition, authorization snapshot registration, and interactive scope check."""
    slug = f"scope-auth-{uuid.uuid4().hex[:8]}"
    runner.invoke(app, ["program", "create", "--slug", slug, "--name", "Scope Auth Test"])

    # Add allow and deny rules
    scope_add_res = runner.invoke(
        app,
        ["scope", "add", "--program", slug, "--allow", "*.testcorp.com", "--deny", "secret.testcorp.com"],
    )
    assert scope_add_res.exit_code == 0
    assert "*.testcorp.com" in scope_add_res.output
    assert "secret.testcorp" in scope_add_res.output

    # Check before auth registration -> should be DENIED due to missing authorization snapshot
    check_pre_auth = runner.invoke(
        app, ["scope", "check", "--program", slug, "--target", "public.testcorp.com", "--json"]
    )
    assert check_pre_auth.exit_code == 0
    dec_pre = json.loads(check_pre_auth.output)
    assert dec_pre["allowed"] is False
    assert dec_pre["matched_tier"] == "EXPIRED_AUTH"

    # Register authorization snapshot
    rules_doc = tmp_path / "rules.json"
    rules_doc.write_text(json.dumps({"terms": "safe harbor terms", "version": "1.0"}), encoding="utf-8")

    auth_reg_res = runner.invoke(
        app, ["auth", "register", "--program", slug, "--rules-file", str(rules_doc), "--valid-from", "now"]
    )
    assert auth_reg_res.exit_code == 0
    assert "Authorization Snapshot Registered" in auth_reg_res.output

    # Verify authorization snapshot
    auth_ver_res = runner.invoke(app, ["auth", "verify", "--program", slug, "--json"])
    assert auth_ver_res.exit_code == 0
    ver_data = json.loads(auth_ver_res.output)
    assert ver_data["verified"] is True

    # Check target that is in-scope wildcard
    check_allow = runner.invoke(
        app, ["scope", "check", "--program", slug, "--target", "public.testcorp.com", "--json"]
    )
    assert check_allow.exit_code == 0
    dec_allow = json.loads(check_allow.output)
    assert dec_allow["allowed"] is True
    assert dec_allow["matched_tier"] == "WILDCARD_ALLOW"

    # Check target that matches explicit deny
    check_deny = runner.invoke(
        app, ["scope", "check", "--program", slug, "--target", "secret.testcorp.com", "--json"]
    )
    assert check_deny.exit_code == 0
    dec_deny = json.loads(check_deny.output)
    assert dec_deny["allowed"] is False
    assert dec_deny["matched_tier"] == "EXPLICIT_DENY"


def test_scope_import(runner: CliRunner, tmp_path) -> None:
    """Verify importing scope rules from line-delimited text and JSON files."""
    slug = f"import-test-{uuid.uuid4().hex[:8]}"
    runner.invoke(app, ["program", "create", "--slug", slug, "--name", "Import Test"])

    import_file = tmp_path / "scope_list.txt"
    import_file.write_text("app1.example.org\napp2.example.org\n!denied.example.org\n", encoding="utf-8")

    res = runner.invoke(app, ["scope", "import", "--program", slug, "--file", str(import_file)])
    assert res.exit_code == 0
    assert "Successfully imported 3 scope rules" in res.output

    # Verify rules are in DB via list --json
    list_res = runner.invoke(app, ["scope", "list", "--program", slug, "--json"])
    assert list_res.exit_code == 0
    rules = json.loads(list_res.output)
    assert len(rules) == 3


def test_asset_and_run_commands(runner: CliRunner) -> None:
    """Verify scan trigger, asset inspection, and run status."""
    slug = f"run-test-{uuid.uuid4().hex[:8]}"
    runner.invoke(app, ["program", "create", "--slug", slug, "--name", "Run Test"])

    # Trigger scan run
    trigger_res = runner.invoke(
        app, ["run", "trigger", "--program", slug, "--asset", "target.mycorp.org", "--module", "nuclei", "--json"]
    )
    assert trigger_res.exit_code == 0
    run_info = json.loads(trigger_res.output)
    assert run_info["status"] == "queued"
    run_id = run_info["run_id"]

    # Verify run status
    status_res = runner.invoke(app, ["run", "status", run_id, "--json"])
    assert status_res.exit_code == 0
    status_data = json.loads(status_res.output)
    assert status_data["run_id"] == run_id
    assert status_data["payload"]["module"] == "nuclei"

    # Inspect assets
    asset_res = runner.invoke(app, ["asset", "inspect", "--program", slug, "--json"])
    assert asset_res.exit_code == 0
    assets = json.loads(asset_res.output)
    assert any(a["canonical_key"] == "target.mycorp.org" for a in assets)


def test_finding_query_and_show(runner: CliRunner) -> None:
    """Verify querying and inspecting findings with joined detector templates."""
    slug = f"find-test-{uuid.uuid4().hex[:8]}"
    runner.invoke(app, ["program", "create", "--slug", slug, "--name", "Finding Test"])

    finding_id = uuid.uuid4()
    template_id = f"cve-2026-test-{uuid.uuid4().hex[:6]}"

    async def _seed_data():
        async with get_async_session() as session:
            stmt = select(Program).where(Program.slug == slug)
            res = await session.execute(stmt)
            prog = res.scalar_one()

            # Seed template
            tpl = TemplateCatalog(
                id=template_id,
                upstream_revision="v1.0",
                bundle_hash="a" * 64,
                name="CVE-2026 Test Disclosure",
                protocol="http",
                impact_class=ImpactClass.SAFE_READ_ONLY.value,
                severity="critical",
                cve_id="CVE-2026-9999",
                raw_yaml="id: test\ninfo:\n  name: test",
            )
            session.add(tpl)

            # Seed asset
            asset = Asset(
                program_id=prog.id,
                canonical_key="vulnerable.example.org",
                asset_type="domain",
                scope_state="in_scope_explicit",
            )
            session.add(asset)
            await session.flush()

            # Seed finding
            finding = Finding(
                id=finding_id,
                program_id=prog.id,
                asset_id=asset.id,
                dedup_key="b" * 64,
                detector_id=template_id,
                advisory_id="GHSA-test",
                status=FindingStatus.VALIDATED.value,
                evidence_level="E2",
                confidence=FindingConfidence.HIGH.value,
            )
            session.add(finding)
            await session.commit()

    run_async(_seed_data())

    # Query finding with JSON output
    query_res = runner.invoke(app, ["finding", "query", "--program", slug, "--severity", "critical", "--json"])
    assert query_res.exit_code == 0
    findings = json.loads(query_res.output)
    assert len(findings) == 1
    assert findings[0]["detector_id"] == template_id
    assert findings[0]["severity"] == "critical"
    assert findings[0]["status"] == "validated"

    # Show finding
    show_res = runner.invoke(app, ["finding", "show", str(finding_id), "--json"])
    assert show_res.exit_code == 0
    f_detail = json.loads(show_res.output)
    assert f_detail["id"] == str(finding_id)
    assert f_detail["detector"]["name"] == "CVE-2026 Test Disclosure"


def test_scope_ports_and_paths(runner: CliRunner) -> None:
    """Verify scope rules with explicit ports, denied paths, and error on malformed ports."""
    slug = f"ports-paths-{uuid.uuid4().hex[:8]}"
    runner.invoke(app, ["program", "create", "--slug", slug, "--name", "Ports Test"])

    # Malformed ports must error with exit code 1
    err_res = runner.invoke(app, ["scope", "add", "--program", slug, "--allow", "api.example.com", "--ports", "80,abc"])
    assert err_res.exit_code == 1
    assert "Invalid ports" in err_res.output

    # Valid ports and denied paths
    ok_res = runner.invoke(
        app,
        [
            "scope",
            "add",
            "--program",
            slug,
            "--allow",
            "api.example.com",
            "--ports",
            "80,443,8443",
            "--denied-paths",
            "/admin,/oauth/revoke",
            "--json",
        ],
    )
    assert ok_res.exit_code == 0
    data = json.loads(ok_res.output)
    assert len(data["rules"]) == 1
    assert data["rules"][0]["allowed_ports"] == [80, 443, 8443]
    assert data["rules"][0]["denied_paths"] == ["/admin", "/oauth/revoke"]


def test_global_json_flag_placement(runner: CliRunner) -> None:
    """Verify --json works before subcommand and after subcommand."""
    # Before subcommand: pentefino --json program list
    res_before = runner.invoke(app, ["--json", "program", "list"])
    assert res_before.exit_code == 0
    parsed_before = json.loads(res_before.output)
    assert isinstance(parsed_before, list)

    # After subcommand: pentefino program list --json
    res_after = runner.invoke(app, ["program", "list", "--json"])
    assert res_after.exit_code == 0
    parsed_after = json.loads(res_after.output)
    assert isinstance(parsed_after, list)


def test_scope_anti_ssrf_rejection(runner: CliRunner, tmp_path) -> None:
    """Verify that private IP / cloud metadata is rejected by scope check under bounty environment."""
    slug = f"ssrf-test-{uuid.uuid4().hex[:8]}"
    runner.invoke(app, ["program", "create", "--slug", slug, "--name", "SSRF Test"])

    # Allow everything pattern
    runner.invoke(app, ["scope", "add", "--program", slug, "--allow", "*", "--asset-type", "domain"])

    # Register auth
    doc = tmp_path / "auth.txt"
    doc.write_text("ssrf authorization", encoding="utf-8")
    runner.invoke(app, ["auth", "register", "--program", slug, "--rules-file", str(doc)])

    # Check loopback
    res_loopback = runner.invoke(app, ["scope", "check", "--program", slug, "--target", "http://127.0.0.1:8080", "--json"])
    assert res_loopback.exit_code == 0
    dec_loopback = json.loads(res_loopback.output)
    assert dec_loopback["allowed"] is False
    assert "PROHIBITED_IP_SPACE" in dec_loopback["reason"]

    # Check cloud metadata IP
    res_meta = runner.invoke(app, ["scope", "check", "--program", slug, "--target", "http://169.254.169.254/latest", "--json"])
    assert res_meta.exit_code == 0
    dec_meta = json.loads(res_meta.output)
    assert dec_meta["allowed"] is False
    assert "PROHIBITED_IP_SPACE" in dec_meta["reason"]


def test_finding_export(runner: CliRunner) -> None:
    """Verify exporting findings in json and markdown formats."""
    slug = f"export-prog-{uuid.uuid4().hex[:8]}"
    runner.invoke(app, ["program", "create", "--slug", slug, "--name", "Export Test"])

    # JSON export
    res_json = runner.invoke(app, ["finding", "export", "--program", slug, "--format", "json"])
    assert res_json.exit_code == 0
    data = json.loads(res_json.output)
    assert data["program"] == slug
    assert "findings" in data

    # Markdown export
    res_md = runner.invoke(app, ["finding", "export", "--program", slug, "--format", "markdown"])
    assert res_md.exit_code == 0
    assert f"# Findings Report for {slug}" in res_md.output


def test_api_and_gui_cli_commands(runner: CliRunner) -> None:
    """Verify pentefino api and pentefino gui dry-run CLI commands."""
    res_api = runner.invoke(app, ["api", "--dry-run", "--port", "8005", "--json"])
    assert res_api.exit_code == 0
    api_data = json.loads(res_api.output)
    assert api_data["status"] == "ready"
    assert api_data["port"] == 8005
    assert api_data["url"] == "http://127.0.0.1:8005"

    res_gui = runner.invoke(app, ["gui", "--dry-run", "--api-port", "8005", "--gui-port", "4325", "--json"])
    assert res_gui.exit_code == 0
    gui_data = json.loads(res_gui.output)
    assert gui_data["status"] == "ready"
    assert gui_data["api_url"] == "http://127.0.0.1:8005"
    assert gui_data["gui_url"] == "http://127.0.0.1:4325"

