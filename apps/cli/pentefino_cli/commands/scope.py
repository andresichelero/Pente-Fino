from __future__ import annotations

import json
from pathlib import Path
from typing import Optional
import typer
from sqlalchemy import select

from pentefino_cli.db import get_program_by_slug, record_audit_event, run_async
from pentefino_cli.formatters.json_output import print_json
from pentefino_cli.formatters.tables import (
    print_error,
    print_scope_check_result,
    print_scope_rules_table,
    print_success,
)
from pentefino_domain.enums import AssetType, ScopeAction
from pentefino_domain.models import AuthorizationSnapshot, ScopeRule
from pentefino_domain.session import get_async_session
from pentefino_scope.engine import ScopeEngine
from pentefino_scope.enums import (
    AssetType as ScopeAssetType,
    ScopeAction as ScopeRuleAction,
)
from pentefino_scope.models import (
    AuthorizationSnapshot as ScopeAuthSnapshot,
    ScopeRule as ScopeEngineRule,
    ScopeTarget,
)

app = typer.Typer(help="Manage and evaluate scope rules and target authorization.")


def _infer_asset_type(pattern: str) -> str:
    """Infer the asset type from pattern string if not explicitly given."""
    pattern = pattern.strip()
    if pattern.startswith("*."):
        return AssetType.WILDCARD_DOMAIN.value
    if pattern.startswith("http://") or pattern.startswith("https://") or ("/" in pattern and "/" not in pattern.split(".")[0]):
        # Check if CIDR
        import ipaddress
        try:
            ipaddress.ip_network(pattern, strict=False)
            return AssetType.CIDR.value
        except ValueError:
            return AssetType.URL.value
    import ipaddress
    try:
        ipaddress.ip_address(pattern)
        return AssetType.IP.value
    except ValueError:
        pass
    try:
        ipaddress.ip_network(pattern, strict=False)
        return AssetType.CIDR.value
    except ValueError:
        pass
    return AssetType.DOMAIN.value


@app.command("add")
def add_scope(
    ctx: typer.Context,
    program: str = typer.Option(
        ..., "--program", "-p", help="Target program slug."
    ),
    allow: Optional[str] = typer.Option(
        None, "--allow", help="Pattern to authorize (in-scope)."
    ),
    deny: Optional[str] = typer.Option(
        None, "--deny", help="Pattern to explicitly forbid (out-of-scope)."
    ),
    asset_type: Optional[str] = typer.Option(
        None, "--asset-type", "--type", help="Asset type (domain, wildcard_domain, hostname, url, cidr, ip)."
    ),
    ports: Optional[str] = typer.Option(
        None, "--ports", help="Comma-separated list of allowed ports (e.g. 80,443,8443)."
    ),
    denied_paths: Optional[str] = typer.Option(
        None, "--denied-paths", help="Comma-separated list of denied URL paths (e.g. /admin,/logout)."
    ),
    priority: Optional[int] = typer.Option(
        None, "--priority", help="Evaluation priority (lower values take higher precedence)."
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Format output as JSON."
    ),
) -> None:
    """Add explicit allow and/or deny scope rules to a program."""
    is_json = json_output or (ctx.obj and ctx.obj.get("json", False))

    if not allow and not deny:
        msg = "At least one of --allow or --deny must be specified."
        if is_json:
            print_json({"status": "error", "error": msg})
        else:
            print_error(msg)
        raise typer.Exit(code=1)

    parsed_ports = None
    if ports:
        try:
            parsed_ports = [int(p.strip()) for p in ports.split(",") if p.strip()]
        except ValueError:
            msg = f"Invalid ports specification: '{ports}'. Must be comma-separated integers."
            if is_json:
                print_json({"status": "error", "error": msg})
            else:
                print_error(msg)
            raise typer.Exit(code=1)

    parsed_paths = None
    if denied_paths:
        parsed_paths = [p.strip() for p in denied_paths.split(",") if p.strip()]

    async def _add_rules() -> dict:
        async with get_async_session() as session:
            prog = await get_program_by_slug(session, program)
            if not prog:
                return {"error": f"Program '{program}' not found."}

            created_rules = []

            # Add allow rule if requested
            if allow:
                inferred_type = asset_type or _infer_asset_type(allow)
                prio = priority if priority is not None else 100
                allow_rule = ScopeRule(
                    program_id=prog.id,
                    pattern=allow.strip(),
                    action=ScopeAction.ALLOW.value,
                    asset_type=inferred_type,
                    priority=prio,
                    allowed_ports=parsed_ports,
                    denied_paths=parsed_paths,
                )
                session.add(allow_rule)
                await session.flush()
                await record_audit_event(
                    session=session,
                    event_type="cli.scope.add",
                    object_type="scope_rule",
                    object_id=allow_rule.id,
                    payload={
                        "program_slug": prog.slug,
                        "action": "allow",
                        "pattern": allow.strip(),
                        "asset_type": inferred_type,
                        "priority": prio,
                    },
                )
                created_rules.append(allow_rule)

            # Add deny rule if requested
            if deny:
                inferred_type = asset_type or _infer_asset_type(deny)
                prio = priority if priority is not None else 10  # Deny takes higher priority by default
                deny_rule = ScopeRule(
                    program_id=prog.id,
                    pattern=deny.strip(),
                    action=ScopeAction.DENY.value,
                    asset_type=inferred_type,
                    priority=prio,
                    allowed_ports=parsed_ports,
                    denied_paths=parsed_paths,
                )
                session.add(deny_rule)
                await session.flush()
                await record_audit_event(
                    session=session,
                    event_type="cli.scope.add",
                    object_type="scope_rule",
                    object_id=deny_rule.id,
                    payload={
                        "program_slug": prog.slug,
                        "action": "deny",
                        "pattern": deny.strip(),
                        "asset_type": inferred_type,
                        "priority": prio,
                    },
                )
                created_rules.append(deny_rule)

            await session.commit()

            return {
                "status": "added",
                "program": prog.slug,
                "rules": [
                    {
                        "id": str(r.id),
                        "action": r.action,
                        "pattern": r.pattern,
                        "asset_type": r.asset_type,
                        "priority": r.priority,
                        "allowed_ports": r.allowed_ports,
                        "denied_paths": r.denied_paths,
                    }
                    for r in created_rules
                ],
            }

    result = run_async(_add_rules())

    if "error" in result:
        if is_json:
            print_json({"status": "error", "error": result["error"]})
        else:
            print_error(result["error"])
        raise typer.Exit(code=1)

    if is_json:
        print_json(result)
    else:
        class _RuleView:
            def __init__(self, d: dict):
                self.action = d["action"]
                self.pattern = d["pattern"]
                self.asset_type = d["asset_type"]
                self.priority = d["priority"]
                self.allowed_ports = d["allowed_ports"]
                self.denied_paths = d["denied_paths"]

        items = [_RuleView(d) for d in result["rules"]]
        print_scope_rules_table(result["program"], items)


@app.command("import")
def import_scope(
    ctx: typer.Context,
    program: str = typer.Option(
        ..., "--program", "-p", help="Target program slug."
    ),
    file_path: Path = typer.Option(
        ..., "--file", "-f", help="Path to scope file (JSON or line-delimited text)."
    ),
    format_type: str = typer.Option(
        "generic", "--format", help="Scope file format (generic, h1, bugcrowd)."
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Format output as JSON."
    ),
) -> None:
    """Import scope rules from a file in bulk."""
    is_json = json_output or (ctx.obj and ctx.obj.get("json", False))

    if not file_path.exists():
        msg = f"File not found: {file_path}"
        if is_json:
            print_json({"status": "error", "error": msg})
        else:
            print_error(msg)
        raise typer.Exit(code=1)

    content = file_path.read_text(encoding="utf-8")
    raw_rules: list[dict] = []

    try:
        parsed_json = json.loads(content)
        if isinstance(parsed_json, list):
            for item in parsed_json:
                if isinstance(item, str):
                    raw_rules.append({"pattern": item.strip()})
                elif isinstance(item, dict):
                    raw_rules.append(item)
        elif isinstance(parsed_json, dict):
            # Check for HackerOne format
            if "targets" in parsed_json and "in_scope" in parsed_json["targets"]:
                for t in parsed_json["targets"]["in_scope"]:
                    raw_rules.append({
                        "pattern": t.get("asset_identifier", ""),
                        "action": "allow",
                        "asset_type": t.get("asset_type", "domain"),
                    })
                for t in parsed_json["targets"].get("out_of_scope", []):
                    raw_rules.append({
                        "pattern": t.get("asset_identifier", ""),
                        "action": "deny",
                        "asset_type": t.get("asset_type", "domain"),
                    })
            elif "rules" in parsed_json:
                raw_rules = parsed_json["rules"]
    except json.JSONDecodeError:
        # Line-delimited plain text
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("!"):
                raw_rules.append({"pattern": line[1:].strip(), "action": "deny"})
            else:
                raw_rules.append({"pattern": line, "action": "allow"})

    async def _import_all() -> dict:
        async with get_async_session() as session:
            prog = await get_program_by_slug(session, program)
            if not prog:
                return {"error": f"Program '{program}' not found."}

            created_rules = []
            for item in raw_rules:
                pat = item.get("pattern", "").strip()
                if not pat:
                    continue
                act = item.get("action", "allow").lower()
                atype = item.get("asset_type") or _infer_asset_type(pat)
                prio = item.get("priority", 10 if act == "deny" else 100)

                rule = ScopeRule(
                    program_id=prog.id,
                    pattern=pat,
                    action=act,
                    asset_type=atype,
                    priority=prio,
                )
                session.add(rule)
                created_rules.append(rule)

            await session.flush()
            await record_audit_event(
                session=session,
                event_type="cli.scope.import",
                object_type="program",
                object_id=prog.id,
                payload={
                    "program_slug": prog.slug,
                    "imported_count": len(created_rules),
                    "file": str(file_path),
                },
            )
            await session.commit()
            return {
                "status": "imported",
                "program": prog.slug,
                "count": len(created_rules),
            }

    result = run_async(_import_all())
    if "error" in result:
        if is_json:
            print_json({"status": "error", "error": result["error"]})
        else:
            print_error(result["error"])
        raise typer.Exit(code=1)

    if is_json:
        print_json(result)
    else:
        print_success(f"Successfully imported {result['count']} scope rules into '{result['program']}'.")


@app.command("check")
def check_scope(
    ctx: typer.Context,
    program: str = typer.Option(
        ..., "--program", "-p", help="Target program slug."
    ),
    target: str = typer.Option(
        ..., "--target", "-t", help="Target URL or domain to evaluate against active scope rules."
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Format output as JSON."
    ),
) -> None:
    """Interactively evaluate a target against the 7-tier fail-closed scope engine."""
    is_json = json_output or (ctx.obj and ctx.obj.get("json", False))

    async def _evaluate() -> dict:
        async with get_async_session() as session:
            prog = await get_program_by_slug(session, program)
            if not prog:
                return {"error": f"Program '{program}' not found."}

            # Fetch active scope rules
            rules_stmt = select(ScopeRule).where(ScopeRule.program_id == prog.id).order_by(ScopeRule.priority.asc())
            rules_res = await session.execute(rules_stmt)
            db_rules = rules_res.scalars().all()

            # Fetch latest auth snapshot
            auth_stmt = (
                select(AuthorizationSnapshot)
                .where(AuthorizationSnapshot.program_id == prog.id)
                .order_by(AuthorizationSnapshot.created_at.desc())
            )
            auth_res = await session.execute(auth_stmt)
            db_auth = auth_res.scalar_one_or_none()

            # Convert to scope engine models
            engine_rules = []
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

            engine_snapshot = None
            if db_auth:
                engine_snapshot = ScopeAuthSnapshot(
                    id=db_auth.id,
                    program_id=db_auth.program_id,
                    source_url=db_auth.source_url,
                    policy_hash=db_auth.policy_hash,
                    rules_json=db_auth.rules_json,
                    valid_from=db_auth.valid_from,
                    valid_until=db_auth.valid_until,
                )

            engine = ScopeEngine(
                snapshot=engine_snapshot,
                rules=engine_rules,
                environment_class=prog.platform if prog.platform == "lab" else "bounty",
            )

            scope_target = ScopeTarget.from_url(target)
            decision = engine.evaluate_target(scope_target)

            return {
                "allowed": decision.allowed,
                "matched_tier": decision.matched_tier.value,
                "reason": decision.reason,
                "matched_rule_id": str(decision.matched_rule_id) if decision.matched_rule_id else None,
                "matched_pattern": decision.matched_pattern,
                "resolved_ip": decision.resolved_ip,
                "target_canonical": decision.target_canonical,
            }

    data = run_async(_evaluate())
    if "error" in data:
        if is_json:
            print_json({"status": "error", "error": data["error"]})
        else:
            print_error(data["error"])
        raise typer.Exit(code=1)

    if is_json:
        print_json(data)
    else:
        class _DecisionView:
            pass
        d = _DecisionView()
        d.allowed = data["allowed"]
        d.matched_tier = data["matched_tier"]
        d.reason = data["reason"]
        d.matched_rule_id = data["matched_rule_id"]
        d.matched_pattern = data["matched_pattern"]
        d.resolved_ip = data["resolved_ip"]
        print_scope_check_result(d)


@app.command("list")
def list_scope(
    ctx: typer.Context,
    program: str = typer.Option(
        ..., "--program", "-p", help="Target program slug."
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Format output as JSON."
    ),
) -> None:
    """List all scope rules configured for a program."""
    is_json = json_output or (ctx.obj and ctx.obj.get("json", False))

    async def _list() -> dict:
        async with get_async_session() as session:
            prog = await get_program_by_slug(session, program)
            if not prog:
                return {"error": f"Program '{program}' not found."}

            stmt = select(ScopeRule).where(ScopeRule.program_id == prog.id).order_by(ScopeRule.priority.asc())
            result = await session.execute(stmt)
            rules = result.scalars().all()

            return {
                "program": prog.slug,
                "rules": [
                    {
                        "id": str(r.id),
                        "action": r.action,
                        "pattern": r.pattern,
                        "asset_type": r.asset_type,
                        "priority": r.priority,
                        "allowed_ports": r.allowed_ports,
                        "denied_paths": r.denied_paths,
                    }
                    for r in rules
                ],
            }

    data = run_async(_list())
    if "error" in data:
        if is_json:
            print_json({"status": "error", "error": data["error"]})
        else:
            print_error(data["error"])
        raise typer.Exit(code=1)

    if is_json:
        print_json(data["rules"])
    else:
        class _RuleView:
            def __init__(self, d: dict):
                self.action = d["action"]
                self.pattern = d["pattern"]
                self.asset_type = d["asset_type"]
                self.priority = d["priority"]
                self.allowed_ports = d["allowed_ports"]
                self.denied_paths = d["denied_paths"]

        items = [_RuleView(d) for d in data["rules"]]
        print_scope_rules_table(data["program"], items)
