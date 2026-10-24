from __future__ import annotations

from typing import Optional
import typer
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from pentefino_cli.db import get_program_by_slug, record_audit_event, run_async
from pentefino_cli.formatters.json_output import print_json
from pentefino_cli.formatters.tables import (
    print_error,
    print_program_created,
    print_programs_table,
)
from pentefino_domain.enums import ProgramPlatform, ProgramState
from pentefino_domain.models import Program
from pentefino_domain.session import get_async_session

app = typer.Typer(help="Manage bug bounty programs and governance policies.")


@app.command("create")
def create_program(
    ctx: typer.Context,
    slug: str = typer.Option(
        ..., "--slug", "-s", help="Unique URL-friendly slug identifier for the program."
    ),
    name: str = typer.Option(
        ..., "--name", "-n", help="Display name of the bug bounty program."
    ),
    platform: str = typer.Option(
        ProgramPlatform.HACKERONE.value,
        "--platform",
        "-p",
        help="Bug bounty platform (hackerone, bugcrowd, intigriti, private, lab).",
    ),
    policy: str = typer.Option(
        "bounty-safe",
        "--policy",
        help="Default policy ID associated with the program.",
    ),
    state: str = typer.Option(
        ProgramState.ACTIVE.value,
        "--state",
        help="Initial state of the program (active, suspended, archived).",
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Format output as JSON."
    ),
) -> None:
    """Create a new bug bounty program record."""
    is_json = json_output or (ctx.obj and ctx.obj.get("json", False))

    # Validate platform and state
    valid_platforms = [p.value for p in ProgramPlatform]
    if platform not in valid_platforms:
        msg = f"Invalid platform '{platform}'. Must be one of: {', '.join(valid_platforms)}"
        if is_json:
            print_json({"status": "error", "error": msg})
        else:
            print_error(msg)
        raise typer.Exit(code=1)

    valid_states = [s.value for s in ProgramState]
    if state not in valid_states:
        msg = f"Invalid state '{state}'. Must be one of: {', '.join(valid_states)}"
        if is_json:
            print_json({"status": "error", "error": msg})
        else:
            print_error(msg)
        raise typer.Exit(code=1)

    async def _create() -> dict:
        async with get_async_session() as session:
            existing = await get_program_by_slug(session, slug)
            if existing:
                return {
                    "error": f"Program with slug '{slug}' already exists (ID: {existing.id})."
                }

            program = Program(
                slug=slug,
                name=name,
                platform=platform,
                state=state,
                default_policy_id=policy,
            )
            session.add(program)
            await session.flush()

            await record_audit_event(
                session=session,
                event_type="cli.program.create",
                object_type="program",
                object_id=program.id,
                payload={
                    "slug": program.slug,
                    "name": program.name,
                    "platform": program.platform,
                    "state": program.state,
                    "policy": program.default_policy_id,
                },
            )
            await session.commit()
            return {
                "status": "created",
                "id": str(program.id),
                "slug": program.slug,
                "name": program.name,
                "platform": program.platform,
                "state": program.state,
                "default_policy_id": program.default_policy_id,
                "created_at": program.created_at.isoformat() if program.created_at else None,
            }

    result = run_async(_create())

    if "error" in result:
        if is_json:
            print_json({"status": "error", "error": result["error"]})
        else:
            print_error(result["error"])
        raise typer.Exit(code=1)

    if is_json:
        print_json(result)
    else:
        # Create a lightweight dummy-like object for table formatter
        class _Prog:
            pass
        p = _Prog()
        p.id = result["id"]
        p.slug = result["slug"]
        p.name = result["name"]
        p.platform = result["platform"]
        p.state = result["state"]
        p.default_policy_id = result["default_policy_id"]
        print_program_created(p)


@app.command("list")
def list_programs(
    ctx: typer.Context,
    state: Optional[str] = typer.Option(
        None, "--state", help="Filter by program state (active, suspended, archived)."
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Format output as JSON."
    ),
) -> None:
    """List all registered bug bounty programs."""
    is_json = json_output or (ctx.obj and ctx.obj.get("json", False))

    async def _list() -> list[dict]:
        async with get_async_session() as session:
            stmt = select(Program).order_by(Program.created_at.desc())
            if state:
                stmt = stmt.where(Program.state == state)
            result = await session.execute(stmt)
            programs = result.scalars().all()

            output = []
            for p in programs:
                output.append({
                    "id": str(p.id),
                    "slug": p.slug,
                    "name": p.name,
                    "platform": p.platform,
                    "state": p.state,
                    "default_policy_id": p.default_policy_id,
                    "created_at": p.created_at.isoformat() if p.created_at else None,
                })
            return output

    programs_data = run_async(_list())

    if is_json:
        print_json(programs_data)
    else:
        class _ProgItem:
            def __init__(self, d: dict):
                self.id = d["id"]
                self.slug = d["slug"]
                self.name = d["name"]
                self.platform = d["platform"]
                self.state = d["state"]
                self.default_policy_id = d["default_policy_id"]
                from datetime import datetime
                self.created_at = (
                    datetime.fromisoformat(d["created_at"])
                    if d["created_at"]
                    else None
                )

        items = [_ProgItem(d) for d in programs_data]
        print_programs_table(items)


@app.command("show")
def show_program(
    ctx: typer.Context,
    slug: str = typer.Option(
        ..., "--slug", "-s", help="Unique slug identifier of the program."
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Format output as JSON."
    ),
) -> None:
    """Show detailed metadata and scope statistics for a program."""
    is_json = json_output or (ctx.obj and ctx.obj.get("json", False))

    async def _show() -> dict:
        async with get_async_session() as session:
            stmt = (
                select(Program)
                .options(
                    selectinload(Program.scope_rules),
                    selectinload(Program.authorization_snapshots),
                    selectinload(Program.assets),
                )
                .where(Program.slug == slug)
            )
            result = await session.execute(stmt)
            prog = result.scalar_one_or_none()
            if not prog:
                return {"error": f"Program '{slug}' not found."}

            return {
                "id": str(prog.id),
                "slug": prog.slug,
                "name": prog.name,
                "platform": prog.platform,
                "state": prog.state,
                "default_policy_id": prog.default_policy_id,
                "created_at": prog.created_at.isoformat() if prog.created_at else None,
                "scope_rules_count": len(prog.scope_rules),
                "assets_count": len(prog.assets),
                "snapshots_count": len(prog.authorization_snapshots),
            }

    data = run_async(_show())
    if "error" in data:
        if is_json:
            print_json({"status": "error", "error": data["error"]})
        else:
            print_error(data["error"])
        raise typer.Exit(code=1)

    if is_json:
        print_json(data)
    else:
        from rich.panel import Panel
        from rich.console import Console
        content = (
            f"[bold cyan]ID:[/bold cyan] {data['id']}\n"
            f"[bold cyan]Slug:[/bold cyan] {data['slug']}\n"
            f"[bold cyan]Name:[/bold cyan] {data['name']}\n"
            f"[bold cyan]Platform:[/bold cyan] {data['platform']}\n"
            f"[bold cyan]State:[/bold cyan] {data['state']}\n"
            f"[bold cyan]Default Policy:[/bold cyan] {data['default_policy_id']}\n"
            f"[bold cyan]Scope Rules:[/bold cyan] {data['scope_rules_count']}\n"
            f"[bold cyan]Assets:[/bold cyan] {data['assets_count']}\n"
            f"[bold cyan]Auth Snapshots:[/bold cyan] {data['snapshots_count']}"
        )
        Console().print(Panel(content, title=f"Program: {slug}", border_style="cyan"))
