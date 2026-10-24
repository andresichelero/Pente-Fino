from __future__ import annotations

import uuid
from typing import Optional
import typer
from sqlalchemy import select

from pentefino_cli.db import get_program_by_slug, record_audit_event, run_async
from pentefino_cli.formatters.json_output import print_json
from pentefino_cli.formatters.tables import print_error, print_run_triggered
from pentefino_domain.enums import AssetType, ScopeState
from pentefino_domain.models import Asset, AuditEvent
from pentefino_domain.session import get_async_session

app = typer.Typer(help="Trigger and monitor scanning and discovery runs.")


@app.command("trigger")
def trigger_run(
    ctx: typer.Context,
    program: str = typer.Option(
        ..., "--program", "-p", help="Target program slug."
    ),
    asset: str = typer.Option(
        ..., "--asset", "-a", help="Target canonical asset to scan (e.g. app.example.com)."
    ),
    module: str = typer.Option(
        "nuclei", "--module", "-m", help="Scanner engine module (nuclei, httpx, subfinder, dnsx)."
    ),
    tags: Optional[str] = typer.Option(
        None, "--tags", "-t", help="Optional tags or template filters (e.g. cve,exposure)."
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Format output as JSON."
    ),
) -> None:
    """Trigger an asynchronous scanner run against a scoped target asset."""
    is_json = json_output or (ctx.obj and ctx.obj.get("json", False))

    async def _trigger() -> dict:
        async with get_async_session() as session:
            prog = await get_program_by_slug(session, program)
            if not prog:
                return {"error": f"Program '{program}' not found."}

            clean_asset = asset.strip().lower()
            if "://" in clean_asset:
                import urllib.parse
                clean_asset = urllib.parse.urlsplit(clean_asset).netloc or clean_asset

            # Check or create asset
            stmt = select(Asset).where(
                Asset.program_id == prog.id,
                Asset.canonical_key == clean_asset,
            )
            res = await session.execute(stmt)
            target_asset = res.scalar_one_or_none()

            if not target_asset:
                # Determine asset type
                atype = AssetType.DOMAIN.value
                if "*" in clean_asset:
                    atype = AssetType.WILDCARD_DOMAIN.value
                target_asset = Asset(
                    program_id=prog.id,
                    canonical_key=clean_asset,
                    asset_type=atype,
                    scope_state=ScopeState.IN_SCOPE_EXPLICIT.value,
                )
                session.add(target_asset)
                await session.flush()

            run_id = uuid.uuid4()

            await record_audit_event(
                session=session,
                event_type="cli.run.trigger",
                object_type="run",
                object_id=run_id,
                payload={
                    "program_slug": prog.slug,
                    "target_asset": clean_asset,
                    "module": module,
                    "tags": tags,
                    "status": "queued",
                },
            )
            await session.commit()

            return {
                "status": "queued",
                "run_id": str(run_id),
                "program": prog.slug,
                "asset": clean_asset,
                "module": module,
                "tags": tags,
            }

    data = run_async(_trigger())
    if "error" in data:
        if is_json:
            print_json({"status": "error", "error": data["error"]})
        else:
            print_error(data["error"])
        raise typer.Exit(code=1)

    if is_json:
        print_json(data)
    else:
        print_run_triggered(data["run_id"], data["program"], data["asset"], data["module"])


@app.command("status")
def run_status(
    ctx: typer.Context,
    run_id: str = typer.Argument(
        ..., help="UUID of the scanner run."
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Format output as JSON."
    ),
) -> None:
    """Check the status of a scheduled scanner run."""
    is_json = json_output or (ctx.obj and ctx.obj.get("json", False))

    async def _status() -> dict:
        async with get_async_session() as session:
            stmt = (
                select(AuditEvent)
                .where(AuditEvent.object_type == "run", AuditEvent.object_id == run_id.strip())
                .order_by(AuditEvent.occurred_at.desc())
            )
            res = await session.execute(stmt)
            event = res.scalars().first()

            if not event:
                return {"error": f"No run found with ID '{run_id}'."}

            return {
                "run_id": run_id,
                "event_type": event.event_type,
                "payload": event.payload,
                "occurred_at": event.occurred_at.isoformat(),
            }

    data = run_async(_status())
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
        p = data["payload"]
        content = (
            f"[bold cyan]Run ID:[/bold cyan] {data['run_id']}\n"
            f"[bold cyan]Program:[/bold cyan] {p.get('program_slug', '-')}\n"
            f"[bold cyan]Asset:[/bold cyan] {p.get('target_asset', '-')}\n"
            f"[bold cyan]Module:[/bold cyan] {p.get('module', '-')}\n"
            f"[bold cyan]Status:[/bold cyan] [bold yellow]{p.get('status', 'QUEUED').upper()}[/bold yellow]\n"
            f"[bold cyan]Triggered At:[/bold cyan] {data['occurred_at'][:19]}"
        )
        Console().print(Panel(content, title="Scanner Run Status", border_style="cyan"))


@app.command("list")
def list_runs(
    ctx: typer.Context,
    program: Optional[str] = typer.Option(
        None, "--program", "-p", help="Filter by program slug."
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Format output as JSON."
    ),
) -> None:
    """List recent scanner runs recorded in the audit log."""
    is_json = json_output or (ctx.obj and ctx.obj.get("json", False))

    async def _list() -> list[dict]:
        async with get_async_session() as session:
            stmt = (
                select(AuditEvent)
                .where(AuditEvent.object_type == "run")
                .order_by(AuditEvent.occurred_at.desc())
                .limit(50)
            )
            res = await session.execute(stmt)
            events = res.scalars().all()

            results = []
            for ev in events:
                p = ev.payload or {}
                if program and p.get("program_slug") != program:
                    continue
                results.append({
                    "run_id": ev.object_id,
                    "program": p.get("program_slug", "-"),
                    "asset": p.get("target_asset", "-"),
                    "module": p.get("module", "-"),
                    "status": p.get("status", "QUEUED"),
                    "occurred_at": ev.occurred_at.isoformat(),
                })
            return results

    runs_data = run_async(_list())
    if is_json:
        print_json(runs_data)
    else:
        from rich.table import Table
        from rich.console import Console
        table = Table(title="Scanner Runs", border_style="cyan")
        table.add_column("Run ID", style="cyan")
        table.add_column("Program", style="bold green")
        table.add_column("Target Asset", style="white")
        table.add_column("Module", style="magenta")
        table.add_column("Status", style="yellow")
        table.add_column("Triggered At", style="dim")

        for r in runs_data:
            table.add_row(
                r["run_id"][:8] + "...",
                r["program"],
                r["asset"],
                r["module"],
                r["status"].upper(),
                r["occurred_at"][:19],
            )
        Console().print(table)
