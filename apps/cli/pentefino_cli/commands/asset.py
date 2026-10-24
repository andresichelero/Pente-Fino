from __future__ import annotations

from typing import Optional
import typer
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from pentefino_cli.db import get_program_by_slug, run_async
from pentefino_cli.formatters.json_output import print_json
from pentefino_cli.formatters.tables import print_assets_table, print_error
from pentefino_domain.models import Asset
from pentefino_domain.session import get_async_session

app = typer.Typer(help="Inspect and query target assets within program scopes.")


@app.command("inspect")
def inspect_asset(
    ctx: typer.Context,
    program: str = typer.Option(
        ..., "--program", "-p", help="Target program slug."
    ),
    asset: Optional[str] = typer.Option(
        None, "--asset", "-a", help="Specific canonical asset key to inspect."
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Format output as JSON."
    ),
) -> None:
    """Inspect assets under a program, optionally filtering by specific asset canonical key."""
    is_json = json_output or (ctx.obj and ctx.obj.get("json", False))

    async def _inspect() -> dict:
        async with get_async_session() as session:
            prog = await get_program_by_slug(session, program)
            if not prog:
                return {"error": f"Program '{program}' not found."}

            if asset:
                stmt = (
                    select(Asset)
                    .options(selectinload(Asset.findings))
                    .where(Asset.program_id == prog.id, Asset.canonical_key == asset.strip())
                )
                result = await session.execute(stmt)
                db_asset = result.scalar_one_or_none()
                if not db_asset:
                    return {"error": f"Asset '{asset}' not found in program '{program}'."}

                return {
                    "asset": {
                        "id": str(db_asset.id),
                        "canonical_key": db_asset.canonical_key,
                        "asset_type": db_asset.asset_type,
                        "scope_state": db_asset.scope_state,
                        "first_seen": db_asset.first_seen.isoformat(),
                        "last_seen": db_asset.last_seen.isoformat(),
                        "findings_count": len(db_asset.findings),
                        "findings": [
                            {
                                "id": str(f.id),
                                "detector_id": f.detector_id,
                                "status": f.status,
                                "evidence_level": f.evidence_level,
                            }
                            for f in db_asset.findings
                        ],
                    }
                }
            else:
                stmt = select(Asset).where(Asset.program_id == prog.id).order_by(Asset.first_seen.desc())
                result = await session.execute(stmt)
                assets = result.scalars().all()

                return {
                    "program": prog.slug,
                    "assets": [
                        {
                            "id": str(a.id),
                            "canonical_key": a.canonical_key,
                            "asset_type": a.asset_type,
                            "scope_state": a.scope_state,
                            "first_seen": a.first_seen.isoformat(),
                            "last_seen": a.last_seen.isoformat(),
                        }
                        for a in assets
                    ],
                }

    data = run_async(_inspect())
    if "error" in data:
        if is_json:
            print_json({"status": "error", "error": data["error"]})
        else:
            print_error(data["error"])
        raise typer.Exit(code=1)

    if is_json:
        print_json(data.get("asset") or data.get("assets", []))
    else:
        if "asset" in data:
            a = data["asset"]
            from rich.panel import Panel
            from rich.console import Console
            content = (
                f"[bold cyan]ID:[/bold cyan] {a['id']}\n"
                f"[bold cyan]Canonical Key:[/bold cyan] [bold white]{a['canonical_key']}[/bold white]\n"
                f"[bold cyan]Asset Type:[/bold cyan] {a['asset_type']}\n"
                f"[bold cyan]Scope State:[/bold cyan] [yellow]{a['scope_state']}[/yellow]\n"
                f"[bold cyan]First Seen:[/bold cyan] {a['first_seen'][:19]}\n"
                f"[bold cyan]Last Seen:[/bold cyan] {a['last_seen'][:19]}\n"
                f"[bold cyan]Findings Associated:[/bold cyan] {a['findings_count']}"
            )
            Console().print(Panel(content, title=f"Asset: {a['canonical_key']}", border_style="cyan"))
        else:
            class _AssetItem:
                def __init__(self, d: dict):
                    self.canonical_key = d["canonical_key"]
                    self.asset_type = d["asset_type"]
                    self.scope_state = d["scope_state"]
                    from datetime import datetime
                    self.first_seen = datetime.fromisoformat(d["first_seen"])
                    self.last_seen = datetime.fromisoformat(d["last_seen"])

            items = [_AssetItem(d) for d in data["assets"]]
            print_assets_table(data["program"], items)


@app.command("list")
def list_assets(
    ctx: typer.Context,
    program: str = typer.Option(
        ..., "--program", "-p", help="Target program slug."
    ),
    scope_state: Optional[str] = typer.Option(
        None, "--scope-state", help="Filter by scope state (in_scope_explicit, in_scope_derived, candidate, out_of_scope)."
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Format output as JSON."
    ),
) -> None:
    """List assets for a program with optional scope state filtering."""
    is_json = json_output or (ctx.obj and ctx.obj.get("json", False))

    async def _list() -> dict:
        async with get_async_session() as session:
            prog = await get_program_by_slug(session, program)
            if not prog:
                return {"error": f"Program '{program}' not found."}

            stmt = select(Asset).where(Asset.program_id == prog.id)
            if scope_state:
                stmt = stmt.where(Asset.scope_state == scope_state)
            stmt = stmt.order_by(Asset.first_seen.desc())

            result = await session.execute(stmt)
            assets = result.scalars().all()

            return {
                "program": prog.slug,
                "assets": [
                    {
                        "id": str(a.id),
                        "canonical_key": a.canonical_key,
                        "asset_type": a.asset_type,
                        "scope_state": a.scope_state,
                        "first_seen": a.first_seen.isoformat(),
                        "last_seen": a.last_seen.isoformat(),
                    }
                    for a in assets
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
        print_json(data["assets"])
    else:
        class _AssetItem:
            def __init__(self, d: dict):
                self.canonical_key = d["canonical_key"]
                self.asset_type = d["asset_type"]
                self.scope_state = d["scope_state"]
                from datetime import datetime
                self.first_seen = datetime.fromisoformat(d["first_seen"])
                self.last_seen = datetime.fromisoformat(d["last_seen"])

        items = [_AssetItem(d) for d in data["assets"]]
        print_assets_table(data["program"], items)
