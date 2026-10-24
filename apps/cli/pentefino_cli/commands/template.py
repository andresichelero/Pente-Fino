from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from sqlalchemy import any_, func, select

from pentefino_cli.db import run_async
from pentefino_cli.formatters.json_output import print_json
from pentefino_cli.formatters.tables import print_error
from pentefino_domain.models.template import TemplateCatalog
from pentefino_domain.session import get_async_session
from pentefino_template_indexer import (
    StaticTemplateClassifier,
    TemplateCatalogIngester,
    TemplateSyncManager,
)

logger = logging.getLogger(__name__)
console = Console(safe_box=True)

app = typer.Typer(help="Manage and inspect security templates catalog.")


@app.command("sync")
def sync_templates(
    ctx: typer.Context,
    repo: str = typer.Option(
        "https://github.com/projectdiscovery/nuclei-templates.git",
        "--repo",
        "-r",
        help="Git repository URL for official nuclei-templates.",
    ),
    path: Optional[str] = typer.Option(
        None,
        "--path",
        "-p",
        help="Custom local directory path for cloned or test fixture templates.",
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Format output as JSON."
    ),
) -> None:
    """Synchronize upstream Nuclei templates and index into template catalog."""
    is_json = json_output or (ctx.obj and ctx.obj.get("json", False))

    async def _execute_sync() -> dict:
        async with get_async_session() as session:
            sync_mgr = TemplateSyncManager(
                repo_url=repo,
                local_path=Path(path) if path else Path("storage/templates/nuclei-templates"),
                custom_templates_dir=Path(path) if path else None,
            )

            if not is_json:
                console.print(f"[cyan]>> Synchronizing templates from {repo}...[/cyan]")

            revision = await sync_mgr.sync()
            templates_dir = sync_mgr.get_templates_dir()

            # Crawl and classify YAML template definitions
            classifier = StaticTemplateClassifier()
            classified_templates = []

            yaml_files = list(templates_dir.rglob("*.yaml")) + list(templates_dir.rglob("*.yml"))
            for y_file in yaml_files:
                try:
                    meta = classifier.classify_file(y_file)
                    classified_templates.append(meta)
                except Exception:
                    continue

            # Ingest into PostgreSQL template_catalog table
            ingester = TemplateCatalogIngester(db_session=session)
            ingested_count = await ingester.ingest_batch(
                templates=classified_templates,
                upstream_revision=revision,
            )
            await session.commit()

            return {
                "status": "synced",
                "revision": revision,
                "templates_dir": str(templates_dir),
                "classified_count": len(classified_templates),
                "ingested_count": ingested_count,
            }

    data = run_async(_execute_sync())
    if "error" in data:
        if is_json:
            print_json({"status": "error", "error": data["error"]})
        else:
            print_error(data["error"])
        raise typer.Exit(code=1)

    if is_json:
        print_json(data)
        return

    content = (
        f"[bold cyan]Upstream Revision:[/bold cyan] {data['revision']}\n"
        f"[bold cyan]Templates Path:[/bold cyan] {data['templates_dir']}\n"
        f"[bold cyan]Classified Templates:[/bold cyan] {data['classified_count']}\n"
        f"[bold cyan]Ingested / Updated:[/bold cyan] [bold green]{data['ingested_count']}[/bold green]"
    )
    console.print(Panel(content, title="[bold green]Template Catalog Synchronized[/bold green]", border_style="green"))


@app.command("list")
def list_templates(
    ctx: typer.Context,
    impact: Optional[str] = typer.Option(
        None,
        "--impact",
        "-i",
        help="Filter by impact class (safe_read_only, active_reviewed, stateful, intrusive, lab_only).",
    ),
    tech: Optional[str] = typer.Option(
        None,
        "--tech",
        "-t",
        help="Filter by technology tag (e.g. nginx, apache, wordpress).",
    ),
    severity: Optional[str] = typer.Option(
        None,
        "--severity",
        "-s",
        help="Filter by severity (info, low, medium, high, critical).",
    ),
    limit: int = typer.Option(
        50,
        "--limit",
        "-l",
        help="Maximum number of templates to display.",
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Format output as JSON."
    ),
) -> None:
    """Query and filter security templates in catalog."""
    is_json = json_output or (ctx.obj and ctx.obj.get("json", False))

    async def _execute_list() -> list[dict]:
        async with get_async_session() as session:
            stmt = select(TemplateCatalog)

            if impact:
                clean_impact = impact.strip().lower()
                stmt = stmt.where(func.lower(TemplateCatalog.impact_class) == clean_impact)

            if severity:
                clean_sev = severity.strip().lower()
                stmt = stmt.where(func.lower(TemplateCatalog.severity) == clean_sev)

            if tech:
                clean_tech = tech.strip().lower()
                stmt = stmt.where(
                    (clean_tech == any_(TemplateCatalog.technologies))
                    | (clean_tech == any_(TemplateCatalog.tags))
                    | TemplateCatalog.id.ilike(f"%{clean_tech}%")
                    | TemplateCatalog.name.ilike(f"%{clean_tech}%")
                )

            stmt = stmt.order_by(TemplateCatalog.id.asc()).limit(limit)

            res = await session.execute(stmt)
            templates = res.scalars().all()

            if tech:
                clean_tech = tech.strip().lower()
                matched = []
                for t in templates:
                    t_techs = [x.lower() for x in (t.technologies or [])]
                    t_tags = [x.lower() for x in (t.tags or [])]
                    if (
                        clean_tech in t_techs
                        or clean_tech in t_tags
                        or clean_tech in t.id.lower()
                        or clean_tech in (t.name or "").lower()
                    ):
                        matched.append(t)
                templates = matched[:limit]

            return [
                {
                    "id": t.id,
                    "name": t.name,
                    "protocol": t.protocol,
                    "impact_class": t.impact_class,
                    "severity": t.severity or "info",
                    "cve_id": t.cve_id,
                    "cwe_id": t.cwe_id,
                    "technologies": t.technologies or [],
                    "tags": t.tags or [],
                    "upstream_revision": t.upstream_revision,
                }
                for t in templates
            ]

    items = run_async(_execute_list())

    if is_json:
        print_json(items)
        return

    table = Table(title=f"Template Catalog ({len(items)} templates)", border_style="cyan")
    table.add_column("Template ID", style="bold white", overflow="fold")
    table.add_column("Name", style="white", overflow="fold")
    table.add_column("Protocol", style="cyan")
    table.add_column("Impact Class", style="yellow")
    table.add_column("Severity", style="magenta")
    table.add_column("Technologies", style="blue")

    for t in items:
        tech_str = ", ".join(t.get("technologies") or []) or "-"
        table.add_row(
            t["id"],
            (t["name"] or "-")[:35],
            t["protocol"],
            t["impact_class"],
            t["severity"].upper(),
            tech_str,
        )
    console.print(table)
