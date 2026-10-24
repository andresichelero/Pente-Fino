from __future__ import annotations

from typing import Optional
from uuid import UUID
import typer
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from pentefino_cli.db import get_program_by_slug, run_async
from pentefino_cli.formatters.json_output import print_json
from pentefino_cli.formatters.tables import print_error, print_findings_table
from pentefino_domain.models import Asset, Finding, TemplateCatalog
from pentefino_domain.session import get_async_session

app = typer.Typer(help="Query, inspect, and export vulnerability findings.")


@app.command("query")
def query_findings(
    ctx: typer.Context,
    program: str = typer.Option(
        ..., "--program", "-p", help="Target program slug."
    ),
    severity: Optional[str] = typer.Option(
        None, "--severity", "-s", help="Filter by severity (critical, high, medium, low, info)."
    ),
    status: Optional[str] = typer.Option(
        None, "--status", help="Filter by finding status (candidate, validated, false_positive, reported, etc.)."
    ),
    evidence_level: Optional[str] = typer.Option(
        None, "--evidence-level", "-e", help="Filter by evidence level (E0, E1, E2, E3)."
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Format output as JSON."
    ),
) -> None:
    """Query and filter vulnerability findings for a program."""
    is_json = json_output or (ctx.obj and ctx.obj.get("json", False))

    async def _query() -> dict:
        async with get_async_session() as session:
            prog = await get_program_by_slug(session, program)
            if not prog:
                return {"error": f"Program '{program}' not found."}

            stmt = (
                select(Finding, Asset, TemplateCatalog)
                .join(Asset, Finding.asset_id == Asset.id)
                .outerjoin(TemplateCatalog, Finding.detector_id == TemplateCatalog.id)
                .where(Finding.program_id == prog.id)
            )

            if status:
                stmt = stmt.where(Finding.status == status.lower())
            if evidence_level:
                stmt = stmt.where(Finding.evidence_level == evidence_level.upper())
            if severity:
                stmt = stmt.where(TemplateCatalog.severity == severity.lower())

            stmt = stmt.order_by(Finding.first_seen.desc())
            result = await session.execute(stmt)
            rows = result.all()

            findings_list = []
            for f, a, t in rows:
                findings_list.append({
                    "id": str(f.id),
                    "detector_id": f.detector_id,
                    "advisory_id": f.advisory_id,
                    "canonical_asset": a.canonical_key if a else "unknown",
                    "severity": t.severity if t else "unknown",
                    "status": f.status,
                    "evidence_level": f.evidence_level,
                    "confidence": f.confidence,
                    "dedup_key": f.dedup_key,
                    "first_seen": f.first_seen.isoformat(),
                    "last_seen": f.last_seen.isoformat(),
                })

            return {"program": prog.slug, "findings": findings_list}

    data = run_async(_query())
    if "error" in data:
        if is_json:
            print_json({"status": "error", "error": data["error"]})
        else:
            print_error(data["error"])
        raise typer.Exit(code=1)

    if is_json:
        print_json(data["findings"])
    else:
        print_findings_table(data["program"], data["findings"])


@app.command("show")
def show_finding(
    ctx: typer.Context,
    finding_id: str = typer.Argument(
        ..., help="UUID of the finding."
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Format output as JSON."
    ),
) -> None:
    """Show detailed metadata, detector template, and evidence pointers for a finding."""
    is_json = json_output or (ctx.obj and ctx.obj.get("json", False))

    async def _show() -> dict:
        async with get_async_session() as session:
            try:
                fid = UUID(finding_id.strip())
            except ValueError:
                return {"error": f"Invalid UUID: '{finding_id}'."}

            stmt = (
                select(Finding)
                .options(
                    selectinload(Finding.asset),
                    selectinload(Finding.detector),
                    selectinload(Finding.evidence_items),
                )
                .where(Finding.id == fid)
            )
            result = await session.execute(stmt)
            finding = result.scalar_one_or_none()
            if not finding:
                return {"error": f"Finding '{finding_id}' not found."}

            return {
                "id": str(finding.id),
                "program_id": str(finding.program_id),
                "detector_id": finding.detector_id,
                "advisory_id": finding.advisory_id,
                "status": finding.status,
                "evidence_level": finding.evidence_level,
                "confidence": finding.confidence,
                "dedup_key": finding.dedup_key,
                "first_seen": finding.first_seen.isoformat(),
                "last_seen": finding.last_seen.isoformat(),
                "asset": {
                    "id": str(finding.asset.id),
                    "canonical_key": finding.asset.canonical_key,
                    "asset_type": finding.asset.asset_type,
                    "scope_state": finding.asset.scope_state,
                }
                if finding.asset
                else None,
                "detector": {
                    "name": finding.detector.name,
                    "protocol": finding.detector.protocol,
                    "severity": finding.detector.severity,
                    "impact_class": finding.detector.impact_class,
                    "cve_id": finding.detector.cve_id,
                }
                if finding.detector
                else None,
                "evidence_items": [
                    {
                        "id": str(e.id),
                        "evidence_type": e.evidence_type,
                        "sanitized_sha256": e.sanitized_sha256,
                        "seaweed_object_key": e.seaweed_object_key,
                    }
                    for e in finding.evidence_items
                ],
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
        d = data.get("detector") or {}
        a = data.get("asset") or {}
        content = (
            f"[bold cyan]Finding ID:[/bold cyan] {data['id']}\n"
            f"[bold cyan]Detector ID:[/bold cyan] {data['detector_id']}\n"
            f"[bold cyan]Detector Name:[/bold cyan] {d.get('name', '-')}\n"
            f"[bold cyan]Severity:[/bold cyan] [bold magenta]{(d.get('severity') or 'unknown').upper()}[/bold magenta]\n"
            f"[bold cyan]CVE ID:[/bold cyan] {d.get('cve_id') or '-'}\n"
            f"[bold cyan]Asset:[/bold cyan] [bold white]{a.get('canonical_key', '-')}[/bold white]\n"
            f"[bold cyan]Status:[/bold cyan] [yellow]{data['status']}[/yellow]\n"
            f"[bold cyan]Evidence Level:[/bold cyan] [blue]{data['evidence_level']}[/blue]\n"
            f"[bold cyan]Confidence:[/bold cyan] [green]{data['confidence']}[/green]\n"
            f"[bold cyan]Dedup Key:[/bold cyan] {data['dedup_key']}\n"
            f"[bold cyan]Evidence Blobs:[/bold cyan] {len(data['evidence_items'])}"
        )
        Console().print(Panel(content, title="Vulnerability Finding Details", border_style="cyan"))


@app.command("export")
def export_findings(
    ctx: typer.Context,
    program: str = typer.Option(
        ..., "--program", "-p", help="Target program slug."
    ),
    format_type: str = typer.Option(
        "json", "--format", help="Export format (json or markdown)."
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Format output as JSON."
    ),
) -> None:
    """Export validated program findings report for bug bounty platform submission."""
    is_json = json_output or (ctx.obj and ctx.obj.get("json", False)) or (format_type.lower() == "json")

    async def _export() -> dict:
        async with get_async_session() as session:
            prog = await get_program_by_slug(session, program)
            if not prog:
                return {"error": f"Program '{program}' not found."}

            stmt = (
                select(Finding, Asset, TemplateCatalog)
                .join(Asset, Finding.asset_id == Asset.id)
                .outerjoin(TemplateCatalog, Finding.detector_id == TemplateCatalog.id)
                .where(Finding.program_id == prog.id)
                .order_by(Finding.first_seen.desc())
            )
            result = await session.execute(stmt)
            rows = result.all()

            findings = []
            for f, a, t in rows:
                findings.append({
                    "id": str(f.id),
                    "detector": t.name if t else f.detector_id,
                    "cve_id": t.cve_id if t else None,
                    "severity": t.severity if t else "unknown",
                    "asset": a.canonical_key if a else "unknown",
                    "status": f.status,
                    "evidence_level": f.evidence_level,
                    "first_seen": f.first_seen.isoformat(),
                })

            return {"program": prog.slug, "total": len(findings), "findings": findings}

    data = run_async(_export())
    if "error" in data:
        if is_json:
            print_json({"status": "error", "error": data["error"]})
        else:
            print_error(data["error"])
        raise typer.Exit(code=1)

    if is_json:
        print_json(data)
    else:
        # Markdown export
        md_lines = [
            f"# Findings Report for {data['program']}",
            f"Total Findings: {data['total']}",
            "",
            "| ID | Detector | Severity | Target Asset | Status | Evidence Level |",
            "|---|---|---|---|---|---|",
        ]
        for f in data["findings"]:
            md_lines.append(f"| {f['id'][:8]} | {f['detector']} | {f['severity']} | {f['asset']} | {f['status']} | {f['evidence_level']} |")

        print("\n".join(md_lines))
