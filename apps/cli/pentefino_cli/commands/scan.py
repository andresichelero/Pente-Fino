from __future__ import annotations

import logging
from typing import Optional
import urllib.parse
import uuid

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from sqlalchemy import select

from pentefino_cli.db import get_program_by_slug, record_audit_event, run_async
from pentefino_cli.formatters.json_output import print_json
from pentefino_cli.formatters.tables import print_error
from pentefino_detection import (
    DetectionPlan,
    DetectionPlanner,
    FindingNormalizer,
    HardenedNucleiRunner,
)
from pentefino_domain.enums import ImpactClass
from pentefino_domain.models import Asset, Observation
from pentefino_domain.session import get_async_session
from pentefino_runner import EphemeralRunner

logger = logging.getLogger(__name__)
console = Console(safe_box=True)

app = typer.Typer(help="Manage and execute targeted vulnerability scans.")


@app.command("run")
def run_scan(
    ctx: typer.Context,
    program: str = typer.Option(
        ..., "--program", "-p", help="Target program slug."
    ),
    asset: str = typer.Option(
        ..., "--asset", "-a", help="Target canonical asset hostname or URL (e.g. app.example.com)."
    ),
    tags: Optional[str] = typer.Option(
        None, "--tags", "-t", help="Optional comma-separated tags filter (e.g. cve,misconfig)."
    ),
    severity: Optional[str] = typer.Option(
        None, "--severity", "-s", help="Optional severity filter (e.g. high,critical)."
    ),
    async_mode: bool = typer.Option(
        False, "--async", help="Dispatch scan task asynchronously."
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Format output as JSON."
    ),
) -> None:
    """Execute targeted, safe Nuclei scan matching detected asset technologies."""
    is_json = json_output or (ctx.obj and ctx.obj.get("json", False))
    clean_asset = asset.strip().lower()
    if "://" in clean_asset:
        clean_asset = urllib.parse.urlsplit(clean_asset).netloc or clean_asset

    async def _execute_scan() -> dict:
        async with get_async_session() as session:
            prog = await get_program_by_slug(session, program)
            if not prog:
                return {"error": f"Program '{program}' not found."}

            # Check if asset exists in database for this program
            stmt = select(Asset).where(
                Asset.program_id == prog.id,
                Asset.canonical_key == clean_asset,
            )
            res = await session.execute(stmt)
            target_asset = res.scalar_one_or_none()

            if not target_asset:
                return {
                    "error": f"Asset '{clean_asset}' not found in program '{program}'. Run discovery first."
                }

            if async_mode:
                run_id = uuid.uuid4()
                await record_audit_event(
                    session=session,
                    event_type="cli.scan.dispatch",
                    object_type="scan_run",
                    object_id=run_id,
                    payload={
                        "program_slug": prog.slug,
                        "target_asset": target_asset.canonical_key,
                        "tags": tags,
                        "severity": severity,
                        "status": "queued",
                    },
                )
                await session.commit()
                return {
                    "status": "queued",
                    "run_id": str(run_id),
                    "program": prog.slug,
                    "asset": target_asset.canonical_key,
                    "tags": tags,
                    "severity": severity,
                    "message": f"Scan run for {target_asset.canonical_key} dispatched asynchronously.",
                }

            # Synchronous Execution
            # 1. Fetch detected technologies from asset observations
            obs_stmt = select(Observation).where(
                Observation.asset_id == target_asset.id,
                Observation.observation_type == "http_probe",
            )
            obs_res = await session.execute(obs_stmt)
            observations = obs_res.scalars().all()

            detected_techs: set[str] = set()
            for obs in observations:
                if isinstance(obs.metadata_json, dict):
                    tech_list = obs.metadata_json.get("technologies") or []
                    for t in tech_list:
                        if t and str(t).strip():
                            detected_techs.add(str(t).strip().lower())

            # 2. Plan detection scan
            planner = DetectionPlanner(db_session=session)
            plan: DetectionPlan = await planner.create_plan(
                asset=target_asset,
                detected_technologies=sorted(detected_techs),
                severity_filter=severity,
                tag_filter=tags,
                max_impact_class=ImpactClass.SAFE_READ_ONLY,
            )

            # 3. Execute scan via HardenedNucleiRunner
            runner = EphemeralRunner()
            nuclei_runner = HardenedNucleiRunner(runner=runner)

            if not is_json:
                console.print(
                    f"[cyan]>> Executing scan with {plan.total_templates} safe read-only template(s)...[/cyan]"
                )

            raw_findings = await nuclei_runner.execute_scan(plan=plan)

            # 4. Normalize & Persist Findings
            normalizer = FindingNormalizer(db_session=session)
            persisted_findings = await normalizer.normalize_and_persist(
                raw_nuclei_results=raw_findings,
                program_id=prog.id,
                asset_id=target_asset.id,
                run_id=plan.plan_id,
            )

            # 5. Audit Log
            await record_audit_event(
                session=session,
                event_type="cli.scan.completed",
                object_type="scan_run",
                object_id=plan.plan_id,
                payload={
                    "program_slug": prog.slug,
                    "target_asset": target_asset.canonical_key,
                    "total_templates": plan.total_templates,
                    "findings_count": len(persisted_findings),
                    "tags": tags,
                    "severity": severity,
                },
            )
            await session.commit()

            return {
                "status": "completed",
                "plan_id": str(plan.plan_id),
                "program": prog.slug,
                "asset": target_asset.canonical_key,
                "target_url": plan.target_url,
                "matched_technologies": plan.matched_technologies,
                "total_templates": plan.total_templates,
                "findings_count": len(persisted_findings),
                "findings": [
                    {
                        "id": str(f.id),
                        "dedup_key": f.dedup_key,
                        "detector_id": f.detector_id,
                        "advisory_id": f.advisory_id,
                        "status": f.status,
                        "evidence_level": f.evidence_level,
                        "confidence": f.confidence,
                    }
                    for f in persisted_findings
                ],
            }

    data = run_async(_execute_scan())
    if "error" in data:
        if is_json:
            print_json({"status": "error", "error": data["error"]})
        else:
            print_error(data["error"])
        raise typer.Exit(code=1)

    if is_json:
        print_json(data)
        return

    # Rich formatting
    if data.get("status") == "queued":
        content = (
            f"[bold cyan]Run ID:[/bold cyan] {data['run_id']}\n"
            f"[bold cyan]Program:[/bold cyan] {data['program']}\n"
            f"[bold cyan]Asset:[/bold cyan] {data['asset']}\n"
            f"[bold cyan]Tags:[/bold cyan] {data.get('tags') or 'safe default'}\n"
            f"[bold cyan]Severity:[/bold cyan] {data.get('severity') or 'all'}\n"
            f"[bold cyan]Status:[/bold cyan] [bold yellow]QUEUED[/bold yellow]"
        )
        console.print(Panel(content, title="[bold green]Scan Task Dispatched[/bold green]", border_style="green"))
        return

    # Synchronous completion output
    matched_tech_str = ", ".join(data.get("matched_technologies") or []) or "None (Generic Baseline)"
    summary = (
        f"[bold cyan]Plan ID:[/bold cyan] {data['plan_id']}\n"
        f"[bold cyan]Program:[/bold cyan] {data['program']}\n"
        f"[bold cyan]Asset:[/bold cyan] {data['asset']}\n"
        f"[bold cyan]Target URL:[/bold cyan] {data['target_url']}\n"
        f"[bold cyan]Technologies Matched:[/bold cyan] {matched_tech_str}\n"
        f"[bold cyan]Safe Templates Executed:[/bold cyan] {data['total_templates']}\n"
        f"[bold cyan]Vulnerabilities Identified:[/bold cyan] [bold {'red' if data['findings_count'] > 0 else 'green'}]{data['findings_count']}[/bold {'red' if data['findings_count'] > 0 else 'green'}]"
    )
    console.print(Panel(summary, title="[bold green]Targeted Scan Completed[/bold green]", border_style="green"))

    findings = data.get("findings", [])
    if findings:
        table = Table(title=f"Findings for {data['asset']} ({len(findings)})", border_style="red")
        table.add_column("Detector ID", style="cyan", overflow="fold")
        table.add_column("Dedup Key", style="dim", overflow="fold")
        table.add_column("Evidence Level", style="magenta")
        table.add_column("Confidence", style="blue")
        table.add_column("Status", style="yellow")

        for f in findings:
            table.add_row(
                f["detector_id"],
                f["dedup_key"][:16] + "...",
                f["evidence_level"],
                f["confidence"].upper(),
                f["status"].upper(),
            )
        console.print(table)
    else:
        console.print("[green]No vulnerabilities detected matching safe read-only criteria.[/green]")
