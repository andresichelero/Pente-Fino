from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional
import urllib.parse
import uuid

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from sqlalchemy import select

from pentefino_adapters import (
    DnsxAdapter,
    HttpxAdapter,
    ReconPipeline,
    SubfinderAdapter,
)
from pentefino_cli.db import get_program_by_slug, record_audit_event, run_async
from pentefino_cli.formatters.json_output import print_json
from pentefino_cli.formatters.tables import print_error
from pentefino_domain.models import AuthorizationSnapshot, ScopeRule
from pentefino_domain.session import get_async_session
from pentefino_runner import EphemeralRunner
from pentefino_scope.engine import ScopeEngine
from pentefino_scope.enums import (
    AssetType as ScopeAssetType,
    ScopeAction as ScopeRuleAction,
)
from pentefino_scope.models import (
    AuthorizationSnapshot as ScopeAuthSnapshot,
    ScopeRule as ScopeEngineRule,
)

logger = logging.getLogger(__name__)
console = Console(safe_box=True)

app = typer.Typer(help="Manage and execute reconnaissance workflows.")


async def _load_scope_engine(session, prog) -> ScopeEngine:
    """Load ScopeEngine instance populated with active rules and authorization for program."""
    rules_stmt = (
        select(ScopeRule)
        .where(ScopeRule.program_id == prog.id)
        .order_by(ScopeRule.priority.asc())
    )
    rules_res = await session.execute(rules_stmt)
    db_rules = rules_res.scalars().all()

    auth_stmt = (
        select(AuthorizationSnapshot)
        .where(AuthorizationSnapshot.program_id == prog.id)
        .order_by(AuthorizationSnapshot.created_at.desc())
    )
    auth_res = await session.execute(auth_stmt)
    db_auth = auth_res.scalar_one_or_none()

    engine_rules: list[ScopeEngineRule] = []
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

    engine_snapshot: Optional[ScopeAuthSnapshot] = None
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

    env_class = "lab" if getattr(prog, "platform", None) == "lab" else "bounty"
    return ScopeEngine(
        snapshot=engine_snapshot,
        rules=engine_rules,
        environment_class=env_class,
    )


@app.command("run")
def run_recon(
    ctx: typer.Context,
    program: str = typer.Option(
        ..., "--program", "-p", help="Target program slug."
    ),
    domain: str = typer.Option(
        ..., "--domain", "-d", help="Target domain for reconnaissance (e.g. example.com)."
    ),
    bruteforce: bool = typer.Option(
        False, "--bruteforce", "-b", help="Enable active DNS subdomain brute-forcing."
    ),
    async_mode: bool = typer.Option(
        False, "--async", help="Dispatch reconnaissance task asynchronously."
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Format output as JSON."
    ),
) -> None:
    """Execute multi-stage reconnaissance (Subfinder -> dnsx -> httpx)."""
    is_json = json_output or (ctx.obj and ctx.obj.get("json", False))
    clean_domain = domain.strip().lower()
    if "://" in clean_domain:
        clean_domain = urllib.parse.urlsplit(clean_domain).netloc or clean_domain

    async def _execute_recon() -> dict:
        async with get_async_session() as session:
            prog = await get_program_by_slug(session, program)
            if not prog:
                return {"error": f"Program '{program}' not found."}

            if async_mode:
                task_id = uuid.uuid4()
                await record_audit_event(
                    session=session,
                    event_type="cli.recon.dispatch",
                    object_type="recon_task",
                    object_id=task_id,
                    payload={
                        "program_slug": prog.slug,
                        "domain": clean_domain,
                        "bruteforce": bruteforce,
                        "status": "queued",
                    },
                )
                await session.commit()
                return {
                    "status": "queued",
                    "task_id": str(task_id),
                    "program": prog.slug,
                    "domain": clean_domain,
                    "bruteforce": bruteforce,
                    "message": f"Recon task for {clean_domain} dispatched asynchronously.",
                }

            # Synchronous pipeline execution
            scope_engine = await _load_scope_engine(session, prog)
            runner = EphemeralRunner()
            subfinder = SubfinderAdapter(runner=runner, scope_engine=scope_engine)
            dnsx = DnsxAdapter(runner=runner, scope_engine=scope_engine)
            httpx = HttpxAdapter(runner=runner)
            pipeline = ReconPipeline(
                subfinder=subfinder,
                dnsx=dnsx,
                httpx=httpx,
                scope_engine=scope_engine,
            )

            wordlist_path: Optional[Path] = None
            if bruteforce:
                default_wordlist = Path("data/wordlists/subdomains-top5k.txt")
                if default_wordlist.is_file():
                    wordlist_path = default_wordlist

            # Setup interactive Rich progress if not JSON mode
            def _progress_cb(stage: str, current: int, total: int) -> None:
                if not is_json:
                    console.print(
                        f"[bold cyan]>> [Stage {current}/{total}][/bold cyan] Running [bold green]{stage}[/bold green] adapter..."
                    )

            recon_result = await pipeline.run(
                domain=clean_domain,
                program_id=prog.id,
                bruteforce=bruteforce,
                wordlist_path=wordlist_path,
                session=session,
                progress_callback=_progress_cb,
            )

            run_id = uuid.uuid4()
            await record_audit_event(
                session=session,
                event_type="cli.recon.completed",
                object_type="recon_run",
                object_id=run_id,
                payload={
                    "program_slug": prog.slug,
                    "domain": clean_domain,
                    "bruteforce": bruteforce,
                    "total_discovered": recon_result.total_discovered,
                    "in_scope_count": recon_result.in_scope_count,
                    "resolved_count": recon_result.resolved_count,
                    "live_http_count": recon_result.live_http_count,
                },
            )
            await session.commit()

            return {
                "status": "completed",
                "run_id": str(run_id),
                "program": prog.slug,
                "domain": clean_domain,
                "bruteforce": bruteforce,
                "total_discovered": recon_result.total_discovered,
                "in_scope_count": recon_result.in_scope_count,
                "resolved_count": recon_result.resolved_count,
                "live_http_count": recon_result.live_http_count,
                "candidates": [
                    {
                        "host": c.host,
                        "sources": getattr(c, "sources", []),
                        "scope_state": c.scope_state.value if hasattr(c.scope_state, "value") else str(c.scope_state),
                    }
                    for c in recon_result.candidates
                ],
                "dns_records": [
                    {
                        "host": r.host,
                        "a": r.a,
                        "aaaa": r.aaaa,
                        "cname": r.cname,
                        "is_prohibited_ip": r.is_prohibited_ip,
                    }
                    for r in recon_result.dns_records
                ],
                "http_probes": [
                    {
                        "url": p.url,
                        "input_host": p.input_host,
                        "status_code": p.status_code,
                        "title": p.title,
                        "webserver": p.webserver,
                        "technologies": [c.name for c in p.components],
                        "failed": p.failed,
                    }
                    for p in recon_result.http_probes
                ],
            }

    data = run_async(_execute_recon())
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
            f"[bold cyan]Task ID:[/bold cyan] {data['task_id']}\n"
            f"[bold cyan]Program:[/bold cyan] {data['program']}\n"
            f"[bold cyan]Domain:[/bold cyan] {data['domain']}\n"
            f"[bold cyan]Bruteforce:[/bold cyan] {data['bruteforce']}\n"
            f"[bold cyan]Status:[/bold cyan] [bold yellow]QUEUED[/bold yellow]"
        )
        console.print(Panel(content, title="[bold green]Recon Task Dispatched[/bold green]", border_style="green"))
        return

    # Synchronous completion output
    summary = (
        f"[bold cyan]Program:[/bold cyan] {data['program']}\n"
        f"[bold cyan]Domain:[/bold cyan] {data['domain']}\n"
        f"[bold cyan]Bruteforce Active:[/bold cyan] {data['bruteforce']}\n"
        f"[bold cyan]Discovered Subdomains:[/bold cyan] {data['total_discovered']}\n"
        f"[bold cyan]In-Scope Candidates:[/bold cyan] [bold green]{data['in_scope_count']}[/bold green]\n"
        f"[bold cyan]Resolved Live Hosts:[/bold cyan] {data['resolved_count']}\n"
        f"[bold cyan]Live HTTP Probes:[/bold cyan] [bold green]{data['live_http_count']}[/bold green]"
    )
    console.print(Panel(summary, title="[bold green]Reconnaissance Complete[/bold green]", border_style="green"))

    # Table 1: Discovered Subdomains
    if data.get("candidates"):
        cand_table = Table(title=f"Discovered Subdomains ({len(data['candidates'])})", border_style="cyan")
        cand_table.add_column("Host", style="bold white")
        cand_table.add_column("Scope State", style="green")
        cand_table.add_column("Sources", style="dim")
        for c in data["candidates"][:50]:
            sources_val = ", ".join(c.get("sources") or []) or "subfinder"
            cand_table.add_row(c["host"], c["scope_state"], sources_val)
        console.print(cand_table)

    # Table 2: DNS Records
    if data.get("dns_records"):
        dns_table = Table(title=f"DNS Answers ({len(data['dns_records'])})", border_style="blue")
        dns_table.add_column("Host", style="bold white")
        dns_table.add_column("A Records", style="cyan")
        dns_table.add_column("AAAA Records", style="magenta")
        dns_table.add_column("CNAME", style="yellow")
        for r in data["dns_records"][:50]:
            dns_table.add_row(
                r["host"],
                ", ".join(r["a"]) if r.get("a") else "-",
                ", ".join(r["aaaa"]) if r.get("aaaa") else "-",
                ", ".join(r["cname"]) if r.get("cname") else "-",
            )
        console.print(dns_table)

    # Table 3: HTTP Probes
    if data.get("http_probes"):
        http_table = Table(title=f"Live HTTP Probes ({len(data['http_probes'])})", border_style="green")
        http_table.add_column("Target URL", style="bold white")
        http_table.add_column("Status", style="yellow")
        http_table.add_column("Title", style="cyan")
        http_table.add_column("Web Server", style="magenta")
        http_table.add_column("Technologies", style="blue")
        for p in data["http_probes"][:50]:
            st = str(p["status_code"]) if p.get("status_code") is not None else "[red]FAIL[/red]"
            tech = ", ".join(p.get("technologies") or []) if p.get("technologies") else "-"
            http_table.add_row(
                p.get("url") or p.get("input_host") or "-",
                st,
                (p.get("title") or "-")[:40],
                p.get("webserver") or "-",
                tech,
            )
        console.print(http_table)
