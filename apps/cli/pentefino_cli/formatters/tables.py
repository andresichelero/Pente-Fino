from __future__ import annotations

from typing import Any, Iterable
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console(safe_box=True)


def print_error(message: str) -> None:
    """Print error message to stderr with styling."""
    console.print(f"[bold red]Error:[/bold red] {message}", style="red")


def print_success(message: str) -> None:
    """Print success message."""
    console.print(f"[bold green]Success:[/bold green] {message}")


def print_program_created(program: Any) -> None:
    """Display newly created program panel."""
    content = (
        f"[bold cyan]ID:[/bold cyan] {program.id}\n"
        f"[bold cyan]Slug:[/bold cyan] {program.slug}\n"
        f"[bold cyan]Name:[/bold cyan] {program.name}\n"
        f"[bold cyan]Platform:[/bold cyan] {program.platform}\n"
        f"[bold cyan]State:[/bold cyan] {program.state}\n"
        f"[bold cyan]Default Policy:[/bold cyan] {program.default_policy_id}"
    )
    console.print(Panel(content, title="[bold green]Program Created[/bold green]", border_style="green"))


def print_programs_table(programs: Iterable[Any]) -> None:
    """Render Rich table of programs."""
    table = Table(title="PenteFino Programs", border_style="cyan")
    table.add_column("Slug", style="bold green")
    table.add_column("Name", style="white")
    table.add_column("Platform", style="magenta")
    table.add_column("State", style="yellow")
    table.add_column("Default Policy", style="blue")
    table.add_column("Created At", style="dim")

    for p in programs:
        created = p.created_at.strftime("%Y-%m-%d %H:%M:%S") if getattr(p, "created_at", None) else "-"
        table.add_row(
            p.slug,
            p.name,
            p.platform,
            p.state,
            p.default_policy_id,
            created,
        )
    console.print(table)


def print_scope_rules_table(program_slug: str, rules: Iterable[Any]) -> None:
    """Render Rich table of scope rules for a program."""
    table = Table(title=f"Scope Rules for '{program_slug}'", border_style="cyan")
    table.add_column("Action", style="bold")
    table.add_column("Pattern", style="bold white", overflow="fold")
    table.add_column("Asset Type", style="cyan", overflow="fold")
    table.add_column("Priority", justify="right", style="yellow")
    table.add_column("Ports", style="magenta")
    table.add_column("Denied Paths", style="red")

    for r in rules:
        action_style = "[green]ALLOW[/green]" if r.action == "allow" else "[red]DENY[/red]" if r.action == "deny" else "[yellow]DISCOVER[/yellow]"
        ports = ",".join(str(p) for p in r.allowed_ports) if r.allowed_ports else "*"
        paths = ",".join(r.denied_paths) if r.denied_paths else "-"
        table.add_row(
            action_style,
            r.pattern,
            r.asset_type,
            str(r.priority),
            ports,
            paths,
        )
    console.print(table)


def print_scope_check_result(decision: Any) -> None:
    """Display interactive scope evaluation decision."""
    allowed = getattr(decision, "allowed", False)
    status_text = "[bold green]ALLOWED[/bold green]" if allowed else "[bold red]DENIED[/bold red]"
    border_color = "green" if allowed else "red"

    content = (
        f"[bold]Verdict:[/bold] {status_text}\n"
        f"[bold]Matched Tier:[/bold] {getattr(decision, 'matched_tier', '-')}\n"
        f"[bold]Reason:[/bold] {getattr(decision, 'reason', '-')}\n"
        f"[bold]Matched Rule ID:[/bold] {getattr(decision, 'matched_rule_id', None) or '-'}\n"
        f"[bold]Matched Pattern:[/bold] {getattr(decision, 'matched_pattern', None) or '-'}\n"
        f"[bold]Resolved IP(s):[/bold] {getattr(decision, 'resolved_ip', None) or '-'}"
    )
    console.print(Panel(content, title=f"Scope Check Decision ({status_text})", border_style=border_color))


def print_auth_snapshot(snapshot: Any, program_slug: str) -> None:
    """Render authorization snapshot panel."""
    valid_from = snapshot.valid_from.strftime("%Y-%m-%d %H:%M:%S UTC") if getattr(snapshot, "valid_from", None) else "-"
    valid_until = snapshot.valid_until.strftime("%Y-%m-%d %H:%M:%S UTC") if getattr(snapshot, "valid_until", None) else "Indefinite"
    content = (
        f"[bold cyan]Snapshot ID:[/bold cyan] {snapshot.id}\n"
        f"[bold cyan]Program:[/bold cyan] {program_slug}\n"
        f"[bold cyan]Policy SHA-256:[/bold cyan] {snapshot.policy_hash}\n"
        f"[bold cyan]Source URL:[/bold cyan] {snapshot.source_url or '-'}\n"
        f"[bold cyan]Valid From:[/bold cyan] {valid_from}\n"
        f"[bold cyan]Valid Until:[/bold cyan] {valid_until}"
    )
    console.print(Panel(content, title="[bold green]Authorization Snapshot Registered[/bold green]", border_style="green"))


def print_assets_table(program_slug: str, assets: Iterable[Any]) -> None:
    """Render Rich table of assets for a program."""
    table = Table(title=f"Assets for '{program_slug}'", border_style="cyan")
    table.add_column("Canonical Key", style="bold white")
    table.add_column("Asset Type", style="cyan")
    table.add_column("Scope State", style="yellow")
    table.add_column("First Seen", style="dim")
    table.add_column("Last Seen", style="dim")

    for a in assets:
        first = a.first_seen.strftime("%Y-%m-%d %H:%M:%S") if getattr(a, "first_seen", None) else "-"
        last = a.last_seen.strftime("%Y-%m-%d %H:%M:%S") if getattr(a, "last_seen", None) else "-"
        table.add_row(
            a.canonical_key,
            a.asset_type,
            a.scope_state,
            first,
            last,
        )
    console.print(table)


def print_run_triggered(run_id: Any, program_slug: str, asset: str, module: str) -> None:
    """Render scan run triggered confirmation panel."""
    content = (
        f"[bold cyan]Run ID:[/bold cyan] {run_id}\n"
        f"[bold cyan]Program:[/bold cyan] {program_slug}\n"
        f"[bold cyan]Target Asset:[/bold cyan] {asset}\n"
        f"[bold cyan]Module:[/bold cyan] {module}\n"
        f"[bold cyan]Status:[/bold cyan] [bold yellow]QUEUED[/bold yellow]"
    )
    console.print(Panel(content, title="[bold green]Scan Run Triggered[/bold green]", border_style="green"))


def print_findings_table(program_slug: str, findings: Iterable[dict[str, Any]]) -> None:
    """Render Rich table of findings."""
    table = Table(title=f"Findings for '{program_slug}'", border_style="cyan")
    table.add_column("Finding ID", style="bold cyan")
    table.add_column("Detector / Rule", style="white")
    table.add_column("Asset", style="bold white")
    table.add_column("Severity", style="magenta")
    table.add_column("Status", style="yellow")
    table.add_column("Evidence", style="blue")
    table.add_column("Confidence", style="green")

    for f in findings:
        sev = str(f.get("severity") or "unknown").upper()
        sev_style = (
            "[bold red]" + sev + "[/bold red]"
            if sev in ("CRITICAL", "HIGH")
            else "[yellow]" + sev + "[/yellow]"
            if sev == "MEDIUM"
            else "[cyan]" + sev + "[/cyan]"
        )
        table.add_row(
            str(f.get("id"))[:8] + "...",
            str(f.get("detector_id")),
            str(f.get("canonical_asset")),
            sev_style,
            str(f.get("status")),
            str(f.get("evidence_level")),
            str(f.get("confidence")),
        )
    console.print(table)
