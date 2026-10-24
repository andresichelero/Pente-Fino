from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import typer
from rich.console import Console
from rich.panel import Panel

from pentefino_cli.formatters.json_output import print_json

console = Console(safe_box=True)


def run_api_server(
    ctx: typer.Context,
    host: str = typer.Option(
        "127.0.0.1", "--host", "-h", help="Host address to bind FastAPI server (default: 127.0.0.1)."
    ),
    port: int = typer.Option(
        8000, "--port", "-p", help="Port to bind FastAPI server (default: 8000)."
    ),
    reload: bool = typer.Option(
        False, "--reload", help="Enable auto-reload for development."
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Print server configuration without blocking."
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Format output as JSON."
    ),
) -> None:
    """Start the PenteFino FastAPI REST & WebSocket backend server (apps/api)."""
    is_json = json_output or (ctx.obj and ctx.obj.get("json", False))
    api_url = f"http://{host}:{port}"

    if dry_run:
        payload = {
            "status": "ready",
            "service": "pentefino-api",
            "host": host,
            "port": port,
            "url": api_url,
            "reload": reload,
        }
        if is_json:
            print_json(payload)
        else:
            console.print(
                Panel(
                    f"[bold green]FastAPI Server Ready (Dry-Run)[/bold green]\n"
                    f"URL: [cyan]{api_url}[/cyan]\n"
                    f"Docs: [cyan]{api_url}/docs[/cyan]",
                    title="PenteFino API",
                )
            )
        return

    if not is_json:
        console.print(
            Panel(
                f"[bold green]Starting PenteFino FastAPI Server[/bold green]\n"
                f"API Base: [cyan]{api_url}/api/v1[/cyan]\n"
                f"OpenAPI Docs: [cyan]{api_url}/docs[/cyan]\n"
                f"Security Mode: [yellow]LOCAL-ONLY BIND ({host})[/yellow]",
                title="PenteFino API (Phase 5)",
            )
        )

    import uvicorn

    uvicorn.run(
        "pentefino_api.main:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )


def run_gui_stack(
    ctx: typer.Context,
    host: str = typer.Option(
        "127.0.0.1", "--host", "-h", help="Host address to bind services (default: 127.0.0.1)."
    ),
    api_port: int = typer.Option(
        8000, "--api-port", help="FastAPI backend port (default: 8000)."
    ),
    gui_port: int = typer.Option(
        4321, "--gui-port", help="Astro 5 Dashboard port (default: 4321)."
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Print stack configuration without starting processes."
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Format output as JSON."
    ),
) -> None:
    """Start both the FastAPI backend and the Astro 5 Web GUI dashboard."""
    is_json = json_output or (ctx.obj and ctx.obj.get("json", False))
    repo_root = Path(__file__).resolve().parents[4]
    dashboard_dir = repo_root / "apps" / "dashboard"

    api_url = f"http://{host}:{api_port}"
    gui_url = f"http://{host}:{gui_port}"

    if dry_run:
        payload = {
            "status": "ready",
            "service": "pentefino-gui-stack",
            "host": host,
            "api_url": api_url,
            "gui_url": gui_url,
            "dashboard_dir": str(dashboard_dir),
        }
        if is_json:
            print_json(payload)
        else:
            console.print(
                Panel(
                    f"[bold green]PenteFino Web GUI Stack Ready (Dry-Run)[/bold green]\n"
                    f"Dashboard URL: [cyan]{gui_url}[/cyan]\n"
                    f"Backend API:   [cyan]{api_url}[/cyan]",
                    title="PenteFino Web GUI",
                )
            )
        return

    if not is_json:
        console.print(
            Panel(
                f"[bold green]Launching PenteFino Full GUI Stack[/bold green]\n"
                f"Astro 5 Dashboard: [bold cyan]{gui_url}[/bold cyan]\n"
                f"FastAPI Backend:   [cyan]{api_url}[/cyan]\n"
                f"WebSocket Hub:     [cyan]ws://{host}:{api_port}/ws[/cyan]",
                title="PenteFino Phase 5 GUI",
            )
        )

    api_proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "pentefino_api.main:app",
            "--host",
            host,
            "--port",
            str(api_port),
        ],
        cwd=str(repo_root),
    )

    npm_cmd = "npm.cmd" if sys.platform.startswith("win") else "npm"
    gui_proc = subprocess.Popen(
        [npm_cmd, "run", "dev", "--", "--host", host, "--port", str(gui_port)],
        cwd=str(dashboard_dir),
    )

    try:
        api_proc.wait()
        gui_proc.wait()
    except KeyboardInterrupt:
        api_proc.terminate()
        gui_proc.terminate()
