from __future__ import annotations

import os
from typing import Optional
from dotenv import load_dotenv
import typer

load_dotenv()

from pentefino_cli import __version__
from pentefino_cli.commands import (
    asset,
    auth,
    finding,
    gui,
    intel,
    program,
    recon,
    run,
    scan,
    scope,
    template,
)
from pentefino_cli.formatters.json_output import print_json

app = typer.Typer(
    name="pentefino",
    help="PenteFino: Production-grade, evidence-centric attack surface management and traffic control platform.",
    no_args_is_help=True,
    add_completion=False,
)


@app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
    json_output: bool = typer.Option(
        False, "--json", help="Format all output as machine-readable JSON."
    ),
    version: Optional[bool] = typer.Option(
        None, "--version", "-v", is_eager=True, help="Show PenteFino version and exit."
    ),
) -> None:
    """PenteFino attack surface and traffic control plane management CLI."""
    if version:
        if json_output:
            print_json({"name": "pentefino", "version": __version__})
        else:
            typer.echo(f"pentefino version {__version__}")
        raise typer.Exit(code=0)

    ctx.ensure_object(dict)
    ctx.obj["json"] = json_output

    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit(code=0)


# Subcommands registration
app.add_typer(program.app, name="program")
app.add_typer(scope.app, name="scope")
app.add_typer(auth.app, name="auth")
app.add_typer(asset.app, name="asset")
app.add_typer(run.app, name="run")
app.add_typer(finding.app, name="finding")
app.add_typer(recon.app, name="recon")
app.add_typer(scan.app, name="scan")
app.add_typer(template.app, name="template")
app.add_typer(intel.app, name="intel")
app.command(name="api")(gui.run_api_server)
app.command(name="gui")(gui.run_gui_stack)


if __name__ == "__main__":
    app()
