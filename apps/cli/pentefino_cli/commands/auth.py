from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import typer
from sqlalchemy import select

from pentefino_cli.db import get_program_by_slug, record_audit_event, run_async
from pentefino_cli.formatters.json_output import print_json
from pentefino_cli.formatters.tables import (
    print_auth_snapshot,
    print_error,
    print_success,
)
from pentefino_domain.models import AuthorizationSnapshot
from pentefino_domain.session import get_async_session

app = typer.Typer(help="Manage cryptographically hashed authorization snapshots and program terms.")


def _parse_iso_datetime(value: Optional[str]) -> Optional[datetime]:
    """Parse ISO 8601 string into timezone-aware UTC datetime."""
    if not value or value.lower() in ("none", "null", ""):
        return None
    if value.lower() == "now":
        return datetime.now(timezone.utc)
    # Parse standard ISO formats
    clean_val = value.replace("Z", "+00:00")
    dt = datetime.fromisoformat(clean_val)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


@app.command("register")
def register_auth(
    ctx: typer.Context,
    program: str = typer.Option(
        ..., "--program", "-p", help="Target program slug."
    ),
    rules_file: Path = typer.Option(
        ..., "--rules-file", help="Path to rules or scope policy document (JSON/text)."
    ),
    valid_from: Optional[str] = typer.Option(
        "now", "--valid-from", help="ISO 8601 start timestamp (or 'now')."
    ),
    valid_until: Optional[str] = typer.Option(
        None, "--valid-until", help="ISO 8601 expiration timestamp (optional)."
    ),
    source_url: Optional[str] = typer.Option(
        None, "--source-url", help="Origin policy or bounty brief URL."
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Format output as JSON."
    ),
) -> None:
    """Register an immutable legal authorization snapshot with SHA-256 integrity verification."""
    is_json = json_output or (ctx.obj and ctx.obj.get("json", False))

    if not rules_file.exists():
        msg = f"Rules file not found: {rules_file}"
        if is_json:
            print_json({"status": "error", "error": msg})
        else:
            print_error(msg)
        raise typer.Exit(code=1)

    file_bytes = rules_file.read_bytes()
    policy_hash = hashlib.sha256(file_bytes).hexdigest()

    try:
        rules_json = json.loads(file_bytes.decode("utf-8"))
        if not isinstance(rules_json, dict):
            rules_json = {"items": rules_json}
    except Exception:
        rules_json = {"raw_content": file_bytes.decode("utf-8", errors="replace")}

    try:
        dt_from = _parse_iso_datetime(valid_from) or datetime.now(timezone.utc)
        dt_until = _parse_iso_datetime(valid_until)
    except Exception as exc:
        msg = f"Invalid timestamp format: {exc}"
        if is_json:
            print_json({"status": "error", "error": msg})
        else:
            print_error(msg)
        raise typer.Exit(code=1)

    async def _register() -> dict:
        async with get_async_session() as session:
            prog = await get_program_by_slug(session, program)
            if not prog:
                return {"error": f"Program '{program}' not found."}

            snapshot = AuthorizationSnapshot(
                program_id=prog.id,
                source_url=source_url,
                policy_hash=policy_hash,
                rules_json=rules_json,
                valid_from=dt_from,
                valid_until=dt_until,
            )
            session.add(snapshot)
            await session.flush()

            await record_audit_event(
                session=session,
                event_type="cli.auth.register",
                object_type="authorization_snapshot",
                object_id=snapshot.id,
                payload={
                    "program_slug": prog.slug,
                    "policy_hash": policy_hash,
                    "valid_from": dt_from.isoformat(),
                    "valid_until": dt_until.isoformat() if dt_until else None,
                    "source_url": source_url,
                },
            )
            await session.commit()

            return {
                "status": "registered",
                "snapshot_id": str(snapshot.id),
                "program": prog.slug,
                "policy_hash": snapshot.policy_hash,
                "source_url": snapshot.source_url,
                "valid_from": snapshot.valid_from.isoformat(),
                "valid_until": snapshot.valid_until.isoformat() if snapshot.valid_until else None,
            }

    result = run_async(_register())
    if "error" in result:
        if is_json:
            print_json({"status": "error", "error": result["error"]})
        else:
            print_error(result["error"])
        raise typer.Exit(code=1)

    if is_json:
        print_json(result)
    else:
        class _SnapView:
            pass
        s = _SnapView()
        s.id = result["snapshot_id"]
        s.policy_hash = result["policy_hash"]
        s.source_url = result["source_url"]
        s.valid_from = datetime.fromisoformat(result["valid_from"])
        s.valid_until = (
            datetime.fromisoformat(result["valid_until"])
            if result["valid_until"]
            else None
        )
        print_auth_snapshot(s, result["program"])


@app.command("verify")
def verify_auth(
    ctx: typer.Context,
    program: str = typer.Option(
        ..., "--program", "-p", help="Target program slug."
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Format output as JSON."
    ),
) -> None:
    """Verify that a program holds a valid, non-expired authorization snapshot."""
    is_json = json_output or (ctx.obj and ctx.obj.get("json", False))

    async def _verify() -> dict:
        async with get_async_session() as session:
            prog = await get_program_by_slug(session, program)
            if not prog:
                return {"error": f"Program '{program}' not found."}

            stmt = (
                select(AuthorizationSnapshot)
                .where(AuthorizationSnapshot.program_id == prog.id)
                .order_by(AuthorizationSnapshot.created_at.desc())
            )
            result = await session.execute(stmt)
            snapshot = result.scalars().first()

            if not snapshot:
                return {
                    "verified": False,
                    "program": prog.slug,
                    "reason": "No authorization snapshot registered for this program.",
                }

            now = datetime.now(timezone.utc)
            if snapshot.valid_from > now:
                return {
                    "verified": False,
                    "program": prog.slug,
                    "snapshot_id": str(snapshot.id),
                    "policy_hash": snapshot.policy_hash,
                    "reason": f"Authorization snapshot is not active yet (starts at {snapshot.valid_from.isoformat()}).",
                }

            if snapshot.valid_until and snapshot.valid_until <= now:
                return {
                    "verified": False,
                    "program": prog.slug,
                    "snapshot_id": str(snapshot.id),
                    "policy_hash": snapshot.policy_hash,
                    "reason": f"Authorization snapshot expired at {snapshot.valid_until.isoformat()}.",
                }

            return {
                "verified": True,
                "program": prog.slug,
                "snapshot_id": str(snapshot.id),
                "policy_hash": snapshot.policy_hash,
                "valid_from": snapshot.valid_from.isoformat(),
                "valid_until": snapshot.valid_until.isoformat() if snapshot.valid_until else None,
                "reason": "Authorization snapshot is active and valid.",
            }

    data = run_async(_verify())
    if "error" in data:
        if is_json:
            print_json({"status": "error", "error": data["error"]})
        else:
            print_error(data["error"])
        raise typer.Exit(code=1)

    if is_json:
        print_json(data)
    else:
        if data["verified"]:
            print_success(f"Program '{data['program']}' authorization verified: {data['reason']} (Hash: {data['policy_hash'][:16]}...)")
        else:
            print_error(f"Program '{data['program']}' authorization invalid: {data['reason']}")


@app.command("list")
def list_auth(
    ctx: typer.Context,
    program: str = typer.Option(
        ..., "--program", "-p", help="Target program slug."
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Format output as JSON."
    ),
) -> None:
    """List authorization snapshots registered for a program."""
    is_json = json_output or (ctx.obj and ctx.obj.get("json", False))

    async def _list() -> dict:
        async with get_async_session() as session:
            prog = await get_program_by_slug(session, program)
            if not prog:
                return {"error": f"Program '{program}' not found."}

            stmt = (
                select(AuthorizationSnapshot)
                .where(AuthorizationSnapshot.program_id == prog.id)
                .order_by(AuthorizationSnapshot.created_at.desc())
            )
            result = await session.execute(stmt)
            snapshots = result.scalars().all()

            return {
                "program": prog.slug,
                "snapshots": [
                    {
                        "id": str(s.id),
                        "policy_hash": s.policy_hash,
                        "source_url": s.source_url,
                        "valid_from": s.valid_from.isoformat(),
                        "valid_until": s.valid_until.isoformat() if s.valid_until else None,
                        "created_at": s.created_at.isoformat() if s.created_at else None,
                    }
                    for s in snapshots
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
        print_json(data["snapshots"])
    else:
        from rich.table import Table
        from rich.console import Console
        table = Table(title=f"Authorization Snapshots for '{data['program']}'", border_style="cyan")
        table.add_column("Snapshot ID", style="cyan")
        table.add_column("Policy Hash (SHA-256)", style="bold white")
        table.add_column("Valid From", style="green")
        table.add_column("Valid Until", style="yellow")
        table.add_column("Source URL", style="dim")

        for s in data["snapshots"]:
            table.add_row(
                s["id"][:8] + "...",
                s["policy_hash"][:16] + "...",
                s["valid_from"][:19],
                s["valid_until"][:19] if s["valid_until"] else "Indefinite",
                s["source_url"] or "-",
            )
        Console().print(table)
