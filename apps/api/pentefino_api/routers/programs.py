from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from pentefino_api.deps import get_db_session, get_program_or_404, record_api_audit
from pentefino_api.schemas import ProgramCreate, ProgramResponse, ProgramUpdate
from pentefino_domain.enums import ProgramPlatform, ProgramState
from pentefino_domain.models.authorization import AuthorizationSnapshot
from pentefino_domain.models.program import Program

router = APIRouter(prefix="/api/v1/programs", tags=["programs"])


def _serialize_program(prog: Program) -> ProgramResponse:
    return ProgramResponse(
        id=str(prog.id),
        slug=prog.slug,
        name=prog.name,
        platform=prog.platform,
        state=prog.state,
        default_policy_id=prog.default_policy_id,
        created_at=prog.created_at.isoformat() if prog.created_at else None,
        scope_rules_count=len(prog.scope_rules) if "scope_rules" in prog.__dict__ else 0,
        assets_count=len(prog.assets) if "assets" in prog.__dict__ else 0,
        findings_count=len(prog.findings) if "findings" in prog.__dict__ else 0,
        snapshots_count=(
            len(prog.authorization_snapshots)
            if "authorization_snapshots" in prog.__dict__
            else 0
        ),
    )


@router.get("", response_model=list[ProgramResponse])
async def list_programs(
    state: Optional[str] = Query(None, description="Filter by program state"),
    session: AsyncSession = Depends(get_db_session),
) -> list[ProgramResponse]:
    """Return all bug bounty programs with asset, scope rule, and finding counts."""
    stmt = (
        select(Program)
        .options(
            selectinload(Program.scope_rules),
            selectinload(Program.assets),
            selectinload(Program.findings),
            selectinload(Program.authorization_snapshots),
        )
        .order_by(Program.created_at.desc())
    )
    if state:
        stmt = stmt.where(Program.state == state.strip().lower())

    result = await session.execute(stmt)
    programs = result.scalars().all()
    return [_serialize_program(p) for p in programs]


@router.post("", response_model=ProgramResponse, status_code=status.HTTP_201_CREATED)
async def create_program(
    payload: ProgramCreate,
    session: AsyncSession = Depends(get_db_session),
) -> ProgramResponse:
    """Create a new bug bounty program and record an audit event."""
    clean_slug = payload.slug.strip().lower()
    valid_platforms = {p.value for p in ProgramPlatform}
    if payload.platform not in valid_platforms:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid platform '{payload.platform}'. Allowed: {sorted(valid_platforms)}",
        )

    valid_states = {s.value for s in ProgramState}
    if payload.state not in valid_states:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid state '{payload.state}'. Allowed: {sorted(valid_states)}",
        )

    existing_stmt = select(Program).where(Program.slug == clean_slug)
    existing_res = await session.execute(existing_stmt)
    if existing_res.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Program with slug '{clean_slug}' already exists.",
        )

    prog = Program(
        slug=clean_slug,
        name=payload.name.strip(),
        platform=payload.platform,
        state=payload.state,
        default_policy_id=payload.default_policy_id,
    )
    session.add(prog)
    await session.flush()

    policy_hash = hashlib.sha256(
        f"{prog.slug}:{prog.default_policy_id}:init".encode("utf-8")
    ).hexdigest()
    snapshot = AuthorizationSnapshot(
        program_id=prog.id,
        source_url=f"https://pentefino.local/programs/{prog.slug}/policy",
        policy_hash=policy_hash,
        rules_json={"policy": prog.default_policy_id, "auto_initialized": True},
        valid_from=datetime.now(timezone.utc),
    )
    session.add(snapshot)
    await session.flush()

    await record_api_audit(
        session=session,
        event_type="api.program.create",
        object_type="program",
        object_id=prog.id,
        payload={
            "slug": prog.slug,
            "name": prog.name,
            "platform": prog.platform,
            "state": prog.state,
            "default_policy_id": prog.default_policy_id,
        },
    )

    return ProgramResponse(
        id=str(prog.id),
        slug=prog.slug,
        name=prog.name,
        platform=prog.platform,
        state=prog.state,
        default_policy_id=prog.default_policy_id,
        created_at=prog.created_at.isoformat() if prog.created_at else None,
        scope_rules_count=0,
        assets_count=0,
        findings_count=0,
        snapshots_count=1,
    )


@router.get("/{slug}", response_model=ProgramResponse)
async def get_program(
    slug: str,
    session: AsyncSession = Depends(get_db_session),
) -> ProgramResponse:
    """Get program details and counts by slug."""
    stmt = (
        select(Program)
        .options(
            selectinload(Program.scope_rules),
            selectinload(Program.assets),
            selectinload(Program.findings),
            selectinload(Program.authorization_snapshots),
        )
        .where(Program.slug == slug)
    )
    res = await session.execute(stmt)
    prog = res.scalar_one_or_none()
    if not prog:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Program '{slug}' not found.",
        )
    return _serialize_program(prog)


@router.patch("/{slug}", response_model=ProgramResponse)
async def update_program(
    slug: str,
    payload: ProgramUpdate,
    session: AsyncSession = Depends(get_db_session),
) -> ProgramResponse:
    """Update a program's name, state, or default_policy_id."""
    prog = await get_program_or_404(session, slug)

    if payload.name is not None:
        prog.name = payload.name.strip()
    if payload.state is not None:
        valid_states = {s.value for s in ProgramState}
        if payload.state not in valid_states:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid state '{payload.state}'. Allowed: {sorted(valid_states)}",
            )
        prog.state = payload.state
    if payload.default_policy_id is not None:
        prog.default_policy_id = payload.default_policy_id.strip()

    await session.flush()
    await record_api_audit(
        session=session,
        event_type="api.program.update",
        object_type="program",
        object_id=prog.id,
        payload=payload.model_dump(exclude_none=True),
    )

    stmt = (
        select(Program)
        .options(
            selectinload(Program.scope_rules),
            selectinload(Program.assets),
            selectinload(Program.findings),
            selectinload(Program.authorization_snapshots),
        )
        .where(Program.id == prog.id)
    )
    res = await session.execute(stmt)
    refreshed = res.scalar_one()
    return _serialize_program(refreshed)
