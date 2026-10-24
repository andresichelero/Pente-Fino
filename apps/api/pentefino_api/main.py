from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from pentefino_api.deps import get_db_session
from pentefino_api.routers import (
    assets,
    findings,
    programs,
    scans,
    scope,
    templates,
    ws,
)
from pentefino_domain.models.program import Program
from pentefino_domain.models.template import TemplateCatalog


def create_app() -> FastAPI:
    """Create and configure the PenteFino FastAPI application."""
    app = FastAPI(
        title="PenteFino Security Governance & Recon API",
        version="0.1.0",
        description=(
            "Hard-gate fail-closed scope governance, CDN-pruned Nuclei detection planner, "
            "and forensic bug bounty triage API."
        ),
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:4321",
            "http://127.0.0.1:4321",
            "http://localhost:3000",
            "*",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/api/v1/health", tags=["health"])
    async def health_check(
        session: AsyncSession = Depends(get_db_session),
    ) -> dict[str, Any]:
        """Check database connectivity, template catalog count, and active programs count."""
        db_status = "connected"
        templates_count = 0
        active_programs_count = 0

        try:
            tpl_res = await session.execute(
                select(func.count()).select_from(TemplateCatalog)
            )
            templates_count = int(tpl_res.scalar_one() or 0)

            prog_res = await session.execute(
                select(func.count())
                .select_from(Program)
                .where(Program.state == "active")
            )
            active_programs_count = int(prog_res.scalar_one() or 0)
        except Exception as exc:
            db_status = f"degraded ({type(exc).__name__})"

        return {
            "status": "ok" if db_status == "connected" else "degraded",
            "service": "pentefino-api",
            "version": "0.1.0",
            "database": db_status,
            "templates_count": templates_count,
            "active_programs_count": active_programs_count,
        }

    app.include_router(programs.router)
    app.include_router(scope.router)
    app.include_router(assets.router)
    app.include_router(templates.router)
    app.include_router(scans.router)
    app.include_router(findings.router)
    app.include_router(ws.router)

    return app


app = create_app()
