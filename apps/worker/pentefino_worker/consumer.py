"""Asynchronous Scan Task Worker Consumer.

Processes queued scan jobs dispatched via CLI (`--async`) or API queue,
enforcing fail-closed scope verification before invoking DetectionPlanner,
HardenedNucleiRunner, and FindingNormalizer.
"""
from __future__ import annotations

from typing import Any
import uuid
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pentefino_detection import (
    DetectionPlanner,
    FindingNormalizer,
    HardenedNucleiRunner,
)
from pentefino_domain.enums import ImpactClass
from pentefino_domain.models.asset import Asset
from pentefino_domain.models.program import Program
from pentefino_runner import EphemeralRunner


class ScanTaskJob(BaseModel):
    """Represents a queued scan job payload."""

    run_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    program_slug: str
    target_asset: str
    severity: str | None = None
    tags: str | None = None
    container_name: str | None = None


class ReconTaskJob(BaseModel):
    """Represents a queued recon task payload."""

    run_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    program_slug: str
    domain: str
    bruteforce: bool = False
    container_name: str | None = None


class IntelTaskJob(BaseModel):
    """Represents a queued threat intelligence sync payload."""

    run_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    action: str = "sync"
    sources: list[str] = Field(default_factory=lambda: ["epss", "kev"])



class ScanTaskWorker:
    """Executes queued scan jobs with fail-closed scope verification."""

    def __init__(
        self,
        db_session: AsyncSession,
        runner: EphemeralRunner | None = None,
        s3_client: Any | None = None,
    ):
        self.db_session = db_session
        self.runner = runner or EphemeralRunner()
        self.s3_client = s3_client

    async def process_job(self, job: ScanTaskJob) -> dict[str, Any]:
        """Process a single queued ScanTaskJob."""
        prog_stmt = select(Program).where(Program.slug == job.program_slug.strip().lower())
        prog_res = await self.db_session.execute(prog_stmt)
        prog = prog_res.scalar_one_or_none()
        if not prog:
            return {
                "status": "failed",
                "run_id": str(job.run_id),
                "error": f"Program '{job.program_slug}' not found.",
            }

        clean_asset = job.target_asset.strip().lower()
        asset_stmt = select(Asset).where(
            Asset.program_id == prog.id,
            Asset.canonical_key == clean_asset,
        )
        asset_res = await self.db_session.execute(asset_stmt)
        asset = asset_res.scalar_one_or_none()
        if not asset:
            return {
                "status": "failed",
                "run_id": str(job.run_id),
                "error": f"Asset '{clean_asset}' not found in program '{prog.slug}'.",
            }

        # Hard-Gate Fail-Closed Scope State Check
        if asset.scope_state not in ("in_scope_explicit", "in_scope_derived"):
            return {
                "status": "rejected_out_of_scope",
                "run_id": str(job.run_id),
                "asset": asset.canonical_key,
                "scope_state": asset.scope_state,
                "error": (
                    f"Hard-Gate Fail-Closed: Asset '{asset.canonical_key}' has scope_state="
                    f"'{asset.scope_state}' and cannot be scanned."
                ),
            }

        planner = DetectionPlanner(db_session=self.db_session)
        plan = await planner.create_plan(
            asset=asset,
            severity_filter=job.severity,
            tag_filter=job.tags,
            max_impact_class=ImpactClass.SAFE_READ_ONLY,
        )

        nuclei_runner = HardenedNucleiRunner(runner=self.runner)
        raw_findings = await nuclei_runner.execute_scan(plan=plan)

        normalizer = FindingNormalizer(
            db_session=self.db_session,
            s3_client=self.s3_client,
        )
        persisted = await normalizer.normalize_and_persist(
            raw_nuclei_results=raw_findings,
            program_id=prog.id,
            asset_id=asset.id,
            run_id=job.run_id,
        )

        return {
            "status": "completed",
            "run_id": str(job.run_id),
            "plan_id": str(plan.plan_id),
            "program_slug": prog.slug,
            "asset": asset.canonical_key,
            "total_templates": plan.total_templates,
            "findings_count": len(persisted),
        }
