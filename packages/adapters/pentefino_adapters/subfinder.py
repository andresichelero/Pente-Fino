from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pentefino_adapters.models import DiscoveredCandidate
from pentefino_domain.enums import AssetType, ScopeState
from pentefino_domain.models import Asset, Observation
from pentefino_runner import EphemeralRunner, RunConfig
from pentefino_scope import ScopeEngine
from pentefino_scope.enums import PrecedenceTier
from pentefino_scope.models import ScopeTarget

logger = logging.getLogger(__name__)


class SubfinderAdapter:
    """Adapter for ProjectDiscovery Subfinder passive subdomain enumeration."""

    def __init__(
        self,
        runner: EphemeralRunner,
        scope_engine: ScopeEngine,
        image: str = "projectdiscovery/subfinder:v2.6.6",
    ):
        self.runner = runner
        self.scope_engine = scope_engine
        self.image = image

    def build_run_config(
        self,
        domain: str,
        extra_args: Optional[List[str]] = None,
    ) -> RunConfig:
        """Constructs RunConfig for executing subfinder in an ephemeral container."""
        command = ["-d", domain, "-silent", "-json", "-all"]
        if extra_args:
            command.extend(extra_args)

        return RunConfig(
            image=self.image,
            command=command,
            timeout_seconds=300.0,
        )

    def parse_ndjson(self, raw_output: str) -> List[DiscoveredCandidate]:
        """Parses subfinder NDJSON output and evaluates scope state for each host."""
        candidates: List[DiscoveredCandidate] = []
        seen = set()

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("Skipping malformed NDJSON line from subfinder: %r", line)
                continue

            if not isinstance(data, dict):
                continue

            raw_host = data.get("host")
            if not raw_host:
                continue

            host = str(raw_host).strip().lower().rstrip(".")
            if not host or host in seen:
                continue
            seen.add(host)

            sources = data.get("sources") or []
            if isinstance(sources, str):
                sources = [sources]
            input_domain = str(data.get("input", ""))

            # Authoritative Scope Engine Evaluation with is_derived=True
            target = ScopeTarget.from_url(host, is_derived=True)
            decision = self.scope_engine.evaluate_target(target)

            if decision.allowed:
                if decision.matched_tier == PrecedenceTier.WILDCARD_ALLOW:
                    scope_state = ScopeState.IN_SCOPE_DERIVED
                elif decision.matched_tier == PrecedenceTier.EXPLICIT_ALLOW:
                    scope_state = ScopeState.IN_SCOPE_EXPLICIT
                else:
                    scope_state = ScopeState.IN_SCOPE_DERIVED
            elif decision.matched_tier == PrecedenceTier.DERIVED_CANDIDATE:
                scope_state = ScopeState.CANDIDATE
            else:
                # Explicit Deny, Path/Port Deny, Prohibited IP, or Unknown Deny
                scope_state = ScopeState.OUT_OF_SCOPE

            candidates.append(
                DiscoveredCandidate(
                    host=host,
                    sources=list(sources),
                    input=input_domain,
                    scope_state=scope_state,
                    matched_tier=decision.matched_tier,
                    raw_json=data,
                )
            )

        return candidates

    async def persist(
        self,
        session: AsyncSession,
        program_id: uuid.UUID,
        candidates: List[DiscoveredCandidate],
    ) -> List[Asset]:
        """Upserts discovered hostnames into assets table and records discovery observations."""
        saved_assets: List[Asset] = []

        for candidate in candidates:
            stmt = select(Asset).where(
                Asset.program_id == program_id,
                Asset.canonical_key == candidate.host,
                Asset.asset_type == AssetType.HOSTNAME.value,
            )
            res = await session.execute(stmt)
            asset = res.scalar_one_or_none()

            if not asset:
                asset = Asset(
                    program_id=program_id,
                    canonical_key=candidate.host,
                    asset_type=AssetType.HOSTNAME.value,
                    scope_state=candidate.scope_state.value,
                )
                session.add(asset)
                await session.flush()
            else:
                asset.last_seen = datetime.now(timezone.utc)
                # Promote candidate to in_scope_derived if new authorization allows it
                if (
                    asset.scope_state == ScopeState.CANDIDATE.value
                    and candidate.scope_state
                    in (ScopeState.IN_SCOPE_DERIVED, ScopeState.IN_SCOPE_EXPLICIT)
                ):
                    asset.scope_state = candidate.scope_state.value

            obs = Observation(
                asset_id=asset.id,
                observation_type="subdomain_discovery",
                raw_data=json.dumps(candidate.raw_json) if candidate.raw_json else None,
                metadata_json={
                    "host": candidate.host,
                    "sources": candidate.sources,
                    "input": candidate.input,
                    "scope_state": candidate.scope_state.value,
                },
            )
            session.add(obs)
            saved_assets.append(asset)

        await session.commit()
        return saved_assets

    async def discover(
        self,
        domain: str,
        program_id: Optional[uuid.UUID] = None,
        session: Optional[AsyncSession] = None,
        extra_args: Optional[List[str]] = None,
    ) -> List[DiscoveredCandidate]:
        """Runs subfinder container, parses output, and optionally persists records."""
        config = self.build_run_config(domain, extra_args=extra_args)
        result = await self.runner.run(config)
        candidates = self.parse_ndjson(result.stdout)

        if session is not None and program_id is not None and candidates:
            await self.persist(session, program_id, candidates)

        return candidates
