from __future__ import annotations

import json
import logging
import urllib.parse
import uuid
from typing import List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pentefino_adapters.models import HttpProbeRecord, TechnologyComponent
from pentefino_domain.models import Asset, Observation
from pentefino_runner import EphemeralRunner, RunConfig
from pentefino_scope import ScopeEngine
from pentefino_scope.models import ScopeTarget

logger = logging.getLogger(__name__)

DEFAULT_PROXY_URL: str = "http://pentefino_proxy:8080"


class HttpxAdapter:
    """Adapter for ProjectDiscovery httpx HTTP/HTTPS probing with cloaking & technology fingerprinting."""

    def __init__(
        self,
        runner: EphemeralRunner,
        proxy_url: str = DEFAULT_PROXY_URL,
        scope_engine: Optional[ScopeEngine] = None,
        image: str = "projectdiscovery/httpx:v1.6.0",
    ):
        self.runner = runner
        self.proxy_url = proxy_url
        self.scope_engine = scope_engine
        self.image = image

    def filter_targets(self, targets: List[str]) -> List[str]:
        """
        Filters targets to only probe authorized in-scope assets.
        Candidate assets, out-of-scope assets, and prohibited targets are excluded.
        """
        if not self.scope_engine:
            return targets

        filtered: List[str] = []
        for target_str in targets:
            target = ScopeTarget.from_url(target_str, is_derived=True)
            decision = self.scope_engine.evaluate_target(target)
            if decision.allowed:
                filtered.append(target_str)
            else:
                logger.info(
                    "Skipping target '%s' from HTTP probing (scope decision: %s, tier: %s)",
                    target_str,
                    decision.reason,
                    decision.matched_tier,
                )

        return filtered

    def build_run_config(
        self,
        targets: Optional[List[str]] = None,
        target_url: Optional[str] = None,
        extra_args: Optional[List[str]] = None,
    ) -> RunConfig:
        """Constructs RunConfig routing all traffic through forward egress proxy."""
        command = [
            "-http-proxy",
            self.proxy_url,
            "-silent",
            "-json",
            "-status-code",
            "-title",
            "-web-server",
            "-tech-detect",
            "-content-length",
        ]

        if target_url:
            command.extend(["-u", target_url])
        elif targets:
            for t in targets:
                command.extend(["-u", t])

        if extra_args:
            command.extend(extra_args)

        return RunConfig(
            image=self.image,
            command=command,
            http_proxy=self.proxy_url,
            https_proxy=self.proxy_url,
            timeout_seconds=300.0,
        )

    @staticmethod
    def normalize_technology(raw_tech: str) -> TechnologyComponent:
        """Normalizes raw technology string (e.g. 'Nginx:1.24.0' or 'FastAPI') into typed component."""
        cleaned = raw_tech.strip()
        if ":" in cleaned:
            parts = cleaned.split(":", 1)
            name = parts[0].strip().lower()
            version = parts[1].strip() or None
        else:
            name = cleaned.lower()
            version = None

        return TechnologyComponent(name=name, version=version, confidence=1.0)

    def parse_ndjson(self, raw_output: str) -> List[HttpProbeRecord]:
        """Parses httpx NDJSON stream and normalizes technology components."""
        probes: List[HttpProbeRecord] = []

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("Skipping malformed NDJSON line from httpx: %r", line)
                continue

            if not isinstance(data, dict):
                continue

            url = str(data.get("url") or "")
            input_host = str(data.get("input") or "")
            if not url and not input_host:
                continue

            if not input_host and url:
                parsed = urllib.parse.urlparse(url)
                input_host = parsed.hostname or ""

            # Check for probe errors/failures
            failed = bool(data.get("failed", False))
            error = str(data.get("err") or "") if failed or "err" in data else None

            status_code = data.get("status_code")
            if status_code is not None:
                try:
                    status_code = int(status_code)
                except (ValueError, TypeError):
                    status_code = None

            title = data.get("title")
            webserver = data.get("webserver")
            content_length = data.get("content_length")
            if content_length is not None:
                try:
                    content_length = int(content_length)
                except (ValueError, TypeError):
                    content_length = None

            raw_tech_list = data.get("tech") or []
            if isinstance(raw_tech_list, str):
                raw_tech_list = [raw_tech_list]

            components: List[TechnologyComponent] = [
                self.normalize_technology(t) for t in raw_tech_list if t
            ]

            tls_info = data.get("tls") if isinstance(data.get("tls"), dict) else None
            chain = data.get("chain") if isinstance(data.get("chain"), list) else []
            final_url = data.get("final_url")

            probes.append(
                HttpProbeRecord(
                    url=url,
                    input_host=input_host,
                    status_code=status_code,
                    title=str(title) if title is not None else None,
                    webserver=str(webserver) if webserver is not None else None,
                    content_length=content_length,
                    technologies=[c.name for c in components],
                    components=components,
                    tls=tls_info,
                    chain=chain,
                    final_url=str(final_url) if final_url else None,
                    failed=failed,
                    error=error,
                    raw_json=data,
                )
            )

        return probes

    async def persist(
        self,
        session: AsyncSession,
        program_id: uuid.UUID,
        probes: List[HttpProbeRecord],
    ) -> List[Observation]:
        """Persists HTTP probing observations in PostgreSQL."""
        saved_observations: List[Observation] = []

        for probe in probes:
            host_key = probe.input_host.lower()
            if not host_key and probe.url:
                parsed = urllib.parse.urlparse(probe.url)
                host_key = (parsed.hostname or "").lower()

            stmt = select(Asset).where(
                Asset.program_id == program_id,
                Asset.canonical_key == host_key,
            )
            res = await session.execute(stmt)
            asset = res.scalar_one_or_none()

            if not asset:
                continue

            obs = Observation(
                asset_id=asset.id,
                observation_type="http_probe",
                raw_data=json.dumps(probe.raw_json) if probe.raw_json else None,
                metadata_json={
                    "url": probe.url,
                    "input_host": probe.input_host,
                    "status_code": probe.status_code,
                    "title": probe.title,
                    "webserver": probe.webserver,
                    "content_length": probe.content_length,
                    "technologies": [c.name for c in probe.components],
                    "components": [
                        {"name": c.name, "version": c.version}
                        for c in probe.components
                    ],
                    "tls": probe.tls,
                    "failed": probe.failed,
                    "error": probe.error,
                },
            )
            session.add(obs)
            saved_observations.append(obs)

        await session.commit()
        return saved_observations

    async def probe(
        self,
        targets: Optional[List[str]] = None,
        target_url: Optional[str] = None,
        program_id: Optional[uuid.UUID] = None,
        session: Optional[AsyncSession] = None,
        extra_args: Optional[List[str]] = None,
    ) -> List[HttpProbeRecord]:
        """Filters targets, executes httpx via proxy, parses output, and optionally persists observations."""
        raw_targets = list(targets or [])
        if target_url and target_url not in raw_targets:
            raw_targets.append(target_url)

        valid_targets = self.filter_targets(raw_targets)
        if not valid_targets:
            logger.info("No authorized targets to probe with httpx.")
            return []

        config = self.build_run_config(targets=valid_targets, extra_args=extra_args)
        result = await self.runner.run(config)
        probes = self.parse_ndjson(result.stdout)

        if session is not None and program_id is not None and probes:
            await self.persist(session, program_id, probes)

        return probes

    parse_output = parse_ndjson
