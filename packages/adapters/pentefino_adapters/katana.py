from __future__ import annotations

import json
import logging
import re
import urllib.parse
import uuid
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pentefino_adapters.models import KatanaEndpointRecord
from pentefino_domain.models import Asset, Observation
from pentefino_runner import EphemeralRunner, RunConfig
from pentefino_scope import ScopeEngine
from pentefino_scope.models import ScopeTarget

logger = logging.getLogger(__name__)

DEFAULT_PROXY_URL: str = "http://pentefino_proxy:8080"


class KatanaAdapter:
    """Adapter for ProjectDiscovery Katana crawler with scope confinement and proxy routing."""

    def __init__(
        self,
        runner: EphemeralRunner,
        proxy_url: str = DEFAULT_PROXY_URL,
        scope_engine: Optional[ScopeEngine] = None,
        image: str = "projectdiscovery/katana:v1.1.0",
    ):
        self.runner = runner
        self.proxy_url = proxy_url
        self.scope_engine = scope_engine
        self.image = image

    def derive_scope_regexes(self, target_url: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Derives crawl scope regex (-cs) and crawl out-of-scope regex (-cos) from target URL and ScopeEngine.
        """
        parsed = urllib.parse.urlsplit(target_url)
        hostname = (parsed.hostname or "").strip().lower()
        if not hostname:
            return None, None

        escaped_host = re.escape(hostname)
        crawl_scope_regex = rf"^https?://([a-zA-Z0-9-]+\.)*{escaped_host}(:[0-9]+)?(/.*)?$"

        crawl_out_scope_regex: Optional[str] = None
        if self.scope_engine:
            denied_patterns: List[str] = []
            for rule in getattr(self.scope_engine, "rules", []):
                action = getattr(rule, "action", None)
                action_str = getattr(action, "value", str(action)) if action is not None else ""
                if str(action_str).lower() == "deny":
                    pattern = getattr(rule, "pattern", "")
                    if pattern:
                        denied_patterns.append(re.escape(pattern.strip()))
            if denied_patterns:
                crawl_out_scope_regex = rf"({'|'.join(denied_patterns)})"

        return crawl_scope_regex, crawl_out_scope_regex

    def build_run_config(
        self,
        target_url: str,
        crawl_scope_regex: Optional[str] = None,
        crawl_out_scope_regex: Optional[str] = None,
        depth: int = 2,
        headless: bool = False,
        rate_limit: int = 10,
        concurrency: int = 10,
        extra_args: Optional[List[str]] = None,
    ) -> RunConfig:
        """
        Constructs RunConfig with strict scope confinement flags (-cs, -cos) and egress proxy.
        """
        derived_cs, derived_cos = self.derive_scope_regexes(target_url)
        cs = crawl_scope_regex or derived_cs
        cos = crawl_out_scope_regex or derived_cos

        command: List[str] = [
            "-u",
            target_url,
            "-silent",
            "-json",
            "-d",
            str(depth),
            "-jc",
            "-kf",
            "all",
            "-proxy",
            self.proxy_url,
        ]

        if cs:
            command.extend(["-cs", cs])
        if cos:
            command.extend(["-cos", cos])
        if headless:
            command.append("-headless")
        if rate_limit:
            command.extend(["-rl", str(rate_limit)])
        if concurrency:
            command.extend(["-c", str(concurrency)])
        if extra_args:
            command.extend(extra_args)

        return RunConfig(
            image=self.image,
            command=command,
            http_proxy=self.proxy_url,
            https_proxy=self.proxy_url,
            timeout_seconds=300.0,
        )

    def parse_ndjson(self, raw_output: str) -> List[KatanaEndpointRecord]:
        """
        Parses Katana NDJSON output stream, extracts endpoints, methods, forms,
        and evaluates every discovered endpoint against ScopeEngine.
        """
        records: List[KatanaEndpointRecord] = []

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("Skipping malformed NDJSON line from Katana: %r", line)
                continue

            if not isinstance(data, dict):
                continue

            req = data.get("request") or {}
            resp = data.get("response") or {}

            endpoint = ""
            if isinstance(req, dict) and req.get("endpoint"):
                endpoint = str(req.get("endpoint") or "")
            elif data.get("endpoint"):
                endpoint = str(data.get("endpoint") or "")
            elif data.get("url"):
                endpoint = str(data.get("url") or "")

            if not endpoint:
                continue

            method = "GET"
            if isinstance(req, dict) and req.get("method"):
                method = str(req.get("method")).upper()
            elif data.get("method"):
                method = str(data.get("method")).upper()

            parsed_url = urllib.parse.urlsplit(endpoint)
            path = parsed_url.path or "/"
            if parsed_url.query:
                path = f"{path}?{parsed_url.query}"

            status_code: Optional[int] = None
            raw_status = resp.get("status_code") if isinstance(resp, dict) else data.get("status_code")
            if raw_status is not None:
                try:
                    status_code = int(raw_status)
                except (ValueError, TypeError):
                    status_code = None

            raw_tech = resp.get("technologies") if isinstance(resp, dict) else (data.get("technologies") or data.get("tech"))
            technologies: List[str] = []
            if isinstance(raw_tech, list):
                technologies = [str(t).strip().lower() for t in raw_tech if t]
            elif isinstance(raw_tech, str) and raw_tech.strip():
                technologies = [raw_tech.strip().lower()]

            form_data: Optional[Dict[str, Any]] = None
            if isinstance(req, dict) and req.get("form"):
                form_data = req.get("form")
            elif isinstance(req, dict) and req.get("body"):
                form_data = {"body": req.get("body")}
            elif data.get("form"):
                form_data = data.get("form")

            is_in_scope = True
            scope_tier = None
            scope_reason = None

            if self.scope_engine:
                try:
                    target = ScopeTarget.from_url(endpoint, is_derived=True)
                    decision = self.scope_engine.evaluate_target(target)
                    is_in_scope = decision.allowed
                    scope_tier = decision.matched_tier
                    scope_reason = decision.reason
                except Exception as ex:
                    logger.warning("Scope evaluation failed for endpoint %s: %s", endpoint, ex)
                    is_in_scope = False
                    scope_reason = f"SCOPE_EVAL_ERROR: {ex}"

            records.append(
                KatanaEndpointRecord(
                    endpoint=endpoint,
                    url=endpoint,
                    path=path,
                    method=method,
                    status_code=status_code,
                    technologies=technologies,
                    form_data=form_data,
                    is_in_scope=is_in_scope,
                    scope_tier=scope_tier,
                    scope_reason=scope_reason,
                    raw_json=data,
                )
            )

        return records

    async def persist(
        self,
        session: AsyncSession,
        program_id: uuid.UUID,
        records: List[KatanaEndpointRecord],
    ) -> List[Observation]:
        """Persists crawled endpoint observations in PostgreSQL."""
        saved_observations: List[Observation] = []

        for record in records:
            parsed = urllib.parse.urlsplit(record.endpoint)
            host_key = (parsed.hostname or "").lower()
            if not host_key:
                continue

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
                observation_type="crawled_endpoint",
                raw_data=json.dumps(record.raw_json) if record.raw_json else None,
                metadata_json={
                    "endpoint": record.endpoint,
                    "url": record.url,
                    "path": record.path,
                    "method": record.method,
                    "status_code": record.status_code,
                    "technologies": record.technologies,
                    "form_data": record.form_data,
                    "is_in_scope": record.is_in_scope,
                    "scope_tier": record.scope_tier.value if record.scope_tier else None,
                    "scope_reason": record.scope_reason,
                },
            )
            session.add(obs)
            saved_observations.append(obs)

        if saved_observations:
            await session.commit()
        return saved_observations

    async def crawl(
        self,
        target_url: str,
        crawl_scope_regex: Optional[str] = None,
        crawl_out_scope_regex: Optional[str] = None,
        depth: int = 2,
        headless: bool = False,
        rate_limit: int = 10,
        concurrency: int = 10,
        extra_args: Optional[List[str]] = None,
        filter_out_of_scope: bool = False,
        program_id: Optional[uuid.UUID] = None,
        session: Optional[AsyncSession] = None,
    ) -> List[KatanaEndpointRecord]:
        """
        Executes Katana crawler via EphemeralRunner, parses NDJSON, and evaluates scope.
        """
        if self.scope_engine:
            target = ScopeTarget.from_url(target_url, is_derived=True)
            decision = self.scope_engine.evaluate_target(target)
            if not decision.allowed:
                logger.warning(
                    "Target URL '%s' rejected by ScopeEngine: %s (%s)",
                    target_url,
                    decision.reason,
                    decision.matched_tier,
                )
                return []

        config = self.build_run_config(
            target_url=target_url,
            crawl_scope_regex=crawl_scope_regex,
            crawl_out_scope_regex=crawl_out_scope_regex,
            depth=depth,
            headless=headless,
            rate_limit=rate_limit,
            concurrency=concurrency,
            extra_args=extra_args,
        )

        result = await self.runner.run(config)
        records = self.parse_ndjson(result.stdout)

        if filter_out_of_scope:
            records = [r for r in records if r.is_in_scope]

        if session is not None and program_id is not None and records:
            await self.persist(session, program_id, records)

        return records

    parse_output = parse_ndjson
