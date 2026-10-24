from __future__ import annotations

import json
import logging
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Union
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pentefino_adapters.models import DnsRecord
from pentefino_domain.enums import AssetType, ScopeState
from pentefino_domain.models import Asset, Observation
from pentefino_runner import EphemeralRunner, RunConfig, VolumeMount
from pentefino_scope import ScopeEngine
from pentefino_scope.enums import PrecedenceTier
from pentefino_scope.ip_filter import is_prohibited_ip
from pentefino_scope.models import ScopeTarget

logger = logging.getLogger(__name__)

DEFAULT_RESOLVERS: List[str] = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
DEFAULT_WORDLIST_PATH = "data/wordlists/subdomains-top5k.txt"
CONTAINER_WORDLIST_PATH = "/data/wordlists/subdomains-top5k.txt"


class DnsxAdapter:
    """Adapter for ProjectDiscovery dnsx multi-resolver DNS enumeration and brute-forcing."""

    def __init__(
        self,
        runner: EphemeralRunner,
        resolvers: Optional[List[str]] = None,
        scope_engine: Optional[ScopeEngine] = None,
        image: str = "projectdiscovery/dnsx:v1.2.1",
    ):
        self.runner = runner
        self.resolvers = resolvers if resolvers is not None else list(DEFAULT_RESOLVERS)
        self.scope_engine = scope_engine
        self.image = image

    def build_run_config(
        self,
        hosts: Optional[List[str]] = None,
        domain: Optional[str] = None,
        wordlist_path: Optional[Union[Path, str]] = None,
        bruteforce: bool = False,
        extra_args: Optional[List[str]] = None,
    ) -> RunConfig:
        """Builds RunConfig enforcing trusted public resolvers and wordlist mounting if brute-forcing."""
        command = [
            "-r",
            ",".join(self.resolvers),
            "-a",
            "-aaaa",
            "-cname",
            "-resp",
            "-json",
            "-silent",
        ]

        volumes: List[VolumeMount] = []

        if bruteforce:
            target_domain = domain or (hosts[0] if hosts else None)
            if target_domain:
                command.extend(["-d", target_domain])

            raw_wl = wordlist_path if wordlist_path is not None else DEFAULT_WORDLIST_PATH
            wl_path = Path(raw_wl)
            if wl_path.is_file():
                host_wl_path = wl_path
            else:
                stripped = Path(str(raw_wl).lstrip("/\\"))
                if stripped.is_file():
                    host_wl_path = stripped
                else:
                    workspace_root = Path(__file__).resolve().parents[3]
                    cand = workspace_root / stripped
                    if cand.is_file():
                        host_wl_path = cand
                    else:
                        host_wl_path = wl_path

            container_wl = CONTAINER_WORDLIST_PATH
            command.extend(["-w", container_wl])
            volumes.append(
                VolumeMount(
                    host_path=str(host_wl_path),
                    container_path=container_wl,
                    mode="ro",
                )
            )
        else:
            if domain:
                command.extend(["-d", domain])
            elif hosts:
                for h in hosts:
                    command.extend(["-d", h])

        if extra_args:
            command.extend(extra_args)

        return RunConfig(
            image=self.image,
            command=command,
            volumes=volumes,
            timeout_seconds=300.0,
        )

    def parse_ndjson(self, raw_output: str) -> List[DnsRecord]:
        """Parses dnsx NDJSON stream, performs anti-SSRF IP inspection and CNAME evaluation."""
        records: List[DnsRecord] = []

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("Skipping malformed NDJSON line from dnsx: %r", line)
                continue

            if not isinstance(data, dict):
                continue

            raw_host = data.get("host")
            if not raw_host:
                continue

            host = str(raw_host).strip().lower().rstrip(".")
            a_records = [str(ip).strip() for ip in (data.get("a") or []) if ip]
            aaaa_records = [str(ip).strip() for ip in (data.get("aaaa") or []) if ip]
            cname_records = [
                str(c).strip().lower().rstrip(".")
                for c in (data.get("cname") or [])
                if c
            ]
            resolvers = [str(r).strip() for r in (data.get("resolver") or []) if r]

            # Anti-SSRF inspection on all resolved IPs
            prohibited = False
            prohibited_reason: Optional[str] = None

            for ip in a_records + aaaa_records:
                is_proh, reason = is_prohibited_ip(ip)
                if is_proh:
                    prohibited = True
                    prohibited_reason = f"PROHIBITED_IP_SPACE: {reason} ({ip})"
                    break

            # CNAME Scope Evaluation
            cname_evals: Dict[str, ScopeState] = {}
            if self.scope_engine:
                for cname in cname_records:
                    cname_target = ScopeTarget.from_url(cname, is_derived=True)
                    decision = self.scope_engine.evaluate_target(cname_target)
                    if decision.allowed:
                        if decision.matched_tier == PrecedenceTier.WILDCARD_ALLOW:
                            cname_evals[cname] = ScopeState.IN_SCOPE_DERIVED
                        elif decision.matched_tier == PrecedenceTier.EXPLICIT_ALLOW:
                            cname_evals[cname] = ScopeState.IN_SCOPE_EXPLICIT
                        else:
                            cname_evals[cname] = ScopeState.IN_SCOPE_DERIVED
                    elif decision.matched_tier == PrecedenceTier.DERIVED_CANDIDATE:
                        cname_evals[cname] = ScopeState.CANDIDATE
                    else:
                        cname_evals[cname] = ScopeState.OUT_OF_SCOPE

            records.append(
                DnsRecord(
                    host=host,
                    a=a_records,
                    aaaa=aaaa_records,
                    cname=cname_records,
                    resolver=resolvers,
                    is_prohibited_ip=prohibited,
                    prohibited_reason=prohibited_reason,
                    cname_evaluations=cname_evals,
                    raw_json=data,
                )
            )

        return records

    async def persist(
        self,
        session: AsyncSession,
        program_id: uuid.UUID,
        records: List[DnsRecord],
    ) -> List[Observation]:
        """
        Persists DNS resolution answers strictly as Observation records.

        CRITICAL IP INVARIANT:
        Resolved A/AAAA IP addresses must be recorded strictly as observations attached
        to the hostname Asset; resolved IPs must NEVER be promoted or converted to
        in-scope Asset records in the database.
        """
        saved_observations: List[Observation] = []

        for record in records:
            # Look up existing hostname asset
            stmt = select(Asset).where(
                Asset.program_id == program_id,
                Asset.canonical_key == record.host,
            )
            res = await session.execute(stmt)
            asset = res.scalar_one_or_none()

            if not asset:
                # If asset was not found, determine scope state via ScopeEngine if available
                if record.is_prohibited_ip:
                    scope_state = ScopeState.OUT_OF_SCOPE.value
                elif self.scope_engine:
                    target = ScopeTarget.from_url(record.host, is_derived=True)
                    decision = self.scope_engine.evaluate_target(target)
                    if decision.matched_tier == PrecedenceTier.WILDCARD_ALLOW:
                        scope_state = ScopeState.IN_SCOPE_DERIVED.value
                    elif decision.matched_tier == PrecedenceTier.EXPLICIT_ALLOW:
                        scope_state = ScopeState.IN_SCOPE_EXPLICIT.value
                    elif decision.matched_tier == PrecedenceTier.DERIVED_CANDIDATE:
                        scope_state = ScopeState.CANDIDATE.value
                    else:
                        scope_state = ScopeState.OUT_OF_SCOPE.value
                else:
                    scope_state = ScopeState.IN_SCOPE_DERIVED.value

                # Create hostname asset (not an IP asset!)
                asset = Asset(
                    program_id=program_id,
                    canonical_key=record.host,
                    asset_type=AssetType.HOSTNAME.value,
                    scope_state=scope_state,
                )
                session.add(asset)
                await session.flush()

            # Record DNS answer strictly as Observation attached to hostname asset
            obs = Observation(
                asset_id=asset.id,
                observation_type="dns",
                raw_data=json.dumps(record.raw_json) if record.raw_json else None,
                metadata_json={
                    "host": record.host,
                    "a": record.a,
                    "aaaa": record.aaaa,
                    "cname": record.cname,
                    "resolver": record.resolver,
                    "is_prohibited_ip": record.is_prohibited_ip,
                    "prohibited_reason": record.prohibited_reason,
                    "cname_evaluations": {
                        k: v.value for k, v in record.cname_evaluations.items()
                    },
                },
            )
            session.add(obs)
            saved_observations.append(obs)

        await session.commit()
        return saved_observations

    async def resolve(
        self,
        hosts: Optional[List[str]] = None,
        domain: Optional[str] = None,
        wordlist_path: Optional[Union[Path, str]] = None,
        bruteforce: bool = False,
        program_id: Optional[uuid.UUID] = None,
        session: Optional[AsyncSession] = None,
        extra_args: Optional[List[str]] = None,
    ) -> List[DnsRecord]:
        """Executes dnsx container, parses responses, and optionally persists DNS observations."""
        config = self.build_run_config(
            hosts=hosts,
            domain=domain,
            wordlist_path=wordlist_path,
            bruteforce=bruteforce,
            extra_args=extra_args,
        )
        result = await self.runner.run(config)
        records = self.parse_ndjson(result.stdout)

        if session is not None and program_id is not None and records:
            await self.persist(session, program_id, records)

        return records
