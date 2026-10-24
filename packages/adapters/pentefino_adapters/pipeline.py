from __future__ import annotations

import logging
import uuid
from pathlib import Path
from typing import Callable, List, Optional, Union
from sqlalchemy.ext.asyncio import AsyncSession

from pentefino_adapters.dnsx import DnsxAdapter
from pentefino_adapters.httpx import HttpxAdapter
from pentefino_adapters.models import ReconResult
from pentefino_adapters.subfinder import SubfinderAdapter
from pentefino_domain.enums import ScopeState
from pentefino_scope import ScopeEngine

logger = logging.getLogger(__name__)


class ReconPipeline:
    """Orchestrates Subfinder -> dnsx -> httpx sequential reconnaissance stages."""

    def __init__(
        self,
        subfinder: SubfinderAdapter,
        dnsx: DnsxAdapter,
        httpx: HttpxAdapter,
        scope_engine: Optional[ScopeEngine] = None,
    ):
        self.subfinder = subfinder
        self.dnsx = dnsx
        self.httpx = httpx
        self.scope_engine = scope_engine

    async def run(
        self,
        domain: str,
        program_id: Optional[uuid.UUID] = None,
        bruteforce: bool = False,
        wordlist_path: Optional[Union[Path, str]] = None,
        session: Optional[AsyncSession] = None,
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
    ) -> ReconResult:
        """
        Executes complete multi-stage recon workflow:
        1. Subfinder: Passive subdomain discovery & Scope Engine candidate evaluation.
        2. dnsx: Multi-resolver DNS resolution & Anti-SSRF filtering.
        3. httpx: Cloaked HTTP probing via proxy & technology fingerprinting.
        """
        clean_domain = domain.strip().lower()

        # -------------------------------------------------------------
        # Stage 1: Subfinder (Passive Discovery)
        # -------------------------------------------------------------
        if progress_callback:
            progress_callback("subfinder", 1, 3)
        logger.info("Starting Stage 1: Subfinder passive discovery on %s", clean_domain)

        candidates = await self.subfinder.discover(
            domain=clean_domain,
            program_id=program_id,
            session=session,
        )

        in_scope_candidates = [
            c
            for c in candidates
            if c.scope_state
            in (ScopeState.IN_SCOPE_DERIVED, ScopeState.IN_SCOPE_EXPLICIT)
        ]
        in_scope_hosts = [c.host for c in in_scope_candidates]

        # -------------------------------------------------------------
        # Stage 2: dnsx (Multi-Resolver Resolution & Anti-SSRF)
        # -------------------------------------------------------------
        if progress_callback:
            progress_callback("dnsx", 2, 3)
        logger.info(
            "Starting Stage 2: dnsx resolution on %d candidates (bruteforce=%s)",
            len(in_scope_hosts),
            bruteforce,
        )

        dns_records = await self.dnsx.resolve(
            hosts=in_scope_hosts,
            domain=clean_domain if bruteforce else None,
            wordlist_path=wordlist_path,
            bruteforce=bruteforce,
            program_id=program_id,
            session=session,
        )

        # Filter out hosts resolving to prohibited IP ranges (RFC1918, loopback, metadata)
        live_hosts: List[str] = [
            r.host
            for r in dns_records
            if (r.a or r.aaaa) and not r.is_prohibited_ip
        ]

        # -------------------------------------------------------------
        # Stage 3: httpx (Cloaked HTTP Probing & Technology Detection)
        # -------------------------------------------------------------
        if progress_callback:
            progress_callback("httpx", 3, 3)
        logger.info(
            "Starting Stage 3: httpx probing on %d live verified hosts",
            len(live_hosts),
        )

        http_probes = []
        if live_hosts:
            http_probes = await self.httpx.probe(
                targets=live_hosts,
                program_id=program_id,
                session=session,
            )

        live_http_count = len(
            [p for p in http_probes if not p.failed and p.status_code is not None]
        )

        logger.info(
            "ReconPipeline finished for %s: %d subdomains, %d in-scope, %d resolved, %d HTTP live",
            clean_domain,
            len(candidates),
            len(in_scope_candidates),
            len(live_hosts),
            live_http_count,
        )

        return ReconResult(
            domain=clean_domain,
            program_id=program_id,
            candidates=candidates,
            dns_records=dns_records,
            http_probes=http_probes,
            total_discovered=len(candidates),
            in_scope_count=len(in_scope_candidates),
            resolved_count=len(live_hosts),
            live_http_count=live_http_count,
        )
