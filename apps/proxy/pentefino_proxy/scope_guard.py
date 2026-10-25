from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from uuid import UUID

from pentefino_scope import (
    PrecedenceTier,
    ScopeDecision,
    ScopeEngine,
    ScopeTarget,
    check_dns_rebinding,
    is_prohibited_ip,
)

logger = logging.getLogger("pentefino.proxy.scope_guard")


class ScopeGuardError(Exception):
    """Exception raised when an out-of-scope or prohibited request is detected."""

    def __init__(self, decision: ScopeDecision, status_code: int = 403):
        self.decision = decision
        self.status_code = status_code
        super().__init__(f"Scope violation: {decision.reason} (tier: {decision.matched_tier})")


class ScopeGuard:
    """
    Scope Guard integrates the forward proxy with the ScopeEngine.
    Enforces strict 7-tier precedence and anti-SSRF / DNS rebinding guards.
    """

    def __init__(
        self,
        default_engine: Optional[ScopeEngine] = None,
        engine_resolver: Optional[Callable[[Optional[UUID]], Optional[ScopeEngine]]] = None,
        environment_class: str = "bounty",
    ):
        self.default_engine = default_engine
        self.engine_resolver = engine_resolver
        self.environment_class = environment_class
        self._programs: Dict[UUID, ScopeEngine] = {}

    def register_engine(self, program_id: UUID, engine: ScopeEngine) -> None:
        """Associates a ScopeEngine instance with a specific program ID."""
        self._programs[program_id] = engine

    async def sync_from_db(
        self, session: Any, program_id: Optional[UUID] = None
    ) -> None:
        """
        Dynamically loads active ScopeRule and AuthorizationSnapshot records from PostgreSQL
        and updates the in-memory ScopeEngine instances for the specified program_id
        or for all programs if program_id is None.
        """
        from sqlalchemy import select
        from pentefino_domain.models import AuthorizationSnapshot, Program, ScopeRule
        from pentefino_scope.enums import (
            AssetType as ScopeAssetType,
            ScopeAction as ScopeRuleAction,
        )
        from pentefino_scope.models import (
            AuthorizationSnapshot as ScopeAuthSnapshot,
            ScopeRule as ScopeEngineRule,
        )

        if program_id is not None:
            # Sync single program
            prog_stmt = select(Program).where(Program.id == program_id)
            prog_res = await session.execute(prog_stmt)
            prog = prog_res.scalar_one_or_none()

            rules_stmt = (
                select(ScopeRule)
                .where(ScopeRule.program_id == program_id)
                .order_by(ScopeRule.priority.asc())
            )
            rules_res = await session.execute(rules_stmt)
            db_rules = rules_res.scalars().all()

            auth_stmt = (
                select(AuthorizationSnapshot)
                .where(AuthorizationSnapshot.program_id == program_id)
                .order_by(AuthorizationSnapshot.created_at.desc())
            )
            auth_res = await session.execute(auth_stmt)
            db_auth = auth_res.scalar_one_or_none()

            engine_rules: List[ScopeEngineRule] = []
            for r in db_rules:
                try:
                    engine_rules.append(
                        ScopeEngineRule(
                            id=r.id,
                            program_id=r.program_id,
                            priority=r.priority,
                            asset_type=ScopeAssetType(r.asset_type),
                            pattern=r.pattern,
                            action=ScopeRuleAction(r.action),
                            allowed_ports=r.allowed_ports,
                            denied_paths=r.denied_paths,
                        )
                    )
                except Exception as e:
                    logger.warning("Error parsing scope rule %s: %s", getattr(r, "id", None), e)
                    continue

            engine_snapshot: Optional[ScopeAuthSnapshot] = None
            if db_auth:
                engine_snapshot = ScopeAuthSnapshot(
                    id=db_auth.id,
                    program_id=db_auth.program_id,
                    source_url=db_auth.source_url,
                    policy_hash=db_auth.policy_hash,
                    rules_json=db_auth.rules_json,
                    valid_from=db_auth.valid_from,
                    valid_until=db_auth.valid_until,
                )

            env_class = (
                "lab"
                if (prog and getattr(prog, "platform", None) == "lab")
                else self.environment_class
            )
            engine = ScopeEngine(
                snapshot=engine_snapshot,
                rules=engine_rules,
                environment_class=env_class,
            )
            self.register_engine(program_id, engine)
        else:
            # Sync all programs
            prog_stmt = select(Program.id)
            prog_res = await session.execute(prog_stmt)
            prog_ids = [pid for pid in prog_res.scalars().all() if pid]

            if not prog_ids:
                rule_progs_stmt = select(ScopeRule.program_id).distinct()
                rule_progs_res = await session.execute(rule_progs_stmt)
                prog_ids = [pid for pid in rule_progs_res.scalars().all() if pid]

            for pid in prog_ids:
                await self.sync_from_db(session, program_id=pid)

    def get_engine(self, program_id: Optional[UUID] = None) -> ScopeEngine:
        """Resolves the ScopeEngine for the given program or returns the default."""
        if program_id and program_id in self._programs:
            return self._programs[program_id]

        if self.engine_resolver and program_id:
            resolved = self.engine_resolver(program_id)
            if resolved:
                self._programs[program_id] = resolved
                return resolved

        if self.default_engine:
            return self.default_engine

        # Fail-closed fallback: engine with no rules denies everything
        logger.warning("No engine configured for program %s; using empty fail-closed engine", program_id)
        return ScopeEngine(environment_class=self.environment_class)

    def evaluate(
        self,
        url: str,
        method: str = "GET",
        program_id: Optional[UUID] = None,
        is_derived: bool = False,
        resolved_ips: Optional[List[str]] = None,
        check_dns: bool = True,
    ) -> ScopeDecision:
        """
        Evaluates an inbound outbound request against the Scope Engine and anti-SSRF checks.
        Returns a ScopeDecision.
        """
        target = ScopeTarget.from_url(
            url,
            method=method,
            is_derived=is_derived,
            resolved_ips=resolved_ips,
        )

        engine = self.get_engine(program_id)

        # Anti-SSRF / DNS Rebinding check for non-lab environments
        if self.environment_class != "lab":
            # Check literal IP
            if target.is_ip_literal:
                prohibited, reason = is_prohibited_ip(target.host)
                if prohibited:
                    return ScopeDecision(
                        allowed=False,
                        matched_tier=PrecedenceTier.EXPLICIT_DENY,
                        reason=f"PROHIBITED_IP: {reason}",
                        target_canonical=target.canonical_url,
                        resolved_ip=target.host,
                    )

            # Check resolved IPs
            if check_dns and not target.is_ip_literal and target.host:
                allowed, ips, reason = check_dns_rebinding(
                    target.host,
                    environment_class=self.environment_class,
                    resolved_ips=resolved_ips or target.resolved_ips or None,
                )
                if not allowed:
                    return ScopeDecision(
                        allowed=False,
                        matched_tier=PrecedenceTier.EXPLICIT_DENY,
                        reason=f"DNS_REBINDING_BLOCK: {reason}",
                        target_canonical=target.canonical_url,
                        resolved_ip=ips[0] if ips else None,
                    )
                if ips and not target.resolved_ips:
                    target.resolved_ips = ips

        # Primary Scope Engine evaluation
        decision = engine.evaluate_target(target)
        if decision.allowed and not decision.resolved_ip and target.resolved_ips:
            decision.resolved_ip = str(target.resolved_ips[0])
        return decision

    def enforce(
        self,
        url: str,
        method: str = "GET",
        program_id: Optional[UUID] = None,
        is_derived: bool = False,
        resolved_ips: Optional[List[str]] = None,
        check_dns: bool = True,
    ) -> ScopeDecision:
        """
        Enforces scope policy. If out-of-scope, raises ScopeGuardError.
        """
        decision = self.evaluate(
            url=url,
            method=method,
            program_id=program_id,
            is_derived=is_derived,
            resolved_ips=resolved_ips,
            check_dns=check_dns,
        )
        if not decision.allowed:
            raise ScopeGuardError(decision)
        return decision

    def evaluate_redirect(
        self,
        current_target: Union[str, ScopeTarget],
        redirect_url: str,
        hop_count: int = 0,
        program_id: Optional[UUID] = None,
    ) -> Tuple[bool, ScopeTarget, str]:
        """
        Evaluates a hop-by-hop HTTP redirect.
        Returns (allowed, next_target, reason).
        """
        engine = self.get_engine(program_id)
        if isinstance(current_target, str):
            current_target = ScopeTarget.from_url(current_target)
        return engine.evaluate_redirect(current_target, redirect_url, hop_count=hop_count)

    @staticmethod
    def build_403_response(decision: ScopeDecision, target_url: str) -> Dict[str, Any]:
        """
        Builds standard HTTP 403 Forbidden payload and headers.
        """
        tier_val = (
            decision.matched_tier.value
            if hasattr(decision.matched_tier, "value")
            else str(decision.matched_tier)
        )
        return {
            "status_code": 403,
            "headers": {
                "Content-Type": "application/json",
                "X-PenteFino-Proxy": "Egress-Traffic-Controller",
                "X-PenteFino-Decision": "DENY",
                "X-PenteFino-Reason": decision.reason,
                "X-PenteFino-Tier": tier_val,
            },
            "body": {
                "status": "error",
                "code": 403,
                "error": "out_of_scope_violation",
                "reason": decision.reason,
                "target": target_url,
                "tier": tier_val,
                "message": "PenteFino Scope Engine hard-gate rejected this request (fail-closed).",
            },
        }
