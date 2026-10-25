"""Build a program's ScopeEngine from the database, fail-closed."""
from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pentefino_api.activity import activity
from pentefino_domain.models import AuthorizationSnapshot, Program, ScopeRule
from pentefino_scope import ScopeEngine
from pentefino_scope.enums import AssetType as ScopeAssetType
from pentefino_scope.enums import ScopeAction as ScopeRuleAction
from pentefino_scope.models import AuthorizationSnapshot as ScopeAuthSnapshot
from pentefino_scope.models import ScopeDecision, ScopeTarget
from pentefino_scope.models import ScopeRule as ScopeEngineRule

logger = logging.getLogger(__name__)


async def load_program_scope_engine(session: AsyncSession, prog: Program) -> ScopeEngine:
    """Load the program's rules and newest authorization snapshot.

    No snapshot is ever fabricated here: without one the engine denies every
    target at the EXPIRED_AUTH tier, which is the intended fail-closed outcome.
    """
    db_rules = (
        await session.execute(
            select(ScopeRule).where(ScopeRule.program_id == prog.id).order_by(ScopeRule.priority.asc())
        )
    ).scalars().all()

    db_auth = (
        await session.execute(
            select(AuthorizationSnapshot)
            .where(AuthorizationSnapshot.program_id == prog.id)
            .order_by(AuthorizationSnapshot.created_at.desc())
        )
    ).scalars().first()

    engine_rules: list[ScopeEngineRule] = []
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
        except Exception as exc:
            # A rule the engine cannot parse is dropped; for an ALLOW rule that narrows scope,
            # for a DENY rule it would widen it, so refuse to build a partial engine.
            if r.action == "deny":
                raise ValueError(f"Unparseable deny rule {r.id} ({r.pattern!r}): {exc}") from exc
            logger.warning("Skipping unparseable allow rule %s (%r): %s", r.id, r.pattern, exc)

    snapshot = None
    if db_auth is not None:
        snapshot = ScopeAuthSnapshot(
            id=db_auth.id,
            program_id=db_auth.program_id,
            source_url=db_auth.source_url,
            policy_hash=db_auth.policy_hash,
            rules_json=db_auth.rules_json,
            valid_from=db_auth.valid_from,
            valid_until=db_auth.valid_until,
        )

    env_class = "lab" if getattr(prog, "platform", None) == "lab" else "bounty"
    return ScopeEngine(snapshot=snapshot, rules=engine_rules, environment_class=env_class)


def evaluate_and_count(engine: ScopeEngine, target: ScopeTarget | str) -> ScopeDecision:
    """Evaluate a target and record the decision in the live activity counters."""
    decision = engine.evaluate_target(target)
    activity.record_scope_decision(decision.allowed, decision.reason or "")
    return decision


def domain_within_allow_rules(engine: ScopeEngine, domain: str) -> bool:
    """True if `domain` is an allowed host, or the base of an allowed wildcard (recon root)."""
    clean = domain.strip().lower().rstrip(".")
    if evaluate_and_count(engine, clean).allowed:
        return True
    probe = evaluate_and_count(engine, f"pentefino-recon-probe.{clean}")
    return probe.allowed
