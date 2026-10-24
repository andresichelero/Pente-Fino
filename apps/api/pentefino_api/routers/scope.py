from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import ipaddress
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from pentefino_api.deps import get_db_session, get_program_or_404, record_api_audit
from pentefino_api.schemas import (
    ScopeEvaluateRequest,
    ScopeEvaluateResponse,
    ScopeRuleCreate,
    ScopeRuleResponse,
)
from pentefino_domain.enums import AssetType, ScopeAction, ScopeState
from pentefino_domain.models.authorization import AuthorizationSnapshot
from pentefino_domain.models.scope_rule import ScopeRule
from pentefino_scope.engine import ScopeEngine
from pentefino_scope.enums import (
    AssetType as ScopeAssetType,
    PrecedenceTier,
    ScopeAction as ScopeRuleAction,
)
from pentefino_scope.models import (
    AuthorizationSnapshot as ScopeAuthSnapshot,
    ScopeRule as ScopeEngineRule,
    ScopeTarget,
)

router = APIRouter(prefix="/api/v1/programs/{slug}/scope", tags=["scope"])


def _infer_asset_type(pattern: str) -> str:
    """Infer asset type from pattern string if not explicitly given."""
    pattern = pattern.strip()
    if pattern.startswith("*."):
        return AssetType.WILDCARD_DOMAIN.value
    if (
        pattern.startswith("http://")
        or pattern.startswith("https://")
        or ("/" in pattern and "/" not in pattern.split(".")[0])
    ):
        try:
            ipaddress.ip_network(pattern, strict=False)
            return AssetType.CIDR.value
        except ValueError:
            return AssetType.URL.value
    try:
        ipaddress.ip_address(pattern)
        return AssetType.IP.value
    except ValueError:
        pass
    try:
        ipaddress.ip_network(pattern, strict=False)
        return AssetType.CIDR.value
    except ValueError:
        pass
    return AssetType.DOMAIN.value


def _serialize_rule(rule: ScopeRule) -> ScopeRuleResponse:
    return ScopeRuleResponse(
        id=str(rule.id),
        program_id=str(rule.program_id),
        action=rule.action,
        pattern=rule.pattern,
        asset_type=rule.asset_type,
        priority=rule.priority,
        allowed_ports=rule.allowed_ports,
        denied_paths=rule.denied_paths,
        max_impact_class=rule.max_impact_class,
        created_at=rule.created_at.isoformat() if rule.created_at else None,
    )


def _tier_to_scope_state(tier: PrecedenceTier, allowed: bool) -> str:
    if not allowed:
        if tier == PrecedenceTier.DERIVED_CANDIDATE:
            return ScopeState.CANDIDATE.value
        return ScopeState.OUT_OF_SCOPE.value
    if tier == PrecedenceTier.EXPLICIT_ALLOW:
        return ScopeState.IN_SCOPE_EXPLICIT.value
    if tier == PrecedenceTier.WILDCARD_ALLOW:
        return ScopeState.IN_SCOPE_DERIVED.value
    return ScopeState.OUT_OF_SCOPE.value


@router.get("", response_model=list[ScopeRuleResponse])
async def list_scope_rules(
    slug: str,
    session: AsyncSession = Depends(get_db_session),
) -> list[ScopeRuleResponse]:
    """List scope rules for a program ordered by priority ASC."""
    prog = await get_program_or_404(session, slug)
    stmt = (
        select(ScopeRule)
        .where(ScopeRule.program_id == prog.id)
        .order_by(ScopeRule.priority.asc(), ScopeRule.created_at.asc())
    )
    res = await session.execute(stmt)
    rules = res.scalars().all()
    return [_serialize_rule(r) for r in rules]


@router.post("", response_model=ScopeRuleResponse, status_code=status.HTTP_201_CREATED)
async def create_scope_rule(
    slug: str,
    payload: ScopeRuleCreate,
    session: AsyncSession = Depends(get_db_session),
) -> ScopeRuleResponse:
    """Create a scope rule and ensure an active AuthorizationSnapshot exists."""
    prog = await get_program_or_404(session, slug)

    clean_action = payload.action.strip().lower()
    valid_actions = {a.value for a in ScopeAction}
    if clean_action not in valid_actions:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid action '{payload.action}'. Allowed: {sorted(valid_actions)}",
        )

    clean_pattern = payload.pattern.strip()
    inferred_type = (
        payload.asset_type.strip().lower()
        if payload.asset_type
        else _infer_asset_type(clean_pattern)
    )
    valid_types = {t.value for t in AssetType}
    if inferred_type not in valid_types:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid asset_type '{inferred_type}'. Allowed: {sorted(valid_types)}",
        )

    prio = (
        payload.priority
        if payload.priority is not None
        else (10 if clean_action == ScopeAction.DENY.value else 100)
    )

    rule = ScopeRule(
        program_id=prog.id,
        action=clean_action,
        pattern=clean_pattern,
        asset_type=inferred_type,
        priority=prio,
        allowed_ports=payload.allowed_ports,
        denied_paths=payload.denied_paths,
        max_impact_class=payload.max_impact_class,
    )
    session.add(rule)
    await session.flush()

    # Ensure an active AuthorizationSnapshot exists for this program
    auth_stmt = (
        select(AuthorizationSnapshot)
        .where(AuthorizationSnapshot.program_id == prog.id)
        .order_by(AuthorizationSnapshot.created_at.desc())
    )
    auth_res = await session.execute(auth_stmt)
    if auth_res.scalars().first() is None:
        policy_hash = hashlib.sha256(
            f"{prog.slug}:{rule.id}".encode("utf-8")
        ).hexdigest()
        snapshot = AuthorizationSnapshot(
            program_id=prog.id,
            source_url=f"https://pentefino.local/programs/{prog.slug}/scope",
            policy_hash=policy_hash,
            rules_json={"auto_created": True},
            valid_from=datetime.now(timezone.utc),
        )
        session.add(snapshot)
        await session.flush()

    await record_api_audit(
        session=session,
        event_type="api.scope.add",
        object_type="scope_rule",
        object_id=rule.id,
        payload={
            "program_slug": prog.slug,
            "action": rule.action,
            "pattern": rule.pattern,
            "asset_type": rule.asset_type,
            "priority": rule.priority,
        },
    )

    return _serialize_rule(rule)


@router.delete("/{rule_id}")
async def delete_scope_rule(
    slug: str,
    rule_id: str,
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, str]:
    """Delete a scope rule from a program."""
    prog = await get_program_or_404(session, slug)
    try:
        rid = uuid.UUID(rule_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid rule UUID '{rule_id}'.",
        ) from exc

    stmt = select(ScopeRule).where(
        ScopeRule.id == rid,
        ScopeRule.program_id == prog.id,
    )
    res = await session.execute(stmt)
    rule = res.scalar_one_or_none()
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scope rule '{rule_id}' not found in program '{slug}'.",
        )

    await session.delete(rule)
    await session.flush()
    await record_api_audit(
        session=session,
        event_type="api.scope.delete",
        object_type="scope_rule",
        object_id=rid,
        payload={"program_slug": prog.slug, "pattern": rule.pattern},
    )
    return {"status": "deleted", "id": str(rid)}


@router.post("/evaluate", response_model=ScopeEvaluateResponse)
async def evaluate_scope_target(
    slug: str,
    payload: ScopeEvaluateRequest,
    session: AsyncSession = Depends(get_db_session),
) -> ScopeEvaluateResponse:
    """Evaluate a target against the program's 7-tier fail-closed ScopeEngine."""
    prog = await get_program_or_404(session, slug)

    rules_stmt = (
        select(ScopeRule)
        .where(ScopeRule.program_id == prog.id)
        .order_by(ScopeRule.priority.asc())
    )
    rules_res = await session.execute(rules_stmt)
    db_rules = rules_res.scalars().all()

    auth_stmt = (
        select(AuthorizationSnapshot)
        .where(AuthorizationSnapshot.program_id == prog.id)
        .order_by(AuthorizationSnapshot.created_at.desc())
    )
    auth_res = await session.execute(auth_stmt)
    db_auth = auth_res.scalars().first()

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
                    max_impact_class=r.max_impact_class,
                )
            )
        except Exception:
            continue

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
    else:
        # Provide an active transient snapshot if program has rules but no snapshot row yet
        engine_snapshot = ScopeAuthSnapshot(
            id=uuid.uuid4(),
            program_id=prog.id,
            source_url=None,
            policy_hash="0" * 64,
            rules_json={},
            valid_from=datetime.now(timezone.utc),
            valid_until=None,
        )

    engine = ScopeEngine(
        snapshot=engine_snapshot,
        rules=engine_rules,
        environment_class="lab" if prog.platform == "lab" else "bounty",
    )

    scope_target = ScopeTarget.from_url(payload.target)
    if payload.port is not None:
        scope_target.port = payload.port
    if payload.path is not None:
        scope_target.path = (
            payload.path if payload.path.startswith("/") else f"/{payload.path}"
        )

    decision = engine.evaluate_target(scope_target)
    scope_state = _tier_to_scope_state(decision.matched_tier, decision.allowed)

    return ScopeEvaluateResponse(
        target=payload.target,
        allowed=decision.allowed,
        scope_state=scope_state,
        precedence_tier=decision.matched_tier.value,
        matched_rule_id=str(decision.matched_rule_id) if decision.matched_rule_id else None,
        matched_pattern=decision.matched_pattern,
        reason=decision.reason,
        resolved_ip=decision.resolved_ip,
        target_canonical=decision.target_canonical,
    )
