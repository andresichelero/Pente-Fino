"""
pentefino_scope: Hard-gate fail-closed scope engine for PenteFino.
"""
from .enums import AssetType, DecisionTier, PrecedenceTier, ScopeAction
from .engine import ScopeEngine, evaluate_target, normalize_target
from .ip_filter import (
    check_dns_rebinding,
    is_prohibited_ip,
    parse_and_normalize_ip,
    resolve_host,
)
from .models import AuthorizationSnapshot, ScopeDecision, ScopeRule, ScopeTarget
from .redirects import evaluate_redirect

__all__ = [
    "PrecedenceTier",
    "DecisionTier",
    "AssetType",
    "ScopeAction",
    "ScopeTarget",
    "ScopeRule",
    "AuthorizationSnapshot",
    "ScopeDecision",
    "ScopeEngine",
    "evaluate_target",
    "normalize_target",
    "is_prohibited_ip",
    "parse_and_normalize_ip",
    "resolve_host",
    "check_dns_rebinding",
    "evaluate_redirect",
]
