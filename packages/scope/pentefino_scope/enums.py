from __future__ import annotations

from enum import Enum


class PrecedenceTier(str, Enum):
    """The 7 strict precedence tiers for scope evaluation."""
    EXPLICIT_DENY = "EXPLICIT_DENY"
    EXPIRED_AUTH = "EXPIRED_AUTH"
    PATH_PORT_DENY = "PATH_PORT_DENY"
    EXPLICIT_ALLOW = "EXPLICIT_ALLOW"
    WILDCARD_ALLOW = "WILDCARD_ALLOW"
    DERIVED_CANDIDATE = "DERIVED_CANDIDATE"
    UNKNOWN_DENY = "UNKNOWN_DENY"


# Alias for compatibility with survey reports
DecisionTier = PrecedenceTier


class AssetType(str, Enum):
    """Categorization of scope assets."""
    DOMAIN = "domain"
    WILDCARD_DOMAIN = "wildcard_domain"
    HOSTNAME = "hostname"
    URL = "url"
    CIDR = "cidr"
    IP = "ip"


class ScopeAction(str, Enum):
    """Action associated with a scope rule."""
    ALLOW = "allow"
    DENY = "deny"
    DISCOVER_ONLY = "discover_only"
