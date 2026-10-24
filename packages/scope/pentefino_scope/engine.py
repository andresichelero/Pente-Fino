from __future__ import annotations

import fnmatch
import ipaddress
import posixpath
import re
import urllib.parse
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Union

from .enums import AssetType, PrecedenceTier, ScopeAction
from .ip_filter import is_prohibited_ip, parse_and_normalize_ip
from .models import AuthorizationSnapshot, ScopeDecision, ScopeRule, ScopeTarget
from .redirects import evaluate_redirect as _redirect_evaluator


def _normalize_dt(dt: Optional[datetime]) -> Optional[datetime]:
    """Ensures datetime is timezone-aware in UTC for safe comparison."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def normalize_target(target_in: Union[str, ScopeTarget]) -> ScopeTarget:
    """Normalizes input into a validated ScopeTarget."""
    if isinstance(target_in, ScopeTarget):
        return target_in
    return ScopeTarget.from_url(str(target_in))


def _path_matches(target_path: str, denied_pattern: str) -> bool:
    """Checks if a normalized target path matches a denied path pattern."""
    # Unquote and normalize path
    unquoted_target = urllib.parse.unquote(target_path)
    norm_target = posixpath.normpath(unquoted_target)
    if not norm_target.startswith("/"):
        norm_target = f"/{norm_target}"

    unquoted_pattern = urllib.parse.unquote(denied_pattern.strip())
    
    # Regex match if starts with ^
    if unquoted_pattern.startswith("^"):
        try:
            return bool(re.search(unquoted_pattern, norm_target))
        except re.error:
            pass

    norm_pattern = posixpath.normpath(unquoted_pattern)
    if not norm_pattern.startswith("/") and not unquoted_pattern.startswith("*"):
        norm_pattern = f"/{norm_pattern}"

    # Exact match
    if norm_target == norm_pattern:
        return True

    # Prefix match with boundary (e.g. /admin matches /admin/dashboard)
    boundary_prefix = norm_pattern.rstrip("/") + "/"
    if norm_target.startswith(boundary_prefix):
        return True

    # Glob match (e.g. /api/private* or */admin/*)
    if fnmatch.fnmatch(norm_target, unquoted_pattern):
        return True

    return False


def _match_exact(target: ScopeTarget, rule: ScopeRule) -> bool:
    """Checks exact match for DOMAIN, HOSTNAME, IP, or URL."""
    clean_pattern = rule.pattern.strip().lower()

    if rule.asset_type in (AssetType.DOMAIN, AssetType.HOSTNAME):
        # Case-insensitive exact FQDN match
        target_host = target.host.lower().rstrip(".")
        clean_pattern = clean_pattern.rstrip(".")
        return target_host == clean_pattern

    elif rule.asset_type == AssetType.IP:
        if not target.is_ip_literal:
            return False
        target_ip = parse_and_normalize_ip(target.host)
        rule_ip = parse_and_normalize_ip(clean_pattern)
        return target_ip is not None and rule_ip is not None and target_ip == rule_ip

    elif rule.asset_type == AssetType.URL:
        # Match URL prefix
        return target.canonical_url.lower().startswith(clean_pattern)

    return False


def _match_wildcard_or_cidr(target: ScopeTarget, rule: ScopeRule) -> bool:
    """
    Checks wildcard domain or CIDR match.
    INVARIANT: Wildcard domain rules NEVER match an IP literal.
    """
    clean_pattern = rule.pattern.strip().lower()

    if rule.asset_type == AssetType.WILDCARD_DOMAIN or clean_pattern.startswith("*."):
        # Strict invariant: direct IP literal CANNOT match domain wildcard
        if target.is_ip_literal:
            return False

        base_domain = clean_pattern.lstrip("*.").rstrip(".")
        target_host = target.host.lower().rstrip(".")

        # Must be a subdomain of base_domain (e.g. sub.example.com ends with .example.com)
        return target_host.endswith(f".{base_domain}")

    elif rule.asset_type == AssetType.CIDR:
        if not target.is_ip_literal:
            return False
        try:
            net = ipaddress.ip_network(rule.pattern.strip(), strict=False)
            target_ip = parse_and_normalize_ip(target.host)
            return target_ip is not None and target_ip in net
        except ValueError:
            return False

    return False


def _rule_matches_target_identity(target: ScopeTarget, rule: ScopeRule) -> bool:
    """Checks if a rule matches the target host/domain/IP regardless of action."""
    clean_pattern = rule.pattern.strip().lower()
    if clean_pattern.startswith("*.") or rule.asset_type in (AssetType.WILDCARD_DOMAIN, AssetType.CIDR):
        # For explicit deny, also cover apex domain if wildcard domain is denied
        if rule.action == ScopeAction.DENY and (rule.asset_type == AssetType.WILDCARD_DOMAIN or clean_pattern.startswith("*.")):
            base_domain = clean_pattern.lstrip("*.").rstrip(".")
            target_host = target.host.lower().rstrip(".")
            if not target.is_ip_literal and (target_host == base_domain or target_host.endswith(f".{base_domain}")):
                return True
        return _match_wildcard_or_cidr(target, rule)
    else:
        return _match_exact(target, rule)


class ScopeEngine:
    """
    Authoritative Hard-Gate Scope Engine enforcing strict 7-tier evaluation precedence:
      Tier 1: Explicit Deny
      Tier 2: Expired Auth
      Tier 3: Path / Port Deny
      Tier 4: Explicit Allow
      Tier 5: Wildcard Allow
      Tier 6: Derived Candidate
      Tier 7: Unknown (Default Deny)
    """

    def __init__(
        self,
        snapshot: Optional[AuthorizationSnapshot] = None,
        rules: Optional[List[ScopeRule]] = None,
        environment_class: str = "bounty",
    ):
        self.snapshot = snapshot
        self.rules: List[ScopeRule] = rules or []
        self.environment_class = environment_class

    def is_prohibited_ip(self, ip_str: str) -> Tuple[bool, str]:
        """Validates IP against Anti-SSRF policies."""
        return is_prohibited_ip(ip_str, environment_class=self.environment_class)

    def evaluate_target(
        self,
        target_in: Union[str, ScopeTarget],
        now: Optional[datetime] = None,
    ) -> ScopeDecision:
        """
        Evaluates a target destination against all 7 precedence tiers.
        """
        try:
            target = normalize_target(target_in)
        except Exception as exc:
            return ScopeDecision(
                allowed=False,
                matched_tier=PrecedenceTier.UNKNOWN_DENY,
                reason=f"MALFORMED_TARGET_FAIL_CLOSED: {str(exc)}",
                target_canonical=str(target_in),
            )

        current_time = _normalize_dt(now) or datetime.now(timezone.utc)
        target_canonical = target.canonical_url

        # -------------------------------------------------------------
        # Pre-Gate: Anti-SSRF / Prohibited IP Enforcement
        # -------------------------------------------------------------
        if target.is_ip_literal:
            prohibited, reason = self.is_prohibited_ip(target.host)
            if prohibited:
                return ScopeDecision(
                    allowed=False,
                    matched_tier=PrecedenceTier.EXPLICIT_DENY,
                    reason=f"PROHIBITED_IP_SPACE: {reason}",
                    target_canonical=target_canonical,
                    resolved_ip=target.host,
                )

        if target.resolved_ips:
            for rip in target.resolved_ips:
                prohibited, reason = self.is_prohibited_ip(str(rip))
                if prohibited:
                    return ScopeDecision(
                        allowed=False,
                        matched_tier=PrecedenceTier.EXPLICIT_DENY,
                        reason=f"RESOLVED_IP_PROHIBITED: {rip} is {reason}",
                        target_canonical=target_canonical,
                        resolved_ip=str(rip),
                    )

        # -------------------------------------------------------------
        # Tier 1: Explicit Deny
        # -------------------------------------------------------------
        for rule in self.rules:
            if rule.action == ScopeAction.DENY:
                if _rule_matches_target_identity(target, rule):
                    return ScopeDecision(
                        allowed=False,
                        matched_tier=PrecedenceTier.EXPLICIT_DENY,
                        matched_rule_id=rule.id,
                        matched_pattern=rule.pattern,
                        reason="EXPLICIT_DENY_RULE_MATCHED",
                        target_canonical=target_canonical,
                    )

        # -------------------------------------------------------------
        # Tier 2: Expired Auth (Snapshot validity)
        # -------------------------------------------------------------
        if self.snapshot is None:
            return ScopeDecision(
                allowed=False,
                matched_tier=PrecedenceTier.EXPIRED_AUTH,
                reason="MISSING_AUTHORIZATION_SNAPSHOT",
                target_canonical=target_canonical,
            )

        snap_from = _normalize_dt(self.snapshot.valid_from)
        snap_until = _normalize_dt(self.snapshot.valid_until)

        if snap_from and current_time < snap_from:
            return ScopeDecision(
                allowed=False,
                matched_tier=PrecedenceTier.EXPIRED_AUTH,
                reason="AUTHORIZATION_NOT_YET_ACTIVE",
                target_canonical=target_canonical,
            )

        if snap_until and current_time > snap_until:
            return ScopeDecision(
                allowed=False,
                matched_tier=PrecedenceTier.EXPIRED_AUTH,
                reason="AUTHORIZATION_EXPIRED",
                target_canonical=target_canonical,
            )

        # -------------------------------------------------------------
        # Tier 3: Path / Port Deny
        # Evaluated on rules that would otherwise match and allow the host
        # -------------------------------------------------------------
        for rule in self.rules:
            if rule.action == ScopeAction.ALLOW and _rule_matches_target_identity(target, rule):
                # Port restriction
                if rule.allowed_ports and target.port not in rule.allowed_ports:
                    return ScopeDecision(
                        allowed=False,
                        matched_tier=PrecedenceTier.PATH_PORT_DENY,
                        matched_rule_id=rule.id,
                        matched_pattern=rule.pattern,
                        reason=f"PORT_NOT_ALLOWED: port {target.port} not in {rule.allowed_ports}",
                        target_canonical=target_canonical,
                    )

                # Path restriction
                if rule.denied_paths:
                    for dp in rule.denied_paths:
                        if _path_matches(target.path or "/", dp):
                            return ScopeDecision(
                                allowed=False,
                                matched_tier=PrecedenceTier.PATH_PORT_DENY,
                                matched_rule_id=rule.id,
                                matched_pattern=rule.pattern,
                                reason=f"PATH_DENIED: path {target.path} matches denied path {dp}",
                                target_canonical=target_canonical,
                            )

        # -------------------------------------------------------------
        # Tier 4: Explicit Allow (Exact FQDN, Exact IP, or Exact URL)
        # -------------------------------------------------------------
        for rule in self.rules:
            if rule.action == ScopeAction.ALLOW and rule.asset_type in (
                AssetType.DOMAIN,
                AssetType.HOSTNAME,
                AssetType.IP,
                AssetType.URL,
            ):
                if _match_exact(target, rule):
                    return ScopeDecision(
                        allowed=True,
                        matched_tier=PrecedenceTier.EXPLICIT_ALLOW,
                        matched_rule_id=rule.id,
                        matched_pattern=rule.pattern,
                        reason="EXPLICIT_ALLOW_MATCHED",
                        target_canonical=target_canonical,
                    )

        # -------------------------------------------------------------
        # Tier 5: Wildcard Allow (Wildcard Domain or CIDR)
        # -------------------------------------------------------------
        for rule in self.rules:
            if rule.action == ScopeAction.ALLOW and (
                rule.asset_type in (AssetType.WILDCARD_DOMAIN, AssetType.CIDR)
                or rule.pattern.strip().startswith("*.")
            ):
                if _match_wildcard_or_cidr(target, rule):
                    return ScopeDecision(
                        allowed=True,
                        matched_tier=PrecedenceTier.WILDCARD_ALLOW,
                        matched_rule_id=rule.id,
                        matched_pattern=rule.pattern,
                        reason="WILDCARD_ALLOW_MATCHED",
                        target_canonical=target_canonical,
                    )

        # -------------------------------------------------------------
        # Tier 6: Derived Candidate
        # Recon-discovered assets are observations, not authorized targets
        # -------------------------------------------------------------
        if target.is_derived:
            return ScopeDecision(
                allowed=False,
                matched_tier=PrecedenceTier.DERIVED_CANDIDATE,
                reason="DERIVED_CANDIDATE_REQUIRES_PROMOTION",
                target_canonical=target_canonical,
            )

        # -------------------------------------------------------------
        # Tier 7: Unknown (Default Deny)
        # -------------------------------------------------------------
        return ScopeDecision(
            allowed=False,
            matched_tier=PrecedenceTier.UNKNOWN_DENY,
            reason="UNKNOWN_TARGET_DEFAULT_DENY",
            target_canonical=target_canonical,
        )

    def evaluate_redirect(
        self,
        current_target: Union[str, ScopeTarget],
        redirect_url: str,
        hop_count: int = 0,
        max_hops: int = 3,
    ) -> Tuple[bool, ScopeTarget, str]:
        """
        Evaluates an HTTP redirect hop-by-hop.
        """
        return _redirect_evaluator(
            engine=self,
            current_target=current_target,
            redirect_url=redirect_url,
            hop_count=hop_count,
            max_hops=max_hops,
        )


def evaluate_target(
    target_in: Union[str, ScopeTarget],
    rules: List[ScopeRule],
    snapshot: Optional[AuthorizationSnapshot] = None,
    now: Optional[datetime] = None,
    environment_class: str = "bounty",
) -> ScopeDecision:
    """Functional convenience wrapper for ScopeEngine.evaluate_target."""
    engine = ScopeEngine(snapshot=snapshot, rules=rules, environment_class=environment_class)
    return engine.evaluate_target(target_in, now=now)
