from __future__ import annotations

import urllib.parse
from typing import TYPE_CHECKING, Tuple, Union

from .models import ScopeTarget

if TYPE_CHECKING:
    from .engine import ScopeEngine


def evaluate_redirect(
    engine: ScopeEngine,
    current_target: Union[str, ScopeTarget],
    redirect_url: str,
    hop_count: int = 0,
    max_hops: int = 3,
) -> Tuple[bool, ScopeTarget, str]:
    """
    Evaluates an HTTP redirect hop-by-hop (301, 302, 303, 307, 308).
    Prevents out-of-scope jumps, redirect loops, and SSRF pivots.
    
    Returns:
        (allowed, new_target, reason)
    """
    if isinstance(current_target, str):
        curr = ScopeTarget.from_url(current_target)
    else:
        curr = current_target

    if hop_count >= max_hops:
        return False, curr, f"MAX_REDIRECT_HOPS_EXCEEDED: hop count {hop_count} reached maximum {max_hops}"

    cleaned_url = redirect_url.strip()
    if not cleaned_url:
        return False, curr, "EMPTY_REDIRECT_LOCATION"

    # Resolve relative URL against current canonical URL
    resolved_url = urllib.parse.urljoin(curr.canonical_url, cleaned_url)
    
    # Preserve request method (or follow HTTP standard redirect method transitions)
    # Default to GET for subsequent hops
    next_target = ScopeTarget.from_url(resolved_url, method="GET")

    # Anti-SSRF check on destination host/IP
    if next_target.is_ip_literal:
        prohibited, reason = engine.is_prohibited_ip(next_target.host)
        if prohibited:
            return False, next_target, f"REDIRECT_TARGET_PROHIBITED_IP: {reason}"

    # Evaluate next hop through the full 7-tier Scope Engine
    decision = engine.evaluate_target(next_target)
    if decision.allowed:
        return True, next_target, f"REDIRECT_ALLOWED: hop {hop_count + 1} to {next_target.canonical_url}"
    else:
        return False, next_target, f"REDIRECT_OUT_OF_SCOPE: {decision.reason} ({decision.matched_tier.value})"
