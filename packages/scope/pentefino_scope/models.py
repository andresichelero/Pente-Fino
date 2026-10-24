from __future__ import annotations

import posixpath
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


from .enums import AssetType, PrecedenceTier, ScopeAction


class ScopeTarget(BaseModel):
    """Represents a normalized network destination or URL target."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    raw: str
    scheme: Optional[str] = "https"
    host: str
    port: Optional[int] = None
    path: Optional[str] = "/"
    method: Optional[str] = "GET"
    is_ip_literal: bool = False
    is_derived: bool = False
    resolved_ips: List[str] = Field(default_factory=list)

    @property
    def canonical_url(self) -> str:
        """Returns normalized URL string."""
        scheme = (self.scheme or "https").lower()
        host = self.host.lower()
        port = self.port
        path = self.path or "/"
        if not path.startswith("/"):
            path = f"/{path}"
        
        # Omit default ports for standard schemes
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443) or port is None:
            netloc = host
        else:
            netloc = f"{host}:{port}"
        return f"{scheme}://{netloc}{path}"

    @classmethod
    def from_url(
        cls,
        raw: str,
        method: str = "GET",
        is_derived: bool = False,
        resolved_ips: Optional[List[str]] = None,
    ) -> ScopeTarget:
        """Constructs a normalized ScopeTarget from raw URL or hostname."""
        cleaned = raw.strip()
        if "://" not in cleaned:
            # Assume https by default
            candidate_url = f"https://{cleaned}"
        else:
            candidate_url = cleaned

        parsed = urllib.parse.urlsplit(candidate_url)
        scheme = parsed.scheme.lower() if parsed.scheme else "https"
        host = parsed.hostname.lower() if parsed.hostname else ""
        port = parsed.port
        if port is None:
            port = 80 if scheme == "http" else 443

        path = parsed.path if parsed.path else "/"
        # RFC 3986 path normalization
        norm_path = posixpath.normpath(path)
        if path.endswith("/") and not norm_path.endswith("/"):
            norm_path = f"{norm_path}/"
        if not norm_path.startswith("/"):
            norm_path = f"/{norm_path}"

        # Punycode normalization for IDN hostnames
        if host:
            try:
                host = host.encode("idna").decode("ascii")
            except Exception:
                pass

        # Detect IP literal
        from .ip_filter import parse_and_normalize_ip
        parsed_ip = parse_and_normalize_ip(host)
        is_ip = parsed_ip is not None
        if is_ip:
            host = str(parsed_ip)

        return cls(
            raw=raw,
            scheme=scheme,
            host=host,
            port=port,
            path=norm_path,
            method=method.upper(),
            is_ip_literal=is_ip,
            is_derived=is_derived,
            resolved_ips=resolved_ips or [],
        )


class ScopeRule(BaseModel):
    """Immutable rule governing access to targets."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    id: UUID = Field(default_factory=uuid4)
    program_id: UUID
    priority: int = 100
    asset_type: AssetType
    pattern: str
    action: ScopeAction
    allowed_ports: Optional[List[int]] = None
    denied_paths: Optional[List[str]] = None
    max_impact_class: str = "safe_read_only"
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    created_at: Optional[datetime] = Field(default_factory=lambda: datetime.now(timezone.utc))


class AuthorizationSnapshot(BaseModel):
    """Cryptographically bounded snapshot of program authorization."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    id: UUID = Field(default_factory=uuid4)
    program_id: UUID
    source_url: Optional[str] = None
    policy_hash: str
    rules_json: Dict[str, Any] = Field(default_factory=dict)
    valid_from: datetime
    valid_until: Optional[datetime] = None
    created_at: Optional[datetime] = Field(default_factory=lambda: datetime.now(timezone.utc))


class ScopeDecision(BaseModel):
    """The result of evaluating a target against scope precedence rules."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    allowed: bool
    matched_tier: PrecedenceTier
    matched_rule_id: Optional[UUID] = None
    matched_pattern: Optional[str] = None
    reason: str
    resolved_ip: Optional[str] = None
    target_canonical: Optional[str] = None
    detail: Optional[str] = None
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def tier(self) -> PrecedenceTier:
        return self.matched_tier
