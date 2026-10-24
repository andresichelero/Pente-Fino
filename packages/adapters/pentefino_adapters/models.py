from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from pentefino_domain.enums import ScopeState
from pentefino_scope.enums import PrecedenceTier


class DiscoveredCandidate(BaseModel):
    """Subdomain discovered during passive enumeration."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    host: str
    sources: List[str] = Field(default_factory=list)
    input: str = ""
    scope_state: ScopeState
    matched_tier: Optional[PrecedenceTier] = None
    raw_json: Optional[Dict[str, Any]] = None


# Alias for backward/spec compatibility
SubfinderRecord = DiscoveredCandidate


class DnsRecord(BaseModel):
    """DNS resolution response for a hostname."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    host: str
    a: List[str] = Field(default_factory=list)
    aaaa: List[str] = Field(default_factory=list)
    cname: List[str] = Field(default_factory=list)
    resolver: List[str] = Field(default_factory=list)
    is_prohibited_ip: bool = False
    prohibited_reason: Optional[str] = None
    cname_evaluations: Dict[str, ScopeState] = Field(default_factory=dict)
    raw_json: Optional[Dict[str, Any]] = None


# Alias for backward/spec compatibility
DnsObservation = DnsRecord


class TechnologyComponent(BaseModel):
    """Detected web technology stack component."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: str
    version: Optional[str] = None
    confidence: float = 1.0


class HttpProbeRecord(BaseModel):
    """HTTP/HTTPS probe response metadata and technology fingerprint."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    url: str
    input_host: str = ""
    status_code: Optional[int] = None
    title: Optional[str] = None
    webserver: Optional[str] = None
    content_length: Optional[int] = None
    technologies: List[str] = Field(default_factory=list)
    components: List[TechnologyComponent] = Field(default_factory=list)
    tls: Optional[Dict[str, Any]] = None
    chain: List[Dict[str, Any]] = Field(default_factory=list)
    final_url: Optional[str] = None
    failed: bool = False
    error: Optional[str] = None
    raw_json: Optional[Dict[str, Any]] = None


# Alias for backward/spec compatibility
HttpObservation = HttpProbeRecord


class ReconResult(BaseModel):
    """Aggregated output of a multi-stage recon execution."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    domain: str
    program_id: Optional[uuid.UUID] = None
    candidates: List[DiscoveredCandidate] = Field(default_factory=list)
    dns_records: List[DnsRecord] = Field(default_factory=list)
    http_probes: List[HttpProbeRecord] = Field(default_factory=list)
    total_discovered: int = 0
    in_scope_count: int = 0
    resolved_count: int = 0
    live_http_count: int = 0
