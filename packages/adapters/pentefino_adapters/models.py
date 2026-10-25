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


class KatanaEndpointRecord(BaseModel):
    """Discovered endpoint from Katana crawler."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    endpoint: str
    url: str = ""
    path: Optional[str] = None
    method: str = "GET"
    status_code: Optional[int] = None
    technologies: List[str] = Field(default_factory=list)
    form_data: Optional[Dict[str, Any]] = None
    is_in_scope: bool = True
    scope_tier: Optional[PrecedenceTier] = None
    scope_reason: Optional[str] = None
    raw_json: Optional[Dict[str, Any]] = None


KatanaRecord = KatanaEndpointRecord


class TlsCertificateInfo(BaseModel):
    """Parsed SSL/TLS X.509 certificate metadata."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    subject: str
    issuer: str
    serial_number: str
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    days_to_expire: float = 0.0
    is_expired: bool = False
    is_self_signed: bool = False
    san_names: List[str] = Field(default_factory=list)
    hostname_matches_san: bool = True
    signature_algorithm: Optional[str] = None
    fingerprint_sha256: Optional[str] = None


class TlsSecurityAnomaly(BaseModel):
    """Specific security anomaly or finding discovered during TLS audit."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    id: str
    title: str
    severity: str  # info, low, medium, high, critical
    description: str
    recommendation: Optional[str] = None


class TlsAuditResult(BaseModel):
    """Aggregated result of safe TLS and cipher suite audit."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    host: str
    port: int = 443
    supported_protocols: List[str] = Field(default_factory=list)
    deprecated_protocols: List[str] = Field(default_factory=list)
    weak_ciphers: List[str] = Field(default_factory=list)
    selected_cipher: Optional[str] = None
    certificate_info: Optional[TlsCertificateInfo] = None
    anomalies: List[TlsSecurityAnomaly] = Field(default_factory=list)
    error: Optional[str] = None
    success: bool = True


class PassiveFindingRecord(BaseModel):
    """Security finding or anomaly detected passively from HTTP traffic."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    rule_id: str
    category: str
    title: str
    severity: str  # info, low, medium, high, critical
    description: str
    matched_text: Optional[str] = None
    url: str
    path: str = "/"
    status_code: Optional[int] = None
    dedup_key: str = ""
    remediation: Optional[str] = None
    confidence: str = "high"
    evidence_level: str = "E1"
    raw_details: Optional[Dict[str, Any]] = None


PassiveFinding = PassiveFindingRecord

