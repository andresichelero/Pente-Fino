from __future__ import annotations

from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class ProgramCreate(BaseModel):
    model_config = ConfigDict(extra="ignore")

    slug: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1)
    platform: str = "hackerone"
    default_policy_id: str = "bounty-safe"
    state: str = "active"


class ProgramUpdate(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str | None = None
    state: str | None = None
    default_policy_id: str | None = None


class ProgramResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    slug: str
    name: str
    platform: str
    state: str
    default_policy_id: str
    created_at: str | None = None
    scope_rules_count: int = 0
    assets_count: int = 0
    findings_count: int = 0
    snapshots_count: int = 0


class ScopeRuleCreate(BaseModel):
    model_config = ConfigDict(extra="ignore")

    action: str = "allow"
    pattern: str = Field(..., min_length=1)
    asset_type: str | None = None
    priority: int | None = None
    allowed_ports: list[int] | None = None
    denied_paths: list[str] | None = None
    max_impact_class: str = "safe_read_only"


class ScopeRuleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    program_id: str
    action: str
    pattern: str
    asset_type: str
    priority: int
    allowed_ports: list[int] | None = None
    denied_paths: list[str] | None = None
    max_impact_class: str = "safe_read_only"
    created_at: str | None = None


class ScopeEvaluateRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    target: str = Field(..., min_length=1)
    port: int | None = None
    path: str | None = None


class ScopeEvaluateResponse(BaseModel):
    target: str
    allowed: bool
    scope_state: str
    precedence_tier: str
    matched_rule_id: str | None = None
    matched_pattern: str | None = None
    reason: str
    resolved_ip: str | None = None
    target_canonical: str | None = None


class ObservationItem(BaseModel):
    id: str
    observation_type: str
    metadata_json: dict[str, Any] = Field(default_factory=dict)
    created_at: str | None = None


class AssetResponse(BaseModel):
    id: str
    program_id: str
    canonical_key: str
    asset_type: str
    scope_state: str
    first_seen: str | None = None
    last_seen: str | None = None
    observations: list[ObservationItem] = Field(default_factory=list)
    findings_count: int = 0
    technologies: list[str] = Field(default_factory=list)


class GraphNode(BaseModel):
    id: str
    label: str
    node_type: str
    scope_state: str | None = None
    asset_type: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source: str
    target: str
    relation: str


class AssetGraphResponse(BaseModel):
    program_slug: str
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)


class TemplateStatsResponse(BaseModel):
    total: int
    by_impact_class: dict[str, int] = Field(default_factory=dict)
    by_severity: dict[str, int] = Field(default_factory=dict)


class TemplateSummaryItem(BaseModel):
    id: str
    name: str
    protocol: str
    http_methods: list[str] | None = None
    impact_class: str
    severity: str | None = None
    cve_id: str | None = None
    cwe_id: str | None = None
    technologies: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    upstream_revision: str
    bundle_hash: str
    raw_yaml: str | None = None
    updated_at: str | None = None


class TemplateListResponse(BaseModel):
    total: int
    page: int = 1
    page_size: int = 25
    total_pages: int = 1
    items: list[TemplateSummaryItem] = Field(default_factory=list)


class TemplateDetailResponse(BaseModel):
    id: str
    name: str
    protocol: str
    http_methods: list[str] | None = None
    impact_class: str
    severity: str | None = None
    cve_id: str | None = None
    cwe_id: str | None = None
    technologies: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    upstream_revision: str
    bundle_hash: str
    raw_yaml: str
    updated_at: str | None = None


class ScanPlanRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    program_slug: str
    asset_key: str
    severity: str | None = None
    tags: str | None = None


class SelectedTemplateItem(BaseModel):
    id: str
    name: str
    severity: str | None = None
    impact_class: str
    cve_id: str | None = None
    technologies: list[str] = Field(default_factory=list)


class ScanPlanResponse(BaseModel):
    plan_id: str
    program_slug: str
    asset_key: str
    target_url: str
    raw_detected_technologies: list[str] = Field(default_factory=list)
    pruned_edge_tags: list[str] = Field(default_factory=list)
    matched_technologies: list[str] = Field(default_factory=list)
    total_templates: int
    selected_templates: list[SelectedTemplateItem] = Field(default_factory=list)


class ScanRunRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    plan_id: str | None = None
    program_slug: str
    asset_key: str
    severity: str | None = None
    tags: str | None = None
    mode: str = "auto"


class ScanRunResponse(BaseModel):
    plan_id: str
    program_slug: str
    asset_key: str
    target_url: str
    status: str
    mode_executed: str
    raw_detected_technologies: list[str] = Field(default_factory=list)
    pruned_edge_tags: list[str] = Field(default_factory=list)
    matched_technologies: list[str] = Field(default_factory=list)
    total_templates: int
    findings_count: int = 0
    findings: list[dict[str, Any]] = Field(default_factory=list)
    message: str | None = None


class ScanHistoryItem(BaseModel):
    sequence: int
    actor: str
    event_type: str
    object_type: str
    object_id: str
    payload: dict[str, Any] = Field(default_factory=dict)
    occurred_at: str
    timestamp: str



class ReconRunRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    program_slug: str
    domain: str
    bruteforce: bool = False


class ReconRunResponse(BaseModel):
    domain: str
    program_slug: str
    total_discovered: int
    in_scope_count: int
    out_of_scope_count: int
    resolved_count: int
    live_http_count: int
    sample_assets: list[str] = Field(default_factory=list)
    message: str


class BatchScanRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    program_slug: str
    severity: str | None = None
    tags: str | None = None
    rate_limit: int = 10
    mode: str = "auto"
    max_assets: int = 50


class BatchScanAssetSummary(BaseModel):
    asset_key: str
    matched_technologies: list[str] = Field(default_factory=list)
    total_templates: int
    findings_count: int = 0
    status: str


class BatchScanResponse(BaseModel):
    program_slug: str
    total_assets_scanned: int
    total_templates_executed: int
    total_findings_discovered: int
    rate_limit_enforced: str
    assets: list[BatchScanAssetSummary] = Field(default_factory=list)
    message: str


class EvidenceItemSchema(BaseModel):
    id: str
    run_id: str
    evidence_type: str
    original_sha256: str | None = None
    sanitized_sha256: str
    seaweed_object_key: str
    redaction_profile: str
    created_at: str | None = None


class DetectorInfoSchema(BaseModel):
    id: str
    name: str
    protocol: str | None = None
    severity: str | None = None
    cve_id: str | None = None
    cwe_id: str | None = None
    impact_class: str


class AssetInfoSchema(BaseModel):
    id: str
    canonical_key: str
    asset_type: str | None = None
    scope_state: str | None = None


class FindingListItem(BaseModel):
    id: str
    program_id: str
    program_slug: str | None = None
    asset_id: str
    detector_id: str
    advisory_id: str | None = None
    status: str
    evidence_level: str
    confidence: str
    dedup_key: str
    first_seen: str
    last_seen: str
    epss_score: float | None = None
    epss_percentile: float | None = None
    in_cisa_kev: bool = False
    priority_tier: str = "standard"
    asset: AssetInfoSchema | None = None
    detector: DetectorInfoSchema | None = None


class FindingDetailResponse(FindingListItem):
    evidence_items: list[EvidenceItemSchema] = Field(default_factory=list)


class FindingStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="ignore")

    status: str


class FindingReportResponse(BaseModel):
    finding_id: str
    title: str
    markdown: str
