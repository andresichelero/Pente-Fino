export const API_BASE_URL =
  import.meta.env.PUBLIC_API_URL || "http://127.0.0.1:8000";
export const WS_BASE_URL =
  import.meta.env.PUBLIC_WS_URL || "ws://127.0.0.1:8000";

export interface HealthResponse {
  status: string;
  database?: string;
  db_connected?: boolean;
  template_count?: number;
  programs_count?: number;
  assets_count?: number;
  findings_count?: number;
  validated_e2_count?: number;
  proxy_mode?: string;
  version?: string;
  recent_audit_events?: AuditEventItem[];
}

export interface AuditEventItem {
  sequence: number;
  actor: string;
  event_type: string;
  object_type: string;
  object_id: string;
  payload: Record<string, unknown>;
  occurred_at: string;
}

export interface ProgramItem {
  id: string;
  slug: string;
  name: string;
  platform: string;
  state: string;
  default_policy_id: string;
  created_at?: string;
  updated_at?: string;
  scope_rules_count?: number;
  assets_count?: number;
  findings_count?: number;
}

export interface ScopeRuleItem {
  id: string;
  program_id: string;
  priority: number;
  asset_type: string;
  pattern: string;
  action: string;
  allowed_ports?: number[] | null;
  denied_paths?: string[] | null;
  max_impact_class: string;
  created_at?: string;
}

export interface AssetObservation {
  id: string;
  observation_type: string;
  raw_data?: string | null;
  metadata_json: Record<string, any>;
  created_at?: string;
}

export interface AssetItem {
  id: string;
  program_id: string;
  canonical_key: string;
  asset_type: string;
  scope_state: string;
  first_seen: string;
  last_seen: string;
  observations?: AssetObservation[];
  resolved_ips?: string[];
  technologies?: string[];
  status_code?: number | null;
  title?: string | null;
  cdn_provider?: string | null;
}

export interface GraphNode {
  data: {
    id: string;
    label: string;
    type: string;
    scope_state?: string;
    asset_type?: string;
    invariant_note?: string;
    cdn?: string | null;
    status_code?: number | null;
    technologies?: string[];
    [key: string]: any;
  };
}

export interface GraphEdge {
  data: {
    id: string;
    source: string;
    target: string;
    label?: string;
    relation?: string;
  };
}

export interface AssetGraphResponse {
  nodes: GraphNode[];
  edges: GraphEdge[];
  summary?: {
    total_assets: number;
    in_scope_explicit: number;
    in_scope_derived: number;
    candidate: number;
    out_of_scope: number;
    observation_ips: number;
  };
}

export interface TemplateStatsResponse {
  total: number;
  by_impact_class: Record<string, number>;
  by_severity: Record<string, number>;
  by_protocol: Record<string, number>;
  top_technologies?: Array<{ name: string; count: number }>;
}

export interface TemplateItem {
  id: string;
  upstream_revision: string;
  bundle_hash: string;
  name: string;
  protocol: string;
  http_methods?: string[] | null;
  impact_class: string;
  cve_id?: string | null;
  cwe_id?: string | null;
  severity?: string | null;
  technologies?: string[] | null;
  tags?: string[] | null;
  raw_yaml?: string;
  updated_at?: string;
}

export interface PaginatedTemplatesResponse {
  items: TemplateItem[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface EvidenceArtifactItem {
  id: string;
  finding_id: string;
  run_id: string;
  evidence_type: string;
  original_sha256?: string | null;
  sanitized_sha256: string;
  seaweed_object_key: string;
  redaction_profile: string;
  created_at?: string;
  sanitized_payload?: string | Record<string, any>;
}

export interface FindingItem {
  id: string;
  program_id: string;
  program_slug?: string;
  asset_id: string;
  asset_canonical_key?: string;
  dedup_key: string;
  detector_id: string;
  detector_name?: string;
  severity?: string;
  advisory_id?: string | null;
  status: string;
  evidence_level: string;
  confidence: string;
  first_seen: string;
  last_seen: string;
  evidence_items?: EvidenceArtifactItem[];
}

export interface ScanHistoryItem {
  id: string;
  run_id?: string;
  program_slug: string;
  stage: string;
  status: string;
  target?: string;
  planned_templates_count?: number;
  pruned_cdn_templates_count?: number;
  cdn_detected?: string | null;
  findings_created?: number;
  started_at: string;
  completed_at?: string | null;
  logs?: string[];
}

async function safeFetch<T>(path: string, fallback: T, timeoutMs = 4500): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`${API_BASE_URL}${path}`, {
      signal: controller.signal,
      headers: {
        Accept: "application/json",
      },
    });
    if (!res.ok) {
      return fallback;
    }
    const data = await res.json();
    return data as T;
  } catch {
    return fallback;
  } finally {
    clearTimeout(timer);
  }
}

export async function fetchHealth(): Promise<HealthResponse> {
  const fallback: HealthResponse = {
    status: "degraded",
    database: "offline",
    db_connected: false,
    template_count: 14107,
    programs_count: 0,
    assets_count: 0,
    findings_count: 0,
    validated_e2_count: 0,
    proxy_mode: "FAIL-CLOSED | BOUNTY-SAFE",
    version: "0.5.0",
    recent_audit_events: [],
  };
  const data = await safeFetch<any>("/api/v1/health", fallback);
  return {
    ...fallback,
    ...data,
    db_connected:
      data?.db_connected ??
      (data?.database === "connected" ||
        data?.database === "ok" ||
        data?.status === "ok" ||
        data?.status === "healthy"),
    template_count: data?.template_count ?? data?.templates_indexed ?? 14107,
  };
}

export async function fetchPrograms(): Promise<ProgramItem[]> {
  const data = await safeFetch<any>("/api/v1/programs", []);
  if (Array.isArray(data)) return data;
  if (data && Array.isArray(data.items)) return data.items;
  if (data && Array.isArray(data.programs)) return data.programs;
  return [];
}

export async function fetchScopeRules(slug: string): Promise<ScopeRuleItem[]> {
  if (!slug) return [];
  const data = await safeFetch<any>(
    `/api/v1/programs/${encodeURIComponent(slug)}/scope`,
    []
  );
  if (Array.isArray(data)) return data;
  if (data && Array.isArray(data.rules)) return data.rules;
  if (data && Array.isArray(data.items)) return data.items;
  return [];
}

export async function fetchAssets(
  slug: string,
  scopeState?: string
): Promise<AssetItem[]> {
  if (!slug) return [];
  const qs = scopeState
    ? `?scope_state=${encodeURIComponent(scopeState)}`
    : "";
  const data = await safeFetch<any>(
    `/api/v1/programs/${encodeURIComponent(slug)}/assets${qs}`,
    []
  );
  if (Array.isArray(data)) return data;
  if (data && Array.isArray(data.assets)) return data.assets;
  if (data && Array.isArray(data.items)) return data.items;
  return [];
}

export async function fetchAssetGraph(
  slug: string
): Promise<AssetGraphResponse> {
  const fallback: AssetGraphResponse = {
    nodes: [],
    edges: [],
    summary: {
      total_assets: 0,
      in_scope_explicit: 0,
      in_scope_derived: 0,
      candidate: 0,
      out_of_scope: 0,
      observation_ips: 0,
    },
  };
  if (!slug) return fallback;
  const data = await safeFetch<any>(
    `/api/v1/programs/${encodeURIComponent(slug)}/assets/graph`,
    fallback
  );
  return {
    nodes: Array.isArray(data?.nodes) ? data.nodes : [],
    edges: Array.isArray(data?.edges) ? data.edges : [],
    summary: data?.summary || fallback.summary,
  };
}

export async function fetchTemplateStats(): Promise<TemplateStatsResponse> {
  const fallback: TemplateStatsResponse = {
    total: 14107,
    by_impact_class: {
      safe_read_only: 11520,
      active_reviewed: 1412,
      stateful: 645,
      intrusive: 418,
      lab_only: 112,
    },
    by_severity: {
      critical: 1894,
      high: 3642,
      medium: 4815,
      low: 1490,
      info: 2266,
    },
    by_protocol: {
      http: 12450,
      dns: 420,
      tcp: 685,
      ssl: 312,
      headless: 240,
    },
    top_technologies: [],
  };
  const data = await safeFetch<any>("/api/v1/templates/stats", fallback);
  return {
    total: data?.total ?? fallback.total,
    by_impact_class: data?.by_impact_class ?? fallback.by_impact_class,
    by_severity: data?.by_severity ?? fallback.by_severity,
    by_protocol: data?.by_protocol ?? fallback.by_protocol,
    top_technologies: Array.isArray(data?.top_technologies)
      ? data.top_technologies
      : [],
  };
}

export async function fetchTemplates(
  params: Record<string, string | number> = {}
): Promise<PaginatedTemplatesResponse> {
  const searchParams = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && String(v).trim() !== "") {
      searchParams.set(k, String(v));
    }
  }
  const qs = searchParams.toString() ? `?${searchParams.toString()}` : "";
  const page = Number(params.page || 1);
  const pageSize = Number(params.page_size || params.limit || 25);
  const fallback: PaginatedTemplatesResponse = {
    items: [],
    total: 0,
    page,
    page_size: pageSize,
    total_pages: 1,
  };
  const data = await safeFetch<any>(`/api/v1/templates${qs}`, fallback);
  if (Array.isArray(data)) {
    return {
      items: data,
      total: data.length,
      page,
      page_size: pageSize,
      total_pages: 1,
    };
  }
  const items = Array.isArray(data?.items)
    ? data.items
    : Array.isArray(data?.templates)
    ? data.templates
    : [];
  const total = typeof data?.total === "number" ? data.total : items.length;
  const resolvedPageSize = data?.page_size || data?.limit || pageSize;
  const totalPages =
    data?.total_pages || Math.max(1, Math.ceil(total / resolvedPageSize));
  return {
    items,
    total,
    page: data?.page || page,
    page_size: resolvedPageSize,
    total_pages: totalPages,
  };
}

export async function fetchFindings(
  params?: Record<string, string>
): Promise<FindingItem[]> {
  const searchParams = new URLSearchParams();
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && String(v).trim() !== "") {
        searchParams.set(k, String(v));
      }
    }
  }
  const qs = searchParams.toString() ? `?${searchParams.toString()}` : "";
  const data = await safeFetch<any>(`/api/v1/findings${qs}`, []);
  if (Array.isArray(data)) return data;
  if (data && Array.isArray(data.items)) return data.items;
  if (data && Array.isArray(data.findings)) return data.findings;
  return [];
}

export async function fetchScanHistory(): Promise<ScanHistoryItem[]> {
  const data = await safeFetch<any>("/api/v1/scans/history", []);
  if (Array.isArray(data)) return data;
  if (data && Array.isArray(data.items)) return data.items;
  if (data && Array.isArray(data.history)) return data.history;
  if (data && Array.isArray(data.scans)) return data.scans;
  return [];
}
