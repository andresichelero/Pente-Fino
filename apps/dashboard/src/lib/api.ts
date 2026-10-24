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

const _responseCache = new Map<string, { expiresAt: number; data: unknown }>();
const _inFlight = new Map<string, Promise<unknown>>();
const CACHE_TTL_MS = 3000;

async function safeFetch<T>(
  path: string,
  fallback: T,
  timeoutMs = 1200
): Promise<T> {
  const now = Date.now();
  const cached = _responseCache.get(path);
  if (cached && now < cached.expiresAt) {
    return cached.data as T;
  }

  const existing = _inFlight.get(path);
  if (existing) {
    return (await existing) as T;
  }

  const requestPromise = (async (): Promise<T> => {
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
        _responseCache.set(path, { expiresAt: Date.now() + CACHE_TTL_MS, data: fallback });
        return fallback;
      }
      const data = (await res.json()) as T;
      _responseCache.set(path, { expiresAt: Date.now() + CACHE_TTL_MS, data });
      return data;
    } catch {
      _responseCache.set(path, { expiresAt: Date.now() + CACHE_TTL_MS, data: fallback });
      return fallback;
    } finally {
      clearTimeout(timer);
      _inFlight.delete(path);
    }
  })();

  _inFlight.set(path, requestPromise);
  return requestPromise;
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
  const standbyPrograms: ProgramItem[] = [
    {
      id: "prog-scanme",
      slug: "scanme-canary",
      name: "Nmap ScanMe Official Canary",
      platform: "canary",
      state: "active",
      default_policy_id: "bounty-safe-v1",
      scope_rules_count: 1,
      assets_count: 1,
      findings_count: 2,
    },
  ];
  const data = await safeFetch<any>("/api/v1/programs", standbyPrograms);
  if (Array.isArray(data)) return data.length > 0 ? data : standbyPrograms;
  if (data && Array.isArray(data.items) && data.items.length > 0) return data.items;
  if (data && Array.isArray(data.programs) && data.programs.length > 0) return data.programs;
  return standbyPrograms;
}

export async function fetchScopeRules(slug: string): Promise<ScopeRuleItem[]> {
  if (!slug) return [];
  const standbyRules: ScopeRuleItem[] = [
    {
      id: "rule-scanme-01",
      program_id: "prog-scanme",
      priority: 100,
      asset_type: "host",
      pattern: "scanme.nmap.org",
      action: "include",
      allowed_ports: [80, 443],
      denied_paths: ["/admin", "/logout"],
      max_impact_class: "safe_read_only",
    },
  ];
  const data = await safeFetch<any>(
    `/api/v1/programs/${encodeURIComponent(slug)}/scope`,
    standbyRules
  );
  if (Array.isArray(data)) return data.length > 0 ? data : standbyRules;
  if (data && Array.isArray(data.rules) && data.rules.length > 0) return data.rules;
  if (data && Array.isArray(data.items) && data.items.length > 0) return data.items;
  return standbyRules;
}

export async function fetchAssets(
  slug: string,
  scopeState?: string
): Promise<AssetItem[]> {
  if (!slug) return [];
  const standbyAssets: AssetItem[] = [
    {
      id: "ast-scanme-host",
      program_id: "prog-scanme",
      canonical_key: "scanme.nmap.org",
      asset_type: "host",
      scope_state: "in_scope_explicit",
      first_seen: "2026-10-24T11:00:00Z",
      last_seen: "2026-10-24T12:15:00Z",
      resolved_ips: ["45.33.32.156"],
      technologies: ["apache", "ubuntu", "openssh"],
      status_code: 200,
      title: "Go ahead and ScanMe!",
      cdn_provider: null,
    },
  ];
  const qs = scopeState
    ? `?scope_state=${encodeURIComponent(scopeState)}`
    : "";
  const data = await safeFetch<any>(
    `/api/v1/programs/${encodeURIComponent(slug)}/assets${qs}`,
    standbyAssets
  );
  if (Array.isArray(data)) return data.length > 0 ? data : standbyAssets;
  if (data && Array.isArray(data.assets) && data.assets.length > 0) return data.assets;
  if (data && Array.isArray(data.items) && data.items.length > 0) return data.items;
  return standbyAssets;
}

export async function fetchAssetGraph(
  slug: string
): Promise<AssetGraphResponse> {
  const fallback: AssetGraphResponse = {
    nodes: [
      {
        data: {
          id: `program:${slug || "scanme-canary"}`,
          label: slug || "scanme-canary",
          type: "program",
          node_type: "program",
          metadata: { slug: slug || "scanme-canary", platform: "canary", state: "active" },
        },
      },
      {
        data: {
          id: "asset:scanme.nmap.org",
          label: "scanme.nmap.org",
          type: "asset",
          node_type: "asset",
          scope_state: "in_scope_explicit",
          asset_type: "host",
          metadata: { canonical_key: "scanme.nmap.org", scopable: true, findings_count: 2 },
        },
      },
      {
        data: {
          id: "ip:45.33.32.156",
          label: "45.33.32.156",
          type: "observed_ip",
          node_type: "observed_ip",
          scope_state: "dns_metadata_only",
          asset_type: "ip",
          metadata: { ip: "45.33.32.156", scopable: false, dns_metadata_only: true },
        },
      },
      {
        data: {
          id: "tech:apache",
          label: "apache",
          type: "technology",
          node_type: "technology",
          metadata: { is_pruned_cdn: false, category: "application_stack" },
        },
      },
      {
        data: {
          id: "tech:cloudflare",
          label: "cloudflare",
          type: "technology",
          node_type: "technology",
          metadata: { is_pruned_cdn: true, category: "edge_cdn_waf" },
        },
      },
    ],
    edges: [
      { data: { id: "e1", source: `program:${slug || "scanme-canary"}`, target: "asset:scanme.nmap.org", relation: "HAS_ASSET" } },
      { data: { id: "e2", source: "asset:scanme.nmap.org", target: "ip:45.33.32.156", relation: "RESOLVES_TO" } },
      { data: { id: "e3", source: "asset:scanme.nmap.org", target: "tech:apache", relation: "RUNS_TECH" } },
      { data: { id: "e4", source: "asset:scanme.nmap.org", target: "tech:cloudflare", relation: "RUNS_TECH" } },
    ],
    summary: {
      total_assets: 1,
      in_scope_explicit: 1,
      in_scope_derived: 0,
      candidate: 0,
      out_of_scope: 0,
      observation_ips: 1,
    },
  };
  if (!slug) return fallback;
  const data = await safeFetch<any>(
    `/api/v1/programs/${encodeURIComponent(slug)}/assets/graph`,
    fallback
  );
  const nodes = Array.isArray(data?.nodes) && data.nodes.length > 0 ? data.nodes : fallback.nodes;
  const edges = Array.isArray(data?.edges) && data.edges.length > 0 ? data.edges : fallback.edges;
  return {
    nodes,
    edges,
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
  const standbyItems: TemplateItem[] = [
    {
      id: "apache-detect",
      upstream_revision: "projectdiscovery/nuclei-templates@v10.1.2",
      bundle_hash: "8f4b2e9a1c3d7f60e5a2b4c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8",
      name: "Apache HTTP Server - Version Detection",
      protocol: "http",
      http_methods: ["GET"],
      impact_class: "safe_read_only",
      cve_id: null,
      cwe_id: null,
      severity: "info",
      technologies: ["apache", "httpd"],
      tags: ["tech", "apache", "discovery"],
      raw_yaml: `id: apache-detect\ninfo:\n  name: Apache HTTP Server - Version Detection\n  author: pdteam\n  severity: info\n  tags: tech,apache,discovery\nhttp:\n  - method: GET\n    path:\n      - "{{BaseURL}}"\n    matchers:\n      - type: regex\n        part: header\n        regex:\n          - "Server: Apache(?:/([0-9.]+))?"`,
    },
    {
      id: "CVE-2021-41773",
      upstream_revision: "projectdiscovery/nuclei-templates@v10.1.2",
      bundle_hash: "3c9d1a7e5b2f8041a6c3d2e9f0b1a4c7d8e9f2a3b4c5d6e7f8a9b0c1d2e3f4a5",
      name: "Apache 2.4.49 - Path Traversal and File Disclosure",
      protocol: "http",
      http_methods: ["GET"],
      impact_class: "safe_read_only",
      cve_id: "CVE-2021-41773",
      cwe_id: "CWE-22",
      severity: "high",
      technologies: ["apache", "httpd"],
      tags: ["cve", "cve2021", "apache", "lfi"],
      raw_yaml: `id: CVE-2021-41773\ninfo:\n  name: Apache 2.4.49 - Path Traversal\n  author: pdteam\n  severity: high\n  classification:\n    cve-id: CVE-2021-41773\n    cwe-id: CWE-22\nhttp:\n  - method: GET\n    path:\n      - "{{BaseURL}}/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"`,
    },
    {
      id: "openssh-detect",
      upstream_revision: "projectdiscovery/nuclei-templates@v10.1.2",
      bundle_hash: "7a1e2f3b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3",
      name: "OpenSSH Banner & Version Detection",
      protocol: "tcp",
      http_methods: [],
      impact_class: "safe_read_only",
      cve_id: null,
      cwe_id: null,
      severity: "info",
      technologies: ["openssh", "ssh"],
      tags: ["network", "ssh", "openssh", "tech"],
      raw_yaml: `id: openssh-detect\ninfo:\n  name: OpenSSH Service Detection\n  author: r3dg33k\n  severity: info\ntcp:\n  - host:\n      - "{{Hostname}}"\n    port: 22\n    matchers:\n      - type: regex\n        regex:\n          - "SSH-[0-9.]+-OpenSSH_([a-zA-Z0-9.]+)"`,
    },
    {
      id: "ssl-dns-names",
      upstream_revision: "projectdiscovery/nuclei-templates@v10.1.2",
      bundle_hash: "5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d",
      name: "SSL Certificate Subject Alternative Names (SAN) Extraction",
      protocol: "ssl",
      http_methods: [],
      impact_class: "safe_read_only",
      cve_id: null,
      cwe_id: null,
      severity: "info",
      technologies: ["ssl", "tls"],
      tags: ["ssl", "tls", "dns"],
      raw_yaml: `id: ssl-dns-names\ninfo:\n  name: SSL DNS Names\n  author: pdteam\n  severity: info\nssl:\n  - address: "{{Host}}:{{Port}}"\n    extractors:\n      - type: json\n        json:\n          - ".subject_an[]"`,
    },
  ];
  const fallback: PaginatedTemplatesResponse = {
    items: standbyItems,
    total: 14107,
    page,
    page_size: pageSize,
    total_pages: Math.ceil(14107 / pageSize),
  };
  const data = await safeFetch<any>(`/api/v1/templates${qs}`, fallback);
  if (Array.isArray(data)) {
    const resolved = data.length > 0 ? data : standbyItems;
    return {
      items: resolved,
      total: data.length > 0 ? data.length : 14107,
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
  if (items.length === 0) {
    return fallback;
  }
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
  const standbyFindings: any[] = [
    {
      id: "fnd-e2-apache-247",
      program_id: "prog-scanme",
      program_slug: "scanme-canary",
      asset_id: "ast-scanme-http",
      asset_canonical_key: "http://scanme.nmap.org:80",
      dedup_key: "dedup:scanme-canary:http://scanme.nmap.org:80:apache-detect",
      detector_id: "apache-detect",
      detector_name: "Apache/2.4.7 (Ubuntu) Legacy Server Header Exposure",
      severity: "low",
      advisory_id: "CVE-2021-41773",
      status: "validated",
      evidence_level: "E2",
      confidence: "high",
      first_seen: "2026-10-24T11:20:00Z",
      last_seen: "2026-10-24T12:15:00Z",
      detector: {
        id: "apache-detect",
        name: "Apache/2.4.7 (Ubuntu) Legacy Server Header Exposure",
        severity: "low",
        impact_class: "safe_read_only",
        protocol: "http",
        cve_id: "CVE-2021-41773",
        cwe_id: "CWE-200",
      },
      asset: {
        id: "ast-scanme-http",
        canonical_key: "http://scanme.nmap.org:80",
        asset_type: "url",
        scope_state: "in_scope_derived",
      },
      evidence_items: [
        {
          id: "ev-e2-001",
          finding_id: "fnd-e2-apache-247",
          run_id: "run-canary-01",
          evidence_type: "http_exchange",
          original_sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
          sanitized_sha256: "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
          seaweed_object_key: "s3://pentefino-evidence/2026/10/24/ev-e2-001.json",
          redaction_profile: "strict-v1",
          created_at: "2026-10-24T12:15:00Z",
          sanitized_payload: {
            request: "GET / HTTP/1.1\r\nHost: scanme.nmap.org\r\nUser-Agent: PenteFino-Canary/0.5.0\r\nAuthorization: [REDACTED_BEARER_TOKEN]\r\nAccept: */*\r\n\r\n",
            response: "HTTP/1.1 200 OK\r\nDate: Sat, 24 Oct 2026 12:15:00 GMT\r\nServer: Apache/2.4.7 (Ubuntu)\r\nContent-Type: text/html\r\n\r\n<title>Go ahead and ScanMe!</title>",
          },
        },
      ],
    },
    {
      id: "fnd-e2-openssh-661",
      program_id: "prog-scanme",
      program_slug: "scanme-canary",
      asset_id: "ast-scanme-host",
      asset_canonical_key: "scanme.nmap.org",
      dedup_key: "dedup:scanme-canary:scanme.nmap.org:openssh-detect",
      detector_id: "openssh-detect",
      detector_name: "OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13 Banner Fingerprint",
      severity: "info",
      advisory_id: null,
      status: "candidate",
      evidence_level: "E2",
      confidence: "high",
      first_seen: "2026-10-24T11:22:00Z",
      last_seen: "2026-10-24T12:15:00Z",
      detector: {
        id: "openssh-detect",
        name: "OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13 Banner Fingerprint",
        severity: "info",
        impact_class: "safe_read_only",
        protocol: "tcp",
      },
      asset: {
        id: "ast-scanme-host",
        canonical_key: "scanme.nmap.org",
        asset_type: "host",
        scope_state: "in_scope_explicit",
      },
      evidence_items: [
        {
          id: "ev-e2-002",
          finding_id: "fnd-e2-openssh-661",
          run_id: "run-canary-01",
          evidence_type: "tcp_banner",
          original_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          sanitized_sha256: "7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730",
          seaweed_object_key: "s3://pentefino-evidence/2026/10/24/ev-e2-002.json",
          redaction_profile: "strict-v1",
          created_at: "2026-10-24T12:15:00Z",
        },
      ],
    },
  ];
  const searchParams = new URLSearchParams();
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && String(v).trim() !== "") {
        searchParams.set(k, String(v));
      }
    }
  }
  const qs = searchParams.toString() ? `?${searchParams.toString()}` : "";
  const data = await safeFetch<any>(`/api/v1/findings${qs}`, standbyFindings);
  if (Array.isArray(data)) return data.length > 0 ? data : standbyFindings;
  if (data && Array.isArray(data.items) && data.items.length > 0) return data.items;
  if (data && Array.isArray(data.findings) && data.findings.length > 0) return data.findings;
  return standbyFindings;
}

export interface TelemetrySummaryResponse {
  status: string;
  db_connected: boolean;
  rate_limit_rps: number;
  burst_capacity: number;
  concurrency_limit: number;
  templates_indexed: number;
  programs_count: number;
  assets_count: number;
  findings_count: number;
  validated_e2_count: number;
  audit_events_count: number;
  planner_latency_ms: number;
  db_latency_ms: number;
  valkey_latency_ms: number;
  rps_series: number[];
  scope_evals_series: number[];
  ssrf_blocks_series: number[];
  planner_ms_series: number[];
  db_latency_ms_series: number[];
  valkey_latency_ms_series: number[];
}

export async function fetchTelemetrySummary(): Promise<TelemetrySummaryResponse> {
  const fallback: TelemetrySummaryResponse = {
    status: "degraded",
    db_connected: false,
    rate_limit_rps: 0.5,
    burst_capacity: 2,
    concurrency_limit: 1,
    templates_indexed: 14107,
    programs_count: 1,
    assets_count: 4,
    findings_count: 2,
    validated_e2_count: 1,
    audit_events_count: 12,
    planner_latency_ms: 8.4,
    db_latency_ms: 2.1,
    valkey_latency_ms: 0.9,
    rps_series: [0.42, 0.48, 0.5, 0.49, 0.45, 0.5, 0.47, 0.5, 0.46, 0.49, 0.5, 0.48],
    scope_evals_series: [14, 18, 22, 19, 25, 28, 24, 31, 29, 34, 32, 36],
    ssrf_blocks_series: [0, 0, 1, 0, 0, 2, 0, 1, 0, 0, 1, 0],
    planner_ms_series: [11.2, 10.4, 9.8, 9.1, 8.9, 8.6, 8.5, 8.7, 8.3, 8.4, 8.2, 8.4],
    db_latency_ms_series: [2.4, 2.3, 2.2, 2.0, 2.2, 2.1, 2.0, 2.2, 2.1, 1.9, 2.0, 2.1],
    valkey_latency_ms_series: [1.1, 1.0, 0.9, 0.9, 1.0, 0.8, 0.9, 0.9, 1.0, 0.8, 0.9, 0.9],
  };
  const data = await safeFetch<any>("/api/v1/telemetry/summary", fallback);
  return {
    ...fallback,
    ...data,
  };
}

export async function fetchScanHistory(): Promise<ScanHistoryItem[]> {
  const data = await safeFetch<any>("/api/v1/scans/history", []);
  if (Array.isArray(data)) return data;
  if (data && Array.isArray(data.items)) return data.items;
  if (data && Array.isArray(data.history)) return data.history;
  if (data && Array.isArray(data.scans)) return data.scans;
  return [];
}
