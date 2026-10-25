/**
 * Browser-side API client. Every call either returns real data or throws an
 * ApiError that says what went wrong; nothing is replaced by placeholder values.
 */
export const API_BASE_URL: string = import.meta.env.PUBLIC_API_URL || "http://127.0.0.1:8000";
export const WS_BASE_URL: string = import.meta.env.PUBLIC_WS_URL || API_BASE_URL.replace(/^http/, "ws");
const API_KEY: string = import.meta.env.PUBLIC_API_KEY || "";

export type ApiErrorKind = "network" | "standby" | "unauthorized" | "not_found" | "rejected" | "server";

export class ApiError extends Error {
  constructor(
    public kind: ApiErrorKind,
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

function headers(extra?: HeadersInit): HeadersInit {
  return {
    Accept: "application/json",
    ...(API_KEY ? { "X-PenteFino-Key": API_KEY } : {}),
    ...(extra || {}),
  };
}

export async function api<T>(path: string, init: RequestInit = {}, timeoutMs = 15000): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let res: Response;
  try {
    res = await fetch(`${API_BASE_URL}${path}`, {
      ...init,
      signal: init.signal ?? controller.signal,
      headers: headers(init.body ? { "Content-Type": "application/json" } : undefined),
    });
  } catch (err) {
    const aborted = (err as Error)?.name === "AbortError";
    throw new ApiError(
      "network",
      0,
      aborted ? `A API não respondeu em ${timeoutMs / 1000}s.` : `API inacessível em ${API_BASE_URL}.`,
    );
  } finally {
    clearTimeout(timer);
  }
  let body: any = null;
  try {
    body = await res.json();
  } catch {
    body = null;
  }
  if (res.ok) return body as T;
  const detail = typeof body?.detail === "string" ? body.detail : res.statusText;
  if (res.status === 503 && body?.status === "standby") {
    throw new ApiError("standby", 503, "PostgreSQL fora do ar: a API está em standby.");
  }
  if (res.status === 401) throw new ApiError("unauthorized", 401, `Não autorizado: ${detail}`);
  if (res.status === 404) throw new ApiError("not_found", 404, detail);
  if (res.status < 500) throw new ApiError("rejected", res.status, formatDetail(body?.detail) || detail);
  throw new ApiError("server", res.status, `Erro ${res.status}: ${detail}`);
}

function formatDetail(detail: unknown): string {
  if (Array.isArray(detail)) {
    return detail.map((d: any) => `${(d.loc || []).slice(1).join(".")}: ${d.msg}`).join("; ");
  }
  return typeof detail === "string" ? detail : "";
}

export const post = <T>(path: string, data: unknown, timeoutMs?: number) =>
  api<T>(path, { method: "POST", body: JSON.stringify(data) }, timeoutMs);
export const patch = <T>(path: string, data: unknown) =>
  api<T>(path, { method: "PATCH", body: JSON.stringify(data) });
export const del = <T>(path: string) => api<T>(path, { method: "DELETE" });

export function wsUrl(path: string): string {
  const url = `${WS_BASE_URL}${path}`;
  return API_KEY ? `${url}${url.includes("?") ? "&" : "?"}key=${encodeURIComponent(API_KEY)}` : url;
}

// ---------------------------------------------------------------------------
// Types (subset of the API schemas actually rendered)
// ---------------------------------------------------------------------------
export interface Check {
  status: "up" | "down" | "degraded" | "unknown";
  latency_ms: number | null;
  checked_at: number;
  source: string;
  detail: string;
  [k: string]: any;
}

export interface ActiveOp {
  run_id: string;
  kind: string;
  program_slug: string;
  target: string;
  started_at: string;
  elapsed_s: number;
  cancelled: boolean;
}

export interface LiveStatus {
  generated_at: number;
  systems: Record<string, Check>;
  execution: {
    checked_at: number;
    active_scans: ActiveOp[];
    active_recon: ActiveOp[];
    amqp: {
      available: boolean;
      detail?: string;
      checked_at?: number;
      total_ready?: number;
      total_unacked?: number;
      queues: { name: string; messages_ready: number; messages_unacked: number; consumers: number }[];
    };
  };
  scope: {
    api: {
      window_s: number;
      evaluations: number;
      denied: number;
      ssrf_blocked: number;
      since_start: Record<string, number>;
      counting_since: string;
      checked_at: number;
    };
    proxy: {
      available: boolean;
      detail?: string;
      checked_at?: number;
      totals?: Record<string, number>;
      requests_last_5m?: number;
    };
  };
  findings: {
    available: boolean;
    detail?: string;
    checked_at?: number;
    needs_triage?: number;
    new_24h?: number;
    by_status?: Record<string, number>;
    open_by_severity?: Record<string, number>;
    open_by_evidence_level?: Record<string, number>;
    recent?: {
      id: string;
      detector_id: string;
      asset: string | null;
      severity: string;
      status: string;
      evidence_level: string;
      first_seen: string | null;
    }[];
  };
  network: NetworkHealth;
}

export interface NetworkTarget {
  name: string;
  host: string;
  latency_ms: number | null;
  jitter_ms: number | null;
  loss_pct: number | null;
  samples?: number;
  status: string;
  checked_at?: number;
}

export interface NetworkHealth {
  status: string;
  overall_latency_ms: number | null;
  overall_jitter_ms: number | null;
  packet_loss_pct: number | null;
  download_kbps?: number;
  upload_kbps?: number;
  packets_sent?: number;
  packets_recv?: number;
  targets: NetworkTarget[];
  source?: string;
  timestamp?: number;
}

export interface Program {
  id: string;
  slug: string;
  name: string;
  platform: string;
  state: string;
  created_at?: string;
  scope_rules_count?: number;
  assets_count?: number;
  findings_count?: number;
  snapshots_count?: number;
}

export interface ScopeRule {
  id: string;
  action: string;
  pattern: string;
  asset_type: string;
  priority: number;
  allowed_ports: number[] | null;
  denied_paths: string[] | null;
  max_impact_class: string;
}

export interface ScopeDecision {
  target: string;
  allowed: boolean;
  scope_state: string;
  precedence_tier: string;
  matched_pattern: string | null;
  reason: string;
  target_canonical: string;
}

export interface AssetItem {
  id: string;
  canonical_key: string;
  asset_type: string;
  scope_state: string;
  first_seen: string;
  last_seen: string;
  findings_count?: number;
  technologies?: string[];
  status_code?: number | null;
  title?: string | null;
}

export interface FindingItem {
  id: string;
  program_slug: string;
  detector_id: string;
  status: string;
  evidence_level: string;
  confidence: string;
  first_seen: string;
  last_seen: string;
  in_cisa_kev: boolean;
  epss_score: number | null;
  asset?: { canonical_key: string; scope_state: string } | null;
  detector?: { name: string; severity: string; cve_id: string | null } | null;
}

export interface TemplateItem {
  id: string;
  name: string;
  protocol: string;
  impact_class: string;
  severity: string;
  cve_id: string | null;
  technologies: string[];
  tags: string[];
}

export interface TemplatePage {
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
  items: TemplateItem[];
}

export interface HistoryItem {
  sequence: number;
  actor: string;
  event_type: string;
  object_type: string;
  object_id: string;
  payload: Record<string, any>;
  occurred_at: string;
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------
export function ms(v: number | null | undefined): string {
  if (v === null || v === undefined) return "indisponível";
  return v < 10 ? `${v.toFixed(1)} ms` : `${Math.round(v)} ms`;
}

export function ago(ts: number | string | null | undefined, now = Date.now()): string {
  if (ts === null || ts === undefined) return "—";
  const t = typeof ts === "number" ? ts * 1000 : Date.parse(ts);
  if (Number.isNaN(t)) return "—";
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 60) return `há ${s}s`;
  if (s < 3600) return `há ${Math.floor(s / 60)} min`;
  if (s < 86400) return `há ${Math.floor(s / 3600)} h`;
  return `há ${Math.floor(s / 86400)} d`;
}

export function dateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? "—"
    : d.toLocaleString("pt-BR", { dateStyle: "short", timeStyle: "short" });
}
