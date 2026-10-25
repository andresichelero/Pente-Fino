import type { ComponentChildren } from "preact";
import { ago, type ApiError } from "../lib/api";
import type { SocketState } from "../lib/hooks";

/** Seconds after which live data is flagged as stale. */
export const STALE_AFTER_S = 15;

export function isStale(checkedAtSeconds: number | null | undefined, now: number, limitS = STALE_AFTER_S): boolean {
  if (!checkedAtSeconds) return true;
  return now / 1000 - checkedAtSeconds > limitS;
}

const STATUS_LABEL: Record<string, string> = {
  up: "Operando",
  down: "Fora do ar",
  degraded: "Degradado",
  unknown: "Sem dados",
  stale: "Desatualizado",
};

export function StatusDot({ status, stale }: { status: string; stale?: boolean }) {
  const s = stale ? "stale" : status;
  return (
    <span class="state">
      <span class={`dot ${s}`} aria-hidden="true" />
      {STATUS_LABEL[s] ?? s}
    </span>
  );
}

export function Loading({ label = "Carregando" }: { label?: string }) {
  return (
    <div role="status" aria-live="polite">
      <div class="loading-line" />
      <p class="muted small">{label}…</p>
    </div>
  );
}

export function Empty({ children }: { children: ComponentChildren }) {
  return <div class="notice">{children}</div>;
}

const ERROR_HINT: Record<string, string> = {
  network: "Inicie a API: python -m uvicorn pentefino_api.main:app --port 8000",
  standby: "Suba o banco: docker compose up -d postgres",
  unauthorized: "Defina PUBLIC_API_KEY no dashboard igual a PENTEFINO_API_KEY da API.",
};

export function ErrorNotice({ error, onRetry }: { error: ApiError; onRetry?: () => void }) {
  return (
    <div class="notice error" role="alert">
      <strong>{error.message}</strong>
      {ERROR_HINT[error.kind] && <div class="small">{ERROR_HINT[error.kind]}</div>}
      {onRetry && (
        <div style="margin-top:8px">
          <button type="button" onClick={onRetry}>
            Tentar de novo
          </button>
        </div>
      )}
    </div>
  );
}

export function SocketBadge({
  state,
  receivedAt,
  now,
  nextRetryAt,
  lastError,
}: {
  state: SocketState;
  receivedAt: number | null;
  now: number;
  nextRetryAt: number | null;
  lastError: string | null;
}) {
  const stale = receivedAt === null || (now - receivedAt) / 1000 > STALE_AFTER_S;
  let text: string;
  let dot: string;
  if (state === "open" && !stale) {
    text = `Ao vivo · atualizado ${ago(receivedAt! / 1000, now)}`;
    dot = "up";
  } else if (state === "open") {
    text = "Conectado, sem atualização recente";
    dot = "stale";
  } else if (state === "reconnecting") {
    const wait = nextRetryAt ? Math.max(0, Math.ceil((nextRetryAt - now) / 1000)) : 0;
    text = `${lastError ?? "Desconectado"} Nova tentativa em ${wait}s`;
    dot = "down";
  } else {
    text = "Conectando…";
    dot = "unknown";
  }
  return (
    <span class="state" role="status" aria-live="polite">
      <span class={`dot ${dot}`} aria-hidden="true" />
      {text}
    </span>
  );
}

export function Sparkline({ values, label }: { values: (number | null)[]; label: string }) {
  const pts = values.map((v, i) => [i, v] as const).filter((p): p is readonly [number, number] => p[1] !== null);
  if (pts.length < 2) return <span class="muted small">Série ainda sem amostras suficientes</span>;
  const xs = values.length - 1 || 1;
  const vals = pts.map((p) => p[1]);
  const min = Math.min(...vals);
  const max = Math.max(...vals);
  const span = max - min || 1;
  const d = pts
    .map(([i, v], k) => `${k ? "L" : "M"}${((i / xs) * 100).toFixed(2)},${(32 - ((v - min) / span) * 28).toFixed(2)}`)
    .join(" ");
  return (
    <svg class="spark" viewBox="0 0 100 36" preserveAspectRatio="none" role="img" aria-label={label}>
      <path d={d} vector-effect="non-scaling-stroke" />
    </svg>
  );
}

export function SeverityText({ sev }: { sev: string | null | undefined }) {
  const s = (sev || "unknown").toLowerCase();
  const label: Record<string, string> = {
    critical: "Crítica",
    high: "Alta",
    medium: "Média",
    low: "Baixa",
    info: "Info",
    unknown: "Sem severidade",
  };
  return <span class={`sev-${s}`}>{label[s] ?? s}</span>;
}
