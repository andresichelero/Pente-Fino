import { useRef, useState } from "preact/hooks";
import { api, ApiError, dateTime, post, type HistoryItem, type Program } from "../../lib/api";
import { useLiveSocket, useNow, useResource } from "../../lib/hooks";
import { Empty, ErrorNotice, Loading, SocketBadge } from "../ui";

interface PlanResponse {
  plan_id: string;
  asset_key: string;
  target_url: string;
  raw_detected_technologies: string[];
  pruned_edge_tags: string[];
  matched_technologies: string[];
  total_templates: number;
  selected_templates: { id: string; name: string; severity: string; impact_class: string }[];
}

interface RunResponse {
  plan_id: string;
  status: string;
  mode_executed: string;
  total_templates: number;
  findings_count: number;
  message: string;
}

interface ReconResponse {
  task_id: string;
  domain: string;
  total_discovered: number;
  in_scope_count: number;
  out_of_scope_count: number;
  resolved_count: number;
  live_http_count: number;
  message: string;
}

interface Line {
  tool: string;
  text: string;
}

const q = (name: string): string =>
  typeof window === "undefined" ? "" : new URLSearchParams(window.location.search).get(name) ?? "";

const reconId = (): string => `recon-${Math.random().toString(36).slice(2, 10)}`;

export default function ScansConsole() {
  const programs = useResource(() => api<Program[]>("/api/v1/programs"), []);
  const history = useResource(() => api<HistoryItem[]>("/api/v1/scans/history?limit=20"), []);
  const now = useNow();

  const [slug, setSlug] = useState(q("program"));
  const [asset, setAsset] = useState(q("asset"));
  const [domain, setDomain] = useState("");
  const [plan, setPlan] = useState<PlanResponse | null>(null);
  const [result, setResult] = useState<string | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState<null | "plan" | "scan" | "recon">(null);

  // The channel id we subscribe to for live tool output.
  const [channel, setChannel] = useState<string | null>(null);
  const [lines, setLines] = useState<Line[]>([]);
  const logRef = useRef<HTMLPreElement>(null);

  const sock = useLiveSocket<Line | { done: true }>(channel ? `/ws/scans/${channel}` : null, (m) => {
    if (m?.line !== undefined || m?.message !== undefined) {
      return { tool: m.tool ?? m.stage ?? m.event ?? "", text: String(m.line ?? m.message ?? "") };
    }
    return undefined;
  });

  // Append each socket frame to the log.
  if (sock.data && "text" in sock.data) {
    const last = lines[lines.length - 1];
    if (!last || last.text !== sock.data.text) {
      queueMicrotask(() => {
        setLines((prev) =>
          prev.length && prev[prev.length - 1].text === (sock.data as Line).text ? prev : [...prev, sock.data as Line],
        );
        if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
      });
    }
  }

  const reset = () => {
    setError(null);
    setResult(null);
  };

  const guard = async (kind: "plan" | "scan" | "recon", fn: () => Promise<void>) => {
    reset();
    setBusy(kind);
    try {
      await fn();
    } catch (e) {
      setError(e instanceof ApiError ? e : new ApiError("server", 0, String(e)));
    } finally {
      setBusy(null);
    }
  };

  const makePlan = () =>
    guard("plan", async () => {
      setPlan(await post<PlanResponse>("/api/v1/scans/plan", { program_slug: slug, asset_key: asset }, 30000));
    });

  const runScan = (mode: "dry_run" | "auto") =>
    guard("scan", async () => {
      setLines([]);
      const r = await post<RunResponse>(
        "/api/v1/scans/run",
        { program_slug: slug, asset_key: asset, mode },
        mode === "auto" ? 180000 : 30000,
      );
      setChannel(r.plan_id);
      setResult(`${r.status} · ${r.mode_executed} · ${r.total_templates} template(s) · ${r.findings_count} achado(s). ${r.message}`);
      history.reload();
    });

  const runRecon = () =>
    guard("recon", async () => {
      setLines([]);
      const id = reconId();
      setChannel(id);
      const r = await post<ReconResponse>(
        "/api/v1/recon/run",
        { program_slug: slug, domain, task_id: id },
        180000,
      );
      setResult(
        `${r.total_discovered} subdomínio(s): ${r.in_scope_count} no escopo, ${r.out_of_scope_count} fora, ${r.resolved_count} resolvido(s), ${r.live_http_count} com HTTP. ${r.message}`,
      );
      history.reload();
    });

  const cancel = () =>
    guard("scan", async () => {
      if (channel) await post(`/api/v1/scans/${channel}/cancel`, {});
    });

  const canScan = slug && asset && !busy;
  const canRecon = slug && domain.trim() && !busy;

  return (
    <>
      {error && (
        <div class="banner">
          <ErrorNotice error={error} />
        </div>
      )}

      <div class="grid-2">
        <section class="section" aria-labelledby="h-recon">
          <div class="section-head">
            <h2 id="h-recon">Descoberta (recon)</h2>
            <span class="meta">Subfinder → dnsx → httpx</span>
          </div>
          <p class="muted small">
            Enumera subdomínios de um domínio raiz coberto por uma regra de allow. Domínio fora do escopo é recusado antes
            de qualquer ferramenta rodar.
          </p>
          <form class="form-row" onSubmit={(e) => (e.preventDefault(), runRecon())}>
            <label class="field">
              Programa
              <ProgramSelect programs={programs.data} value={slug} onChange={setSlug} />
            </label>
            <label class="field">
              Domínio raiz
              <input value={domain} onInput={(e) => setDomain((e.target as HTMLInputElement).value)} placeholder="exemplo.com" />
            </label>
            <button type="submit" class="primary" disabled={!canRecon}>
              {busy === "recon" ? "Executando…" : "Rodar recon"}
            </button>
          </form>
        </section>

        <section class="section" aria-labelledby="h-scan">
          <div class="section-head">
            <h2 id="h-scan">Varredura de um ativo</h2>
            <span class="meta">templates safe_read_only</span>
          </div>
          <p class="muted small">
            O plano mostra o que seria executado. "Simular" não envia nada; "Executar" só roda templates compatíveis com a
            tecnologia detectada, pelo proxy.
          </p>
          <form class="form-row" onSubmit={(e) => (e.preventDefault(), makePlan())}>
            <label class="field">
              Programa
              <ProgramSelect programs={programs.data} value={slug} onChange={setSlug} />
            </label>
            <label class="field">
              Ativo
              <input value={asset} onInput={(e) => setAsset((e.target as HTMLInputElement).value)} placeholder="app.exemplo.com" />
            </label>
            <button type="submit" disabled={!canScan}>
              {busy === "plan" ? "Planejando…" : "Planejar"}
            </button>
          </form>
          <div class="form-row" style="margin-top:0">
            <button type="button" onClick={() => runScan("dry_run")} disabled={!canScan}>
              Simular
            </button>
            <button type="button" class="primary" onClick={() => runScan("auto")} disabled={!canScan}>
              Executar
            </button>
            {channel && (
              <button type="button" class="danger" onClick={cancel} disabled={!busy}>
                Cancelar
              </button>
            )}
          </div>
        </section>
      </div>

      {plan && (
        <section class="section" aria-labelledby="h-plan">
          <div class="section-head">
            <h2 id="h-plan">Plano para {plan.asset_key}</h2>
            <span class="meta">{plan.total_templates} template(s) selecionado(s)</span>
          </div>
          <dl class="kv" style="margin-bottom:12px">
            <dt>Tecnologias detectadas</dt>
            <dd>{plan.raw_detected_technologies.join(", ") || "nenhuma (ative recon/httpx primeiro)"}</dd>
            <dt>Tags de CDN/WAF podadas</dt>
            <dd>{plan.pruned_edge_tags.join(", ") || "—"}</dd>
            <dt>Tecnologias casadas</dt>
            <dd>{plan.matched_technologies.join(", ") || "—"}</dd>
          </dl>
          {plan.selected_templates.length === 0 ? (
            <Empty>Nenhum template casa com as tecnologias deste ativo: a execução é pulada.</Empty>
          ) : (
            <div class="table-wrap">
              <table class="stack">
                <thead>
                  <tr>
                    <th>Template</th>
                    <th>Severidade</th>
                    <th>Classe</th>
                  </tr>
                </thead>
                <tbody>
                  {plan.selected_templates.map((t) => (
                    <tr key={t.id}>
                      <td data-label="Template">
                        <span class="mono">{t.id}</span>
                        <div class="small muted">{t.name}</div>
                      </td>
                      <td data-label="Severidade">{t.severity}</td>
                      <td data-label="Classe">{t.impact_class}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      {(channel || result) && (
        <section class="section" aria-labelledby="h-live">
          <div class="section-head">
            <h2 id="h-live">Saída ao vivo</h2>
            <span class="meta">
              {channel && (
                <SocketBadge
                  state={sock.state}
                  receivedAt={sock.receivedAt}
                  now={now}
                  nextRetryAt={sock.nextRetryAt}
                  lastError={sock.lastError}
                />
              )}
            </span>
          </div>
          {result && <div class="notice" style="margin-bottom:12px">{result}</div>}
          {lines.length === 0 ? (
            <p class="muted small">Sem saída ainda. As linhas das ferramentas aparecem aqui conforme chegam.</p>
          ) : (
            <pre class="log" ref={logRef}>
              {lines.map((l, i) => `${l.tool ? `[${l.tool}] ` : ""}${l.text}`).join("\n")}
            </pre>
          )}
        </section>
      )}

      <section class="section" aria-labelledby="h-hist">
        <div class="section-head">
          <h2 id="h-hist">Histórico recente</h2>
          <span class="meta">eventos de auditoria</span>
        </div>
        {history.error && <ErrorNotice error={history.error} onRetry={history.reload} />}
        {!history.data && history.loading && <Loading />}
        {history.data && history.data.length === 0 && <Empty>Nenhum evento ainda.</Empty>}
        {history.data && history.data.length > 0 && (
          <div class="table-wrap">
            <table class="stack">
              <thead>
                <tr>
                  <th>Quando</th>
                  <th>Evento</th>
                  <th>Programa</th>
                  <th>Resumo</th>
                </tr>
              </thead>
              <tbody>
                {history.data.map((h) => (
                  <tr key={h.sequence}>
                    <td data-label="Quando">{dateTime(h.occurred_at)}</td>
                    <td data-label="Evento" class="mono small">
                      {h.event_type}
                    </td>
                    <td data-label="Programa">{h.payload?.program_slug ?? "—"}</td>
                    <td data-label="Resumo" class="small muted">
                      {summarize(h)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}

function ProgramSelect({
  programs,
  value,
  onChange,
}: {
  programs: Program[] | null;
  value: string;
  onChange: (v: string) => void;
}) {
  return (
    <select value={value} onChange={(e) => onChange((e.target as HTMLSelectElement).value)}>
      <option value="">Escolha…</option>
      {programs?.map((p) => (
        <option value={p.slug} key={p.id}>
          {p.name}
        </option>
      ))}
    </select>
  );
}

function summarize(h: HistoryItem): string {
  const p = h.payload ?? {};
  if (h.event_type.includes("recon")) return `${p.total_discovered ?? "?"} descoberto(s), ${p.in_scope ?? "?"} no escopo`;
  if (h.event_type.includes("scan")) return `${p.total_templates ?? p.templates_executed ?? "?"} template(s), ${p.findings_count ?? p.findings_discovered ?? 0} achado(s)`;
  return Object.entries(p)
    .slice(0, 3)
    .map(([k, v]) => `${k}=${v}`)
    .join(" · ");
}
