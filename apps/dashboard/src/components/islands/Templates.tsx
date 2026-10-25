import { Fragment } from "preact";
import { useState } from "preact/hooks";
import { api, type TemplatePage } from "../../lib/api";
import { useResource } from "../../lib/hooks";
import { Empty, ErrorNotice, Loading, SeverityText } from "../ui";

interface Stats {
  total: number;
  by_impact_class: Record<string, number>;
  by_severity: Record<string, number>;
}

const IMPACT_LABEL: Record<string, string> = {
  safe_read_only: "Leitura segura",
  active_reviewed: "Ativo revisado",
  stateful: "Com estado",
  intrusive: "Intrusivo",
  lab_only: "Só laboratório",
};
const SEV_ORDER = ["critical", "high", "medium", "low", "info", "unknown"];

export default function Templates() {
  const stats = useResource(() => api<Stats>("/api/v1/templates/stats"), []);
  const [impact, setImpact] = useState("safe_read_only");
  const [severity, setSeverity] = useState("");
  const [q, setQ] = useState("");
  const [page, setPage] = useState(1);
  const pageSize = 25;

  const list = useResource(() => {
    const p = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
    if (impact) p.set("impact_class", impact);
    if (severity) p.set("severity", severity);
    if (q.trim()) p.set("q", q.trim());
    return api<TemplatePage>(`/api/v1/templates?${p}`);
  }, [impact, severity, q, page]);

  const onFilter = (fn: () => void) => {
    setPage(1);
    fn();
  };

  return (
    <>
      <section class="section" aria-labelledby="h-stats">
        <div class="section-head">
          <h2 id="h-stats">Catálogo indexado</h2>
          <span class="meta">{stats.data ? `${stats.data.total.toLocaleString("pt-BR")} templates` : ""}</span>
        </div>
        {stats.error && <ErrorNotice error={stats.error} onRetry={stats.reload} />}
        {!stats.data && stats.loading && <Loading />}
        {stats.data && (
          <div class="grid-2">
            <dl class="kv">
              {Object.entries(stats.data.by_impact_class)
                .sort((a, b) => b[1] - a[1])
                .map(([k, v]) => (
                  <Fragment key={k}>
                    <dt>{IMPACT_LABEL[k] ?? k}</dt>
                    <dd>{v.toLocaleString("pt-BR")}</dd>
                  </Fragment>
                ))}
            </dl>
            <dl class="kv">
              {SEV_ORDER.filter((s) => stats.data!.by_severity[s]).map((s) => (
                <Fragment key={s}>
                  <dt>
                    <SeverityText sev={s} />
                  </dt>
                  <dd>{stats.data!.by_severity[s].toLocaleString("pt-BR")}</dd>
                </Fragment>
              ))}
            </dl>
          </div>
        )}
      </section>

      <section class="section" aria-labelledby="h-list">
        <div class="section-head">
          <h2 id="h-list">Templates</h2>
          <span class="meta">{list.data ? `${list.data.total.toLocaleString("pt-BR")} no filtro` : ""}</span>
        </div>
        <form class="form-row" onSubmit={(e) => e.preventDefault()}>
          <label class="field" style="flex:0 1 200px">
            Classe de impacto
            <select value={impact} onChange={(e) => onFilter(() => setImpact((e.target as HTMLSelectElement).value))}>
              <option value="">Todas</option>
              {Object.entries(IMPACT_LABEL).map(([k, v]) => (
                <option value={k} key={k}>
                  {v}
                </option>
              ))}
            </select>
          </label>
          <label class="field" style="flex:0 1 160px">
            Severidade
            <select value={severity} onChange={(e) => onFilter(() => setSeverity((e.target as HTMLSelectElement).value))}>
              <option value="">Todas</option>
              {["critical", "high", "medium", "low", "info"].map((s) => (
                <option value={s} key={s}>
                  {s}
                </option>
              ))}
            </select>
          </label>
          <label class="field">
            Buscar
            <input
              type="search"
              value={q}
              onInput={(e) => onFilter(() => setQ((e.target as HTMLInputElement).value))}
              placeholder="nginx, CVE-2024…"
            />
          </label>
        </form>

        {list.error && <ErrorNotice error={list.error} onRetry={list.reload} />}
        {!list.data && list.loading && <Loading />}
        {list.data && list.data.items.length === 0 && <Empty>Nenhum template com esse filtro.</Empty>}
        {list.data && list.data.items.length > 0 && (
          <>
            <div class="table-wrap">
              <table class="stack">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Nome</th>
                    <th>Severidade</th>
                    <th>Classe</th>
                    <th>Tecnologias</th>
                  </tr>
                </thead>
                <tbody>
                  {list.data.items.map((t) => (
                    <tr key={t.id}>
                      <td data-label="ID" class="mono small">
                        {t.id}
                      </td>
                      <td data-label="Nome">{t.name}</td>
                      <td data-label="Severidade">
                        <SeverityText sev={t.severity} />
                      </td>
                      <td data-label="Classe">{IMPACT_LABEL[t.impact_class] ?? t.impact_class}</td>
                      <td data-label="Tecnologias" class="small muted">
                        {t.technologies.slice(0, 4).join(", ") || "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div class="pager">
              <button type="button" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page <= 1 || list.loading}>
                Anterior
              </button>
              <span>
                Página {list.data.page} de {list.data.total_pages}
              </span>
              <button
                type="button"
                onClick={() => setPage((p) => p + 1)}
                disabled={page >= list.data.total_pages || list.loading}
              >
                Próxima
              </button>
            </div>
          </>
        )}
      </section>
    </>
  );
}
