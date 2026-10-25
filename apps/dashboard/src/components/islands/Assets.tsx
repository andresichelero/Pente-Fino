import { useState } from "preact/hooks";
import { api, dateTime, type AssetItem, type Program } from "../../lib/api";
import { useResource } from "../../lib/hooks";
import { Empty, ErrorNotice, Loading } from "../ui";

const SCOPE_LABEL: Record<string, string> = {
  in_scope_explicit: "No escopo (explícito)",
  in_scope_derived: "No escopo (wildcard)",
  candidate: "Candidato",
  out_of_scope: "Fora do escopo",
};

export default function Assets() {
  const programs = useResource(() => api<Program[]>("/api/v1/programs"), []);
  const [slug, setSlug] = useState(
    typeof window !== "undefined" ? new URLSearchParams(window.location.search).get("program") ?? "" : "",
  );
  const [scope, setScope] = useState("");
  const [q, setQ] = useState("");
  const assets = useResource(() => {
    if (!slug) return Promise.resolve(null);
    const qs = new URLSearchParams();
    if (scope) qs.set("scope_state", scope);
    if (q.trim()) qs.set("q", q.trim());
    return api<AssetItem[]>(`/api/v1/programs/${encodeURIComponent(slug)}/assets${qs.toString() ? `?${qs}` : ""}`);
  }, [slug, scope, q]);

  const withAssets = programs.data?.filter((p) => (p.assets_count ?? 0) > 0) ?? [];

  return (
    <>
      <form class="form-row" onSubmit={(e) => e.preventDefault()}>
        <label class="field">
          Programa
          <select value={slug} onChange={(e) => setSlug((e.target as HTMLSelectElement).value)}>
            <option value="">Escolha um programa</option>
            {withAssets.map((p) => (
              <option value={p.slug} key={p.id}>
                {p.name} ({p.assets_count})
              </option>
            ))}
            {programs.data
              ?.filter((p) => !(p.assets_count ?? 0))
              .map((p) => (
                <option value={p.slug} key={p.id}>
                  {p.name} (sem ativos)
                </option>
              ))}
          </select>
        </label>
        <label class="field" style="flex:0 1 200px">
          Escopo
          <select value={scope} onChange={(e) => setScope((e.target as HTMLSelectElement).value)}>
            <option value="">Todos</option>
            {Object.entries(SCOPE_LABEL).map(([k, v]) => (
              <option value={k} key={k}>
                {v}
              </option>
            ))}
          </select>
        </label>
        <label class="field">
          Buscar host
          <input type="search" value={q} onInput={(e) => setQ((e.target as HTMLInputElement).value)} placeholder="api." />
        </label>
      </form>

      {programs.error && <ErrorNotice error={programs.error} onRetry={programs.reload} />}
      {!slug && !programs.error && <Empty>Escolha um programa para ver os ativos descobertos pelo recon.</Empty>}
      {slug && assets.error && <ErrorNotice error={assets.error} onRetry={assets.reload} />}
      {slug && !assets.data && assets.loading && <Loading />}
      {slug && assets.data && assets.data.length === 0 && (
        <Empty>
          Nenhum ativo {scope || q ? "com esse filtro" : "neste programa"}. <a href="/scans">Rodar recon</a>
        </Empty>
      )}
      {slug && assets.data && assets.data.length > 0 && (
        <>
          <p class="muted small">
            {assets.data.length} ativo(s). IPs resolvidos ficam só como observação: nunca viram alvo por conta própria.
          </p>
          <div class="table-wrap">
            <table class="stack">
              <thead>
                <tr>
                  <th>Host</th>
                  <th>Escopo</th>
                  <th>Tecnologias</th>
                  <th class="num">Achados</th>
                  <th>Visto por último</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {assets.data.map((a) => (
                  <tr key={a.id}>
                    <td data-label="Host" class="mono">
                      {a.canonical_key}
                    </td>
                    <td data-label="Escopo">
                      <span class={`tag ${a.scope_state.startsWith("in_scope") ? "accent" : a.scope_state === "out_of_scope" ? "bad" : ""}`}>
                        {SCOPE_LABEL[a.scope_state] ?? a.scope_state}
                      </span>
                    </td>
                    <td data-label="Tecnologias" class="small">
                      {a.technologies?.length ? a.technologies.join(", ") : <span class="muted">sem probe HTTP</span>}
                    </td>
                    <td data-label="Achados" class="num">
                      {a.findings_count ?? 0}
                    </td>
                    <td data-label="Visto por último">{dateTime(a.last_seen)}</td>
                    <td data-label="">
                      {a.scope_state.startsWith("in_scope") && (
                        <a href={`/scans?program=${encodeURIComponent(slug)}&asset=${encodeURIComponent(a.canonical_key)}`}>
                          Planejar scan
                        </a>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </>
  );
}
