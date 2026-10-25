import { useState } from "preact/hooks";
import { api, ApiError, del, post, type Program, type ScopeDecision, type ScopeRule } from "../../lib/api";
import { useResource } from "../../lib/hooks";
import { Empty, ErrorNotice, Loading } from "../ui";

function initialSlug(): string {
  if (typeof window === "undefined") return "";
  return new URLSearchParams(window.location.search).get("program") ?? "";
}

export default function ProgramsScope() {
  const programs = useResource(() => api<Program[]>("/api/v1/programs"), []);
  const [slug, setSlug] = useState(initialSlug());
  const rules = useResource(
    () => (slug ? api<ScopeRule[]>(`/api/v1/programs/${encodeURIComponent(slug)}/scope`) : Promise.resolve([])),
    [slug],
  );
  const [actionError, setActionError] = useState<ApiError | null>(null);
  const [decision, setDecision] = useState<ScopeDecision | null>(null);
  const [busy, setBusy] = useState(false);

  const select = (s: string) => {
    setSlug(s);
    setDecision(null);
    setActionError(null);
    const url = new URL(window.location.href);
    url.searchParams.set("program", s);
    window.history.replaceState(null, "", url);
  };

  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setActionError(null);
    try {
      await fn();
    } catch (e) {
      setActionError(e instanceof ApiError ? e : new ApiError("server", 0, String(e)));
    } finally {
      setBusy(false);
    }
  };

  const createProgram = (ev: Event) => {
    ev.preventDefault();
    const fd = new FormData(ev.target as HTMLFormElement);
    run(async () => {
      const created = await post<Program>("/api/v1/programs", {
        slug: String(fd.get("slug")).trim(),
        name: String(fd.get("name")).trim(),
        platform: String(fd.get("platform")),
      });
      (ev.target as HTMLFormElement).reset();
      programs.reload();
      select(created.slug);
    });
  };

  const addRule = (ev: Event) => {
    ev.preventDefault();
    const fd = new FormData(ev.target as HTMLFormElement);
    const pattern = String(fd.get("pattern")).trim();
    run(async () => {
      await post(`/api/v1/programs/${encodeURIComponent(slug)}/scope`, {
        pattern,
        action: String(fd.get("action")),
        asset_type: pattern.startsWith("*.") ? "wildcard_domain" : String(fd.get("asset_type")),
      });
      (ev.target as HTMLFormElement).reset();
      rules.reload();
    });
  };

  const removeRule = (rule: ScopeRule) => {
    if (!window.confirm(`Remover a regra ${rule.action} ${rule.pattern}?`)) return;
    run(async () => {
      await del(`/api/v1/programs/${encodeURIComponent(slug)}/scope/${rule.id}`);
      rules.reload();
    });
  };

  const evaluate = (ev: Event) => {
    ev.preventDefault();
    const target = String(new FormData(ev.target as HTMLFormElement).get("target")).trim();
    run(async () => {
      setDecision(await post<ScopeDecision>(`/api/v1/programs/${encodeURIComponent(slug)}/scope/evaluate`, { target }));
    });
  };

  const current = programs.data?.find((p) => p.slug === slug);

  return (
    <>
      <section class="section" aria-labelledby="h-programs">
        <div class="section-head">
          <h2 id="h-programs">Programas</h2>
          <span class="meta">{programs.data ? `${programs.data.length} cadastrados` : ""}</span>
        </div>
        {programs.error && <ErrorNotice error={programs.error} onRetry={programs.reload} />}
        {!programs.data && programs.loading && <Loading />}
        {programs.data && programs.data.length === 0 && (
          <Empty>Nenhum programa ainda. Crie o primeiro no formulário abaixo.</Empty>
        )}
        {programs.data && programs.data.length > 0 && (
          <div class="table-wrap">
            <table class="stack">
              <thead>
                <tr>
                  <th>Programa</th>
                  <th>Plataforma</th>
                  <th class="num">Regras</th>
                  <th class="num">Autorizações</th>
                  <th class="num">Ativos</th>
                  <th class="num">Achados</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {programs.data.map((p) => (
                  <tr key={p.id} aria-current={p.slug === slug ? "true" : undefined}>
                    <td data-label="Programa">
                      <strong>{p.name}</strong>
                      <div class="mono muted small">{p.slug}</div>
                    </td>
                    <td data-label="Plataforma">{p.platform}</td>
                    <td data-label="Regras" class="num">
                      {p.scope_rules_count ?? "—"}
                    </td>
                    <td data-label="Autorizações" class="num">
                      {p.snapshots_count === 0 ? <span class="tag warn">nenhuma</span> : p.snapshots_count ?? "—"}
                    </td>
                    <td data-label="Ativos" class="num">
                      {p.assets_count ?? "—"}
                    </td>
                    <td data-label="Achados" class="num">
                      {p.findings_count ?? "—"}
                    </td>
                    <td data-label="">
                      <button type="button" onClick={() => select(p.slug)} disabled={p.slug === slug}>
                        {p.slug === slug ? "Selecionado" : "Ver escopo"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <form class="form-row" style="margin-top:16px" onSubmit={createProgram}>
          <label class="field">
            Slug
            <input name="slug" required pattern="[a-z0-9][a-z0-9-]{1,62}" placeholder="meu-programa" />
          </label>
          <label class="field">
            Nome
            <input name="name" required placeholder="Nome do programa" />
          </label>
          <label class="field" style="flex:0 1 160px">
            Plataforma
            <select name="platform">
              <option value="hackerone">HackerOne</option>
              <option value="bugcrowd">Bugcrowd</option>
              <option value="intigriti">Intigriti</option>
              <option value="private">Privado</option>
              <option value="lab">Laboratório</option>
            </select>
          </label>
          <button type="submit" class="primary" disabled={busy}>
            Criar programa
          </button>
        </form>
      </section>

      {actionError && (
        <div class="banner">
          <ErrorNotice error={actionError} />
        </div>
      )}

      {slug && (
        <div class="grid-2 wide-left">
          <section class="section" aria-labelledby="h-rules">
            <div class="section-head">
              <h2 id="h-rules">Escopo de {current?.name ?? slug}</h2>
              <span class="meta">deny sempre vence allow</span>
            </div>
            {current?.snapshots_count === 0 && (
              <div class="notice warn banner">
                <strong>Sem autorização registrada.</strong> Recon e scans são recusados até registrar uma:
                <span class="mono"> pentefino auth register --program {slug} --rules-file …</span>
              </div>
            )}
            {rules.error && <ErrorNotice error={rules.error} onRetry={rules.reload} />}
            {!rules.data && rules.loading && <Loading />}
            {rules.data && rules.data.length === 0 && (
              <Empty>Sem regras: todo alvo é negado (padrão fail-closed). Adicione uma regra de allow.</Empty>
            )}
            {rules.data && rules.data.length > 0 && (
              <div class="table-wrap">
                <table class="stack">
                  <thead>
                    <tr>
                      <th>Ação</th>
                      <th>Padrão</th>
                      <th>Tipo</th>
                      <th>Restrições</th>
                      <th />
                    </tr>
                  </thead>
                  <tbody>
                    {rules.data.map((r) => (
                      <tr key={r.id}>
                        <td data-label="Ação">
                          <span class={`tag ${r.action === "deny" ? "bad" : "accent"}`}>{r.action}</span>
                        </td>
                        <td data-label="Padrão" class="mono">
                          {r.pattern}
                        </td>
                        <td data-label="Tipo">{r.asset_type}</td>
                        <td data-label="Restrições" class="small muted">
                          {[
                            r.allowed_ports?.length ? `portas ${r.allowed_ports.join(",")}` : "",
                            r.denied_paths?.length ? `nega ${r.denied_paths.join(", ")}` : "",
                          ]
                            .filter(Boolean)
                            .join(" · ") || "—"}
                        </td>
                        <td data-label="">
                          <button type="button" class="danger" onClick={() => removeRule(r)} disabled={busy}>
                            Remover
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <form class="form-row" style="margin-top:16px" onSubmit={addRule}>
              <label class="field" style="flex:0 1 110px">
                Ação
                <select name="action">
                  <option value="allow">allow</option>
                  <option value="deny">deny</option>
                </select>
              </label>
              <label class="field">
                Padrão
                <input name="pattern" required placeholder="*.exemplo.com ou app.exemplo.com" />
              </label>
              <label class="field" style="flex:0 1 150px">
                Tipo
                <select name="asset_type">
                  <option value="domain">domínio</option>
                  <option value="hostname">hostname</option>
                  <option value="url">URL</option>
                  <option value="ip">IP</option>
                  <option value="cidr">CIDR</option>
                </select>
              </label>
              <button type="submit" disabled={busy}>
                Adicionar regra
              </button>
            </form>
          </section>

          <section class="section" aria-labelledby="h-eval">
            <div class="section-head">
              <h2 id="h-eval">Testar um alvo</h2>
              <span class="meta">só avaliação, nada é acessado</span>
            </div>
            <form class="form-row" onSubmit={evaluate}>
              <label class="field">
                URL ou host
                <input name="target" required placeholder="https://app.exemplo.com/admin" />
              </label>
              <button type="submit" class="primary" disabled={busy}>
                Avaliar
              </button>
            </form>
            {decision && (
              <div class={`notice ${decision.allowed ? "" : "error"}`} role="status">
                <strong>{decision.allowed ? "Permitido" : "Negado"}</strong> — {decision.precedence_tier}
                <dl class="kv" style="margin-top:8px">
                  <dt>Alvo canônico</dt>
                  <dd class="mono">{decision.target_canonical}</dd>
                  <dt>Motivo</dt>
                  <dd>{decision.reason}</dd>
                  <dt>Regra</dt>
                  <dd class="mono">{decision.matched_pattern ?? "nenhuma"}</dd>
                </dl>
              </div>
            )}
          </section>
        </div>
      )}
    </>
  );
}
