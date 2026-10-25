import { useState } from "preact/hooks";
import { api, ApiError, dateTime, patch, type FindingItem, type Program } from "../../lib/api";
import { useResource } from "../../lib/hooks";
import { Empty, ErrorNotice, Loading, SeverityText } from "../ui";

const STATUS_LABEL: Record<string, string> = {
  candidate: "Candidato",
  validated: "Validado",
  reported: "Reportado",
  accepted: "Aceito",
  remediated: "Corrigido",
  resolved: "Resolvido",
  false_positive: "Falso positivo",
  reopened: "Reaberto",
};
// Status transitions offered in the UI; the API enforces the real state machine.
const NEXT: Record<string, string[]> = {
  candidate: ["validated", "false_positive"],
  validated: ["reported", "false_positive"],
  reported: ["accepted", "resolved"],
  accepted: ["remediated", "resolved"],
  remediated: ["resolved", "reopened"],
  resolved: ["reopened"],
  false_positive: ["reopened"],
  reopened: ["validated", "false_positive"],
};
const OPEN = new Set(["candidate", "validated", "reopened"]);

export default function Findings() {
  const programs = useResource(() => api<Program[]>("/api/v1/programs"), []);
  const [program, setProgram] = useState(q("program"));
  const [status, setStatus] = useState("open");
  const [severity, setSeverity] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [actionError, setActionError] = useState<ApiError | null>(null);

  const findings = useResource(() => {
    const p = new URLSearchParams();
    if (program) p.set("program_slug", program);
    if (status && status !== "open") p.set("status", status);
    if (severity) p.set("severity", severity);
    return api<FindingItem[]>(`/api/v1/findings${p.toString() ? `?${p}` : ""}`);
  }, [program, status, severity]);

  const shown = (findings.data ?? []).filter((f) => (status === "open" ? OPEN.has(f.status) : true));

  const move = (f: FindingItem, to: string) => {
    setBusy(f.id);
    setActionError(null);
    patch(`/api/v1/findings/${f.id}/status`, { status: to })
      .then(() => findings.reload())
      .catch((e) => setActionError(e instanceof ApiError ? e : new ApiError("server", 0, String(e))))
      .finally(() => setBusy(null));
  };

  return (
    <>
      <form class="form-row" onSubmit={(e) => e.preventDefault()}>
        <label class="field" style="flex:0 1 240px">
          Programa
          <select value={program} onChange={(e) => setProgram((e.target as HTMLSelectElement).value)}>
            <option value="">Todos</option>
            {programs.data
              ?.filter((p) => (p.findings_count ?? 0) > 0)
              .map((p) => (
                <option value={p.slug} key={p.id}>
                  {p.name} ({p.findings_count})
                </option>
              ))}
          </select>
        </label>
        <label class="field" style="flex:0 1 180px">
          Estado
          <select value={status} onChange={(e) => setStatus((e.target as HTMLSelectElement).value)}>
            <option value="open">Abertos (triagem)</option>
            <option value="">Todos</option>
            {Object.entries(STATUS_LABEL).map(([k, v]) => (
              <option value={k} key={k}>
                {v}
              </option>
            ))}
          </select>
        </label>
        <label class="field" style="flex:0 1 160px">
          Severidade
          <select value={severity} onChange={(e) => setSeverity((e.target as HTMLSelectElement).value)}>
            <option value="">Todas</option>
            {["critical", "high", "medium", "low", "info"].map((s) => (
              <option value={s} key={s}>
                {s}
              </option>
            ))}
          </select>
        </label>
      </form>

      {actionError && (
        <div class="banner">
          <ErrorNotice error={actionError} />
        </div>
      )}
      {findings.error && <ErrorNotice error={findings.error} onRetry={findings.reload} />}
      {!findings.data && findings.loading && <Loading />}
      {findings.data && shown.length === 0 && (
        <Empty>
          {status === "open"
            ? "Nada aguardando triagem. Tudo que foi encontrado já foi classificado."
            : "Nenhum achado com esse filtro."}
        </Empty>
      )}
      {shown.length > 0 && (
        <div class="table-wrap">
          <table class="stack">
            <thead>
              <tr>
                <th>Severidade</th>
                <th>Detector</th>
                <th>Ativo</th>
                <th>Evidência</th>
                <th>Estado</th>
                <th>Visto</th>
                <th>Ações</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((f) => (
                <tr key={f.id}>
                  <td data-label="Severidade">
                    <SeverityText sev={f.detector?.severity} />
                    {f.in_cisa_kev && <span class="tag bad" style="margin-left:6px">KEV</span>}
                  </td>
                  <td data-label="Detector">
                    <div>{f.detector?.name ?? f.detector_id}</div>
                    <div class="mono small muted">{f.detector?.cve_id ?? f.detector_id}</div>
                  </td>
                  <td data-label="Ativo" class="mono small">
                    {f.asset?.canonical_key ?? "—"}
                  </td>
                  <td data-label="Evidência">
                    {f.evidence_level}
                    <span class="muted small"> · {f.confidence}</span>
                  </td>
                  <td data-label="Estado">
                    <span class={`tag ${OPEN.has(f.status) ? "accent" : ""}`}>{STATUS_LABEL[f.status] ?? f.status}</span>
                  </td>
                  <td data-label="Visto" class="small">
                    {dateTime(f.first_seen)}
                  </td>
                  <td data-label="Ações">
                    <div style="display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end">
                      {(NEXT[f.status] ?? []).map((to) => (
                        <button
                          type="button"
                          key={to}
                          class={to === "false_positive" ? "danger" : to === "validated" || to === "reported" ? "primary" : ""}
                          disabled={busy === f.id}
                          onClick={() => move(f, to)}
                        >
                          {STATUS_LABEL[to]}
                        </button>
                      ))}
                      <a href={`${import.meta.env.PUBLIC_API_URL ?? "http://127.0.0.1:8000"}/api/v1/findings/${f.id}/report`} target="_blank" rel="noreferrer">
                        Relatório
                      </a>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

function q(name: string): string {
  return typeof window === "undefined" ? "" : new URLSearchParams(window.location.search).get(name) ?? "";
}
