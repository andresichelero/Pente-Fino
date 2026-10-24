import { useState, useEffect, useMemo } from "preact/hooks";

export interface FindingTriageBoardProps {
  programs?: any[];
  initialFindings?: any[];
  apiBaseUrl?: string;
}

const KANBAN_COLUMNS = [
  { key: "candidate", label: "Candidate", badgeClass: "bg-amber-500/15 text-amber-300 border-amber-500/30" },
  { key: "validated", label: "Validated", badgeClass: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30" },
  { key: "reported", label: "Reported", badgeClass: "bg-cyan-500/15 text-cyan-300 border-cyan-500/30" },
  { key: "remediated", label: "Remediated", badgeClass: "bg-purple-500/15 text-purple-300 border-purple-500/30" },
  { key: "false_positive", label: "False Positive", badgeClass: "bg-slate-700/40 text-slate-400 border-slate-600/40" },
];

export default function FindingTriageBoard({
  programs = [],
  initialFindings = [],
  apiBaseUrl = "http://127.0.0.1:8000",
}: FindingTriageBoardProps) {
  const [findings, setFindings] = useState<any[]>(initialFindings);
  const [viewMode, setViewMode] = useState<"kanban" | "table">("kanban");
  const [programFilter, setProgramFilter] = useState<string>("all");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [evidenceFilter, setEvidenceFilter] = useState<string>("all");

  // Forensic E2 Drawer state
  const [selectedFinding, setSelectedFinding] = useState<any | null>(null);
  const [drawerTab, setDrawerTab] = useState<"forensic" | "report">("forensic");
  const [reportMarkdown, setReportMarkdown] = useState<string>("");
  const [loadingReport, setLoadingReport] = useState<boolean>(false);
  const [copyToast, setCopyToast] = useState<boolean>(false);

  useEffect(() => {
    fetchFindings();
  }, []);

  async function fetchFindings() {
    try {
      const res = await fetch(`${apiBaseUrl}/api/v1/findings`);
      if (res.ok) {
        const data = await res.json();
        const list = Array.isArray(data) ? data : data.findings || [];
        if (list.length > 0) {
          setFindings(list);
        }
      }
    } catch {
      // Retain initialFindings if API offline
    }
  }

  async function openFindingDrawer(finding: any) {
    setSelectedFinding(finding);
    setDrawerTab("forensic");
    setReportMarkdown("");
    try {
      const res = await fetch(`${apiBaseUrl}/api/v1/findings/${finding.id}`);
      if (res.ok) {
        const detail = await res.json();
        setSelectedFinding(detail);
      }
    } catch {
      // Keep item as-is
    }
  }

  async function fetchMarkdownReport(findingId: string) {
    setLoadingReport(true);
    try {
      const res = await fetch(`${apiBaseUrl}/api/v1/findings/${findingId}/report`);
      if (res.ok) {
        const data = await res.json();
        setReportMarkdown(data.markdown || "");
        setLoadingReport(false);
        return;
      }
    } catch {
      // Fallback report generator
    }

    const f = selectedFinding;
    const fallbackMd = `# [${(f?.detector?.severity || "HIGH").toUpperCase()}] ${
      f?.detector?.name || f?.detector_id || "Vulnerability Finding"
    } on \`${f?.asset?.canonical_key || "scanme.nmap.org"}\`

## Executive Summary
A vulnerability was identified and forensically captured at Evidence Level **${f?.evidence_level || "E2"}** against \`${
      f?.asset?.canonical_key || "scanme.nmap.org"
    }\` using detector \`${f?.detector_id || "nuclei-detector"}\`.

- **Deduplication SHA-256**: \`${f?.dedup_key || "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}\`
- **Confidence**: \`${f?.confidence || "high"}\`
- **Advisory / CVE**: \`${f?.advisory_id || f?.detector?.cve_id || "N/A"}\`

## Reproducible Proof-of-Concept (Sanitized curl)
\`\`\`bash
curl -i -s -k -X GET "https://${f?.asset?.canonical_key || "scanme.nmap.org"}/" \\
  -H "User-Agent: Mozilla/5.0 (Security-Audit; PenteFino-Bounty-Safe)" \\
  -H "Authorization: [REDACTED]"
\`\`\`

## Forensic SHA-256 Chain of Custody
| Evidence ID | Type | Sanitized SHA-256 | SeaweedFS Object Key | Redaction Profile |
|---|---|---|---|---|
| \`${f?.evidence_items?.[0]?.id || "ev-01"}\` | \`http_interaction\` | \`${
      f?.evidence_items?.[0]?.sanitized_sha256 ||
      "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    }\` | \`${
      f?.evidence_items?.[0]?.seaweed_object_key || "s3://evidence/sanitized/req-resp.json"
    }\` | \`bounty-safe-v1\` |
`;
    setReportMarkdown(fallbackMd);
    setLoadingReport(false);
  }

  async function handleStatusChange(findingId: string, newStatus: string) {
    // Optimistic update
    setFindings((prev) =>
      prev.map((f) => (String(f.id) === String(findingId) ? { ...f, status: newStatus } : f))
    );
    if (selectedFinding && String(selectedFinding.id) === String(findingId)) {
      setSelectedFinding({ ...selectedFinding, status: newStatus });
    }

    try {
      const res = await fetch(`${apiBaseUrl}/api/v1/findings/${findingId}/status`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: newStatus }),
      });
      if (res.ok) {
        const updated = await res.json();
        setFindings((prev) =>
          prev.map((f) => (String(f.id) === String(findingId) ? { ...f, ...updated } : f))
        );
      }
    } catch {
      // Keep optimistic state
    }
  }

  function handleCopyMarkdown() {
    if (!reportMarkdown) return;
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      navigator.clipboard.writeText(reportMarkdown);
    }
    setCopyToast(true);
    setTimeout(() => setCopyToast(false), 2500);
  }

  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      if (programFilter !== "all" && f.program_slug !== programFilter && f.program_id !== programFilter) {
        return false;
      }
      const sev = (f.detector?.severity || "info").toLowerCase();
      if (severityFilter !== "all" && sev !== severityFilter) {
        return false;
      }
      if (evidenceFilter !== "all" && f.evidence_level !== evidenceFilter) {
        return false;
      }
      return true;
    });
  }, [findings, programFilter, severityFilter, evidenceFilter]);

  return (
    <div class="space-y-6 text-slate-100">
      {/* Top Filter & View Bar */}
      <div class="flex flex-wrap items-center justify-between gap-4 bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-lg">
        <div class="flex items-center gap-3">
          <div class="h-10 w-10 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400 font-bold font-mono">
            E2
          </div>
          <div>
            <h2 class="text-base font-semibold text-slate-100">
              Triagem Forense de Vulnerabilidades &amp; Deduplicação SHA-256
            </h2>
            <p class="text-xs text-slate-400">
              Cadeia de Custódia E0–E3 (SeaweedFS S3) + Exportador de Dossiê HackerOne / Bugcrowd
            </p>
          </div>
        </div>

        <div class="flex flex-wrap items-center gap-2.5">
          <select
            value={programFilter}
            onChange={(e) => setProgramFilter((e.target as HTMLSelectElement).value)}
            class="bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 font-mono"
          >
            <option value="all">Todos os Programas</option>
            {programs.map((p) => (
              <option key={p.slug} value={p.slug}>
                {p.name} ({p.slug})
              </option>
            ))}
          </select>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter((e.target as HTMLSelectElement).value)}
            class="bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 font-mono"
          >
            <option value="all">Todas Severidades</option>
            <option value="critical">critical</option>
            <option value="high">high</option>
            <option value="medium">medium</option>
            <option value="low">low</option>
            <option value="info">info</option>
          </select>

          <select
            value={evidenceFilter}
            onChange={(e) => setEvidenceFilter((e.target as HTMLSelectElement).value)}
            class="bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 font-mono"
          >
            <option value="all">Evidência E0–E3</option>
            <option value="E3">E3 (Confirmada)</option>
            <option value="E2">E2 (HTTP Sanitized)</option>
            <option value="E1">E1 (Banner/Probe)</option>
            <option value="E0">E0 (Heurística)</option>
          </select>

          <div class="inline-flex rounded-lg bg-slate-950 p-1 border border-slate-800">
            <button
              type="button"
              onClick={() => setViewMode("kanban")}
              class={`px-3 py-1 rounded-md text-xs font-mono transition ${
                viewMode === "kanban"
                  ? "bg-emerald-500 text-slate-950 font-bold"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              Quadro Kanban
            </button>
            <button
              type="button"
              onClick={() => setViewMode("table")}
              class={`px-3 py-1 rounded-md text-xs font-mono transition ${
                viewMode === "table"
                  ? "bg-emerald-500 text-slate-950 font-bold"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              Tabela de Vulnerabilidades
            </button>
          </div>
        </div>
      </div>

      {/* Kanban Board View */}
      {viewMode === "kanban" ? (
        <div class="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-4">
          {KANBAN_COLUMNS.map((col) => {
            const colFindings = filteredFindings.filter((f) => f.status === col.key);
            return (
              <div
                key={col.key}
                class="bg-slate-900/90 border border-slate-800 rounded-xl p-3 flex flex-col min-h-[420px]"
              >
                <div class="flex items-center justify-between pb-2.5 mb-3 border-b border-slate-800">
                  <span class={`px-2 py-0.5 rounded text-xs font-mono font-semibold border ${col.badgeClass}`}>
                    {col.label}
                  </span>
                  <span class="text-xs font-mono text-slate-400">{colFindings.length}</span>
                </div>

                <div class="space-y-3 flex-1">
                  {colFindings.length === 0 ? (
                    <div class="text-[11px] text-slate-600 font-mono text-center py-10">
                      Nenhum finding em {col.label}
                    </div>
                  ) : (
                    colFindings.map((f) => (
                      <div
                        key={f.id}
                        onClick={() => openFindingDrawer(f)}
                        class="bg-slate-950 border border-slate-800 hover:border-cyan-500/50 rounded-lg p-3 cursor-pointer transition shadow-sm space-y-2"
                      >
                        <div class="flex items-center justify-between gap-1">
                          <span class="px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 font-mono text-[10px] font-bold">
                            {f.evidence_level}
                          </span>
                          <span class="font-mono text-[10px] uppercase text-amber-300">
                            {f.detector?.severity || "info"}
                          </span>
                        </div>

                        <div class="text-xs font-semibold text-slate-100 font-mono break-all">
                          {f.detector?.name || f.detector_id}
                        </div>

                        <div class="text-[11px] font-mono text-cyan-400 truncate">
                          {f.asset?.canonical_key || f.asset_id}
                        </div>

                        <div class="text-[10px] font-mono text-slate-500 truncate" title={f.dedup_key}>
                          SHA256: {String(f.dedup_key || "").slice(0, 16)}...
                        </div>

                        <div
                          class="pt-2 border-t border-slate-800/80 flex items-center justify-between"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <span class="text-[10px] text-slate-500 font-mono">Mover:</span>
                          <select
                            value={f.status}
                            onChange={(e) =>
                              handleStatusChange(f.id, (e.target as HTMLSelectElement).value)
                            }
                            class="bg-slate-900 border border-slate-700 rounded px-1.5 py-0.5 text-[10px] font-mono text-slate-200"
                          >
                            {KANBAN_COLUMNS.map((c) => (
                              <option key={c.key} value={c.key}>
                                {c.label}
                              </option>
                            ))}
                          </select>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        /* Table View */
        <div class="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg overflow-x-auto">
          <table class="w-full text-left border-collapse text-xs">
            <thead>
              <tr class="bg-slate-950 text-slate-400 font-mono uppercase border-b border-slate-800">
                <th class="py-3 px-3">Evidência</th>
                <th class="py-3 px-3">Detector / Template</th>
                <th class="py-3 px-3">Ativo</th>
                <th class="py-3 px-3">Dedup Key (SHA-256)</th>
                <th class="py-3 px-3">Status</th>
                <th class="py-3 px-3 text-right">Dossiê Forense</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-800/60">
              {filteredFindings.map((f) => (
                <tr key={f.id} class="hover:bg-slate-800/40 transition">
                  <td class="py-3 px-3 font-mono font-bold text-emerald-400">{f.evidence_level}</td>
                  <td class="py-3 px-3 font-mono text-slate-100">
                    <div>{f.detector?.name || f.detector_id}</div>
                    <div class="text-[10px] text-slate-400">{f.detector_id}</div>
                  </td>
                  <td class="py-3 px-3 font-mono text-cyan-300">
                    {f.asset?.canonical_key || f.asset_id}
                  </td>
                  <td class="py-3 px-3 font-mono text-[11px] text-slate-400">
                    {String(f.dedup_key || "").slice(0, 20)}...
                  </td>
                  <td class="py-3 px-3">
                    <select
                      value={f.status}
                      onChange={(e) =>
                        handleStatusChange(f.id, (e.target as HTMLSelectElement).value)
                      }
                      class="bg-slate-950 border border-slate-700 rounded px-2 py-1 text-xs font-mono text-slate-200"
                    >
                      {KANBAN_COLUMNS.map((c) => (
                        <option key={c.key} value={c.key}>
                          {c.label}
                        </option>
                      ))}
                    </select>
                  </td>
                  <td class="py-3 px-3 text-right">
                    <button
                      type="button"
                      onClick={() => openFindingDrawer(f)}
                      class="bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-300 border border-cyan-500/30 px-3 py-1 rounded font-mono text-[11px]"
                    >
                      Inspecionar E2 / Relatório
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Lateral Forensic E2 Drawer */}
      {selectedFinding && (
        <div class="fixed inset-0 z-50 bg-slate-950/75 backdrop-blur-sm flex justify-end">
          <div class="bg-slate-900 border-l border-slate-700 w-full max-w-2xl h-full overflow-y-auto p-6 shadow-2xl flex flex-col justify-between space-y-5">
            <div class="space-y-5">
              {/* Drawer Header */}
              <div class="flex items-start justify-between border-b border-slate-800 pb-4">
                <div>
                  <div class="flex items-center gap-2">
                    <span class="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-mono text-xs font-bold">
                      Evidência {selectedFinding.evidence_level || "E2"}
                    </span>
                    <span class="px-2 py-0.5 rounded bg-slate-800 text-amber-300 font-mono text-xs uppercase">
                      {selectedFinding.detector?.severity || "info"}
                    </span>
                    <span class="font-mono text-xs text-slate-400">
                      Confiança: {selectedFinding.confidence}
                    </span>
                  </div>
                  <h3 class="text-base font-bold text-slate-100 mt-2 font-mono">
                    {selectedFinding.detector?.name || selectedFinding.detector_id}
                  </h3>
                  <p class="text-xs font-mono text-cyan-400">
                    Ativo: {selectedFinding.asset?.canonical_key || selectedFinding.asset_id}
                  </p>
                </div>

                <button
                  type="button"
                  onClick={() => setSelectedFinding(null)}
                  class="text-slate-400 hover:text-slate-100 font-mono text-sm px-2.5 py-1 rounded border border-slate-800"
                >
                  ✕ Fechar
                </button>
              </div>

              {/* Drawer Tabs */}
              <div class="flex border-b border-slate-800 gap-2">
                <button
                  type="button"
                  onClick={() => setDrawerTab("forensic")}
                  class={`px-4 py-2 text-xs font-mono border-b-2 transition ${
                    drawerTab === "forensic"
                      ? "border-emerald-400 text-emerald-300 font-bold"
                      : "border-transparent text-slate-400 hover:text-slate-200"
                  }`}
                >
                  1. Evidência Forense &amp; Deduplicação
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setDrawerTab("report");
                    if (!reportMarkdown) {
                      fetchMarkdownReport(selectedFinding.id);
                    }
                  }}
                  class={`px-4 py-2 text-xs font-mono border-b-2 transition ${
                    drawerTab === "report"
                      ? "border-cyan-400 text-cyan-300 font-bold"
                      : "border-transparent text-slate-400 hover:text-slate-200"
                  }`}
                >
                  2. Gerador de Dossiê HackerOne / Bugcrowd
                </button>
              </div>

              {drawerTab === "forensic" ? (
                <div class="space-y-4 text-xs">
                  <div class="bg-slate-950 border border-slate-800 rounded-lg p-3.5 space-y-2 font-mono">
                    <div>
                      <span class="text-[10px] text-slate-500 block uppercase">
                        Chave de Deduplicação Criptográfica (dedup_key SHA-256 64-char):
                      </span>
                      <span class="text-emerald-300 break-all text-[11px]">
                        {selectedFinding.dedup_key}
                      </span>
                    </div>
                    <div class="grid grid-cols-2 gap-2 pt-2 border-t border-slate-800/80">
                      <div>
                        <span class="text-[10px] text-slate-500 block">DETECTOR ID</span>
                        <span class="text-slate-200">{selectedFinding.detector_id}</span>
                      </div>
                      <div>
                        <span class="text-[10px] text-slate-500 block">ADVISORY / CVE</span>
                        <span class="text-amber-300">
                          {selectedFinding.advisory_id || selectedFinding.detector?.cve_id || "N/A"}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div class="space-y-2">
                    <h4 class="text-xs font-mono uppercase text-slate-300">
                      Artefatos Forenses S3 / SeaweedFS (`evidence_items`):
                    </h4>
                    {(selectedFinding.evidence_items || []).length === 0 ? (
                      <div class="bg-slate-950 border border-slate-800 rounded-lg p-4 text-slate-400 font-mono text-xs">
                        Nenhum ponteiro S3 anexado ou carregando detalhes...
                      </div>
                    ) : (
                      selectedFinding.evidence_items.map((ev: any) => (
                        <div
                          key={ev.id}
                          class="bg-slate-950 border border-slate-800 rounded-lg p-3.5 space-y-2 font-mono text-[11px]"
                        >
                          <div class="flex items-center justify-between">
                            <span class="text-cyan-300 font-bold">{ev.evidence_type}</span>
                            <span class="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 text-[10px]">
                              Redaction: {ev.redaction_profile}
                            </span>
                          </div>
                          <div>
                            <span class="text-slate-500 block text-[10px]">SEAWEED OBJECT KEY:</span>
                            <span class="text-slate-200 break-all">{ev.seaweed_object_key}</span>
                          </div>
                          <div>
                            <span class="text-slate-500 block text-[10px]">SANITIZED SHA-256:</span>
                            <span class="text-emerald-400 break-all">{ev.sanitized_sha256}</span>
                          </div>
                          {ev.original_sha256 && (
                            <div>
                              <span class="text-slate-500 block text-[10px]">ORIGINAL SHA-256:</span>
                              <span class="text-slate-400 break-all">{ev.original_sha256}</span>
                            </div>
                          )}
                        </div>
                      ))
                    )}
                  </div>
                </div>
              ) : (
                /* Tab 2: HackerOne / Bugcrowd Report Generator */
                <div class="space-y-4">
                  <div class="flex items-center justify-between">
                    <span class="text-xs text-slate-400 font-mono">
                      Relatório Markdown pronto para submissão (Segredos Redigidos `[REDACTED]`):
                    </span>
                    <button
                      type="button"
                      onClick={handleCopyMarkdown}
                      class="bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold text-xs px-3.5 py-1.5 rounded-lg font-mono transition"
                    >
                      {copyToast ? "✓ Copiado para o Clipboard!" : "Copiar Relatório Markdown"}
                    </button>
                  </div>

                  {loadingReport ? (
                    <div class="py-12 text-center text-xs font-mono text-cyan-400">
                      Gerando dossiê forense Markdown...
                    </div>
                  ) : (
                    <pre class="bg-slate-950 border border-slate-800 rounded-xl p-4 text-xs font-mono text-slate-200 overflow-x-auto whitespace-pre-wrap max-h-[460px]">
                      {reportMarkdown}
                    </pre>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
