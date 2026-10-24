import { useState, useEffect, useMemo } from "preact/hooks";

export interface FindingTriageBoardProps {
  programs?: any[];
  initialFindings?: any[];
  apiBaseUrl?: string;
}

const KANBAN_COLUMNS = [
  { key: "candidate", label: "Candidate", pillClass: "pill-amber" },
  { key: "validated", label: "Validated", pillClass: "pill-emerald" },
  { key: "reported", label: "Reported", pillClass: "pill-cyan" },
  { key: "remediated", label: "Remediated", pillClass: "pill-purple" },
  { key: "false_positive", label: "False Positive", pillClass: "pill-neutral" },
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
  const [loadingDetail, setLoadingDetail] = useState<boolean>(false);
  const [drawerTab, setDrawerTab] = useState<"forensic" | "report">("forensic");
  const [reportMarkdown, setReportMarkdown] = useState<string>("");
  const [loadingReport, setLoadingReport] = useState<boolean>(false);
  const [copyToast, setCopyToast] = useState<boolean>(false);

  useEffect(() => {
    if (!initialFindings || initialFindings.length === 0) {
      fetchFindings();
    }
  }, []);

  async function fetchFindings() {
    try {
      const res = await fetch(`${apiBaseUrl}/api/v1/findings`);
      if (res.ok) {
        const data = await res.json();
        const list = Array.isArray(data) ? data : data.findings || [];
        setFindings(list);
      } else {
        setFindings([]);
      }
    } catch {
      setFindings([]);
    }
  }

  async function openFindingDrawer(finding: any) {
    setSelectedFinding(finding);
    setDrawerTab("forensic");
    setReportMarkdown("");
    setLoadingDetail(true);
    try {
      const res = await fetch(`${apiBaseUrl}/api/v1/findings/${finding.id}`);
      if (res.ok) {
        const detail = await res.json();
        setSelectedFinding(detail);
      }
    } catch {
      // Keep item as-is
    } finally {
      setLoadingDetail(false);
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

    setReportMarkdown("Não foi possível carregar o relatório forense. O serviço de API está indisponível.");
    setLoadingReport(false);
  }

  async function handleStatusChange(findingId: string, newStatus: string) {
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

  function handleDownloadMarkdown() {
    if (!reportMarkdown || typeof document === "undefined") return;
    const slug = (selectedFinding?.detector_id || "finding").replace(/[^a-zA-Z0-9_-]/g, "_");
    const blob = new Blob([reportMarkdown], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `pentefino-e2-report-${slug}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
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
    <div class="space-y-3">
      {/* Top Filter & Segmented View Bar */}
      <div class="card card-pad flex flex-wrap items-center justify-between gap-2.5">
        <div class="flex flex-wrap items-center gap-2">
          <select
            value={programFilter}
            onChange={(e) => setProgramFilter((e.target as HTMLSelectElement).value)}
            class="input !w-auto"
          >
            <option value="all">All Programs</option>
            {programs.map((p) => (
              <option key={p.slug} value={p.slug}>
                {p.name} ({p.slug})
              </option>
            ))}
          </select>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter((e.target as HTMLSelectElement).value)}
            class="input !w-auto"
          >
            <option value="all">All Severities</option>
            <option value="critical">critical</option>
            <option value="high">high</option>
            <option value="medium">medium</option>
            <option value="low">low</option>
            <option value="info">info</option>
          </select>

          <div class="seg">
            {["all", "E3", "E2", "E1", "E0"].map((ev) => (
              <button
                key={ev}
                type="button"
                onClick={() => setEvidenceFilter(ev)}
                class={`seg-btn ${evidenceFilter === ev ? "active" : ""}`}
              >
                {ev === "all" ? "All E0–E3" : ev}
              </button>
            ))}
          </div>
        </div>

        <div class="flex items-center gap-2">
          <span class="text-[11px] font-mono text-[#7d8590] num">
            {filteredFindings.length} findings
          </span>
          <div class="seg">
            <button
              type="button"
              onClick={() => setViewMode("kanban")}
              class={`seg-btn ${viewMode === "kanban" ? "active" : ""}`}
            >
              Kanban
            </button>
            <button
              type="button"
              onClick={() => setViewMode("table")}
              class={`seg-btn ${viewMode === "table" ? "active" : ""}`}
            >
              Table
            </button>
          </div>
        </div>
      </div>

      {/* Empty State Banner */}
      {filteredFindings.length === 0 && (
        <div class="card card-pad py-8 text-center space-y-1">
          <div class="text-xs font-mono text-[#7d8590]">Nenhum achado registrado</div>
          <div class="text-[11px] text-[#4b5563]">Execute uma varredura para identificar potenciais vulnerabilidades.</div>
        </div>
      )}

      {/* Kanban Board View */}
      {viewMode === "kanban" ? (
        <div class="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-3">
          {KANBAN_COLUMNS.map((col) => {
            const colFindings = filteredFindings.filter((f) => f.status === col.key);
            return (
              <div key={col.key} class="card p-2.5 flex flex-col min-h-[380px]">
                <div class="flex items-center justify-between pb-2 mb-2.5 border-b border-[#1b2230]">
                  <span class={`pill ${col.pillClass}`}>{col.label}</span>
                  <span class="text-xs font-mono text-[#7d8590] num">{colFindings.length}</span>
                </div>

                <div class="space-y-2 flex-1">
                  {colFindings.length === 0 ? (
                    <div class="text-[11px] text-[#7d8590]/50 font-mono text-center py-8">
                      0
                    </div>
                  ) : (
                    colFindings.map((f) => (
                      <div
                        key={f.id}
                        onClick={() => openFindingDrawer(f)}
                        class="bg-[#070a0f] border border-[#1b2230] hover:border-[#06b6d4]/60 rounded p-2.5 cursor-pointer transition space-y-1.5"
                      >
                        <div class="flex items-center justify-between gap-1">
                          <span class="pill pill-emerald">{f.evidence_level || "E2"}</span>
                          <span
                            class={`pill ${
                              f.detector?.severity === "critical" || f.detector?.severity === "high"
                                ? "pill-red"
                                : f.detector?.severity === "medium"
                                ? "pill-amber"
                                : "pill-neutral"
                            }`}
                          >
                            {f.detector?.severity || "info"}
                          </span>
                        </div>

                        <div class="text-xs font-semibold text-[#e6edf3] font-mono break-all leading-snug">
                          {f.detector?.name || f.detector_id}
                        </div>

                        <div class="text-[11px] font-mono text-[#06b6d4] truncate">
                          {f.asset?.canonical_key || f.asset_id}
                        </div>

                        <div class="text-[10px] font-mono text-[#7d8590] truncate num" title={f.dedup_key}>
                          sha256:{String(f.dedup_key || "").slice(0, 14)}…
                        </div>

                        <div
                          class="pt-1.5 border-t border-[#1b2230] flex items-center justify-between"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <span class="text-[10px] text-[#7d8590] font-mono">Status</span>
                          <select
                            value={f.status}
                            onChange={(e) =>
                              handleStatusChange(f.id, (e.target as HTMLSelectElement).value)
                            }
                            class="bg-[#0d1117] border border-[#1b2230] rounded px-1.5 py-0.5 text-[10px] font-mono text-[#e6edf3]"
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
        /* Table View (SESSION BENCHMARKS style) */
        <div class="card overflow-hidden">
          <table class="dtable num">
            <thead>
              <tr>
                <th>Evidence</th>
                <th>Severity</th>
                <th>Detector / Template</th>
                <th>Asset</th>
                <th>Dedup SHA-256</th>
                <th>Status</th>
                <th class="text-right">Forensic Dossier</th>
              </tr>
            </thead>
            <tbody>
              {filteredFindings.length === 0 ? (
                <tr>
                  <td colSpan={7} class="text-center text-[#7d8590] py-8 font-mono text-xs">
                    Nenhum achado registrado
                  </td>
                </tr>
              ) : (
                filteredFindings.map((f) => (
                <tr key={f.id}>
                  <td>
                    <span class="pill pill-emerald">{f.evidence_level || "E2"}</span>
                  </td>
                  <td>
                    <span
                      class={`pill ${
                        f.detector?.severity === "critical" || f.detector?.severity === "high"
                          ? "pill-red"
                          : f.detector?.severity === "medium"
                          ? "pill-amber"
                          : "pill-neutral"
                      }`}
                    >
                      {f.detector?.severity || "info"}
                    </span>
                  </td>
                  <td>
                    <div class="text-[#e6edf3] font-semibold">
                      {f.detector?.name || f.detector_id}
                    </div>
                    <div class="text-[10px] text-[#7d8590]">{f.detector_id}</div>
                  </td>
                  <td class="text-[#06b6d4]">{f.asset?.canonical_key || f.asset_id}</td>
                  <td class="text-[#7d8590]">{String(f.dedup_key || "").slice(0, 18)}…</td>
                  <td>
                    <select
                      value={f.status}
                      onChange={(e) =>
                        handleStatusChange(f.id, (e.target as HTMLSelectElement).value)
                      }
                      class="bg-[#070a0f] border border-[#1b2230] rounded px-2 py-1 text-[11px] font-mono text-[#e6edf3]"
                    >
                      {KANBAN_COLUMNS.map((c) => (
                        <option key={c.key} value={c.key}>
                          {c.label}
                        </option>
                      ))}
                    </select>
                  </td>
                  <td class="text-right">
                    <button
                      type="button"
                      onClick={() => openFindingDrawer(f)}
                      class="btn btn-cyan !py-1 !px-2.5 !text-[10px]"
                    >
                      Inspect E2 / Report
                    </button>
                  </td>
                </tr>
              )))}
            </tbody>
          </table>
        </div>
      )}

      {/* Lateral Forensic E2 Drawer */}
      {selectedFinding && (
        <div class="fixed inset-0 z-50 bg-black/75 backdrop-blur-xs flex justify-end">
          <div class="bg-[#0d1117] border-l border-[#1b2230] w-full max-w-2xl h-full overflow-y-auto p-5 shadow-2xl flex flex-col justify-between space-y-4">
            <div class="space-y-4">
              {/* Drawer Header */}
              <div class="flex items-start justify-between border-b border-[#1b2230] pb-3">
                <div>
                  <div class="flex items-center gap-1.5">
                    <span class="pill pill-emerald">
                      Evidence {selectedFinding.evidence_level || "E2"}
                    </span>
                    <span class="pill pill-amber">
                      {selectedFinding.detector?.severity || "info"}
                    </span>
                    <span class="pill pill-neutral">
                      conf:{selectedFinding.confidence || "high"}
                    </span>
                  </div>
                  <h3 class="text-sm font-bold text-[#e6edf3] mt-2 font-mono">
                    {selectedFinding.detector?.name || selectedFinding.detector_id}
                  </h3>
                  <p class="text-xs font-mono text-[#06b6d4]">
                    Asset: {selectedFinding.asset?.canonical_key || selectedFinding.asset_id}
                  </p>
                </div>

                <button
                  type="button"
                  onClick={() => setSelectedFinding(null)}
                  class="btn btn-ghost !py-1 !px-2.5"
                >
                  ✕ Fechar
                </button>
              </div>

              {/* Drawer Segmented Tabs */}
              <div class="seg w-full flex">
                <button
                  type="button"
                  onClick={() => setDrawerTab("forensic")}
                  class={`seg-btn flex-1 ${drawerTab === "forensic" ? "active" : ""}`}
                >
                  1. Artefatos de Evidência (S3)
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setDrawerTab("report");
                    if (!reportMarkdown) {
                      fetchMarkdownReport(selectedFinding.id);
                    }
                  }}
                  class={`seg-btn flex-1 ${drawerTab === "report" ? "active" : ""}`}
                >
                  2. Relatório de Vulnerabilidade (.md)
                </button>
              </div>

              {drawerTab === "forensic" ? (
                <div class="space-y-3 text-xs font-mono">
                  <div class="bg-[#070a0f] border border-[#1b2230] rounded p-3 space-y-2">
                    <div>
                      <span class="kpi-label block">DEDUP_KEY (SHA-256 64-CHAR)</span>
                      <span class="text-[#10b981] break-all text-[11px] num">
                        {selectedFinding.dedup_key}
                      </span>
                    </div>
                    <div class="grid grid-cols-2 gap-2 pt-2 border-t border-[#1b2230]">
                      <div>
                        <span class="kpi-label block">DETECTOR ID</span>
                        <span class="text-[#e6edf3]">{selectedFinding.detector_id}</span>
                      </div>
                      <div>
                        <span class="kpi-label block">ADVISORY / CVE</span>
                        <span class="text-[#f59e0b]">
                          {selectedFinding.advisory_id || selectedFinding.detector?.cve_id || "N/A"}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div class="space-y-2">
                    <span class="kpi-label block">SEAWEEDFS S3 EVIDENCE ARTIFACTS</span>
                    {loadingDetail ? (
                      <div class="space-y-2">
                        <div class="skeleton h-16 w-full" />
                        <div class="skeleton h-16 w-full" />
                      </div>
                    ) : (selectedFinding.evidence_items || []).length === 0 ? (
                      <div class="bg-[#070a0f] border border-[#1b2230] rounded p-3 text-[#7d8590]">
                        Nenhum apontador S3 associado a este achado.
                      </div>
                    ) : (
                      selectedFinding.evidence_items.map((ev: any) => (
                        <div
                          key={ev.id}
                          class="bg-[#070a0f] border border-[#1b2230] rounded p-3 space-y-1.5 text-[11px] num"
                        >
                          <div class="flex items-center justify-between">
                            <span class="text-[#06b6d4] font-semibold">{ev.evidence_type}</span>
                            <span class="pill pill-emerald">
                              Redaction: {ev.redaction_profile}
                            </span>
                          </div>
                          <div>
                            <span class="kpi-label block">SEAWEED OBJECT KEY</span>
                            <span class="text-[#e6edf3] break-all">{ev.seaweed_object_key}</span>
                          </div>
                          <div>
                            <span class="kpi-label block">SANITIZED SHA-256</span>
                            <span class="text-[#10b981] break-all">{ev.sanitized_sha256}</span>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              ) : (
                /* Tab 2: HackerOne / Bugcrowd Report Generator */
                <div class="space-y-3">
                  <div class="flex flex-wrap items-center justify-between gap-2">
                    <span class="kpi-label">
                      Relatório Forense de Vulnerabilidade
                    </span>
                    <div class="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={handleCopyMarkdown}
                        class="btn btn-primary !py-1 !px-2.5"
                      >
                        {copyToast ? "✓ Copied!" : "Copy Markdown"}
                      </button>
                      <button
                        type="button"
                        onClick={handleDownloadMarkdown}
                        class="btn btn-cyan !py-1 !px-2.5"
                      >
                        ⬇ Download .md
                      </button>
                    </div>
                  </div>

                  {loadingReport ? (
                    <div class="space-y-2">
                      <div class="skeleton h-8 w-2/3" />
                      <div class="skeleton h-48 w-full" />
                    </div>
                  ) : (
                    <pre class="bg-[#070a0f] border border-[#1b2230] rounded p-3.5 text-[11px] font-mono text-[#e6edf3] overflow-x-auto whitespace-pre-wrap max-h-[460px]">
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
