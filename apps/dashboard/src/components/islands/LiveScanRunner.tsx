import { useState, useEffect, useRef } from "preact/hooks";

export interface LiveScanRunnerProps {
  programs?: any[];
  initialSlug?: string;
  initialAssets?: any[];
  scanHistory?: any[];
  apiBaseUrl?: string;
  wsBaseUrl?: string;
}

const ALL_SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

export default function LiveScanRunner({
  programs = [],
  initialSlug = "",
  initialAssets = [],
  scanHistory = [],
  apiBaseUrl = "http://127.0.0.1:8000",
  wsBaseUrl = "ws://127.0.0.1:8000",
}: LiveScanRunnerProps) {
  const [programSlug, setProgramSlug] = useState<string>(
    initialSlug || programs[0]?.slug || ""
  );
  const [assets, setAssets] = useState<any[]>(initialAssets);
  const [assetKey, setAssetKey] = useState<string>(
    initialAssets[0]?.canonical_key || ""
  );
  const [selectedSeverities, setSelectedSeverities] = useState<string[]>([
    "critical",
    "high",
    "medium",
    "low",
    "info",
  ]);
  const [tagsFilter, setTagsFilter] = useState<string>("");
  const [runMode, setRunMode] = useState<"auto" | "dry_run">("auto");

  // Stage 1: DetectionPlanner state
  const [planning, setPlanning] = useState<boolean>(false);
  const [planResult, setPlanResult] = useState<any | null>(null);

  // Stage 2: Scan Execution & WebSocket console state
  const [runningScan, setRunningScan] = useState<boolean>(false);
  const [scanProgress, setScanProgress] = useState<number>(0);
  const [scanResult, setScanResult] = useState<any | null>(null);
  const [terminalLogs, setTerminalLogs] = useState<string[]>([
    "[SYSTEM] Console de Execução Efêmera PenteFino pronto.",
    "[SYSTEM] Hard-gate: Somente templates SAFE_READ_ONLY + Egress Proxy (127.0.0.1:8080).",
  ]);
  const [history, setHistory] = useState<any[]>(scanHistory);

  const wsRef = useRef<WebSocket | null>(null);
  const terminalContainerRef = useRef<HTMLDivElement | null>(null);

  // Read URL query params (?program=...&asset=...) on mount
  useEffect(() => {
    if (typeof window !== "undefined") {
      const params = new URLSearchParams(window.location.search);
      const qProg = params.get("program");
      const qAsset = params.get("asset");
      if (qProg) setProgramSlug(qProg);
      if (qAsset) setAssetKey(qAsset);
    }
  }, []);

  useEffect(() => {
    if (programSlug) {
      if (
        programSlug === initialSlug &&
        initialAssets &&
        initialAssets.length > 0
      ) {
        return;
      }
      fetchProgramAssets(programSlug);
    }
  }, [programSlug]);

  // Auto-scroll terminal container on new logs
  useEffect(() => {
    if (terminalContainerRef.current) {
      terminalContainerRef.current.scrollTop = terminalContainerRef.current.scrollHeight;
    }
  }, [terminalLogs]);

  useEffect(() => {
    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  function appendLog(line: string) {
    const ts = new Date().toISOString().split("T")[1].slice(0, 8);
    setTerminalLogs((prev) => [...prev, `[${ts}] ${line}`]);
  }

  function toggleSeverity(sev: string) {
    setSelectedSeverities((prev) => {
      if (prev.includes(sev)) {
        return prev.length > 1 ? prev.filter((s) => s !== sev) : prev;
      }
      return [...prev, sev];
    });
  }

  async function fetchProgramAssets(slug: string) {
    try {
      const res = await fetch(`${apiBaseUrl}/api/v1/programs/${slug}/assets`);
      if (res.ok) {
        const data = await res.json();
        const list = Array.isArray(data) ? data : data.assets || [];
        setAssets(list);
        if (list.length > 0 && !assetKey) {
          setAssetKey(list[0].canonical_key);
        }
      }
    } catch {
      // Keep current assets
    }
  }

  async function fetchHistory() {
    try {
      const res = await fetch(`${apiBaseUrl}/api/v1/scans/history`);
      if (res.ok) {
        const data = await res.json();
        setHistory(Array.isArray(data) ? data : []);
      }
    } catch {
      // Ignore offline error
    }
  }

  // Stage 1: Simulate Detection Plan
  async function handleSimulatePlan(e?: Event) {
    if (e) e.preventDefault();
    if (!programSlug || !assetKey.trim()) return;
    setPlanning(true);
    setScanResult(null);
    setScanProgress(25);
    const sevString = selectedSeverities.join(",");
    appendLog(`[ETAPA-1] Calculando plano de detecção → '${assetKey.trim()}' (${programSlug}) [sev=${sevString}]`);

    try {
      const res = await fetch(`${apiBaseUrl}/api/v1/scans/plan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          program_slug: programSlug,
          asset_key: assetKey.trim(),
          severity: sevString || null,
          tags: tagsFilter.trim() || null,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setPlanResult(data);
        setScanProgress(50);
        appendLog(
          `[PLANNER] Raw tech: [${(data.raw_detected_technologies || []).join(", ")}] | CDN Pruned: [${(
            data.pruned_edge_tags || []
          ).join(", ")}]`
        );
        appendLog(
          `[PLANNER] plan_id=${data.plan_id} → ${data.total_templates} templates SAFE_READ_ONLY selecionados.`
        );
        setPlanning(false);
        return;
      } else {
        appendLog(`[ERRO] API retornou erro ${res.status} ao gerar plano de detecção.`);
      }
    } catch (err: any) {
      appendLog(`[ERRO] Falha ao consultar plano de detecção na API: ${err?.message || "conexão recusada"}`);
    }

    setPlanResult(null);
    setScanProgress(0);
    setPlanning(false);
  }

  // Stage 2: Connect WebSocket with SAME plan_id & Execute Scan
  async function handleRunScan() {
    const activePlanId = planResult?.plan_id || "live-plan-" + Date.now();
    const sevString = selectedSeverities.join(",");
    setRunningScan(true);
    setScanResult(null);
    setScanProgress(65);

    try {
      if (wsRef.current) {
        wsRef.current.close();
      }
      const wsUrl = `${wsBaseUrl}/ws/scans/${activePlanId}`;
      appendLog(`[WS] Conectando ao stream: ${wsUrl}`);
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        appendLog(`[WS] Canal estabelecido para plan_id=${activePlanId}`);
      };
      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (typeof msg.progress === "number") {
            setScanProgress(Math.max(50, Math.min(100, msg.progress)));
          }
          if (msg.line || msg.message) {
            appendLog(`[RUNNER] ${msg.line || msg.message}`);
          } else if (msg.stage) {
            appendLog(`[STAGE:${String(msg.stage).toUpperCase()}] progress=${msg.progress ?? 0}%`);
          }
        } catch {
          appendLog(`[STREAM] ${event.data}`);
        }
      };
    } catch {
      appendLog(`[WS] WebSocket offline — exibindo telemetria via resposta HTTP.`);
    }

    appendLog(
      `[CONTAINER] docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges:true -e HTTP_PROXY=http://127.0.0.1:8080 projectdiscovery/nuclei`
    );

    try {
      const res = await fetch(`${apiBaseUrl}/api/v1/scans/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          plan_id: activePlanId,
          program_slug: programSlug,
          asset_key: assetKey.trim(),
          severity: sevString || null,
          tags: tagsFilter.trim() || null,
          mode: runMode,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setScanResult(data);
        setScanProgress(100);
        appendLog(
          `[RUNNER] Status: ${data.status.toUpperCase()} | Mode: ${data.mode_executed} | Templates: ${data.total_templates}`
        );
        if (data.message) {
          appendLog(`[INFO] ${data.message}`);
        }
        appendLog(`[DEDUP] Findings gerados/atualizados: ${data.findings_count ?? 0}.`);
        await fetchHistory();
        setRunningScan(false);
        return;
      } else {
        appendLog(`[ERRO] API retornou erro ${res.status} ao executar varredura.`);
      }
    } catch (err: any) {
      appendLog(`[ERRO] Falha ao comunicar com o executor de varreduras: ${err?.message || "conexão recusada"}`);
    }

    setScanProgress(0);
    setScanResult(null);
    setRunningScan(false);
  }

  const stageLabel = runningScan
    ? "Executando varredura no site..."
    : scanResult
    ? "Varredura concluída · Resultados prontos"
    : planning
    ? "Identificando tecnologias do site..."
    : planResult
    ? "Tecnologias identificadas · Pronto para escanear"
    : "Aguardando seleção do alvo";

  if (programs.length === 0) {
    return (
      <div class="card card-pad py-16 text-center space-y-4">
        <div class="w-12 h-12 mx-auto rounded-full bg-[#11161f] border border-[#1b2230] flex items-center justify-center text-[#738196]">
          <svg class="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M13 10V3L4 14h7v7l9-11h-7z" />
          </svg>
        </div>
        <div>
          <h3 class="text-sm font-semibold text-white">Nenhum programa cadastrado</h3>
          <p class="text-xs text-[#738196] mt-1 max-w-sm mx-auto">
            Cadastre um alvo para planejar e executar varreduras com segurança.
          </p>
        </div>
        <div>
          <a href="/programs" class="btn btn-primary">
            + Cadastrar Alvo
          </a>
        </div>
      </div>
    );
  }

  return (
    <div class="space-y-3">
      {/* Hero Strip Progress Bar */}
      <div class="card card-pad">
        <div class="flex flex-wrap items-center justify-between gap-2 mb-2">
          <div class="flex items-center gap-2">
            <span class="pill pill-emerald">Varredura de Detecção</span>
            <span class="text-xs font-mono font-semibold text-[#e6edf3]">
              {assetKey || "Nenhum alvo selecionado"}
            </span>
            <span class="text-[11px] font-mono text-[#7d8590]">({programSlug})</span>
          </div>
          <div class="flex items-center gap-2 text-[11px] font-mono num">
            <span class="pill pill-cyan">{stageLabel}</span>
            {planResult && (
              <span class="pill pill-neutral">{planResult.total_templates} safe_read_only</span>
            )}
            <span class="text-[#10b981] font-bold">{scanProgress}%</span>
          </div>
        </div>
        <div class="bar-track">
          <div
            class={`bar-fill ${runningScan ? "bar-fill-cyan" : "bar-fill-emerald"}`}
            style={{ width: `${scanProgress}%` }}
          />
        </div>
      </div>

      {/* Target & Filter Bar */}
      <form onSubmit={handleSimulatePlan} class="card card-pad space-y-3">
        <div class="grid grid-cols-1 md:grid-cols-12 gap-2.5 items-end">
          <div class="md:col-span-3">
            <label class="kpi-label block mb-1">1. Escolha o Alvo</label>
            <select
              value={programSlug}
              onChange={(e) => setProgramSlug((e.target as HTMLSelectElement).value)}
              class="input"
            >
              {programs.length === 0 ? (
                <option value={programSlug}>{programSlug || "Nenhum"}</option>
              ) : (
                programs.map((p) => (
                  <option key={p.slug} value={p.slug}>
                    {p.name} ({p.slug})
                  </option>
                ))
              )}
            </select>
          </div>

          <div class="md:col-span-3">
            <label class="kpi-label block mb-1">2. Endereço / URL do Site</label>
            <input
              type="text"
              list="scoped-assets-datalist"
              value={assetKey}
              onInput={(e) => setAssetKey((e.target as HTMLInputElement).value)}
              placeholder="ex: app.exemplo.com"
              class="input"
              required
            />
            <datalist id="scoped-assets-datalist">
              {assets.map((a) => (
                <option key={a.id || a.canonical_key} value={a.canonical_key} />
              ))}
            </datalist>
          </div>

          <div class="md:col-span-2">
            <label class="kpi-label block mb-1">Extra Tags (opt)</label>
            <input
              type="text"
              value={tagsFilter}
              onInput={(e) => setTagsFilter((e.target as HTMLInputElement).value)}
              placeholder="cve,exposure,misconfig"
              class="input"
            />
          </div>

          <div class="md:col-span-2">
            <label class="kpi-label block mb-1">Execution Mode</label>
            <div class="seg w-full flex">
              <button
                type="button"
                onClick={() => setRunMode("auto")}
                class={`seg-btn flex-1 ${runMode === "auto" ? "active" : ""}`}
              >
                auto
              </button>
              <button
                type="button"
                onClick={() => setRunMode("dry_run")}
                class={`seg-btn flex-1 ${runMode === "dry_run" ? "active" : ""}`}
              >
                dry_run
              </button>
            </div>
          </div>

          <div class="md:col-span-2">
            <button type="submit" disabled={planning} class="btn btn-cyan w-full">
              {planning ? "Planejando..." : "1. Planejar Varredura"}
            </button>
          </div>
        </div>

        {/* Multi-toggle Severity Pills */}
        <div class="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-[#1b2230]">
          <div class="flex flex-wrap items-center gap-1.5">
            <span class="kpi-label mr-1">Severities:</span>
            {ALL_SEVERITIES.map((sev) => {
              const active = selectedSeverities.includes(sev);
              const colorCls =
                sev === "critical" || sev === "high"
                  ? active
                    ? "pill-red"
                    : "pill-neutral opacity-50"
                  : sev === "medium"
                  ? active
                    ? "pill-amber"
                    : "pill-neutral opacity-50"
                  : active
                  ? "pill-cyan"
                  : "pill-neutral opacity-50";
              return (
                <button
                  key={sev}
                  type="button"
                  onClick={() => toggleSeverity(sev)}
                  class={`pill cursor-pointer transition ${colorCls}`}
                >
                  {active ? "✓ " : ""}
                  {sev}
                </button>
              );
            })}
          </div>
          <div class="flex items-center gap-1.5 text-[10px] font-mono text-[#7d8590]">
            <span>Regra:</span>
            <span class="pill pill-emerald">SAFE_READ_ONLY</span>
            <span class="pill pill-cyan">Proxy 127.0.0.1:8080</span>
          </div>
        </div>
      </form>

      {/* Two-Stage Main Grid */}
      <div class="grid grid-cols-1 lg:grid-cols-12 gap-3">
        {/* Stage 1: DetectionPlan Results & Selected Templates Table */}
        <div class="lg:col-span-6 card flex flex-col justify-between">
          <div>
            <div class="px-3.5 py-2.5 border-b border-[#1b2230] flex items-center justify-between">
              <div class="flex items-center gap-2">
                <span class="kpi-label text-[#06b6d4]">ETAPA 1 · PLANO DE DETECÇÃO</span>
                {planResult && (
                  <span class="text-[10px] font-mono text-[#7d8590]">
                    #{String(planResult.plan_id).slice(0, 12)}
                  </span>
                )}
              </div>
              {planResult && (
                <span class="pill pill-emerald num">{planResult.total_templates} templates</span>
              )}
            </div>

            {!planResult ? (
              <div class="p-8 text-center space-y-2.5">
                <p class="text-xs font-mono text-[#7d8590]">
                  Clique em <strong class="text-[#e6edf3]">1. Planejar Varredura</strong> para filtrar templates compatíveis.
                </p>
                <button
                  type="button"
                  onClick={() => handleSimulatePlan()}
                  class="btn btn-ghost"
                >
                  Calcular Plano de Detecção
                </button>
              </div>
            ) : (
              <div class="p-3.5 space-y-3">
                {/* Matched Tech vs Pruned CDN */}
                <div class="grid grid-cols-2 gap-2.5">
                  <div class="bg-[#070a0f] border border-[#1b2230] rounded p-2.5">
                    <span class="kpi-label block mb-1.5">Matched App Stack</span>
                    <div class="flex flex-wrap gap-1">
                      {(planResult.matched_technologies || []).length === 0 ? (
                        <span class="text-[11px] font-mono text-[#7d8590]">generic-baseline</span>
                      ) : (
                        planResult.matched_technologies.map((tech: string) => (
                          <span key={tech} class="pill pill-cyan">
                            {tech}
                          </span>
                        ))
                      )}
                    </div>
                  </div>

                  <div class="bg-[#070a0f] border border-[#1b2230] rounded p-2.5">
                    <span class="kpi-label text-[#f59e0b] block mb-1.5">CDN / WAF Pruned</span>
                    <div class="flex flex-wrap gap-1">
                      {(planResult.pruned_edge_tags || []).length === 0 ? (
                        <span class="text-[11px] font-mono text-[#7d8590]">none</span>
                      ) : (
                        planResult.pruned_edge_tags.map((cdn: string) => (
                          <span key={cdn} class="pill pill-amber line-through">
                            {cdn}
                          </span>
                        ))
                      )}
                    </div>
                  </div>
                </div>

                {/* Selected Templates Table */}
                <div class="border border-[#1b2230] rounded overflow-hidden max-h-64 overflow-y-auto">
                  <table class="dtable num">
                    <thead>
                      <tr>
                        <th>Template ID</th>
                        <th>Severity</th>
                        <th>CVE</th>
                        <th>Tech</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(planResult.selected_templates || []).map((tpl: any) => (
                        <tr key={tpl.id}>
                          <td>
                            <div
                              class="text-[#06b6d4] font-semibold truncate max-w-[220px]"
                              title={tpl.id}
                            >
                              {tpl.id}
                            </div>
                            <div class="text-[10px] text-[#7d8590] truncate max-w-[220px]">
                              {tpl.name}
                            </div>
                          </td>
                          <td>
                            <span
                              class={`pill ${
                                tpl.severity === "critical" || tpl.severity === "high"
                                  ? "pill-red"
                                  : tpl.severity === "medium"
                                  ? "pill-amber"
                                  : "pill-neutral"
                              }`}
                            >
                              {tpl.severity || "info"}
                            </span>
                          </td>
                          <td class="text-[#f59e0b]">{tpl.cve_id || "—"}</td>
                          <td class="text-[#7d8590]">
                            {(tpl.technologies || []).slice(0, 2).join(", ") || "baseline"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>

          {planResult && (
            <div class="p-3.5 border-t border-[#1b2230]">
              <button
                type="button"
                disabled={runningScan}
                onClick={handleRunScan}
                class="btn btn-primary w-full py-2"
              >
                {runningScan
                  ? "Executando Container..."
                  : `2. Executar Varredura (${planResult.total_templates} Templates)`}
              </button>
            </div>
          )}
        </div>

        {/* Stage 2: Live WebSocket Execution Terminal & Audit History */}
        <div class="lg:col-span-6 space-y-3">
          <div class="card overflow-hidden flex flex-col">
            <div class="px-3.5 py-2.5 border-b border-[#1b2230] flex items-center justify-between bg-[#070a0f]">
              <div class="flex items-center gap-2">
                <span class="h-2 w-2 rounded-full bg-[#10b981] animate-pulse" />
                <span class="kpi-label text-[#e6edf3]">
                  STAGE 2 · LIVE STREAM (/ws/scans/
                  {planResult?.plan_id ? String(planResult.plan_id).slice(0, 10) : "live"})
                </span>
              </div>
              <button
                type="button"
                onClick={() => setTerminalLogs(["[SYSTEM] Console limpo."])}
                class="text-[10px] font-mono text-[#7d8590] hover:text-[#e6edf3]"
              >
                Clear
              </button>
            </div>

            <div
              ref={terminalContainerRef}
              class="p-3 bg-[#05070b] font-mono text-[11px] space-y-1 h-64 overflow-y-auto num"
            >
              {terminalLogs.map((log, i) => (
                <div
                  key={i}
                  class={
                    log.includes("[PLANNER]")
                      ? "text-[#06b6d4]"
                      : log.includes("[CONTAINER]")
                      ? "text-[#f59e0b]"
                      : log.includes("[FALLBACK]")
                      ? "text-[#a855f7]"
                      : "text-[#10b981]"
                  }
                >
                  {log}
                </div>
              ))}
            </div>

            {scanResult && (
              <div class="px-3.5 py-2 bg-[#10b981]/10 border-t border-[#10b981]/30 flex items-center justify-between text-xs font-mono">
                <span class="text-[#10b981]">
                  Status: <strong>{scanResult.status}</strong> ({scanResult.mode_executed})
                </span>
                <a href="/findings" class="text-[#06b6d4] hover:underline font-semibold">
                  Inspect Findings ({scanResult.findings_count ?? 0}) →
                </a>
              </div>
            )}
          </div>

          {/* Recent Scan Audit Trail */}
          <div class="card overflow-hidden">
            <div class="px-3.5 py-2 border-b border-[#1b2230] flex items-center justify-between">
              <span class="kpi-label">RECENT SCAN AUDIT TRAIL</span>
              <span class="text-[10px] font-mono text-[#7d8590] num">{history.length} events</span>
            </div>
            <div class="max-h-36 overflow-y-auto">
              <table class="dtable num">
                <thead>
                  <tr>
                    <th>Seq</th>
                    <th>Event Type</th>
                    <th>Object</th>
                    <th class="text-right">Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {history.length === 0 ? (
                    <tr>
                      <td colSpan={4} class="text-center text-[#7d8590] py-3">
                        No scan events recorded yet.
                      </td>
                    </tr>
                  ) : (
                    history.slice(0, 6).map((h) => (
                      <tr key={h.sequence}>
                        <td class="text-[#06b6d4]">#{h.sequence}</td>
                        <td>{h.event_type}</td>
                        <td class="text-[#7d8590]">{h.object_id}</td>
                        <td class="text-right text-[#7d8590]">{h.occurred_at?.slice(0, 19)}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
