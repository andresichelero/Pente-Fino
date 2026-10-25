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

  // Advanced Tool Parameters & Dropdowns
  const [showAdvancedParams, setShowAdvancedParams] = useState<boolean>(false);
  const [subfinderAll, setSubfinderAll] = useState<boolean>(true);
  const [dnsxWildcard, setDnsxWildcard] = useState<boolean>(true);
  const [dnsxResolvers, setDnsxResolvers] = useState<string>("1.1.1.1,8.8.8.8,9.9.9.9");
  const [httpxPorts, setHttpxPorts] = useState<string>("80,443,8080,8443");
  const [httpxTech, setHttpxTech] = useState<boolean>(true);
  const [httpxFollowRedirects, setHttpxFollowRedirects] = useState<boolean>(true);
  const [naabuEnabled, setNaabuEnabled] = useState<boolean>(false);
  const [tlsxEnabled, setTlsxEnabled] = useState<boolean>(false);
  const [nucleiConcurrency, setNucleiConcurrency] = useState<number>(5);
  const [nucleiRateLimit, setNucleiRateLimit] = useState<number>(10);
  const [nucleiAutoScan, setNucleiAutoScan] = useState<boolean>(true);
  const [nucleiHostPrune, setNucleiHostPrune] = useState<boolean>(true);

  // Circuit Breaker per-domain state & worker slots
  const [circuitBreakerAlerts, setCircuitBreakerAlerts] = useState<any[]>([]);
  const [workerSlots, setWorkerSlots] = useState<{ [domain: string]: { status: string; findings: number; templates: number } }>({});

  // Stage 2: Scan Execution & WebSocket console state
  const [runningScan, setRunningScan] = useState<boolean>(false);
  const [runningRecon, setRunningRecon] = useState<boolean>(false);
  const [runningBatch, setRunningBatch] = useState<boolean>(false);
  const [scanProgress, setScanProgress] = useState<number>(0);
  const [scanResult, setScanResult] = useState<any | null>(null);
  const [lastLiveLines, setLastLiveLines] = useState<
    { id: string; tool: string; text: string; time: string }[]
  >([
    {
      id: "init-1",
      tool: "SYSTEM",
      text: "Console efêmero pronto. Hard-gate: SAFE_READ_ONLY.",
      time: "00:00:00",
    },
    {
      id: "init-2",
      tool: "RATE-LIMIT",
      text: "Limitador de taxa ativo configurado para 10 req/s.",
      time: "00:00:00",
    },
    {
      id: "init-3",
      tool: "PROXY",
      text: "Egress Proxy Guard 127.0.0.1:8080 online com fail-closed.",
      time: "00:00:00",
    },
    {
      id: "init-4",
      tool: "RECON",
      text: "Subfinder + dnsx + httpx prontos para execução em lote.",
      time: "00:00:00",
    },
    {
      id: "init-5",
      tool: "NUCLEI",
      text: "HardenedNucleiRunner preparado com rate-limit: 10 req/s.",
      time: "00:00:00",
    },
  ]);
  const [netHealth, setNetHealth] = useState<any>({
    overall_latency_ms: 125.0,
    overall_jitter_ms: 1.2,
    packet_loss_pct: 0.0,
    download_kbps: 0.0,
    upload_kbps: 0.0,
  });
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
    // Fetch network health stats
    fetch(`${apiBaseUrl}/api/v1/telemetry/network-health`)
      .then((r) => r.json())
      .then((d) => setNetHealth(d))
      .catch(() => {});
  }, [apiBaseUrl]);

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
    let ws: WebSocket | null = null;
    let reconnectTimer: any = null;

    function connectWs() {
      try {
        const wsUrl = `${wsBaseUrl}/ws/scans/live`;
        ws = new WebSocket(wsUrl);
        wsRef.current = ws;

        ws.onopen = () => {
          appendLog("[WS] Conectado ao stream ao vivo (/ws/scans/live).");
        };

        ws.onmessage = (event) => {
          try {
            const msg = JSON.parse(event.data);
            if (typeof msg.progress === "number") {
              setScanProgress(Math.max(10, Math.min(100, msg.progress)));
            }
            if (msg.event === "tool_output") {
              const tool = msg.tool || "CLI";
              const line = msg.line || msg.message || "";
              if (line) {
                appendLog(`[${tool}] ${line}`);
              }
            } else if (msg.event === "circuit_breaker_tripped") {
              const alertItem = {
                domain: msg.domain,
                reason: msg.reason,
                cooldown_sec: msg.cooldown_sec,
                time: new Date().toLocaleTimeString(),
              };
              setCircuitBreakerAlerts((prev) => [alertItem, ...prev.filter((a) => a.domain !== msg.domain).slice(0, 4)]);
              appendLog(`[CIRCUIT BREAKER] 🛑 WAF detectado em '${msg.domain}' (${msg.reason}) -> Domínio em cooldown (60s). Outros workers avançando.`);
            } else if (msg.event === "batch_asset_scanned") {
              setWorkerSlots((prev) => ({
                ...prev,
                [msg.asset_key]: {
                  status: "concluído",
                  findings: msg.findings_count,
                  templates: msg.templates_count,
                },
              }));
              appendLog(`[BATCH:SLOT] Ativo '${msg.asset_key}' finalizado: ${msg.templates_count} templates, ${msg.findings_count} falhas.`);
            } else if (msg.event === "recon_stage") {
              appendLog(`[RECON:${String(msg.stage).toUpperCase()}] ${msg.message}`);
            } else if (msg.event === "recon_completed") {
              appendLog(`[RECON:SUCCESS] ${msg.message}`);
            } else if (msg.line || msg.message) {
              appendLog(msg.line || msg.message);
            }
          } catch {
            // Raw text fallback
          }
        };

        ws.onclose = () => {
          reconnectTimer = setTimeout(connectWs, 3000);
        };
      } catch {
        reconnectTimer = setTimeout(connectWs, 5000);
      }
    }

    connectWs();

    return () => {
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (ws) ws.close();
    };
  }, [wsBaseUrl]);

  function appendLog(line: string) {
    const ts = new Date().toISOString().split("T")[1].slice(0, 8);
    setTerminalLogs((prev) => [...prev, `[${ts}] ${line}`]);

    const lower = line.toLowerCase();
    const tool = lower.includes("nuclei") || lower.includes("[runner]")
      ? "NUCLEI"
      : lower.includes("subfinder") || lower.includes("[recon")
      ? "SUBFINDER"
      : lower.includes("httpx")
      ? "HTTPX"
      : lower.includes("dnsx")
      ? "DNSX"
      : lower.includes("[batch")
      ? "BATCH"
      : lower.includes("[planner]")
      ? "PLANNER"
      : "SCANNER";

    setLastLiveLines((prev) => [
      ...prev.slice(Math.max(0, prev.length - 4)),
      { id: `${Date.now()}-${Math.random()}`, tool, text: line, time: ts },
    ]);
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
      const data = await res.json().catch(() => null);
      if (res.ok && data) {
        setPlanResult(data);
        setScanProgress(50);
        appendLog(
          `[PLANNER] Tecnologias detectadas: [${(data.raw_detected_technologies || []).join(", ") || "genérico"}] | CDN Pruned: [${(
            data.pruned_edge_tags || []
          ).join(", ") || "nenhuma"}]`
        );
        appendLog(
          `[PLANNER] plan_id=${data.plan_id} → ${data.total_templates} testes seguros selecionados.`
        );
        setPlanning(false);
        return;
      } else {
        const errorDetail = data?.detail || `Erro ${res.status}`;
        appendLog(`[ERRO] API retornou erro ${res.status}: ${errorDetail}`);
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

  async function handleResetCircuitBreaker(domain: string) {
    try {
      await fetch(`${apiBaseUrl}/api/v1/scans/circuit-breaker/reset`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain }),
      });
      appendLog(`[CIRCUIT BREAKER] Cooldown resetado para '${domain}'.`);
      setCircuitBreakerAlerts((prev) => prev.filter((a) => a.domain !== domain));
    } catch {
      // Ignore
    }
  }

  // Stage 0: Run Subfinder + dnsx + httpx Reconnaissance Pipeline
  async function handleRunRecon() {
    if (!programSlug) return;
    const cleanDomain = assetKey.trim().replace(/^https?:\/\//i, "").split("/")[0] || programSlug;
    setRunningRecon(true);
    setScanProgress(20);
    appendLog(`[RECON] Iniciando ReconPipeline (Subfinder -> dnsx -wd -> httpx) para '${cleanDomain}'...`);

    try {
      const res = await fetch(`${apiBaseUrl}/api/v1/recon/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          program_slug: programSlug,
          domain: cleanDomain,
          bruteforce: false,
          subfinder_flags: { all: subfinderAll },
          dnsx_flags: { wildcard_detection: dnsxWildcard, resolvers: dnsxResolvers.split(",") },
          httpx_flags: { tech_detect: httpxTech, status_code: true, title: true, follow_redirects: httpxFollowRedirects, ports: httpxPorts },
          naabu_flags: { enabled: naabuEnabled, ports: "80,443,8080,8443" },
          tlsx_flags: { enabled: tlsxEnabled, san: true },
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setScanProgress(100);
        appendLog(`[RECON:SUCCESS] ${data.message}`);
        appendLog(`[RECON] ${data.total_discovered} subdomínios descobertos (${data.in_scope_count} em escopo, ${data.out_of_scope_count} fora de escopo).`);
        await fetchProgramAssets(programSlug);
        await fetchHistory();
        setRunningRecon(false);
        return;
      } else {
        appendLog(`[ERRO] API retornou erro ${res.status} ao executar reconhecimento.`);
      }
    } catch (err: any) {
      appendLog(`[ERRO] Falha ao comunicar com pipeline de reconhecimento: ${err?.message || "conexão recusada"}`);
    }
    setRunningRecon(false);
  }

  // Stage 3: Batch Surgical Scanning across ALL in-scope assets (Max 5 concurrent workers)
  async function handleRunBatchScan() {
    if (!programSlug) return;
    setRunningBatch(true);
    setScanProgress(10);
    const sevString = selectedSeverities.join(",");
    appendLog(`[BATCH-RUN] Disparando varredura cirúrgica concorrente (${nucleiConcurrency} workers simultâneos, rl: ${nucleiRateLimit} req/s por worker, circuit-breaker per-domain ativo)...`);

    try {
      const res = await fetch(`${apiBaseUrl}/api/v1/scans/batch-run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          program_slug: programSlug,
          severity: sevString || null,
          tags: tagsFilter.trim() || null,
          rate_limit: nucleiRateLimit,
          concurrency: nucleiConcurrency,
          mode: runMode,
          max_assets: 100,
          nuclei_flags: { auto_scan: nucleiAutoScan, host_prune: nucleiHostPrune, follow_redirects: true },
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setScanProgress(100);
        appendLog(`[BATCH:SUCCESS] ${data.message}`);
        appendLog(`[BATCH] Ativos escaneados: ${data.total_assets_scanned} | Templates executadas: ${data.total_templates_executed} | Falhas encontradas: ${data.total_findings_discovered}`);
        for (const item of (data.assets || []).slice(0, 10)) {
          appendLog(` -> [${item.asset_key}] Techs: [${(item.matched_technologies || []).join(", ") || "generic"}] | ${item.total_templates} templates -> ${item.findings_count} findings (${item.status})`);
        }
        await fetchHistory();
        setRunningBatch(false);
        return;
      } else {
        appendLog(`[ERRO] API retornou erro ${res.status} ao executar varredura em lote.`);
      }
    } catch (err: any) {
      appendLog(`[ERRO] Falha ao comunicar com executor de varreduras em lote: ${err?.message || "conexão recusada"}`);
    }
    setRunningBatch(false);
  }

  const stageLabel = runningRecon
    ? "Descobrindo subdomínios (Subfinder -> dnsx -> httpx)..."
    : runningBatch
    ? "Executando varredura cirúrgica em lote nos ativos em escopo..."
    : runningScan
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

        {/* Advanced Tool Parameters Toggle */}
        <div class="pt-2 border-t border-[#1b2230] flex items-center justify-between">
          <button
            type="button"
            onClick={() => setShowAdvancedParams(!showAdvancedParams)}
            class="text-xs font-mono text-[#06b6d4] hover:text-[#22d3ee] flex items-center gap-1.5 transition"
          >
            <span>{showAdvancedParams ? "▼" : "▶"}</span>
            <span>⚙ Parâmetros Avançados das Ferramentas (Dropdowns & Flags)</span>
          </button>
          <span class="text-[11px] font-mono text-[#7d8590]">
            Subfinder · dnsx (-wd) · httpx · naabu · tlsx · nuclei (5 workers / rl: {nucleiRateLimit})
          </span>
        </div>

        {/* Advanced Tool Parameters Dropdowns Panel */}
        {showAdvancedParams && (
          <div class="p-3 rounded bg-[#070a0f] border border-[#1b2230] space-y-3 mt-2 text-xs">
            <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
              {/* Subfinder Dropdowns */}
              <div class="space-y-1">
                <label class="kpi-label block text-[#06b6d4]">Subfinder · Fontes</label>
                <select
                  value={subfinderAll ? "all" : "default"}
                  onChange={(e) => setSubfinderAll((e.target as HTMLSelectElement).value === "all")}
                  class="input text-xs"
                >
                  <option value="all">Todas as Fontes OSINT (-all, scanmalware, hackertarget)</option>
                  <option value="default">Apenas Fontes Padrão / Rápidas</option>
                </select>
              </div>

              {/* dnsx Dropdowns */}
              <div class="space-y-1">
                <label class="kpi-label block text-[#06b6d4]">dnsx · Wildcard & Resolvers</label>
                <select
                  value={dnsxWildcard ? "wd_active" : "wd_off"}
                  onChange={(e) => setDnsxWildcard((e.target as HTMLSelectElement).value === "wd_active")}
                  class="input text-xs"
                >
                  <option value="wd_active">✓ Wildcard Filter Ativo (-wd, descarta *.docq.app falsos)</option>
                  <option value="wd_off">Wildcard Filter Desativado (resolver todos)</option>
                </select>
              </div>

              {/* httpx Ports */}
              <div class="space-y-1">
                <label class="kpi-label block text-[#06b6d4]">httpx · Portas Alvo</label>
                <select
                  value={httpxPorts}
                  onChange={(e) => setHttpxPorts((e.target as HTMLSelectElement).value)}
                  class="input text-xs"
                >
                  <option value="80,443,8080,8443">Portas Web Comuns (80, 443, 8080, 8443)</option>
                  <option value="80,443">Apenas Padrão (80, 443)</option>
                  <option value="80,443,8000,8080,8443,8888,9000,9443">Faixa Expandida (80,443,8000,8080,8443,8888,9000)</option>
                </select>
              </div>

              {/* Naabu Layer 4 TCP SYN */}
              <div class="space-y-1">
                <label class="kpi-label block text-[#06b6d4]">Naabu · Scan TCP L4 (SYN)</label>
                <select
                  value={naabuEnabled ? "on" : "off"}
                  onChange={(e) => setNaabuEnabled((e.target as HTMLSelectElement).value === "on")}
                  class="input text-xs"
                >
                  <option value="off">Desativado (Prosseguir direto para HTTP)</option>
                  <option value="on">Ativado (Scan TCP SYN antes de HTTP)</option>
                </select>
              </div>

              {/* TLSx SAN Extraction */}
              <div class="space-y-1">
                <label class="kpi-label block text-[#06b6d4]">TLSx · Certificados SSL</label>
                <select
                  value={tlsxEnabled ? "on" : "off"}
                  onChange={(e) => setTlsxEnabled((e.target as HTMLSelectElement).value === "on")}
                  class="input text-xs"
                >
                  <option value="off">Desativado (Padrão)</option>
                  <option value="on">Ativado (-san, inspecionar nomes alternativos)</option>
                </select>
              </div>

              {/* Nuclei Concurrency & Rate Limit */}
              <div class="space-y-1">
                <label class="kpi-label block text-[#06b6d4]">Nuclei · Workers & Taxa</label>
                <div class="grid grid-cols-2 gap-1.5">
                  <select
                    value={nucleiConcurrency}
                    onChange={(e) => setNucleiConcurrency(Number((e.target as HTMLSelectElement).value))}
                    class="input text-xs"
                    title="Concorrência máxima de domínios simultâneos"
                  >
                    <option value={5}>5 Workers (Máx)</option>
                    <option value={3}>3 Workers</option>
                    <option value={2}>2 Workers</option>
                    <option value={1}>1 Worker (Serial)</option>
                  </select>
                  <select
                    value={nucleiRateLimit}
                    onChange={(e) => setNucleiRateLimit(Number((e.target as HTMLSelectElement).value))}
                    class="input text-xs"
                    title="Rate limit por worker"
                  >
                    <option value={10}>10 req/s (Seguro)</option>
                    <option value={15}>15 req/s (Rápido)</option>
                  </select>
                </div>
              </div>
            </div>
          </div>
        )}
      </form>

      {/* Circuit Breaker Alerts & Per-Domain Cooldown Banner */}
      {circuitBreakerAlerts.length > 0 && (
        <div class="p-3 rounded-lg bg-[#1f1607] border border-[#d97706] text-xs space-y-2">
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-2">
              <span class="text-base">🛑</span>
              <span class="font-bold text-[#fbbf24] uppercase tracking-wide">
                Circuit Breaker Per-Domain Ativo ({circuitBreakerAlerts.length} alvo(s) em cooldown)
              </span>
            </div>
            <span class="text-[11px] font-mono text-[#fde68a]">
              Os outros workers continuam operando normalmente sem interrupção.
            </span>
          </div>
          <div class="flex flex-wrap gap-2">
            {circuitBreakerAlerts.map((alert) => (
              <div
                key={alert.domain}
                class="flex items-center gap-2 px-2.5 py-1 rounded bg-[#2e1d05] border border-[#b45309] text-[11px] font-mono text-white"
              >
                <span class="text-[#f87171] font-semibold">{alert.domain}</span>
                <span class="text-[#fbbf24]">({alert.reason})</span>
                <button
                  type="button"
                  onClick={() => handleResetCircuitBreaker(alert.domain)}
                  class="ml-1 text-[10px] px-1.5 py-0.5 rounded bg-[#451a03] hover:bg-[#78350f] text-[#fde68a] border border-[#78350f] cursor-pointer"
                >
                  Resetar
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Pipeline Automation Toolbar (Reconnaissance + Multi-Target Batch Scan + Network Monitor) */}
      <div class="flex flex-wrap items-center justify-between gap-2.5 p-3 rounded-lg bg-[#0d1117] border border-[#1b2230]">
        <div class="flex flex-wrap items-center gap-2">
          <span class="text-xs font-semibold text-white">Pipeline:</span>
          <span class="pill pill-cyan font-mono">{assets.length} ativos</span>
          <span class="pill pill-amber font-mono">RL: 10 req/s</span>
          {/* Live Network Health Badge */}
          <div class="flex items-center gap-1.5 px-2 py-0.5 rounded bg-[#070a0f] border border-[#1b2230] text-[11px] font-mono">
            <span class="h-1.5 w-1.5 rounded-full bg-[#10b981] animate-pulse" />
            <span class="text-[#7d8590]">Ping:</span>
            <span class="text-[#06b6d4] font-bold">{netHealth?.overall_latency_ms ?? 125}ms</span>
            <span class="text-[#7d8590]">Jitter:</span>
            <span class="text-[#e6edf3] font-bold">{netHealth?.overall_jitter_ms ?? 1.2}ms</span>
            <span class="text-[#7d8590]">Loss:</span>
            <span class="text-[#10b981] font-bold">{netHealth?.packet_loss_pct ?? 0}%</span>
          </div>
        </div>
        <div class="flex items-center gap-2">
          <button
            type="button"
            onClick={handleRunRecon}
            disabled={runningRecon || runningBatch || runningScan}
            class="btn btn-sm btn-ghost border border-[#2d3748] hover:border-cyan-500 text-cyan-400 text-xs flex items-center gap-1.5"
            title="Executar esteira Subfinder -> dnsx -> httpx para descobrir todos os subdomínios"
          >
            {runningRecon ? <span class="animate-spin">⏳</span> : <span>🌐</span>}
            <span>{runningRecon ? "Descobrindo Subdomínios..." : "Descobrir Subdomínios (Subfinder + dnsx + httpx)"}</span>
          </button>

          <button
            type="button"
            onClick={handleRunBatchScan}
            disabled={runningBatch || runningRecon || runningScan || assets.length === 0}
            class="btn btn-sm btn-cyan text-xs flex items-center gap-1.5 font-semibold"
            title="Escanear todos os subdomínios descobertos cirurgicamente por tecnologia com rate limit seguro de 10 req/s"
          >
            {runningBatch ? <span class="animate-spin">⏳</span> : <span>⚡</span>}
            <span>{runningBatch ? "Escaneando em Lote..." : `Escanear Todos em Lote (${assets.length} alvos)`}</span>
          </button>
        </div>
      </div>

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

            {/* HUD: Últimas 5 Linhas ao Vivo das Ferramentas */}
            <div class="p-2.5 bg-[#090d15] border-b border-[#1b2230] space-y-1.5">
              <div class="flex items-center justify-between">
                <span class="text-[10px] font-mono text-[#06b6d4] font-bold tracking-wider flex items-center gap-1.5">
                  <span class="h-1.5 w-1.5 rounded-full bg-[#06b6d4] animate-ping" />
                  ÚLTIMAS 5 LINHAS AO VIVO DOS SCANNERS (CLI OUTPUT)
                </span>
                <span class="text-[10px] font-mono text-[#7d8590]">stream ativo</span>
              </div>
              <div class="space-y-1 font-mono text-[11px]">
                {lastLiveLines.map((item) => (
                  <div key={item.id} class="flex items-start gap-2 bg-[#05070b]/60 px-2 py-1 rounded border border-[#1b2230]/40">
                    <span class={`pill text-[9px] px-1.5 py-0 font-bold shrink-0 ${
                      item.tool === "NUCLEI" ? "pill-cyan" :
                      item.tool === "SUBFINDER" ? "pill-emerald" :
                      item.tool === "HTTPX" ? "pill-purple" :
                      item.tool === "BATCH" ? "pill-amber" :
                      "pill-neutral"
                    }`}>
                      {item.tool}
                    </span>
                    <span class="text-[#7d8590] text-[10px] shrink-0">{item.time}</span>
                    <span class="text-[#e6edf3] truncate" title={item.text}>{item.text}</span>
                  </div>
                ))}
              </div>
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
