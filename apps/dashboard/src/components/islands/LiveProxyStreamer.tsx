import { useState, useEffect, useRef } from "preact/hooks";

export interface LiveProxyStreamerProps {
  wsBaseUrl?: string;
  apiBaseUrl?: string;
}

const SAMPLE_EVENTS = [
  {
    method: "GET",
    url: "https://scanme.nmap.org/",
    host: "scanme.nmap.org",
    status: 200,
    verdict: "ALLOWED",
    tier: "EXPLICIT_ALLOW",
    rate_limit: "0.5 req/s (Token Consumed: 1/1)",
    user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 [Cloaked]",
    redacted_headers: ["Authorization: [REDACTED]", "Cookie: [REDACTED]"],
    sha256: "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4",
  },
  {
    method: "GET",
    url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    host: "169.254.169.254",
    status: 403,
    verdict: "BLOCKED_SSRF",
    tier: "EXPLICIT_DENY",
    rate_limit: "N/A (Dropped Pre-Egress)",
    user_agent: "Blocked by ScopeGuard SSRF Filter",
    redacted_headers: [],
    sha256: "dropped-link-local-metadata-ssrf",
  },
  {
    method: "GET",
    url: "https://scanme.nmap.org/server-status",
    host: "scanme.nmap.org",
    status: 404,
    verdict: "ALLOWED",
    tier: "EXPLICIT_ALLOW",
    rate_limit: "0.5 req/s (Paced +2000ms via Valkey)",
    user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) [Cloaked]",
    redacted_headers: ["X-Api-Key: [REDACTED]"],
    sha256: "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
  },
  {
    method: "GET",
    url: "https://out-of-scope-partner.org/api/v1/health",
    host: "out-of-scope-partner.org",
    status: 403,
    verdict: "BLOCKED_SCOPE",
    tier: "UNKNOWN_DENY",
    rate_limit: "N/A (Dropped Fail-Closed)",
    user_agent: "Blocked by Fail-Closed ScopeEngine",
    redacted_headers: [],
    sha256: "dropped-fail-closed-unknown-deny",
  },
];

export default function LiveProxyStreamer({
  wsBaseUrl = "ws://127.0.0.1:8000",
  apiBaseUrl = "http://127.0.0.1:8000",
}: LiveProxyStreamerProps) {
  const [wsConnected, setWsConnected] = useState<boolean>(false);
  const [simulating, setSimulating] = useState<boolean>(true);
  const [events, setEvents] = useState<any[]>(() =>
    SAMPLE_EVENTS.map((ev, i) => ({
      ...ev,
      id: `init-${i}`,
      timestamp: new Date(Date.now() - (4 - i) * 2000).toISOString(),
    }))
  );

  const wsRef = useRef<WebSocket | null>(null);
  const simCounterRef = useRef<number>(0);

  useEffect(() => {
    let reconnectTimer: any = null;

    function connectWs() {
      try {
        const ws = new WebSocket(`${wsBaseUrl}/ws/proxy/live`);
        wsRef.current = ws;

        ws.onopen = () => {
          setWsConnected(true);
        };

        ws.onmessage = (e) => {
          try {
            const payload = JSON.parse(e.data);
            setEvents((prev) => [
              {
                id: `ws-${Date.now()}-${Math.random()}`,
                timestamp: payload.timestamp || new Date().toISOString(),
                method: payload.method || "GET",
                url: payload.url || "https://scanme.nmap.org/",
                host: payload.host || "scanme.nmap.org",
                status: payload.status ?? 200,
                verdict: payload.verdict || (payload.allowed === false ? "BLOCKED_SCOPE" : "ALLOWED"),
                tier: payload.tier || payload.precedence_tier || "EXPLICIT_ALLOW",
                rate_limit: payload.rate_limit || "0.5 req/s (Burst 1)",
                user_agent: payload.user_agent || "Mozilla/5.0 [Cloaked]",
                redacted_headers: payload.redacted_headers || ["Authorization: [REDACTED]"],
                sha256: payload.sha256 || "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
              },
              ...prev.slice(0, 49),
            ]);
          } catch {
            // Ignore malformed frame
          }
        };

        ws.onclose = () => {
          setWsConnected(false);
          reconnectTimer = setTimeout(connectWs, 4000);
        };
      } catch {
        setWsConnected(false);
      }
    }

    connectWs();

    return () => {
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (wsRef.current) wsRef.current.close();
    };
  }, [wsBaseUrl]);

  // Local simulation interval so operator can observe live token-bucket & redaction behavior
  useEffect(() => {
    if (!simulating) return;
    const timer = setInterval(() => {
      const sample = SAMPLE_EVENTS[simCounterRef.current % SAMPLE_EVENTS.length];
      simCounterRef.current += 1;
      setEvents((prev) => [
        {
          ...sample,
          id: `sim-${Date.now()}-${simCounterRef.current}`,
          timestamp: new Date().toISOString(),
        },
        ...prev.slice(0, 49),
      ]);
    }, 3500);
    return () => clearInterval(timer);
  }, [simulating]);

  const allowedCount = events.filter((e) => e.verdict === "ALLOWED").length;
  const blockedCount = events.filter((e) => e.verdict !== "ALLOWED").length;

  return (
    <div class="space-y-6 text-slate-100">
      {/* Top Status & Telemetry Controls */}
      <div class="flex flex-wrap items-center justify-between gap-4 bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-lg">
        <div class="flex items-center gap-3">
          <div class="h-10 w-10 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 font-bold font-mono">
            PX
          </div>
          <div>
            <h2 class="text-base font-semibold text-slate-100">
              Monitor de Egress Proxy Governado (`127.0.0.1:8080`)
            </h2>
            <p class="text-xs text-slate-400">
              Enforcement de Escopo em Tempo Real, Token-Bucket Valkey (`0.5 req/s`), Cloaking de User-Agent e Redação S3
            </p>
          </div>
        </div>

        <div class="flex items-center gap-3">
          <span
            class={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono border ${
              wsConnected
                ? "bg-emerald-500/15 text-emerald-300 border-emerald-500/30"
                : "bg-amber-500/15 text-amber-300 border-amber-500/30"
            }`}
          >
            <span class={`h-2 w-2 rounded-full ${wsConnected ? "bg-emerald-400 animate-ping" : "bg-amber-400"}`}></span>
            {wsConnected ? "WebSocket /ws/proxy/live Ativo" : "Stream Local (Simulador Ativo)"}
          </span>

          <button
            type="button"
            onClick={() => setSimulating((s) => !s)}
            class={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold border transition ${
              simulating
                ? "bg-cyan-500/20 text-cyan-300 border-cyan-500/40"
                : "bg-slate-800 text-slate-400 border-slate-700"
            }`}
          >
            {simulating ? "⏸ Pausar Simulação de Tráfego" : "▶ Ativar Simulação de Tráfego"}
          </button>
        </div>
      </div>

      {/* 3 Telemetry Gauge Cards */}
      <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Card 1: Valkey Token-Bucket Rate Limiter */}
        <div class="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-lg space-y-2">
          <div class="flex items-center justify-between">
            <span class="text-[11px] font-mono uppercase text-cyan-400">
              Valkey Token-Bucket Rate Limiter
            </span>
            <span class="px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-300 font-mono text-[10px] font-bold">
              ACTIVE
            </span>
          </div>
          <div class="text-xl font-bold font-mono text-slate-100">
            0.5 req/s <span class="text-xs font-normal text-slate-400">por host (Burst: 1)</span>
          </div>
          <p class="text-xs text-slate-400">
            Intervalo mínimo garantido de <code class="text-cyan-300 font-mono">2000ms</code> entre requisições para o mesmo destino, prevenindo bloqueios de WAF e sobrecarga.
          </p>
        </div>

        {/* Card 2: User-Agent Cloaking & Header Normalization */}
        <div class="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-lg space-y-2">
          <div class="flex items-center justify-between">
            <span class="text-[11px] font-mono uppercase text-emerald-400">
              User-Agent Cloaking &amp; Stealth
            </span>
            <span class="px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 font-mono text-[10px] font-bold">
              ENABLED
            </span>
          </div>
          <div class="text-xl font-bold font-mono text-slate-100">
            Rotação Determinística
          </div>
          <p class="text-xs text-slate-400">
            Substitui assinaturas padrão (`Nuclei`, `python-httpx`, `Go-http-client`) por perfis reais de navegador antes do envio.
          </p>
        </div>

        {/* Card 3: Secret Redactor & Forensic Tap */}
        <div class="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-lg space-y-2">
          <div class="flex items-center justify-between">
            <span class="text-[11px] font-mono uppercase text-amber-400">
              Secret Redaction (`bounty-safe-v1`)
            </span>
            <span class="px-2 py-0.5 rounded bg-amber-500/15 text-amber-300 font-mono text-[10px] font-bold">
              SHA-256 TAP
            </span>
          </div>
          <div class="text-xl font-bold font-mono text-slate-100">
            [REDACTED] Pre-Storage
          </div>
          <p class="text-xs text-slate-400">
            Sanitiza <code class="text-amber-300 font-mono">Authorization</code>, <code class="text-amber-300 font-mono">Cookie</code>, <code class="text-amber-300 font-mono">X-Api-Key</code> e Bearer JWTs antes de gravar no SeaweedFS S3.
          </p>
        </div>
      </div>

      {/* Live Egress Stream Feed */}
      <div class="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
        <div class="bg-slate-950 px-4 py-3 border-b border-slate-800 flex flex-wrap items-center justify-between gap-2 text-xs font-mono">
          <div class="flex items-center gap-4">
            <span class="text-slate-200 font-semibold">
              Feed Ao Vivo de Requisições Egress &amp; Bloqueios ScopeGuard
            </span>
            <span class="text-emerald-400">Permitidas: {allowedCount}</span>
            <span class="text-red-400">Bloqueadas (SSRF/Scope): {blockedCount}</span>
          </div>
          <button
            type="button"
            onClick={() => setEvents([])}
            class="text-slate-400 hover:text-slate-200 text-[11px]"
          >
            Limpar Feed
          </button>
        </div>

        <div class="divide-y divide-slate-800/70 max-h-[480px] overflow-y-auto">
          {events.map((ev) => {
            const isAllowed = ev.verdict === "ALLOWED";
            return (
              <div
                key={ev.id}
                class={`p-3.5 text-xs font-mono transition ${
                  isAllowed ? "hover:bg-slate-800/30" : "bg-red-950/20 hover:bg-red-950/30"
                }`}
              >
                <div class="flex flex-wrap items-center justify-between gap-2 mb-1.5">
                  <div class="flex items-center gap-2">
                    <span
                      class={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        isAllowed
                          ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40"
                          : "bg-red-500/20 text-red-300 border border-red-500/40"
                      }`}
                    >
                      {ev.verdict}
                    </span>
                    <span class="px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300 font-bold">
                      {ev.method}
                    </span>
                    <span class="text-slate-100 font-semibold break-all">{ev.url}</span>
                  </div>

                  <div class="flex items-center gap-3 text-[11px]">
                    <span class="text-amber-300">Tier: {ev.tier}</span>
                    <span class="text-slate-400">HTTP {ev.status}</span>
                    <span class="text-slate-500">{ev.timestamp?.split("T")[1]?.slice(0, 8)}</span>
                  </div>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-3 gap-2 text-[11px] text-slate-400 bg-slate-950/70 p-2 rounded border border-slate-800/80">
                  <div>
                    <span class="text-slate-500">Rate Limit: </span>
                    <span class="text-cyan-300">{ev.rate_limit}</span>
                  </div>
                  <div class="truncate">
                    <span class="text-slate-500">UA Cloaking: </span>
                    <span class="text-slate-300">{ev.user_agent}</span>
                  </div>
                  <div class="truncate">
                    <span class="text-slate-500">Redacted: </span>
                    <span class="text-amber-300">
                      {ev.redacted_headers?.length
                        ? ev.redacted_headers.join(", ")
                        : "Nenhum segredo presente"}
                    </span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
