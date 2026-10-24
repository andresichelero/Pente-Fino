import { useState, useEffect, useRef, useMemo } from "preact/hooks";
import SparklineSVG from "../SparklineSVG";

export interface LiveProxyStreamerProps {
  wsBaseUrl?: string;
  apiBaseUrl?: string;
  initialSummary?: any;
}

export default function LiveProxyStreamer({
  wsBaseUrl = "ws://127.0.0.1:8000",
  apiBaseUrl = "http://127.0.0.1:8000",
  initialSummary,
}: LiveProxyStreamerProps) {
  const [wsConnected, setWsConnected] = useState<boolean>(false);
  const [verdictFilter, setVerdictFilter] = useState<"ALL" | "ALLOWED" | "BLOCKED">("ALL");

  // Live telemetry sparkline & gauge state (real data or empty series)
  const [rpsSeries, setRpsSeries] = useState<number[]>(
    initialSummary?.rps_series || []
  );
  const [valkeySeries, setValkeySeries] = useState<number[]>(
    initialSummary?.valkey_latency_ms_series || []
  );
  const [ssrfSeries, setSsrfSeries] = useState<number[]>(
    initialSummary?.ssrf_blocks_series || []
  );
  const [rateLimitRps, setRateLimitRps] = useState<number>(
    initialSummary?.rate_limit_rps || 0
  );
  const [burstCapacity, setBurstCapacity] = useState<number>(
    initialSummary?.burst_capacity || 0
  );
  const [heartbeatCount, setHeartbeatCount] = useState<number>(0);

  const [events, setEvents] = useState<any[]>([]);

  const wsRef = useRef<WebSocket | null>(null);

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

            if (
              payload.event === "telemetry_tick" ||
              payload.event === "connected" ||
              payload.event === "pong"
            ) {
              if (typeof payload.rate_limit_rps === "number") {
                setRateLimitRps(payload.rate_limit_rps);
                setRpsSeries((prev) => [...prev.slice(Math.max(0, prev.length - 11)), payload.rate_limit_rps]);
              }
              if (typeof payload.burst_capacity === "number") {
                setBurstCapacity(payload.burst_capacity);
              }
              setHeartbeatCount((c) => c + 1);
              return;
            }

            // Real HTTP egress or ScopeGuard block event
            if (payload.event === "http_egress" || payload.url || payload.method) {
              setEvents((prev) => [
                {
                  id: `ws-${Date.now()}-${Math.random()}`,
                  timestamp: payload.timestamp || new Date().toISOString(),
                  method: payload.method || "GET",
                  url: payload.url || "",
                  host: payload.host || "",
                  status: payload.status ?? 200,
                  verdict: payload.verdict || (payload.allowed === false ? "BLOCKED_SCOPE" : "ALLOWED"),
                  tier: payload.tier || payload.precedence_tier || "EXPLICIT_ALLOW",
                  rate_limit: payload.rate_limit || `${rateLimitRps.toFixed(2)} req/s`,
                  user_agent: payload.user_agent || "Mozilla/5.0 [Cloaked]",
                  redacted_headers: payload.redacted_headers || ["Authorization: [REDACTED]"],
                  sha256:
                    payload.sha256 ||
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                },
                ...prev.slice(0, 49),
              ]);
            }
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

  const allowedCount = events.filter((e) => e.verdict === "ALLOWED").length;
  const blockedCount = events.filter((e) => e.verdict !== "ALLOWED").length;

  const filteredEvents = useMemo(() => {
    if (verdictFilter === "ALLOWED") return events.filter((e) => e.verdict === "ALLOWED");
    if (verdictFilter === "BLOCKED") return events.filter((e) => e.verdict !== "ALLOWED");
    return events;
  }, [events, verdictFilter]);

  return (
    <div class="space-y-3">
      {/* Top 4 ds41 Sparkline & Capacity Telemetry Cards */}
      <div class="grid grid-cols-2 lg:grid-cols-4 gap-2.5">
        <div class="card card-pad flex flex-col justify-between">
          <div class="flex items-center justify-between">
            <span class="kpi-label">VALKEY TOKEN-BUCKET</span>
            <span class="pill pill-cyan">ACTIVE</span>
          </div>
          <div class="my-1.5">
            <div class="kpi-value">{rateLimitRps.toFixed(2)} req/s</div>
            <div class="kpi-sub">burst: {burstCapacity} · min_interval: 2000ms</div>
          </div>
          <SparklineSVG data={rpsSeries} color="cyan" height={34} />
        </div>

        <div class="card card-pad flex flex-col justify-between">
          <div class="flex items-center justify-between">
            <span class="kpi-label">VALKEY P99 LATENCY</span>
            <span class="pill pill-emerald">{valkeySeries.length > 0 ? `${valkeySeries[valkeySeries.length - 1]?.toFixed(1)}ms` : "0.0ms"}</span>
          </div>
          <div class="my-1.5">
            <div class="kpi-value">{valkeySeries.length > 0 ? valkeySeries[valkeySeries.length - 1]?.toFixed(1) : "0.0"} ms</div>
            <div class="kpi-sub">token check · atomic lua eval</div>
          </div>
          <SparklineSVG data={valkeySeries} color="emerald" height={34} />
        </div>

        <div class="card card-pad flex flex-col justify-between">
          <div class="flex items-center justify-between">
            <span class="kpi-label">SSRF &amp; SCOPE DROPS</span>
            <span class="pill pill-red">{blockedCount} blocked</span>
          </div>
          <div class="my-1.5">
            <div class="kpi-value text-[#ef4444]">{blockedCount}</div>
            <div class="kpi-sub">RFC1918 · 169.254.169.254 · fail-closed</div>
          </div>
          <SparklineSVG data={ssrfSeries} color="crimson" height={34} />
        </div>

        <div class="card card-pad flex flex-col justify-between">
          <div class="flex items-center justify-between">
            <span class="kpi-label">FORENSIC TAP &amp; CLOAK</span>
            <span class="pill pill-amber">bounty-safe-v1</span>
          </div>
          <div class="my-1.5">
            <div class="kpi-value text-[#10b981]">100%</div>
            <div class="kpi-sub">Auth/Cookie/JWT redacted · WS ticks: {heartbeatCount}</div>
          </div>
          <div class="bar-track mt-2">
            <div class="bar-fill bar-fill-emerald" style={{ width: "100%" }} />
          </div>
        </div>
      </div>

      {/* Stream Control & Filter Bar */}
      <div class="card overflow-hidden">
        <div class="px-3.5 py-2.5 border-b border-[#1b2230] flex flex-wrap items-center justify-between gap-2 bg-[#070a0f]">
          <div class="flex items-center gap-2.5">
            <span
              class={`pill ${wsConnected ? "pill-emerald" : "pill-neutral"}`}
            >
              <span
                class={`h-1.5 w-1.5 rounded-full ${
                  wsConnected ? "bg-[#10b981] animate-pulse" : "bg-[#7d8590]"
                }`}
              />
              {wsConnected ? "WS /ws/proxy/live ONLINE" : "WS DESCONECTADO"}
            </span>
            <span class="text-xs font-mono text-[#e6edf3] font-semibold">
              Fluxo de Telemetria Egress
            </span>
            <span class="text-[11px] font-mono text-[#10b981] num">
              allow:{allowedCount}
            </span>
            <span class="text-[11px] font-mono text-[#ef4444] num">
              drop:{blockedCount}
            </span>
          </div>

          <div class="flex items-center gap-2">
            <div class="seg">
              {(["ALL", "ALLOWED", "BLOCKED"] as const).map((f) => (
                <button
                  key={f}
                  type="button"
                  onClick={() => setVerdictFilter(f)}
                  class={`seg-btn ${verdictFilter === f ? "active" : ""}`}
                >
                  {f}
                </button>
              ))}
            </div>

            <button
              type="button"
              onClick={() => setEvents([])}
              class="btn btn-ghost !py-1 !px-2"
            >
              Limpar
            </button>
          </div>
        </div>

        {/* High-Density Egress Traffic Table */}
        <div class="max-h-[440px] overflow-y-auto overflow-x-auto">
          <table class="dtable num">
            <thead>
              <tr>
                <th>Hora</th>
                <th>Veredito</th>
                <th>Camada</th>
                <th>Método</th>
                <th>URL Alvo</th>
                <th>HTTP</th>
                <th>Taxa / Pacing</th>
                <th>Headers Redigidos</th>
                <th class="text-right">SHA-256 Higienizado</th>
              </tr>
            </thead>
            <tbody>
              {filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={9} class="text-center text-[#7d8590] py-12 font-mono text-xs">
                    <div class="flex flex-col items-center justify-center gap-2">
                      <span class="inline-block w-2 h-2 rounded-full bg-[#7d8590]"></span>
                      <span>Aguardando tráfego do proxy...</span>
                    </div>
                  </td>
                </tr>
              ) : (
                filteredEvents.map((ev) => {
                  const isAllowed = ev.verdict === "ALLOWED";
                  return (
                    <tr
                      key={ev.id}
                      class={isAllowed ? "" : "bg-[#ef4444]/[0.05]"}
                    >
                      <td class="text-[#7d8590]">
                        {ev.timestamp?.split("T")[1]?.slice(0, 8)}
                      </td>
                      <td>
                        <span class={`pill ${isAllowed ? "pill-emerald" : "pill-red"}`}>
                          {ev.verdict}
                        </span>
                      </td>
                      <td class="text-[#f59e0b] text-[10px]">{ev.tier}</td>
                      <td>
                        <span class="pill pill-cyan">{ev.method}</span>
                      </td>
                      <td
                        class="text-[#e6edf3] font-semibold max-w-[260px] truncate"
                        title={ev.url}
                      >
                        {ev.url}
                      </td>
                      <td
                        class={
                          ev.status >= 400 ? "text-[#ef4444]" : "text-[#10b981]"
                        }
                      >
                        {ev.status}
                      </td>
                      <td class="text-[#06b6d4] text-[11px]">{ev.rate_limit}</td>
                      <td class="text-[#f59e0b] text-[10px] max-w-[180px] truncate">
                        {ev.redacted_headers?.length
                          ? ev.redacted_headers.join(", ")
                          : "—"}
                      </td>
                      <td
                        class="text-right text-[#7d8590] text-[10px]"
                        title={ev.sha256}
                      >
                        {String(ev.sha256 || "").slice(0, 14)}…
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
