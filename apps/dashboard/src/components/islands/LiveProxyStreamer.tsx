import { useState, useEffect, useRef, useMemo } from "preact/hooks";
import SparklineSVG from "../SparklineSVG";

export interface LiveProxyStreamerProps {
  wsBaseUrl?: string;
  apiBaseUrl?: string;
  initialSummary?: any;
}

const SAMPLE_EVENTS = [
  {
    method: "GET",
    url: "https://scanme.nmap.org/",
    host: "scanme.nmap.org",
    status: 200,
    verdict: "ALLOWED",
    tier: "EXPLICIT_ALLOW",
    rate_limit: "0.50 req/s (Token 1/1)",
    user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) [Cloaked]",
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
    rate_limit: "Dropped Pre-Egress",
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
    rate_limit: "0.50 req/s (+2000ms paced)",
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
    rate_limit: "Dropped Fail-Closed",
    user_agent: "Blocked by Fail-Closed ScopeEngine",
    redacted_headers: [],
    sha256: "dropped-fail-closed-unknown-deny",
  },
];

export default function LiveProxyStreamer({
  wsBaseUrl = "ws://127.0.0.1:8000",
  apiBaseUrl = "http://127.0.0.1:8000",
  initialSummary,
}: LiveProxyStreamerProps) {
  const [wsConnected, setWsConnected] = useState<boolean>(false);
  const [simulating, setSimulating] = useState<boolean>(true);
  const [verdictFilter, setVerdictFilter] = useState<"ALL" | "ALLOWED" | "BLOCKED">("ALL");

  // Live telemetry sparkline & gauge state
  const [rpsSeries, setRpsSeries] = useState<number[]>(
    initialSummary?.rps_series || [0.42, 0.48, 0.5, 0.49, 0.5, 0.45, 0.5, 0.48, 0.5, 0.5, 0.47, 0.5]
  );
  const [valkeySeries, setValkeySeries] = useState<number[]>(
    initialSummary?.valkey_latency_ms_series || [0.8, 0.9, 0.7, 0.8, 1.1, 0.9, 0.8, 0.7, 0.9, 0.8, 0.8, 0.9]
  );
  const [ssrfSeries, setSsrfSeries] = useState<number[]>(
    initialSummary?.ssrf_blocks_series || [0, 0, 1, 0, 0, 2, 0, 1, 0, 0, 1, 0]
  );
  const [rateLimitRps, setRateLimitRps] = useState<number>(0.5);
  const [burstCapacity, setBurstCapacity] = useState<number>(1);
  const [heartbeatCount, setHeartbeatCount] = useState<number>(0);

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

            // Fix Sector 2 Bug #3: Do NOT treat telemetry_tick / connected / pong frames as HTTP requests!
            if (
              payload.event === "telemetry_tick" ||
              payload.event === "connected" ||
              payload.event === "pong"
            ) {
              if (typeof payload.rate_limit_rps === "number") {
                setRateLimitRps(payload.rate_limit_rps);
                setRpsSeries((prev) => [...prev.slice(1), payload.rate_limit_rps]);
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
                  url: payload.url || "https://scanme.nmap.org/",
                  host: payload.host || "scanme.nmap.org",
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

  // Local traffic simulation for live demonstration when proxy is idle
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
      setRpsSeries((prev) => [
        ...prev.slice(1),
        sample.verdict === "ALLOWED" ? 0.5 : 0.45,
      ]);
      setValkeySeries((prev) => [
        ...prev.slice(1),
        Number((0.7 + (simCounterRef.current % 4) * 0.1).toFixed(1)),
      ]);
      setSsrfSeries((prev) => [
        ...prev.slice(1),
        sample.verdict === "BLOCKED_SSRF" ? 1 : 0,
      ]);
    }, 3500);
    return () => clearInterval(timer);
  }, [simulating]);

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
          <SparklineSVG data={rpsSeries} color="#06b6d4" height={34} />
        </div>

        <div class="card card-pad flex flex-col justify-between">
          <div class="flex items-center justify-between">
            <span class="kpi-label">VALKEY P99 LATENCY</span>
            <span class="pill pill-emerald">0.8ms</span>
          </div>
          <div class="my-1.5">
            <div class="kpi-value">{valkeySeries[valkeySeries.length - 1]?.toFixed(1)} ms</div>
            <div class="kpi-sub">token check · atomic lua eval</div>
          </div>
          <SparklineSVG data={valkeySeries} color="#10b981" height={34} />
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
          <SparklineSVG data={ssrfSeries} color="#ef4444" height={34} />
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
              class={`pill ${wsConnected ? "pill-emerald" : "pill-amber"}`}
            >
              <span
                class={`h-1.5 w-1.5 rounded-full ${
                  wsConnected ? "bg-[#10b981] animate-pulse" : "bg-[#f59e0b]"
                }`}
              />
              {wsConnected ? "WS /ws/proxy/live ONLINE" : "LOCAL STREAM SIMULATOR"}
            </span>
            <span class="text-xs font-mono text-[#e6edf3] font-semibold">
              Egress HTTP &amp; ScopeGuard Audit Stream
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
              onClick={() => setSimulating((s) => !s)}
              class={`btn ${simulating ? "btn-cyan" : "btn-ghost"} !py-1 !px-2.5`}
            >
              {simulating ? "⏸ Pause Sim" : "▶ Resume Sim"}
            </button>

            <button
              type="button"
              onClick={() => setEvents([])}
              class="btn btn-ghost !py-1 !px-2"
            >
              Clear
            </button>
          </div>
        </div>

        {/* High-Density Egress Traffic Table (ds41 SESSION BENCHMARKS style) */}
        <div class="max-h-[440px] overflow-y-auto overflow-x-auto">
          <table class="dtable num">
            <thead>
              <tr>
                <th>Time</th>
                <th>Verdict</th>
                <th>Tier</th>
                <th>Method</th>
                <th>Target URL</th>
                <th>HTTP</th>
                <th>Pacing / Rate</th>
                <th>Redacted Headers</th>
                <th class="text-right">Sanitized SHA-256</th>
              </tr>
            </thead>
            <tbody>
              {filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={9} class="text-center text-[#7d8590] py-6">
                    No egress requests matching filter ({verdictFilter}).
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
