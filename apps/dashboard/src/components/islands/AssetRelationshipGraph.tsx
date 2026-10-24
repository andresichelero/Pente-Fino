import { useState, useEffect, useMemo } from "preact/hooks";

export interface AssetRelationshipGraphProps {
  programs?: any[];
  initialSlug?: string;
  initialGraph?: any;
  initialAssets?: any[];
  apiBaseUrl?: string;
}

const SCOPE_COLORS: Record<string, string> = {
  in_scope_explicit: "#34d399",
  in_scope_derived: "#22d3ee",
  candidate: "#fbbf24",
  out_of_scope: "#f87171",
};

export default function AssetRelationshipGraph({
  programs = [],
  initialSlug = "",
  initialGraph = null,
  initialAssets = [],
  apiBaseUrl = "http://127.0.0.1:8000",
}: AssetRelationshipGraphProps) {
  const [selectedSlug, setSelectedSlug] = useState<string>(
    initialSlug || (programs[0]?.slug ?? "nmap-scanme")
  );
  const [viewMode, setViewMode] = useState<"graph" | "table">("graph");
  const [inspectorTab, setInspectorTab] = useState<"summary" | "dns" | "http" | "json">("summary");
  const [graphData, setGraphData] = useState<any>(
    initialGraph || { nodes: [], edges: [] }
  );
  const [assets, setAssets] = useState<any[]>(initialAssets);
  const [selectedNode, setSelectedNode] = useState<any | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [zoom, setZoom] = useState<number>(1);

  useEffect(() => {
    if (selectedSlug) {
      if (
        selectedSlug === initialSlug &&
        initialGraph?.nodes &&
        initialGraph.nodes.length > 0
      ) {
        const firstAsset =
          initialGraph.nodes.find((n: any) => n.node_type === "asset" || n.data?.type === "asset") ||
          initialGraph.nodes[0];
        setSelectedNode(firstAsset?.data ? firstAsset.data : firstAsset);
        return;
      }
      fetchAssetGraphAndList(selectedSlug);
    }
  }, [selectedSlug]);

  async function fetchAssetGraphAndList(slug: string) {
    setLoading(true);
    try {
      const [graphRes, assetsRes] = await Promise.all([
        fetch(`${apiBaseUrl}/api/v1/programs/${slug}/assets/graph`),
        fetch(`${apiBaseUrl}/api/v1/programs/${slug}/assets`),
      ]);
      if (graphRes.ok) {
        const gData = await graphRes.json();
        if (gData.nodes?.length > 0) {
          setGraphData(gData);
          const firstAsset = gData.nodes.find((n: any) => n.node_type === "asset") || gData.nodes[0];
          setSelectedNode(firstAsset);
        }
      }
      if (assetsRes.ok) {
        const aData = await assetsRes.json();
        setAssets(Array.isArray(aData) ? aData : aData.assets || []);
      }
    } catch {
      // Offline fallback below
    } finally {
      setGraphData((curr: any) => {
        if (curr?.nodes?.length > 0) return curr;
        const fallbackNodes = [
          {
            id: `program:${slug}`,
            label: slug,
            node_type: "program",
            metadata: { slug, platform: "hackerone", state: "active" },
          },
          {
            id: "asset:scanme.nmap.org",
            label: "scanme.nmap.org",
            node_type: "asset",
            scope_state: "in_scope_explicit",
            asset_type: "domain",
            metadata: { canonical_key: "scanme.nmap.org", scopable: true, findings_count: 1 },
          },
          {
            id: "ip:45.33.32.156",
            label: "45.33.32.156",
            node_type: "observed_ip",
            scope_state: "dns_metadata_only",
            asset_type: "ip",
            metadata: { ip: "45.33.32.156", scopable: false, dns_metadata_only: true },
          },
          {
            id: "tech:apache",
            label: "apache",
            node_type: "technology",
            metadata: { is_pruned_cdn: false, category: "application_stack" },
          },
          {
            id: "tech:cloudflare",
            label: "cloudflare",
            node_type: "technology",
            metadata: { is_pruned_cdn: true, category: "edge_cdn_waf" },
          },
        ];
        const fallbackEdges = [
          { source: `program:${slug}`, target: "asset:scanme.nmap.org", relation: "HAS_ASSET" },
          { source: "asset:scanme.nmap.org", target: "ip:45.33.32.156", relation: "RESOLVES_TO" },
          { source: "asset:scanme.nmap.org", target: "tech:apache", relation: "RUNS_TECH" },
          { source: "asset:scanme.nmap.org", target: "tech:cloudflare", relation: "RUNS_TECH" },
        ];
        setSelectedNode(fallbackNodes[1]);
        return { program_slug: slug, nodes: fallbackNodes, edges: fallbackEdges };
      });
      setLoading(false);
    }
  }

  // Deterministic non-colliding layered layout (Program root at y=68, columns start at y=155)
  const positionedGraph = useMemo(() => {
    const rawNodes: any[] = graphData?.nodes || [];
    const rawEdges: any[] = graphData?.edges || [];

    const nodes = rawNodes.map((n) => (n.data ? { ...n.data, node_type: n.data.type || n.node_type } : n));
    const edges = rawEdges.map((e) => (e.data ? e.data : e));

    const programNodes = nodes.filter((n) => n.node_type === "program");
    const assetNodes = nodes.filter((n) => n.node_type === "asset");
    const ipNodes = nodes.filter((n) => n.node_type === "observed_ip" || n.node_type === "observation_ip");
    const techNodes = nodes.filter((n) => n.node_type === "technology");

    const posMap: Record<string, { x: number; y: number; node: any }> = {};

    // Top Center: Program Root Node (y=68) — never collides with assets
    programNodes.forEach((n, idx) => {
      posMap[n.id] = { x: 440 + idx * 180, y: 68, node: n };
    });

    // Center Column: Scoped Assets (starting at y=160)
    assetNodes.forEach((n, idx) => {
      posMap[n.id] = { x: 440, y: 160 + idx * 88, node: n };
    });

    // Left Column: Observed DNS IPs (starting at y=160)
    ipNodes.forEach((n, idx) => {
      posMap[n.id] = { x: 145, y: 160 + idx * 84, node: n };
    });

    // Right Column: Technologies & Pruned CDN/WAFs (starting at y=150)
    techNodes.forEach((n, idx) => {
      posMap[n.id] = { x: 735, y: 150 + idx * 74, node: n };
    });

    // Any remaining nodes
    nodes.forEach((n, idx) => {
      if (!posMap[n.id]) {
        posMap[n.id] = { x: 440, y: 160 + (assetNodes.length + idx) * 84, node: n };
      }
    });

    const maxCount = Math.max(assetNodes.length, ipNodes.length, techNodes.length, 3);
    const canvasHeight = Math.max(460, 190 + maxCount * 88);

    return { posMap, nodes, edges, canvasHeight };
  }, [graphData]);

  const selectedAssetDetails = useMemo(() => {
    if (!selectedNode) return null;
    const key = selectedNode.metadata?.canonical_key || selectedNode.label;
    return assets.find((a) => a.canonical_key === key || a.id === selectedNode.id) || null;
  }, [selectedNode, assets]);

  const dnsObservations = useMemo(() => {
    return (selectedAssetDetails?.observations || []).filter((o: any) => o.observation_type === "dns");
  }, [selectedAssetDetails]);

  const httpObservations = useMemo(() => {
    return (selectedAssetDetails?.observations || []).filter((o: any) =>
      ["http", "http_probe"].includes(o.observation_type)
    );
  }, [selectedAssetDetails]);

  return (
    <div class="space-y-4">
      {/* Compact Top Control Bar */}
      <div class="card card-pad flex flex-wrap items-center justify-between gap-3">
        <div class="flex items-center gap-3 flex-wrap">
          <span class="card-title">TOPOLOGY &amp; SURFACE EXPLORER</span>
          {programs.length > 0 && (
            <select
              value={selectedSlug}
              onChange={(e) => setSelectedSlug((e.target as HTMLSelectElement).value)}
              class="input !w-auto min-w-[200px]"
            >
              {programs.map((p) => (
                <option key={p.slug} value={p.slug}>
                  {p.name} ({p.slug})
                </option>
              ))}
            </select>
          )}
          <span class="pill text-[#22d3ee] num">{positionedGraph.nodes.length} nodes</span>
          <span class="pill num">{positionedGraph.edges.length} edges</span>
        </div>

        <div class="seg" role="tablist">
          <button
            type="button"
            aria-selected={viewMode === "graph"}
            onClick={() => setViewMode("graph")}
          >
            Topological Graph
          </button>
          <button
            type="button"
            aria-selected={viewMode === "table"}
            onClick={() => setViewMode("table")}
          >
            Assets Table ({assets.length})
          </button>
        </div>
      </div>

      {viewMode === "graph" ? (
        <div class="grid grid-cols-1 lg:grid-cols-12 gap-4">
          {/* Interactive SVG Canvas (8 cols) */}
          <div class="lg:col-span-8 card overflow-hidden flex flex-col">
            <div class="px-4 py-2.5 border-b border-[#1b2230] flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono">
              <div class="flex flex-wrap items-center gap-3">
                <span class="flex items-center gap-1.5 text-[#34d399]">
                  <span class="dot"></span> explicit
                </span>
                <span class="flex items-center gap-1.5 text-[#22d3ee]">
                  <span class="dot"></span> derived
                </span>
                <span class="flex items-center gap-1.5 text-[#a78bfa]">
                  <span class="dot"></span> observed_ip (DNS only)
                </span>
                <span class="flex items-center gap-1.5 text-[#fbbf24]">
                  <span class="dot"></span> CDN pruned
                </span>
              </div>

              <div class="flex items-center gap-1.5 num">
                <button
                  type="button"
                  onClick={() => setZoom((z) => Math.max(0.65, +(z - 0.15).toFixed(2)))}
                  class="btn !min-h-[24px] !px-2"
                >
                  -
                </button>
                <span class="text-[#8b98a9] w-11 text-center">{Math.round(zoom * 100)}%</span>
                <button
                  type="button"
                  onClick={() => setZoom((z) => Math.min(1.45, +(z + 0.15).toFixed(2)))}
                  class="btn !min-h-[24px] !px-2"
                >
                  +
                </button>
              </div>
            </div>

            <div class="relative flex-1 bg-[#070a0f] overflow-auto">
              {loading && (
                <div class="absolute inset-0 flex items-center justify-center bg-[#070a0f]/75 z-10 text-xs font-mono text-[#22d3ee]">
                  Rendering topology...
                </div>
              )}

              <svg
                viewBox={`0 0 880 ${positionedGraph.canvasHeight}`}
                class="w-full select-none block"
                style={{
                  minHeight: "460px",
                  height: `${positionedGraph.canvasHeight}px`,
                  transform: `scale(${zoom})`,
                  transformOrigin: "center top",
                }}
              >
                <defs>
                  <pattern id="pf-grid" width="28" height="28" patternUnits="userSpaceOnUse">
                    <path d="M 28 0 L 0 0 0 28" fill="none" stroke="#141b26" stroke-width="0.8" />
                  </pattern>
                </defs>
                <rect width="880" height={positionedGraph.canvasHeight} fill="url(#pf-grid)" />

                {/* Column Titles */}
                <text x="145" y="26" text-anchor="middle" fill="#a78bfa" font-size="10" font-family="monospace">
                  OBSERVED DNS IPs (SCOPABLE=FALSE)
                </text>
                <text x="440" y="26" text-anchor="middle" fill="#34d399" font-size="10" font-family="monospace">
                  PROGRAM &amp; SCOPED ASSETS
                </text>
                <text x="735" y="26" text-anchor="middle" fill="#22d3ee" font-size="10" font-family="monospace">
                  TECH STACK &amp; PRUNED CDN
                </text>

                {/* Edges with Animated Flow on Active Selection */}
                {positionedGraph.edges.map((edge, idx) => {
                  const src = positionedGraph.posMap[edge.source];
                  const dst = positionedGraph.posMap[edge.target];
                  if (!src || !dst) return null;
                  const isDnsMeta =
                    edge.relation.toLowerCase().includes("resolve") ||
                    dst.node.node_type === "observed_ip";
                  const isPrunedCdn = Boolean(dst.node.metadata?.is_pruned_cdn);
                  const isConnectedToSelected =
                    selectedNode &&
                    (edge.source === selectedNode.id || edge.target === selectedNode.id);

                  const stroke = isDnsMeta
                    ? "#a78bfa"
                    : isPrunedCdn
                    ? "#fbbf24"
                    : "#22d3ee";

                  return (
                    <g key={idx}>
                      <line
                        x1={src.x}
                        y1={src.y}
                        x2={dst.x}
                        y2={dst.y}
                        stroke={stroke}
                        stroke-width={isConnectedToSelected ? "2.2" : "1.4"}
                        stroke-dasharray={isConnectedToSelected ? "6,4" : isDnsMeta || isPrunedCdn ? "4,4" : "none"}
                        style={
                          isConnectedToSelected
                            ? { animation: "flow 1.2s linear infinite" }
                            : undefined
                        }
                        opacity={isConnectedToSelected ? "0.95" : "0.45"}
                      />
                      <text
                        x={(src.x + dst.x) / 2}
                        y={(src.y + dst.y) / 2 - 5}
                        text-anchor="middle"
                        fill="#738196"
                        font-size="8.5"
                        font-family="monospace"
                      >
                        {edge.relation}
                      </text>
                    </g>
                  );
                })}

                {/* Nodes */}
                {positionedGraph.nodes.map((node) => {
                  const pos = positionedGraph.posMap[node.id];
                  if (!pos) return null;
                  const isSelected = selectedNode?.id === node.id;

                  if (node.node_type === "program") {
                    return (
                      <g
                        key={node.id}
                        transform={`translate(${pos.x}, ${pos.y})`}
                        onClick={() => setSelectedNode(node)}
                        style={{ cursor: "pointer" }}
                      >
                        <rect
                          x="-105"
                          y="-20"
                          width="210"
                          height="40"
                          rx="20"
                          fill="#11161f"
                          stroke={isSelected ? "#34d399" : "#263042"}
                          stroke-width={isSelected ? "2.2" : "1.4"}
                        />
                        <text x="0" y="-2" text-anchor="middle" fill="#e6edf3" font-size="11" font-family="monospace" font-weight="bold">
                          ● {node.label}
                        </text>
                        <text x="0" y="11" text-anchor="middle" fill="#34d399" font-size="8.5" font-family="monospace">
                          PROGRAM ROOT
                        </text>
                      </g>
                    );
                  }

                  if (node.node_type === "observed_ip" || node.node_type === "observation_ip") {
                    return (
                      <g
                        key={node.id}
                        transform={`translate(${pos.x}, ${pos.y})`}
                        onClick={() => setSelectedNode(node)}
                        style={{ cursor: "pointer" }}
                      >
                        <rect
                          x="-110"
                          y="-24"
                          width="220"
                          height="48"
                          rx="8"
                          fill="#131129"
                          stroke={isSelected ? "#c4b5fd" : "#a78bfa"}
                          stroke-width={isSelected ? "2.4" : "1.4"}
                          stroke-dasharray="5,4"
                        />
                        <text x="0" y="-3" text-anchor="middle" fill="#ede9fe" font-size="11.5" font-family="monospace" font-weight="bold">
                          {node.label}
                        </text>
                        <text x="0" y="12" text-anchor="middle" fill="#a78bfa" font-size="8.5" font-family="monospace">
                          DNS METADATA ONLY · UNSCOPED
                        </text>
                      </g>
                    );
                  }

                  if (node.node_type === "technology") {
                    const isPruned = Boolean(node.metadata?.is_pruned_cdn);
                    return (
                      <g
                        key={node.id}
                        transform={`translate(${pos.x}, ${pos.y})`}
                        onClick={() => setSelectedNode(node)}
                        style={{ cursor: "pointer" }}
                      >
                        <rect
                          x="-98"
                          y="-21"
                          width="196"
                          height="42"
                          rx="18"
                          fill={isPruned ? "#231707" : "#09222c"}
                          stroke={isPruned ? "#fbbf24" : "#22d3ee"}
                          stroke-width={isSelected ? "2.4" : "1.4"}
                        />
                        <text
                          x="0"
                          y="-2"
                          text-anchor="middle"
                          fill={isPruned ? "#fde68a" : "#cffafe"}
                          font-size="11.5"
                          font-family="monospace"
                          font-weight="bold"
                          text-decoration={isPruned ? "line-through" : "none"}
                        >
                          {node.label}
                        </text>
                        <text
                          x="0"
                          y="11"
                          text-anchor="middle"
                          fill={isPruned ? "#fbbf24" : "#22d3ee"}
                          font-size="8"
                          font-family="monospace"
                        >
                          {isPruned ? "CDN/WAF PRUNED" : "APP STACK TARGET"}
                        </text>
                      </g>
                    );
                  }

                  const strokeColor = SCOPE_COLORS[node.scope_state || "in_scope_explicit"] || "#34d399";
                  return (
                    <g
                      key={node.id}
                      transform={`translate(${pos.x}, ${pos.y})`}
                      onClick={() => setSelectedNode(node)}
                      style={{ cursor: "pointer" }}
                    >
                      <rect
                        x="-115"
                        y="-25"
                        width="230"
                        height="50"
                        rx="9"
                        fill="#0d1117"
                        stroke={strokeColor}
                        stroke-width={isSelected ? "2.6" : "1.6"}
                      />
                      <circle cx="-96" cy="-4" r="4" fill={strokeColor} />
                      <text x="4" y="-2" text-anchor="middle" fill="#e6edf3" font-size="11.5" font-family="monospace" font-weight="bold">
                        {node.label}
                      </text>
                      <text x="0" y="13" text-anchor="middle" fill={strokeColor} font-size="8.5" font-family="monospace">
                        {node.scope_state || "in_scope_explicit"} · {node.asset_type || "domain"}
                      </text>
                    </g>
                  );
                })}
              </svg>
            </div>
          </div>

          {/* Right 4 Cols: Tabbed Node Inspector */}
          <div class="lg:col-span-4 card card-pad flex flex-col justify-between space-y-3">
            <div class="space-y-3">
              <div class="flex items-center justify-between border-b border-[#1b2230] pb-2.5">
                <div class="min-w-0">
                  <span class="card-title">NODE INSPECTOR</span>
                  <div class="font-mono text-sm font-semibold text-white truncate mt-0.5">
                    {selectedNode ? selectedNode.label : "Select a node"}
                  </div>
                </div>
                {selectedNode && (
                  <span class="pill text-[#22d3ee]">{selectedNode.node_type}</span>
                )}
              </div>

              {/* Inspector Tabs */}
              <div class="seg w-full justify-between" role="tablist">
                {(["summary", "dns", "http", "json"] as const).map((tab) => (
                  <button
                    key={tab}
                    type="button"
                    aria-selected={inspectorTab === tab}
                    onClick={() => setInspectorTab(tab)}
                    class="flex-1 justify-center uppercase"
                  >
                    {tab}
                  </button>
                ))}
              </div>

              {!selectedNode ? (
                <div class="py-12 text-center text-xs text-[#738196] font-mono">
                  Click any node in the graph to inspect DNS/HTTP observations.
                </div>
              ) : inspectorTab === "summary" ? (
                <div class="space-y-3 text-xs num">
                  {selectedNode.node_type === "observed_ip" && (
                    <div class="p-2.5 rounded-lg bg-purple-950/30 border border-[#a78bfa]/40 text-[#ede9fe] text-[11px]">
                      <div class="font-semibold text-[#a78bfa]">CRITICAL IP INVARIANT</div>
                      Observed via DNS resolution only (`scopable: false`). Never promoted to `Asset(type="ip")`.
                    </div>
                  )}

                  {selectedNode.node_type === "technology" && selectedNode.metadata?.is_pruned_cdn && (
                    <div class="p-2.5 rounded-lg bg-amber-950/30 border border-[#fbbf24]/40 text-[#fde68a] text-[11px]">
                      <div class="font-semibold text-[#fbbf24]">PRUNED EDGE CDN/WAF TAG</div>
                      Excluded by `DetectionPlanner` to prevent scanning multi-tenant edge infrastructure.
                    </div>
                  )}

                  <div class="grid grid-cols-2 gap-2 p-2.5 rounded-lg bg-[#070a0f] border border-[#1b2230]">
                    <div>
                      <span class="text-[#738196] block text-[10px]">CANONICAL LABEL</span>
                      <span class="text-white break-all">{selectedNode.label}</span>
                    </div>
                    <div>
                      <span class="text-[#738196] block text-[10px]">SCOPE STATE</span>
                      <span class="text-[#34d399]">
                        {selectedNode.scope_state ||
                          (selectedNode.node_type === "observed_ip" ? "dns_metadata_only" : selectedNode.node_type)}
                      </span>
                    </div>
                  </div>

                  {selectedAssetDetails?.technologies?.length > 0 && (
                    <div>
                      <span class="field-label">Detected Stack</span>
                      <div class="flex flex-wrap gap-1.5">
                        {selectedAssetDetails.technologies.map((t: string) => (
                          <span key={t} class="pill text-[#22d3ee]">
                            {t}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ) : inspectorTab === "dns" ? (
                <div class="space-y-2 text-xs num max-h-72 overflow-y-auto">
                  {dnsObservations.length === 0 ? (
                    <div class="text-[#738196] py-6 text-center">No DNS observations on selected node.</div>
                  ) : (
                    dnsObservations.map((o: any) => (
                      <div key={o.id} class="p-2.5 rounded bg-[#070a0f] border border-[#1b2230] space-y-1">
                        <div class="text-[#a78bfa] font-semibold">DNS Observation</div>
                        <pre class="text-[11px] text-[#e6edf3] overflow-x-auto">
                          {JSON.stringify(o.metadata_json, null, 2)}
                        </pre>
                      </div>
                    ))
                  )}
                </div>
              ) : inspectorTab === "http" ? (
                <div class="space-y-2 text-xs num max-h-72 overflow-y-auto">
                  {httpObservations.length === 0 ? (
                    <div class="text-[#738196] py-6 text-center">No HTTP probe observations on selected node.</div>
                  ) : (
                    httpObservations.map((o: any) => (
                      <div key={o.id} class="p-2.5 rounded bg-[#070a0f] border border-[#1b2230] space-y-1">
                        <div class="text-[#22d3ee] font-semibold">HTTP Probe</div>
                        <pre class="text-[11px] text-[#e6edf3] overflow-x-auto">
                          {JSON.stringify(o.metadata_json, null, 2)}
                        </pre>
                      </div>
                    ))
                  )}
                </div>
              ) : (
                <pre class="p-2.5 rounded bg-[#070a0f] border border-[#1b2230] text-[11px] num text-[#22d3ee] overflow-x-auto max-h-72">
                  {JSON.stringify(selectedAssetDetails || selectedNode, null, 2)}
                </pre>
              )}
            </div>

            {selectedNode?.node_type === "asset" && (
              <a
                href={`/scans?program=${encodeURIComponent(selectedSlug)}&asset=${encodeURIComponent(
                  selectedNode.metadata?.canonical_key || selectedNode.label
                )}`}
                class="btn btn-primary w-full"
              >
                Plan Surgical Scan on Asset →
              </a>
            )}
          </div>
        </div>
      ) : (
        /* SESSION BENCHMARKS Style Assets Table */
        <div class="card overflow-hidden">
          <div class="overflow-x-auto">
            <table class="dtable num">
              <thead>
                <tr>
                  <th>Canonical Key</th>
                  <th>Type</th>
                  <th>Scope State</th>
                  <th>Detected Tech</th>
                  <th class="r">Observations</th>
                  <th class="r">Action</th>
                </tr>
              </thead>
              <tbody>
                {assets.length === 0 ? (
                  <tr>
                    <td colSpan={6} class="py-8 text-center text-[#738196]">
                      No assets registered for this program.
                    </td>
                  </tr>
                ) : (
                  assets.map((asset) => (
                    <tr key={asset.id || asset.canonical_key}>
                      <td class="font-semibold text-white">{asset.canonical_key}</td>
                      <td class="text-[#8b98a9]">{asset.asset_type}</td>
                      <td>
                        <span
                          class="pill"
                          style={{
                            color: SCOPE_COLORS[asset.scope_state] || "#34d399",
                          }}
                        >
                          {asset.scope_state}
                        </span>
                      </td>
                      <td>
                        <div class="flex flex-wrap gap-1">
                          {(asset.technologies || []).map((tech: string) => (
                            <span key={tech} class="pill text-[#22d3ee]">
                              {tech}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td class="r text-[#8b98a9]">{(asset.observations || []).length}</td>
                      <td class="r">
                        <a
                          href={`/scans?program=${encodeURIComponent(selectedSlug)}&asset=${encodeURIComponent(
                            asset.canonical_key
                          )}`}
                          class="text-[#34d399] hover:underline text-xs"
                        >
                          Plan Scan →
                        </a>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
