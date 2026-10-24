import { useState, useEffect, useMemo } from "preact/hooks";

export interface AssetRelationshipGraphProps {
  programs?: any[];
  initialSlug?: string;
  initialGraph?: any;
  initialAssets?: any[];
  apiBaseUrl?: string;
}

const SCOPE_COLORS: Record<string, string> = {
  in_scope_explicit: "#10b981", // emerald-500
  in_scope_derived: "#06b6d4",  // cyan-500
  candidate: "#f59e0b",         // amber-500
  out_of_scope: "#ef4444",      // red-500
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
  const [graphData, setGraphData] = useState<any>(
    initialGraph || { nodes: [], edges: [] }
  );
  const [assets, setAssets] = useState<any[]>(initialAssets);
  const [selectedNode, setSelectedNode] = useState<any | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [zoom, setZoom] = useState<number>(1);

  useEffect(() => {
    if (selectedSlug) {
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
        setGraphData(gData);
        if (gData.nodes?.length > 0 && !selectedNode) {
          setSelectedNode(gData.nodes[0]);
        }
      }
      if (assetsRes.ok) {
        const aData = await assetsRes.json();
        setAssets(Array.isArray(aData) ? aData : aData.assets || []);
      }
    } catch {
      // Fallback sample topological graph if backend is offline
      if (!graphData?.nodes?.length) {
        const fallbackNodes = [
          {
            id: "asset:scanme.nmap.org",
            label: "scanme.nmap.org",
            node_type: "asset",
            scope_state: "in_scope_explicit",
            asset_type: "domain",
            metadata: {
              canonical_key: "scanme.nmap.org",
              scopable: true,
              findings_count: 1,
            },
          },
          {
            id: "ip:45.33.32.156",
            label: "45.33.32.156",
            node_type: "observed_ip",
            scope_state: "dns_metadata_only",
            asset_type: "ip",
            metadata: {
              ip: "45.33.32.156",
              scopable: false,
              invariant_note: "DNS METADATA ONLY — NOT IN SCOPE",
            },
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
          { source: "asset:scanme.nmap.org", target: "ip:45.33.32.156", relation: "resolves_to_dns_meta" },
          { source: "asset:scanme.nmap.org", target: "tech:apache", relation: "runs_technology" },
          { source: "asset:scanme.nmap.org", target: "tech:cloudflare", relation: "fronted_by_cdn" },
        ];
        setGraphData({ program_slug: slug, nodes: fallbackNodes, edges: fallbackEdges });
        setSelectedNode(fallbackNodes[0]);
      }
    } finally {
      setLoading(false);
    }
  }

  // Compute deterministic radial/layered positions for SVG nodes
  const positionedGraph = useMemo(() => {
    const nodes: any[] = graphData?.nodes || [];
    const edges: any[] = graphData?.edges || [];

    const assetNodes = nodes.filter((n) => n.node_type === "asset");
    const ipNodes = nodes.filter((n) => n.node_type === "observed_ip");
    const techNodes = nodes.filter((n) => n.node_type === "technology");

    const posMap: Record<string, { x: number; y: number; node: any }> = {};

    // Column 1 (Center): Assets
    assetNodes.forEach((n, idx) => {
      const y = 110 + idx * Math.max(90, Math.min(140, 420 / Math.max(1, assetNodes.length)));
      posMap[n.id] = { x: 430, y, node: n };
    });

    // Column 2 (Left): Observed DNS IPs (Critical IP Invariant)
    ipNodes.forEach((n, idx) => {
      const y = 110 + idx * Math.max(85, Math.min(130, 420 / Math.max(1, ipNodes.length)));
      posMap[n.id] = { x: 145, y, node: n };
    });

    // Column 3 (Right): Technologies & Pruned CDN/WAFs
    techNodes.forEach((n, idx) => {
      const y = 95 + idx * Math.max(70, Math.min(110, 440 / Math.max(1, techNodes.length)));
      posMap[n.id] = { x: 725, y, node: n };
    });

    // Fallback for any other node types
    nodes.forEach((n, idx) => {
      if (!posMap[n.id]) {
        posMap[n.id] = { x: 430, y: 80 + idx * 70, node: n };
      }
    });

    return { posMap, nodes, edges };
  }, [graphData]);

  // Match asset observations when an asset node is selected
  const selectedAssetDetails = useMemo(() => {
    if (!selectedNode) return null;
    const key = selectedNode.metadata?.canonical_key || selectedNode.label;
    return assets.find((a) => a.canonical_key === key || a.id === selectedNode.id) || null;
  }, [selectedNode, assets]);

  return (
    <div class="space-y-5 text-slate-100">
      {/* Header Controls & View Switcher */}
      <div class="flex flex-wrap items-center justify-between gap-4 bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-lg">
        <div class="flex items-center gap-3">
          <div class="h-10 w-10 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 font-bold font-mono">
            G3
          </div>
          <div>
            <h2 class="text-base font-semibold text-slate-100">
              Superfície de Ataque & Grafo Topológico de Ativos
            </h2>
            <p class="text-xs text-slate-400">
              Separação estrita entre Ativos Escopáveis, IPs de Metadado DNS (`scopable: false`) e Stack/CDN
            </p>
          </div>
        </div>

        <div class="flex flex-wrap items-center gap-3">
          {programs.length > 0 && (
            <select
              value={selectedSlug}
              onChange={(e) => setSelectedSlug((e.target as HTMLSelectElement).value)}
              class="bg-slate-950 border border-slate-700 text-slate-100 text-xs rounded-lg px-3 py-2 font-mono"
            >
              {programs.map((p) => (
                <option key={p.slug} value={p.slug}>
                  {p.name} ({p.slug})
                </option>
              ))}
            </select>
          )}

          <div class="inline-flex rounded-lg bg-slate-950 p-1 border border-slate-800">
            <button
              type="button"
              onClick={() => setViewMode("graph")}
              class={`px-3 py-1.5 rounded-md text-xs font-mono transition ${
                viewMode === "graph"
                  ? "bg-cyan-500 text-slate-950 font-bold"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              Visão em Grafo Topológico
            </button>
            <button
              type="button"
              onClick={() => setViewMode("table")}
              class={`px-3 py-1.5 rounded-md text-xs font-mono transition ${
                viewMode === "table"
                  ? "bg-cyan-500 text-slate-950 font-bold"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              Visão em Tabela de Ativos ({assets.length})
            </button>
          </div>
        </div>
      </div>

      {/* Critical IP Invariant Banner */}
      <div class="bg-purple-950/30 border border-purple-500/40 rounded-xl px-4 py-3 flex flex-wrap items-center justify-between gap-2 text-xs">
        <div class="flex items-center gap-2.5">
          <span class="px-2 py-0.5 rounded bg-purple-500/20 border border-purple-400/50 text-purple-300 font-mono font-bold text-[10px] uppercase">
            Invariante Crítica de IP Ativa
          </span>
          <span class="text-slate-300">
            IPs resolvidos via DNS (<code class="text-purple-300 font-mono">a_records</code>) permanecem exclusivamente em{" "}
            <code class="text-purple-300 font-mono">Observation.metadata_json</code> e nunca são promovidos à tabela <code class="text-emerald-300 font-mono">assets</code>.
          </span>
        </div>
        <span class="font-mono text-[11px] text-purple-300">
          [DNS METADATA ONLY — NOT IN SCOPE]
        </span>
      </div>

      {viewMode === "graph" ? (
        <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Interactive SVG Canvas (8 cols) */}
          <div class="lg:col-span-8 bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg flex flex-col">
            <div class="flex items-center justify-between px-4 py-2.5 bg-slate-950 border-b border-slate-800 text-xs">
              <div class="flex flex-wrap items-center gap-4">
                <span class="flex items-center gap-1.5">
                  <span class="h-2.5 w-2.5 rounded-full bg-emerald-500 inline-block"></span>
                  <span class="text-slate-300 font-mono text-[11px]">in_scope_explicit</span>
                </span>
                <span class="flex items-center gap-1.5">
                  <span class="h-2.5 w-2.5 rounded-full bg-cyan-500 inline-block"></span>
                  <span class="text-slate-300 font-mono text-[11px]">in_scope_derived</span>
                </span>
                <span class="flex items-center gap-1.5">
                  <span class="h-2.5 w-2.5 rounded-full bg-purple-400 border border-dashed border-purple-200 inline-block"></span>
                  <span class="text-purple-300 font-mono text-[11px]">DNS Metadata IP (Unscoped)</span>
                </span>
                <span class="flex items-center gap-1.5">
                  <span class="h-2.5 w-2.5 rounded-full bg-amber-500 inline-block"></span>
                  <span class="text-amber-300 font-mono text-[11px]">CDN/WAF Pruned</span>
                </span>
              </div>

              <div class="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => setZoom((z) => Math.max(0.6, +(z - 0.15).toFixed(2)))}
                  class="px-2 py-0.5 bg-slate-900 border border-slate-700 rounded text-slate-300 font-mono"
                >
                  -
                </button>
                <span class="font-mono text-[11px] text-slate-400 w-12 text-center">
                  {Math.round(zoom * 100)}%
                </span>
                <button
                  type="button"
                  onClick={() => setZoom((z) => Math.min(1.5, +(z + 0.15).toFixed(2)))}
                  class="px-2 py-0.5 bg-slate-900 border border-slate-700 rounded text-slate-300 font-mono"
                >
                  +
                </button>
              </div>
            </div>

            <div class="relative flex-1 min-h-[480px] bg-slate-950/70 overflow-auto">
              {loading && (
                <div class="absolute inset-0 flex items-center justify-center bg-slate-950/60 z-10 text-xs font-mono text-cyan-400">
                  Renderizando grafo topológico...
                </div>
              )}

              <svg
                viewBox="0 0 880 540"
                class="w-full h-[500px] select-none"
                style={{ transform: `scale(${zoom})`, transformOrigin: "center center" }}
              >
                <defs>
                  <pattern id="secops-grid" width="32" height="32" patternUnits="userSpaceOnUse">
                    <path
                      d="M 32 0 L 0 0 0 32"
                      fill="none"
                      stroke="#1e293b"
                      stroke-width="0.7"
                    />
                  </pattern>
                </defs>
                <rect width="880" height="540" fill="url(#secops-grid)" />

                {/* Column Headers inside SVG */}
                <text x="145" y="36" text-anchor="middle" fill="#a855f7" font-size="11" font-family="monospace" font-weight="bold">
                  OBSERVED DNS IPs (METADATA ONLY)
                </text>
                <text x="430" y="36" text-anchor="middle" fill="#10b981" font-size="11" font-family="monospace" font-weight="bold">
                  SCOPED ASSETS (CANONICAL KEYS)
                </text>
                <text x="725" y="36" text-anchor="middle" fill="#06b6d4" font-size="11" font-family="monospace" font-weight="bold">
                  DETECTED TECH &amp; PRUNED CDN/WAF
                </text>

                {/* Edges */}
                {positionedGraph.edges.map((edge, idx) => {
                  const src = positionedGraph.posMap[edge.source];
                  const dst = positionedGraph.posMap[edge.target];
                  if (!src || !dst) return null;
                  const isDnsMeta = edge.relation.includes("dns") || dst.node.node_type === "observed_ip";
                  const isPrunedCdn = Boolean(dst.node.metadata?.is_pruned_cdn);
                  return (
                    <g key={idx}>
                      <line
                        x1={src.x}
                        y1={src.y}
                        x2={dst.x}
                        y2={dst.y}
                        stroke={isDnsMeta ? "#a855f7" : isPrunedCdn ? "#f59e0b" : "#38bdf8"}
                        stroke-width="1.8"
                        stroke-dasharray={isDnsMeta || isPrunedCdn ? "5,5" : "none"}
                        opacity="0.65"
                      />
                      <text
                        x={(src.x + dst.x) / 2}
                        y={(src.y + dst.y) / 2 - 6}
                        text-anchor="middle"
                        fill="#94a3b8"
                        font-size="9"
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

                  if (node.node_type === "observed_ip") {
                    return (
                      <g
                        key={node.id}
                        transform={`translate(${pos.x}, ${pos.y})`}
                        onClick={() => setSelectedNode(node)}
                        style={{ cursor: "pointer" }}
                      >
                        <rect
                          x="-115"
                          y="-28"
                          width="230"
                          height="56"
                          rx="8"
                          fill="#1e1b4b"
                          stroke={isSelected ? "#e879f9" : "#a855f7"}
                          stroke-width={isSelected ? "2.5" : "1.5"}
                          stroke-dasharray="5,4"
                        />
                        <text x="0" y="-5" text-anchor="middle" fill="#f3e8ff" font-size="12" font-family="monospace" font-weight="bold">
                          {node.label}
                        </text>
                        <text x="0" y="14" text-anchor="middle" fill="#d8b4fe" font-size="8.5" font-family="monospace">
                          [DNS METADATA ONLY — NOT IN SCOPE]
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
                          x="-105"
                          y="-24"
                          width="210"
                          height="48"
                          rx="20"
                          fill={isPruned ? "#451a03" : "#083344"}
                          stroke={isPruned ? "#f59e0b" : "#06b6d4"}
                          stroke-width={isSelected ? "2.5" : "1.5"}
                        />
                        <text
                          x="0"
                          y="-3"
                          text-anchor="middle"
                          fill={isPruned ? "#fcd34d" : "#a5f3fc"}
                          font-size="12"
                          font-family="monospace"
                          font-weight="bold"
                          text-decoration={isPruned ? "line-through" : "none"}
                        >
                          {node.label}
                        </text>
                        <text
                          x="0"
                          y="13"
                          text-anchor="middle"
                          fill={isPruned ? "#f87171" : "#38bdf8"}
                          font-size="8.5"
                          font-family="monospace"
                        >
                          {isPruned ? "[CDN/WAF PRUNED]" : "[APP STACK TARGET]"}
                        </text>
                      </g>
                    );
                  }

                  // Default: Asset Node
                  const strokeColor = SCOPE_COLORS[node.scope_state || "in_scope_explicit"] || "#10b981";
                  return (
                    <g
                      key={node.id}
                      transform={`translate(${pos.x}, ${pos.y})`}
                      onClick={() => setSelectedNode(node)}
                      style={{ cursor: "pointer" }}
                    >
                      <rect
                        x="-115"
                        y="-28"
                        width="230"
                        height="56"
                        rx="10"
                        fill="#0f172a"
                        stroke={strokeColor}
                        stroke-width={isSelected ? "3" : "2"}
                      />
                      <circle cx="-95" cy="-6" r="5" fill={strokeColor} />
                      <text x="5" y="-3" text-anchor="middle" fill="#f8fafc" font-size="12" font-family="monospace" font-weight="bold">
                        {node.label}
                      </text>
                      <text x="0" y="15" text-anchor="middle" fill={strokeColor} font-size="9" font-family="monospace">
                        {node.scope_state || "in_scope_explicit"} ({node.asset_type || "domain"})
                      </text>
                    </g>
                  );
                })}
              </svg>
            </div>
          </div>

          {/* Side Inspector Drawer (4 cols) */}
          <div class="lg:col-span-4 bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
            <div class="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <span class="text-[10px] font-mono uppercase tracking-widest text-cyan-400">
                  Inspetor de Nó Topológico
                </span>
                <h3 class="text-sm font-semibold text-slate-100 mt-0.5 font-mono">
                  {selectedNode ? selectedNode.label : "Selecione um nó no grafo"}
                </h3>
              </div>
              {selectedNode && (
                <span class="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-slate-800 text-slate-300">
                  {selectedNode.node_type}
                </span>
              )}
            </div>

            {!selectedNode ? (
              <p class="text-xs text-slate-500 py-8 text-center">
                Clique em qualquer Ativo, IP de Metadado DNS ou Tecnologia no grafo para inspecionar seus metadados e observações.
              </p>
            ) : (
              <div class="space-y-4 text-xs">
                {selectedNode.node_type === "observed_ip" && (
                  <div class="bg-purple-950/40 border border-purple-500/50 rounded-lg p-3 text-purple-200 font-mono text-[11px]">
                    <div class="font-bold text-purple-300 mb-1">
                      [DNS METADATA ONLY — NOT IN SCOPE]
                    </div>
                    Este endereço IP foi observado na resolução DNS (`dnsx`), mas a Invariante Crítica de IP proíbe que IPs derivados de DNS sejam inseridos como ativos escopáveis (`scopable: false`).
                  </div>
                )}

                {selectedNode.node_type === "technology" && selectedNode.metadata?.is_pruned_cdn && (
                  <div class="bg-amber-950/40 border border-amber-500/50 rounded-lg p-3 text-amber-200 font-mono text-[11px]">
                    <div class="font-bold text-amber-300 mb-1">
                      [CDN/WAF PRUNED BY DETECTION PLANNER]
                    </div>
                    Tecnologia de borda/WAF (`{selectedNode.label}`) podada automaticamente pelo `DetectionPlanner` para evitar falso-positivos e ruído contra infraestrutura de terceiros.
                  </div>
                )}

                <div class="grid grid-cols-2 gap-2 bg-slate-950 p-3 rounded-lg border border-slate-800 font-mono">
                  <div>
                    <span class="text-slate-500 block text-[10px]">CANONICAL KEY / ID</span>
                    <span class="text-slate-100 break-all">{selectedNode.label}</span>
                  </div>
                  <div>
                    <span class="text-slate-500 block text-[10px]">SCOPE STATE</span>
                    <span class="text-emerald-400">
                      {selectedNode.scope_state || (selectedNode.node_type === "observed_ip" ? "dns_metadata_only" : "technology_tag")}
                    </span>
                  </div>
                </div>

                <div>
                  <span class="text-[11px] font-mono uppercase text-slate-400 block mb-1.5">
                    Metadados &amp; Observações (DNS / HTTP Probe JSON):
                  </span>
                  <pre class="bg-slate-950 border border-slate-800 rounded-lg p-3 text-[11px] font-mono text-cyan-300 overflow-x-auto max-h-64">
                    {JSON.stringify(
                      selectedAssetDetails
                        ? {
                            canonical_key: selectedAssetDetails.canonical_key,
                            scope_state: selectedAssetDetails.scope_state,
                            technologies: selectedAssetDetails.technologies,
                            observations: selectedAssetDetails.observations,
                          }
                        : selectedNode.metadata || selectedNode,
                      null,
                      2
                    )}
                  </pre>
                </div>

                {selectedNode.node_type === "asset" && (
                  <a
                    href={`/scans?program=${encodeURIComponent(selectedSlug)}&asset=${encodeURIComponent(
                      selectedNode.metadata?.canonical_key || selectedNode.label
                    )}`}
                    class="block w-full text-center bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold text-xs py-2.5 px-4 rounded-lg transition font-mono uppercase tracking-wider"
                  >
                    Simular Plano de Scan neste Ativo →
                  </a>
                )}
              </div>
            )}
          </div>
        </div>
      ) : (
        /* Table View */
        <div class="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
          <div class="overflow-x-auto">
            <table class="w-full text-left border-collapse text-xs">
              <thead>
                <tr class="bg-slate-950 text-slate-400 font-mono uppercase border-b border-slate-800">
                  <th class="py-3 px-4">Canonical Key</th>
                  <th class="py-3 px-4">Tipo</th>
                  <th class="py-3 px-4">Scope State</th>
                  <th class="py-3 px-4">Tecnologias Detectadas</th>
                  <th class="py-3 px-4">Observações (DNS / HTTP)</th>
                  <th class="py-3 px-4 text-right">Ação</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-800/70">
                {assets.length === 0 ? (
                  <tr>
                    <td colSpan={6} class="py-8 text-center text-slate-500 font-mono">
                      Nenhum ativo registrado para este programa.
                    </td>
                  </tr>
                ) : (
                  assets.map((asset) => (
                    <tr key={asset.id || asset.canonical_key} class="hover:bg-slate-800/40 transition">
                      <td class="py-3 px-4 font-mono font-semibold text-slate-100">
                        {asset.canonical_key}
                      </td>
                      <td class="py-3 px-4 font-mono text-slate-300">{asset.asset_type}</td>
                      <td class="py-3 px-4">
                        <span
                          class="px-2 py-0.5 rounded font-mono text-[11px]"
                          style={{
                            backgroundColor: `${SCOPE_COLORS[asset.scope_state] || "#10b981"}20`,
                            color: SCOPE_COLORS[asset.scope_state] || "#10b981",
                            border: `1px solid ${SCOPE_COLORS[asset.scope_state] || "#10b981"}50`,
                          }}
                        >
                          {asset.scope_state}
                        </span>
                      </td>
                      <td class="py-3 px-4">
                        <div class="flex flex-wrap gap-1">
                          {(asset.technologies || []).map((tech: string) => (
                            <span
                              key={tech}
                              class="px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 font-mono text-[10px]"
                            >
                              {tech}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td class="py-3 px-4 font-mono text-slate-400">
                        {(asset.observations || []).length} registros
                      </td>
                      <td class="py-3 px-4 text-right">
                        <a
                          href={`/scans?program=${encodeURIComponent(selectedSlug)}&asset=${encodeURIComponent(
                            asset.canonical_key
                          )}`}
                          class="inline-block bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-300 border border-emerald-500/30 px-3 py-1 rounded font-mono text-[11px] transition"
                        >
                          Simular Plano de Scan neste Ativo
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
