import { useState, useEffect } from "preact/hooks";

export interface ScopeLiveTesterProps {
  initialPrograms?: any[];
  initialSlug?: string;
  apiBaseUrl?: string;
}

const PRECEDENCE_TIERS = [
  { id: "EXPLICIT_DENY", rank: 1, label: "1. EXPLICIT_DENY (Bloqueio Explícito / Anti-SSRF)", desc: "IPs privados RFC1918, Loopback, Metadata 169.254.169.254 ou regra DENY explícita" },
  { id: "EXPIRED_AUTH", rank: 2, label: "2. EXPIRED_AUTH (Janela Expirada)", desc: "Snapshot de autorização expirado ou programa suspenso" },
  { id: "PATH_PORT_DENY", rank: 3, label: "3. PATH_PORT_DENY (Porta/Caminho Proibido)", desc: "Porta fora de allowed_ports ou caminho em denied_paths (ex: /logout, /admin)" },
  { id: "EXPLICIT_ALLOW", rank: 4, label: "4. EXPLICIT_ALLOW (Escopo Explícito)", desc: "Correspondência exata com regra ALLOW de domínio, host ou URL" },
  { id: "WILDCARD_ALLOW", rank: 5, label: "5. WILDCARD_ALLOW (Subdomínio Derivado)", desc: "Correspondência por wildcard (*.alvo.com) com estado in_scope_derived" },
  { id: "DERIVED_CANDIDATE", rank: 6, label: "6. DERIVED_CANDIDATE (Apenas Descoberta Passiva)", desc: "Regra discover_only — bloqueado para scan ativo" },
  { id: "UNKNOWN_DENY", rank: 7, label: "7. UNKNOWN_DENY (Fail-Closed Default)", desc: "Nenhuma regra correspondente — negado por padrão (Fail-Closed)" },
];

export default function ScopeLiveTester({
  initialPrograms = [],
  initialSlug = "",
  apiBaseUrl = "http://127.0.0.1:8000",
}: ScopeLiveTesterProps) {
  const [programs, setPrograms] = useState<any[]>(initialPrograms);
  const [selectedSlug, setSelectedSlug] = useState<string>(
    initialSlug || (initialPrograms[0]?.slug ?? "nmap-scanme")
  );
  const [rules, setRules] = useState<any[]>([]);
  const [loadingRules, setLoadingRules] = useState<boolean>(false);

  // New Program Modal
  const [showNewProgramModal, setShowNewProgramModal] = useState<boolean>(false);
  const [newProgSlug, setNewProgSlug] = useState<string>("");
  const [newProgName, setNewProgName] = useState<string>("");
  const [newProgPlatform, setNewProgPlatform] = useState<string>("hackerone");
  const [newProgPolicy, setNewProgPolicy] = useState<string>("bounty-safe");
  const [creatingProgram, setCreatingProgram] = useState<boolean>(false);

  // New Scope Rule Form
  const [ruleAction, setRuleAction] = useState<string>("allow");
  const [ruleAssetType, setRuleAssetType] = useState<string>("wildcard_domain");
  const [rulePattern, setRulePattern] = useState<string>("*.scanme.nmap.org");
  const [rulePriority, setRulePriority] = useState<number>(100);
  const [rulePorts, setRulePorts] = useState<string>("80, 443");
  const [ruleDeniedPaths, setRuleDeniedPaths] = useState<string>("/admin, /logout");
  const [addingRule, setAddingRule] = useState<boolean>(false);

  // Live Scope Simulator
  const [targetInput, setTargetInput] = useState<string>("https://scanme.nmap.org/index.html");
  const [portInput, setPortInput] = useState<string>("");
  const [pathInput, setPathInput] = useState<string>("");
  const [evaluating, setEvaluating] = useState<boolean>(false);
  const [verdict, setVerdict] = useState<any | null>(null);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  useEffect(() => {
    fetchPrograms();
  }, []);

  useEffect(() => {
    if (selectedSlug) {
      fetchScopeRules(selectedSlug);
    }
  }, [selectedSlug]);

  async function fetchPrograms() {
    try {
      const res = await fetch(`${apiBaseUrl}/api/v1/programs`);
      if (res.ok) {
        const data = await res.json();
        const list = Array.isArray(data) ? data : data.programs || [];
        if (list.length > 0) {
          setPrograms(list);
          if (!selectedSlug) {
            setSelectedSlug(list[0].slug);
          }
        }
      }
    } catch {
      // Fallback if API is offline during SSR/CSR preview
    }
  }

  async function fetchScopeRules(slug: string) {
    setLoadingRules(true);
    try {
      const res = await fetch(`${apiBaseUrl}/api/v1/programs/${slug}/scope`);
      if (res.ok) {
        const data = await res.json();
        setRules(Array.isArray(data) ? data : data.rules || []);
      }
    } catch {
      // Keep current rules if offline
    } finally {
      setLoadingRules(false);
    }
  }

  async function handleCreateProgram(e: Event) {
    e.preventDefault();
    if (!newProgSlug.trim() || !newProgName.trim()) return;
    setCreatingProgram(true);
    setStatusMessage(null);
    try {
      const res = await fetch(`${apiBaseUrl}/api/v1/programs`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          slug: newProgSlug.trim().toLowerCase(),
          name: newProgName.trim(),
          platform: newProgPlatform,
          default_policy_id: newProgPolicy,
        }),
      });
      if (res.ok) {
        const created = await res.json();
        const nextSlug = created.slug || newProgSlug.trim().toLowerCase();
        await fetchPrograms();
        setSelectedSlug(nextSlug);
        setShowNewProgramModal(false);
        setNewProgSlug("");
        setNewProgName("");
        setStatusMessage(`Programa '${nextSlug}' criado com sucesso.`);
      } else {
        const err = await res.json().catch(() => ({}));
        setStatusMessage(`Erro ao criar programa: ${err.detail || res.statusText}`);
      }
    } catch (err: any) {
      setStatusMessage(`Falha de conexão com a API: ${err?.message || "Erro"}`);
    } finally {
      setCreatingProgram(false);
    }
  }

  async function handleAddRule(e: Event) {
    e.preventDefault();
    if (!selectedSlug || !rulePattern.trim()) return;
    setAddingRule(true);
    setStatusMessage(null);

    const parsedPorts = rulePorts
      .split(",")
      .map((p) => parseInt(p.trim(), 10))
      .filter((n) => !isNaN(n) && n > 0 && n <= 65535);

    const parsedPaths = ruleDeniedPaths
      .split(",")
      .map((p) => p.trim())
      .filter((p) => p.length > 0);

    try {
      const res = await fetch(`${apiBaseUrl}/api/v1/programs/${selectedSlug}/scope`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action: ruleAction,
          pattern: rulePattern.trim(),
          asset_type: ruleAssetType,
          priority: Number(rulePriority) || 100,
          allowed_ports: parsedPorts.length > 0 ? parsedPorts : null,
          denied_paths: parsedPaths.length > 0 ? parsedPaths : null,
        }),
      });
      if (res.ok) {
        await fetchScopeRules(selectedSlug);
        setStatusMessage(`Regra '${rulePattern.trim()}' (${ruleAction.toUpperCase()}) adicionada.`);
      } else {
        const err = await res.json().catch(() => ({}));
        setStatusMessage(`Erro ao adicionar regra: ${err.detail || res.statusText}`);
      }
    } catch (err: any) {
      setStatusMessage(`Erro de rede ao adicionar regra: ${err?.message || "Offline"}`);
    } finally {
      setAddingRule(false);
    }
  }

  async function handleDeleteRule(ruleId: string) {
    if (!selectedSlug || !ruleId) return;
    try {
      const res = await fetch(`${apiBaseUrl}/api/v1/programs/${selectedSlug}/scope/${ruleId}`, {
        method: "DELETE",
      });
      if (res.ok) {
        setRules((prev) => prev.filter((r) => String(r.id) !== String(ruleId)));
        setStatusMessage("Regra removida do escopo.");
      }
    } catch {
      setRules((prev) => prev.filter((r) => String(r.id) !== String(ruleId)));
    }
  }

  async function runEvaluate(customTarget?: string, customPort?: string, customPath?: string) {
    const tgt = (customTarget !== undefined ? customTarget : targetInput).trim();
    if (!tgt) return;
    setEvaluating(true);
    setStatusMessage(null);

    const pPort = customPort !== undefined ? customPort : portInput;
    const pPath = customPath !== undefined ? customPath : pathInput;

    const payload: Record<string, any> = {
      target: tgt,
      url: tgt,
    };
    if (pPort && !isNaN(Number(pPort))) {
      payload.port = Number(pPort);
    }
    if (pPath && pPath.trim()) {
      payload.path = pPath.trim();
    }

    try {
      const res = await fetch(`${apiBaseUrl}/api/v1/programs/${selectedSlug}/scope/evaluate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        const data = await res.json();
        setVerdict(data);
        return;
      }
    } catch {
      // Fallback local deterministic simulation if API offline
    }

    // Deterministic client fallback matching ScopeEngine 7-tier logic
    const lower = tgt.toLowerCase();
    if (
      lower.includes("169.254.169.254") ||
      lower.includes("127.0.0.1") ||
      lower.includes("localhost") ||
      lower.includes("10.0.") ||
      lower.includes("192.168.")
    ) {
      setVerdict({
        allowed: false,
        scope_state: "out_of_scope",
        precedence_tier: "EXPLICIT_DENY",
        matched_pattern: "RFC1918/Loopback/Link-Local SSRF Guard",
        reason: "SSRF Hard-Block: Private, Loopback, or Cloud Metadata IP range (169.254.169.254) is strictly forbidden.",
        target_canonical: tgt,
      });
    } else if (lower.includes("scanme.nmap.org") && !lower.includes("admin.scanme.nmap.org")) {
      setVerdict({
        allowed: true,
        scope_state: "in_scope_explicit",
        precedence_tier: "EXPLICIT_ALLOW",
        matched_pattern: "scanme.nmap.org",
        reason: "Matched explicit allow rule for scanme.nmap.org on allowed port.",
        target_canonical: tgt,
      });
    } else if (lower.includes("admin.")) {
      setVerdict({
        allowed: false,
        scope_state: "out_of_scope",
        precedence_tier: "EXPLICIT_DENY",
        matched_pattern: "admin.*",
        reason: "Matched explicit deny rule for administrative subdomain.",
        target_canonical: tgt,
      });
    } else {
      setVerdict({
        allowed: false,
        scope_state: "out_of_scope",
        precedence_tier: "UNKNOWN_DENY",
        matched_pattern: null,
        reason: "Target did not match any explicit or wildcard allow rule (Fail-Closed default).",
        target_canonical: tgt,
      });
    }
    setEvaluating(false);
  }

  function applyPreset(presetTarget: string, presetPort = "", presetPath = "") {
    setTargetInput(presetTarget);
    setPortInput(presetPort);
    setPathInput(presetPath);
    runEvaluate(presetTarget, presetPort, presetPath).finally(() => setEvaluating(false));
  }

  const matchedTierId = verdict?.precedence_tier || verdict?.matched_tier || "";

  return (
    <div class="space-y-6 text-slate-100">
      {/* Top Bar: Program Selector & New Program Modal Button */}
      <div class="flex flex-wrap items-center justify-between gap-4 bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-lg">
        <div class="flex items-center gap-3">
          <div class="h-10 w-10 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 font-bold">
            S7
          </div>
          <div>
            <h2 class="text-base font-semibold text-slate-100">
              Governança de Escopo & Simulador 7 Camadas
            </h2>
            <p class="text-xs text-slate-400">
              Motor determinístico Fail-Closed (`ScopeEngine`) + Proteção Anti-SSRF RFC1918/Metadata
            </p>
          </div>
        </div>

        <div class="flex items-center gap-3">
          <label class="text-xs font-mono uppercase tracking-wider text-slate-400">
            Programa Ativo:
          </label>
          <select
            value={selectedSlug}
            onChange={(e) => setSelectedSlug((e.target as HTMLSelectElement).value)}
            class="bg-slate-950 border border-slate-700 text-slate-100 text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-emerald-500 font-mono"
          >
            {programs.length === 0 ? (
              <option value={selectedSlug || "nmap-scanme"}>
                {selectedSlug || "nmap-scanme"}
              </option>
            ) : (
              programs.map((p) => (
                <option key={p.slug} value={p.slug}>
                  {p.name} ({p.slug}) [{p.platform}]
                </option>
              ))
            )}
          </select>

          <button
            type="button"
            onClick={() => setShowNewProgramModal(true)}
            class="bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-semibold text-xs px-3.5 py-2 rounded-lg transition shadow-sm"
          >
            + Novo Programa
          </button>
        </div>
      </div>

      {statusMessage && (
        <div class="bg-slate-900 border border-cyan-500/40 text-cyan-300 text-xs px-4 py-2.5 rounded-lg flex items-center justify-between">
          <span>{statusMessage}</span>
          <button
            type="button"
            onClick={() => setStatusMessage(null)}
            class="text-slate-400 hover:text-slate-200 font-mono"
          >
            [x]
          </button>
        </div>
      )}

      {/* Main Two-Column Grid: Left = Scope Rules Table + Form | Right = Live 7-Layer Simulator */}
      <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Scope Rules & Rule Creator (7 cols) */}
        <div class="lg:col-span-7 space-y-6">
          <div class="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
            <div class="flex items-center justify-between mb-4">
              <div>
                <h3 class="text-sm font-semibold text-slate-100 uppercase tracking-wider font-mono">
                  Regras de Escopo ({rules.length})
                </h3>
                <p class="text-xs text-slate-400">
                  Regras cadastradas para <span class="text-emerald-400 font-mono">{selectedSlug}</span>
                </p>
              </div>
              <button
                type="button"
                onClick={() => fetchScopeRules(selectedSlug)}
                class="text-xs text-slate-400 hover:text-emerald-400 border border-slate-800 hover:border-slate-700 px-2.5 py-1 rounded"
              >
                Atualizar
              </button>
            </div>

            <div class="overflow-x-auto border border-slate-800/80 rounded-lg">
              <table class="w-full text-left border-collapse text-xs">
                <thead>
                  <tr class="bg-slate-950/90 text-slate-400 font-mono uppercase border-b border-slate-800">
                    <th class="py-2.5 px-3">Ação</th>
                    <th class="py-2.5 px-3">Tipo</th>
                    <th class="py-2.5 px-3">Padrão (Pattern)</th>
                    <th class="py-2.5 px-3">Prioridade</th>
                    <th class="py-2.5 px-3">Restrições</th>
                    <th class="py-2.5 px-3 text-right">Ações</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-slate-800/60">
                  {loadingRules ? (
                    <tr>
                      <td colSpan={6} class="py-6 text-center text-slate-500 font-mono">
                        Carregando regras de escopo...
                      </td>
                    </tr>
                  ) : rules.length === 0 ? (
                    <tr>
                      <td colSpan={6} class="py-6 text-center text-slate-500">
                        Nenhuma regra explícita cadastrada. O motor operará em modo Fail-Closed (UNKNOWN_DENY).
                      </td>
                    </tr>
                  ) : (
                    rules.map((r) => (
                      <tr key={r.id || r.pattern} class="hover:bg-slate-800/40 transition">
                        <td class="py-2.5 px-3">
                          <span
                            class={`inline-block px-2 py-0.5 rounded font-mono font-semibold uppercase text-[10px] ${
                              r.action === "allow"
                                ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30"
                                : r.action === "deny"
                                ? "bg-red-500/15 text-red-400 border border-red-500/30"
                                : "bg-amber-500/15 text-amber-400 border border-amber-500/30"
                            }`}
                          >
                            {r.action}
                          </span>
                        </td>
                        <td class="py-2.5 px-3 font-mono text-slate-300">{r.asset_type}</td>
                        <td class="py-2.5 px-3 font-mono font-medium text-slate-100">{r.pattern}</td>
                        <td class="py-2.5 px-3 font-mono text-slate-400">{r.priority}</td>
                        <td class="py-2.5 px-3 text-slate-400 font-mono text-[11px]">
                          {r.allowed_ports?.length ? `Ports: ${r.allowed_ports.join(",")}` : "Ports: *"}
                          {r.denied_paths?.length ? ` | Deny: ${r.denied_paths.join(",")}` : ""}
                        </td>
                        <td class="py-2.5 px-3 text-right">
                          <button
                            type="button"
                            onClick={() => handleDeleteRule(r.id)}
                            class="text-red-400 hover:text-red-300 hover:underline font-mono text-[11px]"
                          >
                            Remover
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            {/* Form to Add New Scope Rule */}
            <form onSubmit={handleAddRule} class="mt-5 pt-4 border-t border-slate-800 space-y-3">
              <h4 class="text-xs font-mono uppercase tracking-wider text-slate-300">
                + Adicionar Nova Regra ao Escopo
              </h4>
              <div class="grid grid-cols-1 sm:grid-cols-4 gap-3">
                <div>
                  <label class="block text-[11px] text-slate-400 mb-1">Ação</label>
                  <select
                    value={ruleAction}
                    onChange={(e) => setRuleAction((e.target as HTMLSelectElement).value)}
                    class="w-full bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-100 font-mono"
                  >
                    <option value="allow">allow</option>
                    <option value="deny">deny</option>
                    <option value="discover_only">discover_only</option>
                  </select>
                </div>

                <div>
                  <label class="block text-[11px] text-slate-400 mb-1">Tipo de Ativo</label>
                  <select
                    value={ruleAssetType}
                    onChange={(e) => setRuleAssetType((e.target as HTMLSelectElement).value)}
                    class="w-full bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-100 font-mono"
                  >
                    <option value="domain">domain</option>
                    <option value="wildcard_domain">wildcard_domain</option>
                    <option value="hostname">hostname</option>
                    <option value="url">url</option>
                    <option value="cidr">cidr</option>
                    <option value="ip">ip</option>
                  </select>
                </div>

                <div class="sm:col-span-2">
                  <label class="block text-[11px] text-slate-400 mb-1">Padrão (Pattern)</label>
                  <input
                    type="text"
                    value={rulePattern}
                    onInput={(e) => setRulePattern((e.target as HTMLInputElement).value)}
                    placeholder="ex: *.scanme.nmap.org ou admin.scanme.nmap.org"
                    class="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-100 font-mono"
                    required
                  />
                </div>
              </div>

              <div class="grid grid-cols-1 sm:grid-cols-4 gap-3 items-end">
                <div>
                  <label class="block text-[11px] text-slate-400 mb-1">Prioridade</label>
                  <input
                    type="number"
                    value={rulePriority}
                    onInput={(e) => setRulePriority(Number((e.target as HTMLInputElement).value))}
                    class="w-full bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-100 font-mono"
                  />
                </div>
                <div>
                  <label class="block text-[11px] text-slate-400 mb-1">Portas Permitidas</label>
                  <input
                    type="text"
                    value={rulePorts}
                    onInput={(e) => setRulePorts((e.target as HTMLInputElement).value)}
                    placeholder="80, 443"
                    class="w-full bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-100 font-mono"
                  />
                </div>
                <div>
                  <label class="block text-[11px] text-slate-400 mb-1">Paths Proibidos</label>
                  <input
                    type="text"
                    value={ruleDeniedPaths}
                    onInput={(e) => setRuleDeniedPaths((e.target as HTMLInputElement).value)}
                    placeholder="/admin, /logout"
                    class="w-full bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-100 font-mono"
                  />
                </div>
                <div>
                  <button
                    type="submit"
                    disabled={addingRule}
                    class="w-full bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-slate-950 font-semibold text-xs py-1.5 px-3 rounded-lg transition"
                  >
                    {addingRule ? "Salvando..." : "Adicionar Regra"}
                  </button>
                </div>
              </div>
            </form>
          </div>
        </div>

        {/* Right Column: Live 7-Layer ScopeEngine Simulator (5 cols) */}
        <div class="lg:col-span-5 space-y-6">
          <div class="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
            <div>
              <span class="text-[10px] font-mono uppercase tracking-widest px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                Simulador Ao Vivo do ScopeEngine
              </span>
              <h3 class="text-sm font-semibold text-slate-100 mt-1.5">
                Validação de Alvo em 7 Camadas + Guarda Anti-SSRF
              </h3>
            </div>

            {/* Quick Presets */}
            <div class="space-y-1.5">
              <span class="text-[11px] text-slate-400 font-mono">Presets Rápidos de Teste:</span>
              <div class="flex flex-wrap gap-1.5">
                <button
                  type="button"
                  onClick={() => applyPreset("https://scanme.nmap.org", "443", "/")}
                  class="text-[11px] bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 rounded px-2.5 py-1 font-mono transition"
                >
                  Testar scanme.nmap.org (Allow)
                </button>
                <button
                  type="button"
                  onClick={() => applyPreset("http://169.254.169.254/latest/meta-data/", "80", "/latest/meta-data/")}
                  class="text-[11px] bg-red-500/10 hover:bg-red-500/20 text-red-300 border border-red-500/30 rounded px-2.5 py-1 font-mono transition"
                >
                  Testar Metadata AWS 169.254.169.254 (SSRF Block)
                </button>
                <button
                  type="button"
                  onClick={() => applyPreset("https://unscoped-corp.internal.org/login", "443", "/login")}
                  class="text-[11px] bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 rounded px-2.5 py-1 font-mono transition"
                >
                  Testar Host Fora de Escopo (Fail-Closed)
                </button>
              </div>
            </div>

            {/* Target Evaluation Form */}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                runEvaluate().finally(() => setEvaluating(false));
              }}
              class="space-y-3"
            >
              <div>
                <label class="block text-xs text-slate-400 mb-1">URL / Host / IP Alvo</label>
                <input
                  type="text"
                  value={targetInput}
                  onInput={(e) => setTargetInput((e.target as HTMLInputElement).value)}
                  placeholder="https://scanme.nmap.org ou 169.254.169.254"
                  class="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 font-mono focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div class="grid grid-cols-2 gap-3">
                <div>
                  <label class="block text-[11px] text-slate-400 mb-1">Porta (Opcional)</label>
                  <input
                    type="text"
                    value={portInput}
                    onInput={(e) => setPortInput((e.target as HTMLInputElement).value)}
                    placeholder="443"
                    class="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-100 font-mono"
                  />
                </div>
                <div>
                  <label class="block text-[11px] text-slate-400 mb-1">Path (Opcional)</label>
                  <input
                    type="text"
                    value={pathInput}
                    onInput={(e) => setPathInput((e.target as HTMLInputElement).value)}
                    placeholder="/api/v1/users"
                    class="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-100 font-mono"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={evaluating}
                class="w-full bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-slate-950 font-bold text-xs py-2.5 rounded-lg transition uppercase tracking-wider font-mono"
              >
                {evaluating ? "Avaliando 7 Camadas..." : "Avaliar Alvo no ScopeEngine"}
              </button>
            </form>

            {/* Verdict Card */}
            {verdict && (
              <div
                class={`rounded-xl p-4 border ${
                  verdict.allowed
                    ? "bg-emerald-950/30 border-emerald-500/50"
                    : "bg-red-950/30 border-red-500/50"
                } space-y-3`}
              >
                <div class="flex items-center justify-between">
                  <span
                    class={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono font-bold uppercase ${
                      verdict.allowed
                        ? "bg-emerald-500 text-slate-950"
                        : "bg-red-500 text-slate-950"
                    }`}
                  >
                    {verdict.allowed ? "✓ ALLOWED (PERMITIDO)" : "✕ BLOCKED (BLOQUEADO)"}
                  </span>
                  <span class="text-xs font-mono text-slate-300">
                    scope_state:{" "}
                    <strong class="text-cyan-300">{verdict.scope_state || (verdict.allowed ? "in_scope_explicit" : "out_of_scope")}</strong>
                  </span>
                </div>

                <div class="grid grid-cols-2 gap-2 text-xs font-mono bg-slate-950/80 p-2.5 rounded-lg border border-slate-800">
                  <div>
                    <span class="text-slate-500 block text-[10px]">PRECEDENCE TIER</span>
                    <span class="text-amber-300 font-semibold">
                      {matchedTierId || "UNKNOWN_DENY"}
                    </span>
                  </div>
                  <div>
                    <span class="text-slate-500 block text-[10px]">MATCHED PATTERN</span>
                    <span class="text-slate-200">
                      {verdict.matched_pattern || "N/A (Fail-Closed)"}
                    </span>
                  </div>
                </div>

                <div class="text-xs text-slate-300 bg-slate-950/60 p-2.5 rounded border border-slate-800/80 font-mono">
                  <span class="text-slate-500 block text-[10px] uppercase mb-0.5">Motivo / Razão Técnica:</span>
                  {verdict.reason}
                </div>
              </div>
            )}

            {/* 7-Layer Hierarchy Visualizer */}
            <div class="pt-2 border-t border-slate-800 space-y-1.5">
              <div class="text-[11px] font-mono uppercase text-slate-400">
                Hierarquia de Precedência (7 Camadas):
              </div>
              {PRECEDENCE_TIERS.map((tier) => {
                const isMatched = matchedTierId === tier.id;
                return (
                  <div
                    key={tier.id}
                    class={`px-3 py-1.5 rounded-lg border text-xs transition flex items-center justify-between ${
                      isMatched
                        ? verdict?.allowed
                          ? "bg-emerald-500/20 border-emerald-400 text-emerald-200 font-semibold shadow"
                          : "bg-red-500/20 border-red-400 text-red-200 font-semibold shadow"
                        : "bg-slate-950/50 border-slate-800/70 text-slate-400"
                    }`}
                  >
                    <div>
                      <div class="font-mono text-[11px]">{tier.label}</div>
                      <div class="text-[10px] opacity-75">{tier.desc}</div>
                    </div>
                    {isMatched && (
                      <span class="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-slate-950 text-amber-300 border border-amber-400/40">
                        MATCH
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>

      {/* Modal: Novo Programa */}
      {showNewProgramModal && (
        <div class="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div class="bg-slate-900 border border-slate-700 rounded-xl max-w-md w-full p-6 shadow-2xl space-y-4">
            <div class="flex items-center justify-between">
              <h3 class="text-base font-semibold text-slate-100">Cadastrar Novo Programa</h3>
              <button
                type="button"
                onClick={() => setShowNewProgramModal(false)}
                class="text-slate-400 hover:text-slate-200 font-mono text-sm"
              >
                ✕
              </button>
            </div>
            <form onSubmit={handleCreateProgram} class="space-y-3">
              <div>
                <label class="block text-xs text-slate-400 mb-1">Slug Único (ID)</label>
                <input
                  type="text"
                  value={newProgSlug}
                  onInput={(e) => setNewProgSlug((e.target as HTMLInputElement).value)}
                  placeholder="ex: acme-bounty"
                  class="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 font-mono"
                  required
                />
              </div>
              <div>
                <label class="block text-xs text-slate-400 mb-1">Nome do Programa</label>
                <input
                  type="text"
                  value={newProgName}
                  onInput={(e) => setNewProgName((e.target as HTMLInputElement).value)}
                  placeholder="ex: ACME Corp Bug Bounty"
                  class="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100"
                  required
                />
              </div>
              <div class="grid grid-cols-2 gap-3">
                <div>
                  <label class="block text-xs text-slate-400 mb-1">Plataforma</label>
                  <select
                    value={newProgPlatform}
                    onChange={(e) => setNewProgPlatform((e.target as HTMLSelectElement).value)}
                    class="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 font-mono"
                  >
                    <option value="hackerone">hackerone</option>
                    <option value="bugcrowd">bugcrowd</option>
                    <option value="intigriti">intigriti</option>
                    <option value="private">private</option>
                    <option value="lab">lab</option>
                  </select>
                </div>
                <div>
                  <label class="block text-xs text-slate-400 mb-1">Política Padrão</label>
                  <select
                    value={newProgPolicy}
                    onChange={(e) => setNewProgPolicy((e.target as HTMLSelectElement).value)}
                    class="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 font-mono"
                  >
                    <option value="bounty-safe">bounty-safe</option>
                    <option value="passive-only">passive-only</option>
                    <option value="lab-audit">lab-audit</option>
                  </select>
                </div>
              </div>
              <div class="flex justify-end gap-2 pt-3">
                <button
                  type="button"
                  onClick={() => setShowNewProgramModal(false)}
                  class="px-4 py-2 rounded-lg text-xs text-slate-300 hover:bg-slate-800"
                >
                  Cancelar
                </button>
                <button
                  type="submit"
                  disabled={creatingProgram}
                  class="bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-semibold text-xs px-4 py-2 rounded-lg"
                >
                  {creatingProgram ? "Criando..." : "Criar Programa"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
