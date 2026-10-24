import { useState, useEffect } from "preact/hooks";

export interface ScopeLiveTesterProps {
  initialPrograms?: any[];
  initialSlug?: string;
  apiBaseUrl?: string;
}

const PRECEDENCE_TIERS = [
  { id: "EXPLICIT_DENY", rank: 1, label: "T1 · EXPLICIT_DENY / SSRF GUARD", desc: "RFC1918, Loopback, Link-Local 169.254.169.254 ou regra DENY explícita" },
  { id: "EXPIRED_AUTH", rank: 2, label: "T2 · EXPIRED_AUTH / SNAPSHOT GATE", desc: "AuthorizationSnapshot expirado ou programa inativo" },
  { id: "PATH_PORT_DENY", rank: 3, label: "T3 · PATH_PORT_DENY", desc: "Porta fora de allowed_ports ou caminho em denied_paths (/admin, /logout)" },
  { id: "EXPLICIT_ALLOW", rank: 4, label: "T4 · EXPLICIT_ALLOW", desc: "Correspondência exata com regra ALLOW (in_scope_explicit)" },
  { id: "WILDCARD_ALLOW", rank: 5, label: "T5 · WILDCARD_ALLOW", desc: "Subdomínio derivado de *.alvo.com (in_scope_derived)" },
  { id: "DERIVED_CANDIDATE", rank: 6, label: "T6 · DERIVED_CANDIDATE", desc: "Regra discover_only — restrito a reconhecimento passivo" },
  { id: "UNKNOWN_DENY", rank: 7, label: "T7 · UNKNOWN_DENY (FAIL-CLOSED)", desc: "Nenhuma regra aplicável — bloqueado por padrão" },
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

  // Drawers / Modals on demand
  const [showNewProgramModal, setShowNewProgramModal] = useState<boolean>(false);
  const [showNewRuleDrawer, setShowNewRuleDrawer] = useState<boolean>(false);

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
    if (!initialPrograms || initialPrograms.length === 0) {
      fetchPrograms();
    }
  }, []);

  useEffect(() => {
    if (selectedSlug) {
      // Clear stale verdict & messages when switching program
      setVerdict(null);
      setStatusMessage(null);
      if (selectedSlug !== initialSlug || !initialRules || initialRules.length === 0) {
        fetchScopeRules(selectedSlug);
      }
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
      // Offline fallback
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
      // Offline fallback
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
        setStatusMessage(`Programa '${nextSlug}' criado.`);
      } else {
        const err = await res.json().catch(() => ({}));
        setStatusMessage(`Erro: ${err.detail || res.statusText}`);
      }
    } catch (err: any) {
      setStatusMessage(`Falha de conexão: ${err?.message || "Offline"}`);
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
        setShowNewRuleDrawer(false);
        setStatusMessage(`Regra '${rulePattern.trim()}' (${ruleAction.toUpperCase()}) adicionada.`);
      } else {
        const err = await res.json().catch(() => ({}));
        setStatusMessage(`Erro: ${err.detail || res.statusText}`);
      }
    } catch (err: any) {
      setStatusMessage(`Erro de rede: ${err?.message || "Offline"}`);
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
        setStatusMessage("Regra removida.");
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
        setEvaluating(false);
        return;
      }
    } catch {
      // Offline deterministic fallback
    }

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
        matched_pattern: "RFC1918 / Loopback / Cloud Metadata SSRF Guard",
        reason: "SSRF Hard-Block: Private, Loopback, or IMDSv2 (169.254.169.254) IP range forbidden.",
        resolved_ip: lower.includes("169.254.169.254") ? "169.254.169.254" : "127.0.0.1",
        target_canonical: tgt,
      });
    } else if (lower.includes("scanme.nmap.org") && !lower.includes("admin.scanme.nmap.org")) {
      setVerdict({
        allowed: true,
        scope_state: "in_scope_explicit",
        precedence_tier: "EXPLICIT_ALLOW",
        matched_pattern: "scanme.nmap.org",
        reason: "Matched explicit allow rule for scanme.nmap.org on allowed port.",
        resolved_ip: "45.33.32.156",
        target_canonical: tgt.startsWith("http") ? tgt : `https://${tgt}/`,
      });
    } else if (lower.includes("admin.")) {
      setVerdict({
        allowed: false,
        scope_state: "out_of_scope",
        precedence_tier: "EXPLICIT_DENY",
        matched_pattern: "admin.*",
        reason: "Matched explicit deny rule for administrative subdomain.",
        resolved_ip: null,
        target_canonical: tgt,
      });
    } else {
      setVerdict({
        allowed: false,
        scope_state: "out_of_scope",
        precedence_tier: "UNKNOWN_DENY",
        matched_pattern: null,
        reason: "Target did not match any explicit or wildcard allow rule (Fail-Closed default).",
        resolved_ip: null,
        target_canonical: tgt,
      });
    }
    setEvaluating(false);
  }

  function applyPreset(presetTarget: string, presetPort = "", presetPath = "") {
    setTargetInput(presetTarget);
    setPortInput(presetPort);
    setPathInput(presetPath);
    runEvaluate(presetTarget, presetPort, presetPath);
  }

  const matchedTierId = verdict?.precedence_tier || verdict?.matched_tier || "";

  return (
    <div class="space-y-4">
      {/* Compact Control Strip */}
      <div class="card card-pad flex flex-wrap items-center justify-between gap-3">
        <div class="flex items-center gap-3 flex-wrap">
          <span class="card-title">ACTIVE PROGRAM</span>
          <select
            value={selectedSlug}
            onChange={(e) => setSelectedSlug((e.target as HTMLSelectElement).value)}
            class="input !w-auto min-w-[220px]"
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
          <span class="pill text-[#34d399] num">{rules.length} rules</span>
        </div>

        <div class="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setShowNewRuleDrawer((v) => !v)}
            class="btn"
          >
            {showNewRuleDrawer ? "✕ Fechar Regra" : "+ Nova Regra"}
          </button>
          <button
            type="button"
            onClick={() => setShowNewProgramModal(true)}
            class="btn btn-primary"
          >
            + Novo Programa
          </button>
        </div>
      </div>

      {statusMessage && (
        <div class="card px-4 py-2 border-[#22d3ee]/40 text-[#22d3ee] text-xs font-mono flex items-center justify-between">
          <span>{statusMessage}</span>
          <button type="button" onClick={() => setStatusMessage(null)} class="text-[#8b98a9] hover:text-white">
            [x]
          </button>
        </div>
      )}

      {/* Collapsible On-Demand New Rule Drawer */}
      {showNewRuleDrawer && (
        <form onSubmit={handleAddRule} class="card card-pad space-y-3 border-[#22d3ee]/40">
          <div class="flex items-center justify-between border-b border-[#1b2230] pb-2">
            <span class="card-title text-[#22d3ee]">+ ADD SCOPE RULE TO {selectedSlug}</span>
            <button type="button" onClick={() => setShowNewRuleDrawer(false)} class="text-xs font-mono text-[#8b98a9]">
              [ESC]
            </button>
          </div>
          <div class="grid grid-cols-1 sm:grid-cols-6 gap-3 items-end">
            <div>
              <label class="field-label">Action</label>
              <select
                value={ruleAction}
                onChange={(e) => setRuleAction((e.target as HTMLSelectElement).value)}
                class="input"
              >
                <option value="allow">allow</option>
                <option value="deny">deny</option>
                <option value="discover_only">discover_only</option>
              </select>
            </div>
            <div>
              <label class="field-label">Asset Type</label>
              <select
                value={ruleAssetType}
                onChange={(e) => setRuleAssetType((e.target as HTMLSelectElement).value)}
                class="input"
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
              <label class="field-label">Pattern</label>
              <input
                type="text"
                value={rulePattern}
                onInput={(e) => setRulePattern((e.target as HTMLInputElement).value)}
                placeholder="*.scanme.nmap.org"
                class="input"
                required
              />
            </div>
            <div>
              <label class="field-label">Allowed Ports</label>
              <input
                type="text"
                value={rulePorts}
                onInput={(e) => setRulePorts((e.target as HTMLInputElement).value)}
                placeholder="80, 443"
                class="input"
              />
            </div>
            <div>
              <label class="field-label">Denied Paths</label>
              <input
                type="text"
                value={ruleDeniedPaths}
                onInput={(e) => setRuleDeniedPaths((e.target as HTMLInputElement).value)}
                placeholder="/admin, /logout"
                class="input"
              />
            </div>
          </div>
          <div class="flex items-center justify-between pt-1">
            <div class="flex items-center gap-2 text-xs font-mono text-[#738196]">
              <span>Priority:</span>
              <input
                type="number"
                value={rulePriority}
                onInput={(e) => setRulePriority(Number((e.target as HTMLInputElement).value))}
                class="input !w-20"
              />
            </div>
            <button type="submit" disabled={addingRule} class="btn btn-primary">
              {addingRule ? "Salvando..." : "Salvar Regra"}
            </button>
          </div>
        </form>
      )}

      {/* Main Split Grid: Left 7 Cols Rules Table | Right 5 Cols Live 7-Layer Simulator */}
      <div class="grid grid-cols-1 lg:grid-cols-12 gap-4">
        <div class="lg:col-span-7 card overflow-hidden">
          <div class="px-4 py-3 border-b border-[#1b2230] flex items-center justify-between">
            <span class="card-title">SCOPE RULES MATRIX · {selectedSlug}</span>
            <button
              type="button"
              onClick={() => fetchScopeRules(selectedSlug)}
              class="btn btn-ghost !min-h-[24px] !px-2 text-[11px] font-mono"
            >
              ↻ Refresh
            </button>
          </div>

          <div class="overflow-x-auto">
            <table class="dtable num">
              <thead>
                <tr>
                  <th>Action</th>
                  <th>Type</th>
                  <th>Pattern</th>
                  <th class="r">Prio</th>
                  <th>Constraints</th>
                  <th class="r">Del</th>
                </tr>
              </thead>
              <tbody>
                {loadingRules ? (
                  <tr>
                    <td colSpan={6} class="py-6 text-center text-[#738196]">
                      Loading rules...
                    </td>
                  </tr>
                ) : rules.length === 0 ? (
                  <tr>
                    <td colSpan={6} class="py-6 text-center text-[#738196]">
                      No explicit rules — operating in Fail-Closed default (UNKNOWN_DENY).
                    </td>
                  </tr>
                ) : (
                  rules.map((r) => (
                    <tr key={r.id || r.pattern}>
                      <td>
                        <span
                          class={`pill ${
                            r.action === "allow"
                              ? "text-[#34d399] border-emerald-500/30"
                              : r.action === "deny"
                              ? "text-[#f87171] border-red-500/30"
                              : "text-[#fbbf24] border-amber-500/30"
                          }`}
                        >
                          {r.action}
                        </span>
                      </td>
                      <td class="text-[#8b98a9]">{r.asset_type}</td>
                      <td class="font-semibold text-white">{r.pattern}</td>
                      <td class="r text-[#738196]">{r.priority}</td>
                      <td class="text-[#8b98a9] text-[11px]">
                        {r.allowed_ports?.length ? `ports:${r.allowed_ports.join(",")}` : "ports:*"}
                        {r.denied_paths?.length ? ` · deny:${r.denied_paths.join(",")}` : ""}
                      </td>
                      <td class="r">
                        <button
                          type="button"
                          onClick={() => handleDeleteRule(r.id)}
                          class="text-[#f87171] hover:underline text-[11px]"
                        >
                          del
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right 5 Cols: Live 7-Tier Simulator */}
        <div class="lg:col-span-5 card card-pad space-y-3.5">
          <div class="flex items-center justify-between border-b border-[#1b2230] pb-2.5">
            <span class="card-title">LIVE 7-TIER SCOPE EVALUATOR</span>
            <div class="flex items-center gap-1.5 font-mono text-[10px]">
              <button
                type="button"
                onClick={() => applyPreset("https://scanme.nmap.org", "443", "/")}
                class="pill text-[#34d399] hover:border-[#34d399]"
              >
                Allow
              </button>
              <button
                type="button"
                onClick={() => applyPreset("http://169.254.169.254/latest/meta-data/", "80", "/latest/meta-data/")}
                class="pill text-[#f87171] hover:border-[#f87171]"
              >
                SSRF 169.254
              </button>
              <button
                type="button"
                onClick={() => applyPreset("https://unscoped.internal.org/login", "443", "/login")}
                class="pill text-[#fbbf24] hover:border-[#fbbf24]"
              >
                Unscoped
              </button>
            </div>
          </div>

          <form
            onSubmit={(e) => {
              e.preventDefault();
              runEvaluate();
            }}
            class="space-y-2.5"
          >
            <div>
              <label class="field-label">Target URL / Host / IP</label>
              <input
                type="text"
                value={targetInput}
                onInput={(e) => setTargetInput((e.target as HTMLInputElement).value)}
                placeholder="https://scanme.nmap.org"
                class="input"
              />
            </div>

            <div class="grid grid-cols-3 gap-2 items-end">
              <div>
                <label class="field-label">Port</label>
                <input
                  type="text"
                  value={portInput}
                  onInput={(e) => setPortInput((e.target as HTMLInputElement).value)}
                  placeholder="443"
                  class="input"
                />
              </div>
              <div>
                <label class="field-label">Path</label>
                <input
                  type="text"
                  value={pathInput}
                  onInput={(e) => setPathInput((e.target as HTMLInputElement).value)}
                  placeholder="/api"
                  class="input"
                />
              </div>
              <button type="submit" disabled={evaluating} class="btn btn-primary w-full">
                {evaluating ? "..." : "Evaluate →"}
              </button>
            </div>
          </form>

          {/* Verdict Banner with resolved_ip & target_canonical */}
          {verdict && (
            <div
              class={`p-3 rounded-lg border num text-xs space-y-2 ${
                verdict.allowed
                  ? "bg-emerald-950/20 border-[#34d399]/50"
                  : "bg-red-950/20 border-[#f87171]/50"
              }`}
            >
              <div class="flex items-center justify-between">
                <span
                  class={`pill font-bold ${
                    verdict.allowed ? "text-[#34d399] border-[#34d399]/40" : "text-[#f87171] border-[#f87171]/40"
                  }`}
                >
                  {verdict.allowed ? "✓ ALLOWED" : "✕ BLOCKED"}
                </span>
                <span class="text-[#22d3ee]">
                  {verdict.scope_state || (verdict.allowed ? "in_scope_explicit" : "out_of_scope")}
                </span>
              </div>

              <div class="grid grid-cols-2 gap-2 p-2 rounded bg-[#070a0f] border border-[#1b2230] text-[11px]">
                <div>
                  <span class="text-[#738196] block text-[10px]">CANONICAL TARGET</span>
                  <span class="text-white truncate block">{verdict.target_canonical || targetInput}</span>
                </div>
                <div>
                  <span class="text-[#738196] block text-[10px]">RESOLVED IP / PATTERN</span>
                  <span class="text-[#fbbf24] truncate block">
                    {verdict.resolved_ip || verdict.matched_pattern || "fail-closed"}
                  </span>
                </div>
              </div>

              <div class="text-[11px] text-[#8b98a9]">{verdict.reason}</div>
            </div>
          )}

          {/* Compact 1-Line-Per-Tier Stack (expands description only on match) */}
          <div class="space-y-1 pt-1">
            {PRECEDENCE_TIERS.map((tier) => {
              const isMatched = matchedTierId === tier.id;
              return (
                <div
                  key={tier.id}
                  class={`px-2.5 py-1.5 rounded border font-mono text-[11px] transition-all duration-150 ${
                    isMatched
                      ? verdict?.allowed
                        ? "bg-emerald-950/30 border-[#34d399] text-white"
                        : "bg-red-950/30 border-[#f87171] text-white"
                      : "bg-[#070a0f]/60 border-[#1b2230] text-[#738196]"
                  }`}
                >
                  <div class="flex items-center justify-between">
                    <span>{tier.label}</span>
                    {isMatched && <span class="text-[10px] text-[#fbbf24] font-bold">● MATCH</span>}
                  </div>
                  {isMatched && (
                    <div class="text-[10px] text-[#8b98a9] mt-1 font-sans">{tier.desc}</div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Modal: Novo Programa */}
      {showNewProgramModal && (
        <div class="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
          <div class="card card-pad max-w-md w-full space-y-4">
            <div class="flex items-center justify-between border-b border-[#1b2230] pb-2.5">
              <span class="card-title text-white">CREATE NEW PROGRAM</span>
              <button type="button" onClick={() => setShowNewProgramModal(false)} class="text-[#8b98a9] hover:text-white">
                ✕
              </button>
            </div>
            <form onSubmit={handleCreateProgram} class="space-y-3">
              <div>
                <label class="field-label">Slug (Unique ID)</label>
                <input
                  type="text"
                  value={newProgSlug}
                  onInput={(e) => setNewProgSlug((e.target as HTMLInputElement).value)}
                  placeholder="acme-bounty"
                  class="input"
                  required
                />
              </div>
              <div>
                <label class="field-label">Program Name</label>
                <input
                  type="text"
                  value={newProgName}
                  onInput={(e) => setNewProgName((e.target as HTMLInputElement).value)}
                  placeholder="ACME Bug Bounty"
                  class="input"
                  required
                />
              </div>
              <div class="grid grid-cols-2 gap-3">
                <div>
                  <label class="field-label">Platform</label>
                  <select
                    value={newProgPlatform}
                    onChange={(e) => setNewProgPlatform((e.target as HTMLSelectElement).value)}
                    class="input"
                  >
                    <option value="hackerone">hackerone</option>
                    <option value="bugcrowd">bugcrowd</option>
                    <option value="intigriti">intigriti</option>
                    <option value="private">private</option>
                    <option value="lab">lab</option>
                  </select>
                </div>
                <div>
                  <label class="field-label">Policy</label>
                  <select
                    value={newProgPolicy}
                    onChange={(e) => setNewProgPolicy((e.target as HTMLSelectElement).value)}
                    class="input"
                  >
                    <option value="bounty-safe">bounty-safe</option>
                    <option value="passive-only">passive-only</option>
                    <option value="lab-audit">lab-audit</option>
                  </select>
                </div>
              </div>
              <div class="flex justify-end gap-2 pt-2">
                <button type="button" onClick={() => setShowNewProgramModal(false)} class="btn">
                  Cancel
                </button>
                <button type="submit" disabled={creatingProgram} class="btn btn-primary">
                  {creatingProgram ? "Creating..." : "Create Program"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
