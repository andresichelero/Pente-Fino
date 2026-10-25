import { Fragment } from "preact";
import type { Check, LiveStatus } from "../../lib/api";
import { ago, ms } from "../../lib/api";
import { useLiveSocket, useNow } from "../../lib/hooks";
import { isStale, Loading, SeverityText, SocketBadge, StatusDot, STALE_AFTER_S } from "../ui";

const SYSTEM_LABEL: Record<string, string> = {
  api: "API",
  postgres: "PostgreSQL",
  valkey: "Valkey",
  seaweedfs: "SeaweedFS (evidências)",
  rabbitmq: "RabbitMQ",
  proxy: "Proxy de egress",
  worker: "Worker AMQP",
  runners: "Runners (containers)",
};

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"];

function brokenSystems(systems: Record<string, Check>, now: number): string[] {
  return Object.entries(systems)
    .filter(([, c]) => c.status === "down" || c.status === "degraded" || isStale(c.checked_at, now))
    .map(([k]) => SYSTEM_LABEL[k] ?? k);
}

export default function Overview() {
  const sock = useLiveSocket<LiveStatus>("/ws/status", (m) => (m?.event === "status" ? m.data : undefined));
  const now = useNow();
  const d = sock.data;
  const badge = (
    <SocketBadge
      state={sock.state}
      receivedAt={sock.receivedAt}
      now={now}
      nextRetryAt={sock.nextRetryAt}
      lastError={sock.lastError}
    />
  );

  if (!d) {
    return (
      <>
        <p class="small">{badge}</p>
        {sock.state === "reconnecting" ? (
          <div class="notice error" role="alert">
            <strong>Sem conexão com a API.</strong>
            <div class="small">Inicie a API em 127.0.0.1:8000; o painel reconecta sozinho.</div>
          </div>
        ) : (
          <Loading label="Medindo cada subsistema" />
        )}
      </>
    );
  }

  const snapshotStale = sock.receivedAt === null || (now - sock.receivedAt) / 1000 > STALE_AFTER_S;
  const running = [...d.execution.active_scans, ...d.execution.active_recon];
  const broken = brokenSystems(d.systems, now);
  const f = d.findings;

  return (
    <>
      <p class="small" style="margin:0 0 16px">{badge}</p>
      {snapshotStale && (
        <div class="notice warn banner" role="alert">
          <strong>Dados desatualizados.</strong> A última medição chegou {ago(d.generated_at, now)}; os valores abaixo
          podem não refletir o estado atual.
        </div>
      )}

      <section class="questions" aria-label="Resumo operacional">
        <div class="question">
          <h2>O que está rodando agora</h2>
          <div class="answer">{running.length}</div>
          <p>
            {running.length === 0
              ? "Nenhum scan ou recon em execução nesta API."
              : running.map((o) => `${o.kind === "recon" ? "recon" : "scan"} ${o.target}`).join(", ")}
          </p>
        </div>
        <div class="question">
          <h2>O que precisa de triagem</h2>
          <div class={`answer ${f.available && (f.needs_triage ?? 0) > 0 ? "is-warn" : ""}`}>
            {f.available ? f.needs_triage : "—"}
          </div>
          <p>
            {f.available ? (
              <>
                {f.new_24h} novo(s) nas últimas 24 h. <a href="/findings">Abrir triagem</a>
              </>
            ) : (
              `Indisponível: ${f.detail}`
            )}
          </p>
        </div>
        <div class="question">
          <h2>O que quebrou</h2>
          <div class={`answer ${broken.length ? "is-bad" : ""}`}>{broken.length}</div>
          <p>{broken.length ? broken.join(", ") : "Todos os subsistemas responderam na última medição."}</p>
        </div>
      </section>

      <div class="grid-2 wide-left">
        <section class="section" aria-labelledby="h-systems">
          <div class="section-head">
            <h2 id="h-systems">Saúde dos sistemas</h2>
            <span class="meta">marcado como desatualizado após {STALE_AFTER_S}s sem medição</span>
          </div>
          <div class="table-wrap">
            <table class="stack">
              <thead>
                <tr>
                  <th>Sistema</th>
                  <th>Estado</th>
                  <th class="num">Latência</th>
                  <th>Último check</th>
                  <th>Detalhe</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(d.systems).map(([key, c]) => (
                  <tr key={key}>
                    <td data-label="Sistema">{SYSTEM_LABEL[key] ?? key}</td>
                    <td data-label="Estado">
                      <StatusDot status={c.status} stale={isStale(c.checked_at, now)} />
                    </td>
                    <td data-label="Latência" class="num">
                      {c.status === "up" || c.latency_ms !== null ? ms(c.latency_ms) : "—"}
                    </td>
                    <td data-label="Último check">{ago(c.checked_at, now)}</td>
                    <td data-label="Detalhe" class="muted small">
                      {c.detail || c.source}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section class="section" aria-labelledby="h-exec">
          <div class="section-head">
            <h2 id="h-exec">Fila e execução</h2>
            <span class="meta">{ago(d.execution.checked_at, now)}</span>
          </div>
          {running.length === 0 ? (
            <div class="notice">
              Nada em execução. <a href="/scans">Iniciar um scan ou recon</a>
            </div>
          ) : (
            <div class="table-wrap">
              <table class="stack">
                <thead>
                  <tr>
                    <th>Tipo</th>
                    <th>Alvo</th>
                    <th class="num">Tempo</th>
                  </tr>
                </thead>
                <tbody>
                  {running.map((o) => (
                    <tr key={o.run_id}>
                      <td data-label="Tipo">{o.kind}</td>
                      <td data-label="Alvo" class="mono">
                        {o.target}
                      </td>
                      <td data-label="Tempo" class="num">
                        {Math.round(o.elapsed_s)}s
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <dl class="kv" style="margin-top:16px">
            <dt>Fila AMQP (prontas)</dt>
            <dd>{d.execution.amqp.available ? d.execution.amqp.total_ready : `indisponível (${d.execution.amqp.detail})`}</dd>
            <dt>Fila AMQP (sem ack)</dt>
            <dd>{d.execution.amqp.available ? d.execution.amqp.total_unacked : "indisponível"}</dd>
            <dt>Filas declaradas</dt>
            <dd>
              {d.execution.amqp.available
                ? d.execution.amqp.queues.length
                  ? d.execution.amqp.queues.map((q) => `${q.name} (${q.messages_ready})`).join(", ")
                  : "nenhuma (worker nunca declarou a topologia)"
                : "indisponível"}
            </dd>
          </dl>
        </section>
      </div>

      <div class="grid-2">
        <section class="section" aria-labelledby="h-findings">
          <div class="section-head">
            <h2 id="h-findings">Achados abertos</h2>
            <span class="meta">{f.available ? ago(f.checked_at, now) : ""}</span>
          </div>
          {!f.available ? (
            <div class="notice error">Indisponível: {f.detail}</div>
          ) : (f.needs_triage ?? 0) === 0 ? (
            <div class="notice">Nenhum achado aguardando triagem.</div>
          ) : (
            <>
              <dl class="kv">
                {SEVERITY_ORDER.filter((s) => f.open_by_severity?.[s]).map((s) => (
                  <Fragment key={s}>
                    <dt>
                      <SeverityText sev={s} />
                    </dt>
                    <dd>{f.open_by_severity![s]}</dd>
                  </Fragment>
                ))}
                <dt>Evidência</dt>
                <dd>
                  {Object.entries(f.open_by_evidence_level ?? {})
                    .sort()
                    .map(([lvl, n]) => `${lvl}: ${n}`)
                    .join("  ")}
                </dd>
              </dl>
              <div class="table-wrap" style="margin-top:12px">
                <table class="stack">
                  <thead>
                    <tr>
                      <th>Severidade</th>
                      <th>Detector</th>
                      <th>Ativo</th>
                      <th>Ev.</th>
                    </tr>
                  </thead>
                  <tbody>
                    {f.recent?.map((r) => (
                      <tr key={r.id}>
                        <td data-label="Severidade">
                          <SeverityText sev={r.severity} />
                        </td>
                        <td data-label="Detector">
                          <a href={`/findings?id=${r.id}`}>{r.detector_id}</a>
                        </td>
                        <td data-label="Ativo" class="mono">
                          {r.asset ?? "—"}
                        </td>
                        <td data-label="Ev.">{r.evidence_level}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </section>

        <section class="section" aria-labelledby="h-scope">
          <div class="section-head">
            <h2 id="h-scope">Escopo e segurança</h2>
            <span class="meta">janela de {Math.round(d.scope.api.window_s / 60)} min</span>
          </div>
          <dl class="kv">
            <dt>Avaliações do scope engine</dt>
            <dd>{d.scope.api.evaluations}</dd>
            <dt>Negadas</dt>
            <dd>{d.scope.api.denied}</dd>
            <dt>Bloqueios SSRF</dt>
            <dd>{d.scope.api.ssrf_blocked}</dd>
            <dt>Requisições pelo proxy (5 min)</dt>
            <dd>{d.scope.proxy.available ? d.scope.proxy.requests_last_5m : `indisponível — ${d.scope.proxy.detail}`}</dd>
            {d.scope.proxy.available && (
              <>
                <dt>Proxy desde o início</dt>
                <dd>
                  {Object.entries(d.scope.proxy.totals ?? {})
                    .map(([k, v]) => `${k}: ${v}`)
                    .join("  ")}
                </dd>
              </>
            )}
          </dl>
          <p class="muted small">Contadores da API desde {new Date(d.scope.api.counting_since).toLocaleString("pt-BR")}.</p>
        </section>
      </div>

      <section class="section" aria-labelledby="h-net">
        <div class="section-head">
          <h2 id="h-net">Rede</h2>
          <span class="meta">{d.network.timestamp ? ago(d.network.timestamp, now) : ""} · ICMP + contadores do SO</span>
        </div>
        <dl class="kv" style="margin-bottom:12px">
          <dt>Latência (WAN)</dt>
          <dd>{ms(d.network.overall_latency_ms)}</dd>
          <dt>Jitter</dt>
          <dd>{ms(d.network.overall_jitter_ms)}</dd>
          <dt>Perda</dt>
          <dd>{d.network.packet_loss_pct === null ? "indisponível" : `${d.network.packet_loss_pct}%`}</dd>
          <dt>Throughput</dt>
          <dd>
            {d.network.download_kbps !== undefined
              ? `↓ ${d.network.download_kbps} KB/s  ↑ ${d.network.upload_kbps} KB/s`
              : "indisponível"}
          </dd>
        </dl>
        <a href="/telemetry">Detalhes por alvo</a>
      </section>
    </>
  );
}
