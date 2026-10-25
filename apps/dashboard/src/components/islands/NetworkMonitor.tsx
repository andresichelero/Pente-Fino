import type { LiveStatus } from "../../lib/api";
import { ago, ms } from "../../lib/api";
import { useLiveSocket, useNow } from "../../lib/hooks";
import { isStale, Loading, Sparkline, SocketBadge, StatusDot, STALE_AFTER_S } from "../ui";

interface Series {
  t: number[];
  db_latency_ms: (number | null)[];
  valkey_latency_ms: (number | null)[];
  net_latency_ms: (number | null)[];
  scope_evaluations: (number | null)[];
}

export default function NetworkMonitor() {
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
          <div class="notice error">Sem conexão com a API em 127.0.0.1:8000.</div>
        ) : (
          <Loading label="Medindo a rede" />
        )}
      </>
    );
  }

  const net = d.network;
  const snapshotStale = sock.receivedAt === null || (now - sock.receivedAt) / 1000 > STALE_AFTER_S;

  return (
    <>
      <p class="small" style="margin:0 0 16px">{badge}</p>
      {snapshotStale && (
        <div class="notice warn banner">
          <strong>Desatualizado.</strong> Última medição {ago(d.generated_at, now)}.
        </div>
      )}

      <section class="section" aria-labelledby="h-net">
        <div class="section-head">
          <h2 id="h-net">Rede · agregado WAN</h2>
          <span class="meta">{net.source ?? "ICMP + contadores do SO"}</span>
        </div>
        <dl class="kv">
          <dt>Latência média</dt>
          <dd>{ms(net.overall_latency_ms)}</dd>
          <dt>Jitter</dt>
          <dd>{ms(net.overall_jitter_ms)}</dd>
          <dt>Perda de pacotes</dt>
          <dd>{net.packet_loss_pct === null ? "indisponível" : `${net.packet_loss_pct}%`}</dd>
          <dt>Download / Upload</dt>
          <dd>
            {net.download_kbps !== undefined ? `↓ ${net.download_kbps} KB/s · ↑ ${net.upload_kbps} KB/s` : "indisponível"}
          </dd>
          <dt>Pacotes (RX / TX)</dt>
          <dd>
            {net.packets_recv !== undefined
              ? `${net.packets_recv.toLocaleString("pt-BR")} / ${net.packets_sent?.toLocaleString("pt-BR")}`
              : "indisponível"}
          </dd>
        </dl>
      </section>

      <section class="section" aria-labelledby="h-targets">
        <div class="section-head">
          <h2 id="h-targets">Alvos monitorados</h2>
          <span class="meta">ping ICMP, 3 ecos por alvo</span>
        </div>
        <div class="table-wrap">
          <table class="stack">
            <thead>
              <tr>
                <th>Alvo</th>
                <th>Host</th>
                <th>Estado</th>
                <th class="num">Latência</th>
                <th class="num">Jitter</th>
                <th class="num">Perda</th>
              </tr>
            </thead>
            <tbody>
              {net.targets.map((t) => (
                <tr key={t.host}>
                  <td data-label="Alvo">{t.name}</td>
                  <td data-label="Host" class="mono">
                    {t.host}
                  </td>
                  <td data-label="Estado">
                    <StatusDot status={t.status === "online" ? "up" : t.status === "degraded" ? "degraded" : "down"} />
                  </td>
                  <td data-label="Latência" class="num">
                    {ms(t.latency_ms)}
                  </td>
                  <td data-label="Jitter" class="num">
                    {ms(t.jitter_ms)}
                  </td>
                  <td data-label="Perda" class="num">
                    {t.loss_pct === null ? "—" : `${t.loss_pct}%`}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section class="section" aria-labelledby="h-sys">
        <div class="section-head">
          <h2 id="h-sys">Latência dos serviços internos</h2>
          <span class="meta">medida a cada snapshot</span>
        </div>
        <dl class="kv">
          <dt>PostgreSQL</dt>
          <dd>
            <StatusDot status={d.systems.postgres.status} stale={isStale(d.systems.postgres.checked_at, now)} /> ·{" "}
            {ms(d.systems.postgres.latency_ms)}
          </dd>
          <dt>Valkey</dt>
          <dd>
            <StatusDot status={d.systems.valkey.status} stale={isStale(d.systems.valkey.checked_at, now)} /> ·{" "}
            {ms(d.systems.valkey.latency_ms)}
          </dd>
          <dt>SeaweedFS</dt>
          <dd>
            <StatusDot status={d.systems.seaweedfs.status} stale={isStale(d.systems.seaweedfs.checked_at, now)} /> ·{" "}
            {ms(d.systems.seaweedfs.latency_ms)}
          </dd>
          <dt>RabbitMQ</dt>
          <dd>
            <StatusDot status={d.systems.rabbitmq.status} stale={isStale(d.systems.rabbitmq.checked_at, now)} /> ·{" "}
            {ms(d.systems.rabbitmq.latency_ms)}
          </dd>
        </dl>
      </section>
    </>
  );
}
