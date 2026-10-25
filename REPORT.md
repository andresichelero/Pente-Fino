# Auditoria PenteFino — relatório

**Branch:** `review/opus-audit` · **Data:** 2026-10-25 · **Revisor:** Claude (Opus)
**Escopo de teste:** apenas hosts locais e o laboratório local DVWA (`127.0.0.1:8088`). `docq.app` foi deixado de fora a pedido do André (depende de VPN). Nenhum tráfego foi disparado contra terceiros.

> Nada aqui foi commitado. As mudanças estão na árvore de trabalho da branch `review/opus-audit` para você revisar.

---

## 1. Resumo executivo

A plataforma estava **funcionalmente montada, mas não confiável**: o pipeline de governança tinha furos que permitiam varrer alvos fora do escopo, a telemetria apresentava valores fixos como se fossem medidos, e um lote inteiro de rotas quebrava por erros de nome não resolvidos (o lint acusava, mas ninguém tinha rodado).

As correções mais importantes:

1. **Scan ignorava o scope engine** — qualquer `asset_key` era gravado como `in_scope_explicit` e varrido. Agora todo scan/recon reavalia o alvo pelo engine (fail-closed) antes de qualquer pacote.
2. **Nuclei podia rodar sem restrição** — sem templates casados, rodava o catálogo inteiro (incluindo `intrusive`); usava `-as` e seguia redirects entre hosts; nunca passava pelo proxy. Agora recusa rodar sem allowlist, nunca usa `-as`, só segue redirect no mesmo host e roteia pelo proxy quando configurado.
3. **Telemetria fabricada** — séries fixas, `14107` fixo, `/intel/status` sempre "sincronizado agora". Removidos; cada métrica agora tem fonte real ou aparece como indisponível.
4. **Auth fail-open** — sem `PENTEFINO_API_KEY`, a API servia qualquer cliente. Agora, sem chave, só responde a loopback; com chave, exige em todas as rotas HTTP e WebSocket.
5. **Dashboard refeito do zero** — minimalista, uma cor de destaque, claro/escuro por tokens, responsivo até 375px, com estados vazio/carregando/erro/desatualizado explícitos e um painel ao vivo via WebSocket com reconexão e backoff.

**Baseline de testes:** 386 → **421 testes passando** (35 novos cobrindo as correções). **ruff:** 78 erros → **limpo**. **Build do dashboard:** passa.

---

## 2. Baseline (estado inicial, antes das correções)

Comandos executados na primeira passada (não assumi os números do README):

| Verificação | Resultado inicial |
|---|---|
| `pytest tests/ apps/cli/tests/ apps/api/tests/` | **386 passaram**, 1 warning (não os "290" do README) |
| `ruff check packages/ apps/ tests/` | **78 erros** (46 F401, 17 E402, 10 F821 nomes indefinidos reais, 4 F841, 1 F541) |
| `cd apps/dashboard && npm ci && npm run build` | **passou** |
| `docker compose up -d` | **falhou** ao recriar postgres/seaweedfs: `invalid volume specification` (o engine recusa o caminho Windows `D:\...` no bind mount). Os containers já existentes continuaram de pé. |
| `alembic -c packages/domain/alembic.ini upgrade head` | já em `0003_add_filepath_and_threat_intel (head)` |

O `ruff` acusava 78 erros apesar do README dizer que o lint passa. A causa: **não havia configuração de regras do ruff** no projeto — ele rodava com o conjunto padrão. Fixei o conjunto de regras em `pyproject.toml` (`select = ["E4","E7","E9","F"]`, o mesmo conjunto padrão da passada de baseline) para que o resultado seja reproduzível, e corrigi todos os 78.

**Estado final:** `pytest` 421 ok · `ruff` limpo · `npm run build` ok.

---

## 3. Achados por severidade

Severidade: **Crítico** (permite sair do escopo / varrer o que não devia), **Alto** (quebra funcional ou engana o operador), **Médio**, **Baixo**.

### 3.1 CRÍTICO — Scan não consultava o scope engine; stored `scope_state` era confiável
- **Arquivo:** `apps/api/pentefino_api/routers/scans.py:74-80` (antes), `apps/cli/pentefino_cli/commands/scan.py:81`
- **Evidência:** `_resolve_asset_and_techs` criava qualquer `asset_key` com `scope_state="in_scope_explicit"` e seguia. O gate em `run_scan` só olhava o `scope_state` **armazenado** — que o próprio código acabara de gravar. Um POST `/api/v1/scans/run` com `asset_key: "qualquer-coisa.invalid"` passava.
- **Reprodução:** `test_scan_run_unknown_out_of_scope_asset_is_refused`, `test_scan_run_stored_in_scope_flag_is_not_trusted` em `apps/api/tests/test_api_audit_fixes.py`.
- **Correção:** novo módulo `apps/api/pentefino_api/scope_loader.py` (`load_program_scope_engine`, `evaluate_and_count`), fail-closed e tolerante a múltiplos snapshots. `_resolve_asset_and_techs` agora reavalia pelo engine a cada chamada e devolve 403 se negado; `batch-run` reavalia cada ativo armazenado **antes** do canary; o CLI (`_current_scope_decision`) faz o mesmo. Aplicado — com testes.

### 3.2 CRÍTICO — Nuclei rodava o catálogo inteiro sem allowlist; `-as` e redirects cross-host; sem proxy
- **Arquivo:** `apps/api/pentefino_api/real_tools.py:356-444` (antes)
- **Evidência:** `run_real_nuclei` com `template_ids` vazio não passava `-id` nenhum → nuclei usa o catálogo padrão inteiro, incluindo templates `intrusive`/`stateful`. Além disso adicionava `-as` (auto-scan por tecnologia, ignora a classe de impacto) e `-fr` (segue redirect para qualquer host, furando o scope por hop). Nunca passava `-proxy`.
- **Reprodução:** `test_nuclei_refuses_empty_template_list`, `test_nuclei_args_never_auto_scan_and_only_same_host_redirects`, `test_nuclei_require_proxy_without_proxy_is_refused` em `tests/test_audit_fixes.py`.
- **Correção:** `run_real_nuclei` agora **recusa** (`UnsafeScanRequest`) sem `template_ids`; nunca passa `-as`; usa `-fhr` (só redirect no mesmo host); passa `-proxy $PENTEFINO_EGRESS_PROXY` quando setado e recusa se `PENTEFINO_REQUIRE_EGRESS_PROXY=true` sem proxy; limita a 20 templates; aplica timeout (`PENTEFINO_NUCLEI_TIMEOUT`, 900s) matando o processo. Aplicado — com testes.

### 3.3 CRÍTICO — Recon: checagem de IP interno nunca funcionou; snapshot de autorização fabricado
- **Arquivo:** `apps/api/pentefino_api/routers/recon.py:295` e `:68-79` (antes)
- **Evidência 1 (anti-SSRF furado):** `prohibited = any(is_prohibited_ip(ip) for ip in a_ips)` — `is_prohibited_ip` **retorna uma tupla `(bool, str)`**, e uma tupla não-vazia é sempre truthy. Logo `prohibited` era `True` para todo host que resolvia, caindo no fallback `live_resolved_hosts or in_scope_hosts[:50]`, que sondava por httpx **hosts que nunca passaram pela checagem de IP**.
- **Evidência 2 (auth fabricada):** se o programa não tinha `AuthorizationSnapshot`, o recon criava um válido por **1 ano** automaticamente (`db_auth = AuthorizationSnapshot(... valid_until=now+365d)` + `commit`), anulando o tier "Expired Auth" do engine.
- **Reprodução:** `test_prohibited_ips_filters_internal_ranges_only` (unit), `test_recon_skips_hosts_resolving_to_internal_ips`, `test_recon_without_authorization_snapshot_is_refused_and_none_is_fabricated`, `test_recon_out_of_scope_domain_is_refused_before_any_tool`.
- **Correção:** `_prohibited_ips()` desempacota a tupla corretamente e filtra IPv4+IPv6; só hosts resolvidos e aprovados no filtro de IP são sondados (sem o fallback perigoso); o recon recusa domínio fora de allow e nunca fabrica snapshot (usa o `scope_loader` fail-closed). Aplicado — com testes.

### 3.4 CRÍTICO — Proxy e compose expostos em 0.0.0.0 por padrão
- **Arquivo:** `docker-compose.yml` (todas as portas), `apps/proxy/pentefino_proxy/__main__.py:16`
- **Evidência:** `"${BIND_IP:-0.0.0.0}:..."` em postgres, valkey, seaweedfs, rabbitmq; o proxy escutava `PENTEFINO_PROXY_HOST` default `0.0.0.0`. Com o `.env` default (`BIND_IP=0.0.0.0`), tudo ficava acessível na rede. O proxy ainda subia **sem carregar regras do banco** (nega tudo) e sem sessão de DB.
- **Correção:** default do compose passou para `127.0.0.1`; proxy escuta loopback por padrão e agora faz `sync_scope()` do PostgreSQL ao subir. **Pendência sua:** seu `.env` tem `BIND_IP=0.0.0.0` — não alterei seu `.env` (só o `.env.example`). Recomendo `BIND_IP=127.0.0.1`.

### 3.5 ALTO — Rotas de scan quebravam com 500 (nomes indefinidos)
- **Arquivo:** `apps/api/pentefino_api/routers/scans.py:414,418,548,577,634,676` (antes)
- **Evidência:** `asyncio`, `logger`, `Any` usados sem import. Qualquer `POST /api/v1/scans/batch-run` com ativos estourava `NameError` → 500. O lint acusava (F821) mas o teste não cobria o caminho com ativos.
- **Reprodução:** `test_batch_run_no_longer_raises_name_error`.
- **Correção:** imports adicionados; `logger` definido no módulo. Aplicado — com teste.

### 3.6 ALTO — verify_api_key fail-open; standby 200; OSError mascarava erros reais
- **Arquivo:** `apps/api/pentefino_api/main.py:149-163, 191-245` (antes)
- **Evidência (suas 3 suspeitas, confirmadas):**
  - Sem `PENTEFINO_API_KEY`, `verify_api_key` retornava sem checar nada → API aberta a qualquer um.
  - O handler de standby devolvia **HTTP 200** com listas vazias em GET quando o banco estava fora — indistinguível de "sem dados". WebSockets nem passavam pela auth.
  - O handler genérico tratava **qualquer `OSError`** como standby (`isinstance(exc, (OperationalError, InterfaceError, OSError, ...))`), mascarando falhas de S3, docker, binários de scanner etc.
- **Reprodução:** `test_no_api_key_rejects_non_loopback_clients`, `test_websocket_accepts_key_in_query_when_configured`, `test_standby_is_503_for_get_and_health_has_no_placeholder_counts`, `test_oserror_with_db_up_is_a_real_500`.
- **Correção:** auth aplicada a HTTP **e** WebSocket (chave via header ou query `?key=` no WS); sem chave, só loopback (`PENTEFINO_TRUSTED_CLIENTS`); standby agora é **503 com `Retry-After`** em todo método; `OSError`/`TimeoutError` só viram standby se `check_db_available()` confirmar o banco fora. Aplicado — com testes.

### 3.7 ALTO — Telemetria com valores fixos apresentados como medidos (suas suspeitas)
- **Arquivo:** `apps/api/pentefino_api/main.py:269-307` e `routers/ws.py:222-351` (antes)
- **Evidência confirmada:** `/telemetry/summary` devolvia `rps_series`, `planner_latency_ms: 8.4`, `valkey_latency_ms: 0.9`, `scope_evals_series`, `ssrf_blocks_series` — **literais no código**. `templates_count` caía em `14107` fixo. `/ws/proxy/live` transmitia tráfego HTTP **inventado** (docq.app, demo.testfire.net, `169.254.169.254` com sha256 fixo) como se fosse real. O comando `simulate` do WS emitia estágios de scan falsos.
- **Correção:** `/telemetry/summary` só devolve contadores medidos + `configured_limits` (rotulados como configuração) + `series` amostradas do status real (`telemetry_series.py`); `planner_latency_ms` é `null` com nota em `unavailable`. `/ws/proxy/live` agora transmite só eventos reais publicados pelo proxy no Valkey (`pentefino:events:proxy`) + contadores reais; o tráfego fixo e o `simulate` foram removidos. **Regra aplicada em todo o painel: métrica sem fonte real → "indisponível", nunca um número inventado.**

### 3.8 ALTO — `/intel/status` reportava "sincronizado agora" sem sincronização (sua suspeita)
- **Arquivo:** `apps/api/pentefino_api/routers/intel.py:107-114` (antes)
- **Evidência:** `synced_at=datetime.now()` sempre, mesmo que `/intel/sync` nunca tivesse rodado.
- **Reprodução:** `test_intel_status_does_not_invent_a_sync_time`.
- **Correção:** `synced_at` é `null` até um sync real ocorrer; o status reporta a última sync de fato (`_LAST_SYNC`). Aplicado — com teste.

### 3.9 ALTO — Worker: `CancelledError` escapava sem ack (reentrega); cancelamento com corrida
- **Arquivo:** `apps/worker/pentefino_worker/amqp_consumer.py:328` e `cancellation.py:81-95` (antes)
- **Evidência:** `handle_scan_message` capturava `except Exception` — mas `asyncio.CancelledError` é `BaseException`, então ao cancelar um job a mensagem ficava **sem ack e sem reject** (reentregue e re-executada). E `cancel_run` só agia se o job já estivesse registrado: um cancelamento que chegasse **antes** do container iniciar era perdido (o scan rodava assim mesmo).
- **Reprodução:** `test_worker_operator_cancel_settles_message_without_requeue`, `test_worker_shutdown_cancel_requeues_message`, `test_worker_cancel_before_register_refuses_container` em `tests/test_audit_fixes.py`.
- **Correção:** `CancelledError` tratado à parte (cancelamento do operador → `reject(requeue=False)`; shutdown → `reject(requeue=True)`); registro de cancelamento com **tombstone** (`mark_cancelled`), então um container que tente iniciar depois é recusado. O endpoint `/scans/{id}/cancel` da API mata de fato os processos filhos (via `activity.cancel`). Aplicado — com testes.

### 3.10 ALTO — Engine do SQLAlchemy compartilhado entre event loops
- **Arquivo:** `packages/domain/pentefino_domain/session.py:82-120` (antes)
- **Evidência:** o engine/`session_factory` eram cacheados globalmente. Conexões asyncpg são atadas ao loop que as abriu; reusar o engine em outro `asyncio.run()` (um comando do CLI após outro, ou os testes) dava `got Future attached to a different loop` → o snapshot de contagens caía em standby silenciosamente.
- **Reprodução:** `test_engine_cache_is_per_event_loop`.
- **Correção:** cache do engine por event loop (weakref ao loop dono). Aplicado — com teste.

### 3.11 MÉDIO — `httpx` do PATH era o CLI Python (encode/httpx), não o ProjectDiscovery
- **Arquivo:** `apps/api/pentefino_api/real_tools.py:21-30` (antes)
- **Evidência:** `shutil.which("httpx")` achava o console script Python do venv do hermes (`.../hermes-agent/venv/Scripts/httpx`) em vez do httpx de recon. O recon usaria a ferramenta errada.
- **Reprodução:** `test_tool_resolution_skips_python_httpx_cli`.
- **Correção:** `get_tool_command` ignora binários que são entrypoints Python, aceita override `PENTEFINO_<TOOL>_BIN`, e cai para WSL. Aplicado — com teste.

### 3.12 MÉDIO — Rebinding de DNS no proxy HTTP (TOCTOU) e sem limite de corpo
- **Arquivo:** `apps/proxy/pentefino_proxy/server.py:226` (forward HTTP)
- **Evidência:** o caminho CONNECT já conecta no IP fixado pela decisão (`decision.resolved_ip`), mas o forward HTTP refaz `session.request(url=...)`, deixando o aiohttp **re-resolver** o host — janela de rebinding entre a checagem e a conexão. O leitor de requisição também não limitava `Content-Length`.
- **Correção aplicada:** limite de corpo (`max_body_bytes`, 413 acima); publicação de métricas e redação de URL (sem query string/credenciais em logs). **Pendência (não corrigido):** fixar o IP resolvido no forward HTTP (ex.: resolver uma vez e conectar por IP com `Host` preservado) — exige mudar o transporte do aiohttp; registrado como melhoria. Hoje o risco é mitigado porque o forward HTTP só roda para alvos já aprovados e o CONNECT (HTTPS, maioria) já fixa o IP.

### 3.13 MÉDIO — Testes contaminam o banco de desenvolvimento e o catálogo
- **Evidência:** os testes de API/CLI criam programas, assets e findings no banco apontado por `DATABASE_URL` (o seu dev). Pior: `test_db_migrations.py::test_migration_upgrade_downgrade_cycle` roda **downgrade→upgrade**, que dropa e recria as tabelas — **apaga o `template_catalog` inteiro** (vi o catálogo cair de 14.110 para 2 após rodar a suíte).
- **Correção aplicada:** `conftest.py` na raiz desliga as métricas do proxy e ajusta a auth para os testes. **Pendência (recomendação):** rodar a suíte contra um banco descartável (`DATABASE_URL` de teste) — não mudei isso para não alterar seu fluxo sem combinar. O catálogo pode ser repovoado com `pentefino template sync --path storage/templates/nuclei-templates`.

### 3.14 BAIXO — README desatualizado (suas suspeitas, confirmadas)
- Cita `packages/discovery`, `packages/detection_planner`, `packages/finding_normalizer` — **não existem** (o código está em `packages/adapters` e `packages/detection`). Cita **Astro 5**, mas o `package.json` traz **astro ^7**. Cita **290 testes** (são 421 agora). Corrigido na seção 9 e no README.

### Procura dirigida (resultado)
- **SQL por f-string:** nenhuma (todo acesso é via SQLAlchemy ORM/`select`). ✔
- **subprocess com `shell=True` / `os.system`:** nenhum. ✔ (os scanners usam `create_subprocess_exec` com lista de args)
- **Segredos em logs:** o proxy logava a URL completa (com query) — agora redigido (`redact_url`). Cookies/Authorization já eram redigidos pelo `redactor`. ✔
- **Dependências sem pin:** imagens dos scanners pinadas por tag (ex.: `projectdiscovery/nuclei:v3.3.5`); o runner suporta pin por digest (`PENTEFINO_STRICT_DIGEST`). Pins de Python ficam nos `pyproject` de cada pacote. ✔
- **Código morto:** removidos os islands antigos do dashboard e o `SparklineSVG` (substituídos).

---

## 4. Pipeline ponta a ponta

### 4.1 CLI (fluxo do README) — contra laboratório local
Programa de laboratório `opus-lab-docq` criado (docq.app ficou só na avaliação de escopo, sem tráfego, a pedido). Saídas em `scripts/`-adjacentes e no scratchpad.

| Etapa | Comando | Resultado |
|---|---|---|
| program create | `pentefino program create --slug opus-lab-docq --platform bugcrowd` | ok (id retornado) |
| scope add | `pentefino scope add --allow docq.app` / `--allow *.docq.app` | 2 regras |
| auth verify (antes) | `pentefino auth verify` | **`verified: false`** — fail-closed: CLI não fabrica snapshot ✔ |
| auth register | `pentefino auth register --rules-file tests/fixtures/lab/...` | registrado (hash SHA-256) |
| scope check | docq.app / www.docq.app / 127.0.0.1 / 169.254.169.254 / evil.com | `allow / allow(wildcard) / deny(loopback) / deny(metadata) / deny(unknown)` ✔ |
| template sync | `pentefino template sync --path storage/templates/nuclei-templates` | **14.110 classificados e ingeridos em 427 s** (offline, sem download) |

### 4.2 Scanner real contra o laboratório (DVWA)
Programa `opus-lab-dvwa` (platform `lab`) apontando para `127.0.0.1:8088` (DVWA em container). O scope engine libera loopback só em ambiente `lab`; em `bounty` o mesmo alvo é negado como IP proibido.

- **Nuclei real (via WSL) contra DVWA:** `nuclei -u http://127.0.0.1:8088/ -id tech-detect` → detectou **PHP** e **Apache/2.4.25 (Debian)**, exit 0, cookies redigidos pelo próprio nuclei. Saída em `scratchpad/pipeline/lab05_nuclei_direct.txt`. Isso prova a integração do scanner com um alvo de laboratório real.
- **Caminho completo pela API (confirmado):** com o catálogo repovoado (14.112), `POST /scans/plan` para `127.0.0.1:8088` casou **apache+php → 287 templates safe_read_only**; `POST /scans/run` em modo `auto` rodou o nuclei **real** (`mode_executed: real_cli`, cap de 20 templates) via WSL e passou pelo normalizer → `status: completed`, **0 achados** (resultado honesto: os 20 CVEs selecionados por tag são de 2000–2014 e não batem com esta versão do DVWA). Saídas em `scratchpad/pipeline/lab06_plan.json` e `lab07_run.json`. Confirma a cadeia HTTP→planner→nuclei→normalizer de ponta a ponta.
- **Diagnóstico do match 0 (antes do repovoamento):** o `test_migration_upgrade_downgrade_cycle` havia zerado o catálogo para 2 linhas. O planner casa por tag/id/substring (não só por `technologies`), então com o catálogo cheio o match funciona (223 templates safe_read_only casam apache/php por tag).

### 4.3 Matriz de endpoints
Script `scripts/endpoint_matrix.py` exercita cada rota (sucesso, entrada inválida, 404) usando um programa descartável e escopo `*.pentefino.test` (RFC 6761, nunca resolve); scans em `dry_run` (nenhum tráfego).

- **Banco no ar:** 54/55 casos como esperado. O único desvio era expectativa minha e revelou um bug real (**batch-run em dry_run ainda mandava o canary HTTP ao alvo** — corrigido, `test_batch_dry_run_sends_no_canary`).
- **Sem autenticação (instância com `PENTEFINO_API_KEY`):** **todas as 33 rotas** devolvem 401 sem chave e com chave errada; 200 com a chave certa.
- **Banco fora do ar** (parei o postgres temporariamente): **45 rotas de banco → 503 standby**, 7 rotas sem banco → 200, **nenhuma 500**. `/status/live` reporta `postgres: down` com os demais sistemas no ar.

### 4.4 Browser (todas as páginas)
Dev server em `127.0.0.1:4321`, API em `127.0.0.1:8000`. Capturas em `docs/audit/screens/` (`before-*` e `after-*`).

- As 7 páginas (visão geral, programas/escopo, ativos, scans/recon, achados, templates, rede) renderizam com **console limpo** (os 500 vistos numa aba eram transientes do Vite re-otimizando deps após `npm install`; aba nova = zero erros). Requisições 2xx.
- **Estados explícitos:** vazio (ex.: "Nenhum programa ainda"), carregando (barra), erro (com dica de correção), e **desatualizado** (banner âmbar + sistemas marcados) quando a última medição passa de 15 s.
- **WebSocket:** derrubei a API → a UI mostrou "Conexão perdida… Nova tentativa em 3s" (backoff), dados antigos envelhecendo; marcou tudo como desatualizado após 15 s; religuei a API → **reconectou sozinha** e voltou a "Ao vivo · atualizado há Xs". Capturas `after-ws-disconnected/stale/reconnected.jpg`.

---

## 5. Tempo real de múltiplas áreas (Fase 4)

Novo `/ws/status` (e `/api/v1/status/live`) monta um snapshot medido a cada chamada (`apps/api/pentefino_api/live_status.py`), com cache curto compartilhado. Cada valor traz `checked_at` e `source`, ou vem `null` com `detail` do motivo. A tela principal consome via WebSocket com reconexão/backoff e marca "desatualizado" acima de 15 s.

| Área | Fonte real | Quando indisponível |
|---|---|---|
| API / Postgres / Valkey / SeaweedFS / RabbitMQ | `SELECT 1`, `PING`, `GET /cluster/status`, management API | status `down`/`unknown` + motivo |
| Proxy | TCP + heartbeat Valkey (`pentefino:proxy:heartbeat`) | "proxy não está rodando" |
| Worker / runners | heartbeat Valkey do worker · `docker ps` | "sem heartbeat" / "docker CLI ausente" |
| Fila AMQP | management API (ready/unacked por fila) | "indisponível" |
| Escopo e SSRF | contadores reais das decisões do engine nesta API | contador desde o início |
| Requisições pelo proxy | `pentefino:metrics:proxy` (publicado pelo proxy) | "proxy sem métricas" |
| Achados | PostgreSQL (por severidade/evidência, 24 h) | "PostgreSQL indisponível" |
| Rede | ICMP (3 ecos/alvo, em threads) + `psutil.net_io_counters` | `null` quando nenhum eco volta |

O proxy passou a publicar métricas e heartbeat reais (`apps/proxy/pentefino_proxy/metrics.py`); o worker publica heartbeat (`amqp_consumer.py`). **Nenhum valor fixo aparece como medido.** O monitor de rede foi reescrito: antes bloqueava o event loop por até ~14 s e **inventava** `12ms/1ms/0%` quando tudo falhava; agora roda em threads e devolve `null` sem fonte.

---

## 6. Fase 3 — decisões de design do dashboard

Refeito do zero (os islands e o CSS antigos foram removidos). Pergunta operacional por tela: a visão geral responde "o que está rodando / o que precisa de triagem / o que quebrou".

- **Uma cor de destaque** (petróleo `#00708a` claro / `#5cc6db` escuro); neutros frios no resto; vermelho/âmbar só para estado. Sem gradientes, brilhos ou cards decorativos.
- **Tokens CSS** com claro/escuro (OS + toggle persistido); escala tipográfica 1.2; tabelas densas que **empilham com rótulos** abaixo de 640px; sem scroll horizontal; funciona em 375px.
- **Stack:** mantive Astro 7 + Preact islands, mas **troquei Tailwind por CSS com tokens** (`global.css`) — o design pedia uma linguagem própria, e o Tailwind antigo estava gerando o visual "card kit" que você reprovou. Removi `tailwindcss`, `@tailwindcss/vite` e `lucide-preact` das dependências.
- **Rotas mantidas** (`/`, `/programs`, `/assets`, `/scans`, `/findings`, `/templates`, `/telemetry`); a de telemetria passou a se chamar "Rede". Os nomes de navegação ficaram por função, não por número de etapa.

---

## 7. O que não pôde ser verificado (e por quê)

1. **Finding real gravado via API** — o caminho HTTP→planner→nuclei→normalizer foi fechado (seção 4.2), mas terminou com **0 achados** porque os 20 templates que o planner selecionou (ordenados por id, CVEs 2000–2014) não batem com esta versão do DVWA. Não forcei um template que produzisse achado — a API seleciona por tag/severidade, não por id. Para ver um finding gravado ponta a ponta, rode um scan apontando para um ativo cujo plano inclua um template aplicável (ou aumente/filtre a seleção). A gravação do finding em si tem cobertura em `test_finding_dedup_integration.py` e `test_phase_*`.
2. **docq.app** — fora por decisão sua (VPN). Só avaliação de escopo foi feita; nenhum tráfego.
3. **Proxy, worker e runners ao vivo** — não subi os processos do proxy/worker nesta sessão, então o painel os mostra como "fora do ar" (corretamente). A lógica de métricas/heartbeat tem testes unitários, mas não houve uma corrida ponta a ponta com tráfego passando pelo proxy real.
4. **Rebinding no forward HTTP do proxy** — mitigado, não eliminado (3.12).
5. **Isolamento dos testes** — a suíte escreve no seu banco de dev e o teste de migração zera o catálogo (3.13).
6. **`docker compose up -d`** — continua falhando ao recriar containers por causa do bind mount de caminho Windows; usei os containers já de pé. Não reescrevi os mounts (pode ser específico do seu Docker/WSL).

---

## 8. Decisões técnicas que tomei sem consultar

1. **Fixei o conjunto de regras do ruff** em `pyproject.toml` (não havia; o lint rodava no default). Reversível.
2. **Troquei Tailwind por CSS com tokens** no dashboard (ver 6). Removi 3 dependências.
3. **Novos módulos** em `apps/api`: `scope_loader.py`, `activity.py`, `live_status.py`, `telemetry_series.py`; e `apps/proxy/.../metrics.py`. Preferi módulos pequenos e testáveis a inchar os routers.
4. **Auth sem chave = só loopback** (em vez de aberta ou totalmente fechada), com `PENTEFINO_TRUSTED_CLIENTS` configurável — mantém o fluxo local do dev sem expor remotamente.
5. **Standby virou 503 em todo método** (antes 200 em GET). Muda o contrato da API em falha: o dashboard foi escrito para esperar 503.
6. **`conftest.py` na raiz** desliga métricas do proxy e trata `testclient` como loopback, para a suíte rodar com a auth fail-closed nova.
7. **Programas de laboratório** (`opus-lab-docq`, `opus-lab-dvwa`) e fixtures de política em `tests/fixtures/lab/` criados para o pipeline. Descartáveis.
8. **Nuclei roteia pelo proxy só quando `PENTEFINO_EGRESS_PROXY` está setado** (não forcei um default), com modo estrito opcional via `PENTEFINO_REQUIRE_EGRESS_PROXY`.

---

## 9. Correções pendentes recomendadas (não aplicadas)

- Fixar o IP resolvido no forward HTTP do proxy (3.12).
- Rodar a suíte contra um banco descartável e isolar o teste de migração para não zerar o catálogo (3.13).
- Popular `technologies` na classificação de templates (ou documentar que o match é por tag), para o planner selecionar de forma previsível (7.1).
- No seu `.env`, `BIND_IP=127.0.0.1` (3.4).
- Reescrever os bind mounts do compose para subir no seu Docker (7.6).
