# PenteFino

**PenteFino** is a modular, evidence-centric, bug-bounty-safe security control plane and automated vulnerability discovery engine.

It decouples untrusted reconnaissance and scanning tools (`subfinder`, `dnsx`, `httpx`, `nuclei`) from the core control plane using disposable hardened containers, a 7-tier fail-closed scope engine, and a forward egress proxy with token-bucket rate limiting and dual-hash forensic evidence capture.

---

## Architecture Overview

### 1. Control Plane & Governance
- **`packages/domain` (`pentefino_domain`)**: Asynchronous SQLAlchemy 2.0 + PostgreSQL 16 domain models and Alembic migrations (`Program`, `AuthorizationSnapshot`, `ScopeRule`, `Asset`, `Observation`, `TemplateCatalog`, `Finding`, `Evidence`, `AuditEvent`).
- **`packages/scope` (`pentefino_scope`)**: Deterministic, fail-closed 7-tier Scope Engine with pre-connection and post-resolution anti-SSRF filtering (RFC1918, loopback, link-local, cloud metadata `169.254.169.254`, IPv4-mapped IPv6) and dual-stack DNS rebinding defense.
- **`apps/proxy` (`pentefino_proxy`)**: Forward HTTP/HTTPS egress proxy enforcing scope validation, Valkey-backed token-bucket rate limiting ($0.5\text{ req/s}$ per host default), desktop browser User-Agent cloaking, scanner header scrubbing, secret redaction (`[REDACTED]`), and dual-hash SHA-256 forensic evidence tapping to SeaweedFS S3.

### 2. Ephemeral Execution & Reconnaissance
- **`packages/runner` (`pentefino_runner`)**: Hardened container runner (`docker run --rm --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m --cap-drop ALL --security-opt no-new-privileges:true`) routing outbound traffic exclusively through `pentefino_proxy`.
- **`packages/adapters` / `packages/discovery`**: Multi-stage reconnaissance pipeline (`SubfinderAdapter`, `DnsxAdapter`, `HttpxAdapter`) preserving the **Critical IP Invariant** (resolved DNS A/AAAA records are stored strictly as `Observation` metadata and never promoted into in-scope `Asset` records).
- **`data/wordlists/subdomains-top5k.txt`**: Curated 5,000-entry RFC-compliant subdomain wordlist for bounded active DNS brute-forcing.

### 3. Surgical Vulnerability Detection
- **`packages/template_indexer` (`pentefino_template_indexer`)**: Git synchronization of upstream `projectdiscovery/nuclei-templates`, static AST classification into 5 impact classes (`safe_read_only`, `active_reviewed`, `stateful`, `intrusive`, `lab_only`), deterministic SHA-256 bundle hashing, and batch PostgreSQL ingestion.
- **`packages/detection_planner` & `packages/finding_normalizer`**: Technology-aware `DetectionPlanner` with mandatory edge CDN/WAF tag pruning (`cloudflare`, `akamai`, `fastly`, `incapsula`, `sucuri`), `HardenedNucleiRunner`, and `FindingNormalizer` with canonical 5-tuple SHA-256 deduplication (`dedup_key`).

### 4. Operator CLI & Web GUI (Phase 5)
- **`apps/cli` (`pentefino_cli`)**: Typer + Rich CLI supporting interactive tables and `--json` automation across `program`, `scope`, `recon`, `template`, `scan`, `finding`, `api`, and `gui` subcommands.
- **`apps/api` (`pentefino_api`)**: Asynchronous FastAPI REST & WebSocket backend exposing 7-tier scope simulation, asset relationship graphs (enforcing the Critical IP Invariant), `DetectionPlanner` surgical preview, HackerOne/Bugcrowd Markdown report generation, and live scan/proxy WebSocket channels.
- **`apps/dashboard`**: Astro 5 Server/Hybrid (`@astrojs/node`) + Preact Islands + TailwindCSS SecOps Dashboard with 5 isolated interactive islands (`ScopeLiveTester`, `AssetRelationshipGraph`, `LiveScanRunner`, `FindingTriageBoard`, `LiveProxyStreamer`).

---

## Quick Start

### 1. Start Core Infrastructure
```powershell
docker compose up -d
alembic -c packages/domain/alembic.ini upgrade head
```

### 2. CLI Workflow Example
```powershell
# 1. Create a program
pentefino program create --slug acme-bounty --name "ACME Bug Bounty" --platform hackerone

# 2. Configure scope rules
pentefino scope add --program acme-bounty --allow "*.acme.com" --deny "admin.acme.com"

# 3. Synchronize & classify Nuclei templates
pentefino template sync
pentefino template list --impact safe_read_only --severity high --tech nginx

# 4. Run multi-stage reconnaissance
pentefino recon run --program acme-bounty --domain acme.com

# 5. Run targeted, safe vulnerability scan
pentefino scan run --program acme-bounty --asset app.acme.com

# 6. Query and export findings
pentefino finding query --program acme-bounty
pentefino finding export --program acme-bounty --format markdown

# 7. Launch the FastAPI Backend & Astro 5 Web GUI
pentefino gui
```

---

## Testing & Quality Assurance

```powershell
# Run full test suite (290 tests across Phases 1, 2, 3, and 5)
pytest tests/ apps/cli/tests/ apps/api/tests/ -q

# Run static linter
ruff check packages/ apps/ tests/

# Build Astro 5 Dashboard
cd apps/dashboard && npm run build
```
