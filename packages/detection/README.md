# PenteFino Detection (`pentefino_detection`)

Targeted, scope-safe vulnerability detection planning and hardened containerized execution plane for PenteFino.

## Modules
- **`planner` (`DetectionPlanner`)**: Multi-tier detection planner that matches detected asset technologies against `safe_read_only` templates, strictly pruning edge CDN/WAF tags (`cloudflare`, `akamai`, etc.) and supporting severity and tag filters.
- **`runner` (`HardenedNucleiRunner`)**: Ephemeral container runner constructing hardened Nuclei container invocations passing only the planned template paths via `-t`, routing traffic through `pentefino_proxy:8080`, and capturing JSONL results.
- **`normalizer` (`FindingNormalizer`)**: Ingests Nuclei JSON findings, normalizes target coordinates, computes SHA-256 deduplication keys, upserts `Finding` records, and links sanitized evidence artifacts in SeaweedFS S3.
