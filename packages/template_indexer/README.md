# PenteFino Template Indexer (`pentefino_template_indexer`)

Part of the PenteFino attack surface management platform.

Provides:
- Git-based synchronization of Nuclei templates (`TemplateSyncManager`).
- Static AST impact classification (`StaticTemplateClassifier` -> `ImpactClass`).
- Deterministic SHA-256 template bundle digest calculation (`compute_bundle_hash`).
- High-throughput batched ingestion into PostgreSQL `template_catalog` (`TemplateCatalogIngester`).
