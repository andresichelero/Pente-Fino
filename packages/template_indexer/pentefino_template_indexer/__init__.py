"""
PenteFino Template Indexer Package.

Provides:
- TemplateSyncManager: Git shallow clone and commit SHA pinning for Nuclei templates.
- StaticTemplateClassifier: Deterministic AST impact classification and metadata extraction.
- compute_bundle_hash: Cryptographic SHA-256 bundle digest computation.
- TemplateCatalogIngester: Batched PostgreSQL upsert into template_catalog.
"""

from pentefino_template_indexer.bundle import compute_bundle_hash
from pentefino_template_indexer.classifier import (
    StaticTemplateClassifier,
    TemplateMetadata,
)
from pentefino_template_indexer.ingester import TemplateCatalogIngester
from pentefino_template_indexer.sync import (
    TemplateSyncError,
    TemplateSyncManager,
)

__all__ = [
    "TemplateSyncManager",
    "TemplateSyncError",
    "StaticTemplateClassifier",
    "TemplateMetadata",
    "compute_bundle_hash",
    "TemplateCatalogIngester",
]
