"""PenteFino Threat Intelligence Package (ADR-05).

Provides:
- ThreatIntelEnricher: Asynchronous enrichment via FIRST EPSS v4, CISA KEV, and OSV.dev.
- CveEnrichmentResult: Normalized CVE threat intelligence record.
- OsvVulnerabilityRecord: Package/version advisory record from OSV.dev.
"""
from pentefino_intel.enricher import (
    CveEnrichmentResult,
    OsvVulnerabilityRecord,
    ThreatIntelEnricher,
)

__all__ = [
    "CveEnrichmentResult",
    "OsvVulnerabilityRecord",
    "ThreatIntelEnricher",
]
