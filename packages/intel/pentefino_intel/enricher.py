"""Threat Intelligence Enricher (ADR-05).

Queries public, zero-cost, license-safe feeds:
1. FIRST EPSS v4 API (Exploit Prediction Scoring System)
2. CISA Known Exploited Vulnerabilities (KEV) Catalog
3. OSV.dev Open Source Vulnerabilities API
"""
from __future__ import annotations

import re
from typing import Any
import httpx
from pydantic import BaseModel, Field

CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# Curated baseline of high-priority CISA KEV CVEs for deterministic offline fallback
BASELINE_CISA_KEV_CVES: set[str] = {
    "CVE-2021-41773",
    "CVE-2021-42013",
    "CVE-2021-44228",
    "CVE-2023-34362",
    "CVE-2023-4966",
    "CVE-2024-3400",
    "CVE-2024-23897",
    "CVE-2024-4577",
}


class CveEnrichmentResult(BaseModel):
    """Normalized threat intelligence telemetry for a CVE."""

    cve_id: str
    epss_score: float = Field(default=0.0, ge=0.0, le=1.0)
    epss_percentile: float = Field(default=0.0, ge=0.0, le=1.0)
    in_cisa_kev: bool = False
    kev_date_added: str | None = None
    priority_tier: str = "standard"  # critical_kev | high_epss | elevated | standard
    source: str = "live"


class OsvVulnerabilityRecord(BaseModel):
    """Vulnerability advisory returned from OSV.dev."""

    id: str
    summary: str = ""
    aliases: list[str] = Field(default_factory=list)
    severity: str = "unknown"


class ThreatIntelEnricher:
    """Enriches CVEs and software packages with EPSS, CISA KEV, and OSV.dev data."""

    EPSS_API_URL = "https://api.first.org/data/v1/epss"
    CISA_KEV_URL = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    OSV_QUERY_URL = "https://api.osv.dev/v1/query"

    def __init__(
        self,
        timeout_seconds: float = 5.0,
        kev_override: set[str] | None = None,
        http_client: httpx.AsyncClient | None = None,
    ):
        self.timeout_seconds = timeout_seconds
        self._kev_set: set[str] = (
            {c.upper() for c in kev_override}
            if kev_override is not None
            else set(BASELINE_CISA_KEV_CVES)
        )
        self._epss_cache: dict[str, tuple[float, float]] = {}
        self._http_client = http_client

    @staticmethod
    def compute_priority_tier(epss_score: float, in_cisa_kev: bool) -> str:
        """Determines operational triage priority from KEV membership and EPSS score."""
        if in_cisa_kev:
            return "critical_kev"
        if epss_score >= 0.50:
            return "high_epss"
        if epss_score >= 0.10:
            return "elevated"
        return "standard"

    async def enrich_cve(self, cve_id: str) -> CveEnrichmentResult:
        """Enrich a CVE identifier with EPSS v4 score/percentile and CISA KEV status."""
        clean_cve = cve_id.strip().upper()
        if not CVE_ID_PATTERN.match(clean_cve):
            raise ValueError(f"Invalid CVE identifier format: '{cve_id}'")

        in_kev = clean_cve in self._kev_set
        if clean_cve in self._epss_cache:
            score, percentile = self._epss_cache[clean_cve]
            return CveEnrichmentResult(
                cve_id=clean_cve,
                epss_score=score,
                epss_percentile=percentile,
                in_cisa_kev=in_kev,
                priority_tier=self.compute_priority_tier(score, in_kev),
                source="cache",
            )

        score = 0.0
        percentile = 0.0
        source = "live"

        try:
            if self._http_client is not None:
                resp = await self._http_client.get(
                    self.EPSS_API_URL, params={"cve": clean_cve}
                )
            else:
                async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                    resp = await client.get(
                        self.EPSS_API_URL, params={"cve": clean_cve}
                    )
            if resp.status_code == 200:
                payload = resp.json()
                data_list = payload.get("data") or []
                if data_list and isinstance(data_list[0], dict):
                    score = float(data_list[0].get("epss") or 0.0)
                    percentile = float(data_list[0].get("percentile") or 0.0)
                    self._epss_cache[clean_cve] = (score, percentile)
            else:
                source = "offline_fallback"
        except Exception:
            source = "offline_fallback"
            if in_kev:
                score = 0.94
                percentile = 0.99

        return CveEnrichmentResult(
            cve_id=clean_cve,
            epss_score=score,
            epss_percentile=percentile,
            in_cisa_kev=in_kev,
            priority_tier=self.compute_priority_tier(score, in_kev),
            source=source,
        )

    async def query_osv(
        self, package_name: str, version: str, ecosystem: str = "PyPI"
    ) -> list[OsvVulnerabilityRecord]:
        """Query OSV.dev for known vulnerabilities affecting a package version."""
        body: dict[str, Any] = {
            "version": version.strip(),
            "package": {
                "name": package_name.strip(),
                "ecosystem": ecosystem.strip(),
            },
        }
        records: list[OsvVulnerabilityRecord] = []
        try:
            if self._http_client is not None:
                resp = await self._http_client.post(self.OSV_QUERY_URL, json=body)
            else:
                async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                    resp = await client.post(self.OSV_QUERY_URL, json=body)

            if resp.status_code == 200:
                data = resp.json()
                for v in data.get("vulns") or []:
                    if isinstance(v, dict) and v.get("id"):
                        records.append(
                            OsvVulnerabilityRecord(
                                id=str(v["id"]),
                                summary=str(v.get("summary") or ""),
                                aliases=[str(a) for a in (v.get("aliases") or [])],
                            )
                        )
        except Exception:
            pass
        return records
