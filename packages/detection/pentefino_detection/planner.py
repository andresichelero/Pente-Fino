"""Detection Planner for targeted vulnerability scanning.

Matches detected asset technologies against reviewed SAFE_READ_ONLY templates in
TemplateCatalog, strictly pruning generic Edge CDN/WAF tags (Cloudflare, Akamai, etc.)
and supporting severity and tag constraints.
"""
from __future__ import annotations

from pathlib import Path
from typing import Sequence
import uuid

from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import defer

from pentefino_domain.enums import ImpactClass
from pentefino_domain.models.asset import Asset
from pentefino_domain.models.template import TemplateCatalog

# Generic Edge CDN / WAF tags to strictly exclude from detection plans
EDGE_CDN_WAF_TAGS: set[str] = {
    "cloudflare",
    "akamai",
    "fastly",
    "incapsula",
    "sucuri",
    "cloudfront",
    "imperva",
    "ddos-guard",
}

# Generic baseline exposure/configuration tags used when no specific technologies are detected
GENERIC_BASELINE_TAGS: set[str] = {
    "misconfig",
    "exposure",
    "ssl",
    "tls",
    "headers",
    "config",
    "disclosure",
}

# Allowed impact classes by maximum threshold
SAFE_READ_ONLY_CLASSES: set[str] = {
    ImpactClass.SAFE_READ_ONLY.value,
    ImpactClass.PASSIVE.value,
    "safe_read_only",
    "passive",
}
ACTIVE_REVIEWED_CLASSES: set[str] = SAFE_READ_ONLY_CLASSES | {
    ImpactClass.ACTIVE_REVIEWED.value,
    "active_reviewed",
}


class DetectionPlan(BaseModel):
    """Execution plan containing targeted templates for an asset."""

    plan_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    program_id: uuid.UUID
    asset_id: uuid.UUID | None = None
    asset_canonical_key: str
    target_url: str
    selected_template_ids: list[str] = Field(default_factory=list)
    selected_template_paths: list[str] = Field(default_factory=list)
    matched_technologies: list[str] = Field(default_factory=list)
    total_templates: int = 0
    estimated_requests: int = 0


class DetectionPlanner:
    """Plans surgical, safe vulnerability scans against scoped assets."""

    EDGE_CDN_WAF_TAGS = EDGE_CDN_WAF_TAGS
    GENERIC_BASELINE_TAGS = GENERIC_BASELINE_TAGS

    def __init__(
        self,
        db_session: AsyncSession | None = None,
        storage_templates_dir: str | Path = "storage/templates/nuclei-templates",
        templates_container_dir: str = "/templates",
    ):
        self.db_session = db_session
        self.storage_templates_dir = Path(storage_templates_dir)
        self.templates_container_dir = templates_container_dir.rstrip("/")

    async def create_plan(
        self,
        asset: Asset | str,
        detected_technologies: list[str] | None = None,
        severity_filter: list[str] | str | None = None,
        tag_filter: list[str] | str | None = None,
        max_impact_class: ImpactClass | str = ImpactClass.SAFE_READ_ONLY,
        program_id: uuid.UUID | str | None = None,
        target_url: str | None = None,
        templates: Sequence[TemplateCatalog] | None = None,
    ) -> DetectionPlan:
        """Create a targeted DetectionPlan for an asset.

        Args:
            asset: Asset domain instance or string hostname/URL.
            detected_technologies: List of technologies discovered by recon (e.g. ['apache', 'php']).
            severity_filter: Optional severity filter (e.g. ['high', 'critical'] or 'high,critical').
            tag_filter: Optional tag filter (e.g. ['cve'] or 'cve,misconfig').
            max_impact_class: Maximum permissible template impact class (default SAFE_READ_ONLY).
            program_id: Program ID UUID if asset is passed as a string.
            target_url: Target URL if different from asset canonical key.
            templates: Optional in-memory sequence of TemplateCatalog items (bypasses DB query).
        """
        # 1. Resolve Asset Coordinates
        if isinstance(asset, Asset):
            asset_id = asset.id
            canonical_key = asset.canonical_key
            prog_id = asset.program_id
        else:
            asset_id = None
            canonical_key = str(asset).strip()
            if program_id is None:
                prog_id = uuid.uuid4()
            elif isinstance(program_id, uuid.UUID):
                prog_id = program_id
            else:
                prog_id = uuid.UUID(str(program_id).strip())

        if target_url:
            resolved_target_url = target_url
        elif canonical_key.startswith("http://") or canonical_key.startswith("https://"):
            resolved_target_url = canonical_key
        else:
            resolved_target_url = f"https://{canonical_key}"

        # 2. Prune Edge CDN / WAF Tags from Recon Input
        raw_techs = [
            t.strip().lower() for t in (detected_technologies or []) if t and t.strip()
        ]
        clean_technologies = [
            t for t in raw_techs if t not in self.EDGE_CDN_WAF_TAGS
        ]

        # 3. Retrieve Candidate Templates
        allowed_classes = self._get_allowed_impact_classes(max_impact_class)
        if templates is not None:
            candidates = list(templates)
        elif self.db_session is not None:
            stmt = (
                select(TemplateCatalog)
                .options(defer(TemplateCatalog.raw_yaml))
                .where(func.lower(TemplateCatalog.impact_class).in_(allowed_classes))
            )
            result = await self.db_session.execute(stmt)
            candidates = list(result.scalars().all())
        else:
            candidates = []

        # 4. Tier 1: Impact Hard-Gate Filter
        tier1_templates: list[TemplateCatalog] = []
        for t in candidates:
            impact = (t.impact_class or "").lower()
            if impact in allowed_classes:
                tier1_templates.append(t)

        # 5. Tier 2: Edge CDN / WAF Tag Exclusion
        tier2_templates: list[TemplateCatalog] = []
        for t in tier1_templates:
            if not self._has_edge_cdn_waf_tag(t):
                tier2_templates.append(t)

        # 6. Tier 3: Technology Matching or Fallback
        matched_templates: list[TemplateCatalog] = []
        matched_tech_set: set[str] = set()

        if clean_technologies:
            for t in tier2_templates:
                t_techs = {x.strip().lower() for x in (t.technologies or []) if x}
                t_tags = {x.strip().lower() for x in (t.tags or []) if x}
                t_id = (t.id or "").lower()
                t_name = (t.name or "").lower()

                matched = False
                for tech in clean_technologies:
                    # Match on technologies list, tags list, or substring in template id/name
                    if (
                        tech in t_techs
                        or tech in t_tags
                        or tech in t_id
                        or tech in t_name
                    ):
                        matched = True
                        matched_tech_set.add(tech)

                if matched:
                    matched_templates.append(t)
        else:
            # Baseline fallback when no technologies detected or all detected were CDN/WAF
            for t in tier2_templates:
                t_tags = {x.strip().lower() for x in (t.tags or []) if x}
                t_techs = {x.strip().lower() for x in (t.technologies or []) if x}
                if (t_tags | t_techs) & self.GENERIC_BASELINE_TAGS:
                    matched_templates.append(t)

        # 7. Tier 4: Severity & Custom Tag Filtering
        final_templates = matched_templates

        if severity_filter:
            if isinstance(severity_filter, str):
                sev_set = {
                    s.strip().lower() for s in severity_filter.split(",") if s.strip()
                }
            else:
                sev_set = {
                    s.strip().lower() for s in severity_filter if s and s.strip()
                }
            final_templates = [
                t
                for t in final_templates
                if (t.severity or "info").lower() in sev_set
            ]

        if tag_filter:
            if isinstance(tag_filter, str):
                req_tags = {
                    tg.strip().lower() for tg in tag_filter.split(",") if tg.strip()
                }
            else:
                req_tags = {
                    tg.strip().lower() for tg in tag_filter if tg and tg.strip()
                }
            final_templates = [
                t
                for t in final_templates
                if bool({x.strip().lower() for x in (t.tags or [])} & req_tags)
            ]

        # 8. Deduplicate and Construct Template Paths
        seen_ids: set[str] = set()
        selected_ids: list[str] = []
        selected_paths: list[str] = []

        for t in final_templates:
            if t.id not in seen_ids:
                seen_ids.add(t.id)
                selected_ids.append(t.id)
                raw_rel = getattr(t, "file_path", None) or t.id
                path_suffix = raw_rel if raw_rel.endswith((".yaml", ".yml")) else f"{raw_rel}.yaml"
                if not path_suffix.startswith("/"):
                    container_path = f"{self.templates_container_dir}/{path_suffix}"
                else:
                    container_path = path_suffix
                selected_paths.append(container_path)

        return DetectionPlan(
            plan_id=uuid.uuid4(),
            program_id=prog_id,
            asset_id=asset_id,
            asset_canonical_key=canonical_key,
            target_url=resolved_target_url,
            selected_template_ids=selected_ids,
            selected_template_paths=selected_paths,
            matched_technologies=sorted(list(matched_tech_set)),
            total_templates=len(selected_ids),
            estimated_requests=len(selected_ids) * 2,
        )

    def _get_allowed_impact_classes(self, max_impact: ImpactClass | str) -> set[str]:
        """Resolves allowed impact classes for the given threshold."""
        val = max_impact.value if isinstance(max_impact, ImpactClass) else str(max_impact).lower()
        if val in ("active_reviewed", ImpactClass.ACTIVE_REVIEWED.value):
            return ACTIVE_REVIEWED_CLASSES
        return SAFE_READ_ONLY_CLASSES

    def _has_edge_cdn_waf_tag(self, template: TemplateCatalog) -> bool:
        """Returns True if the template contains generic edge CDN/WAF tags."""
        tags = {x.strip().lower() for x in (template.tags or []) if x}
        techs = {x.strip().lower() for x in (template.technologies or []) if x}
        template_id = template.id or ""

        # Check tag intersection
        if tags & self.EDGE_CDN_WAF_TAGS:
            return True
        # Check technology intersection
        if techs & self.EDGE_CDN_WAF_TAGS:
            return True
        # Check template ID for CDN keywords
        template_id_lower = template_id.lower()
        for cdn_tag in self.EDGE_CDN_WAF_TAGS:
            if cdn_tag in template_id_lower:
                return True

        return False
