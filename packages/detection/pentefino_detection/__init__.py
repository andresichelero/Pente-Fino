"""PenteFino Targeted Detection and Hardened Runner Plane.

Provides:
- DetectionPlanner: Targeted multi-tier template planning matching asset technologies.
- DetectionPlan: Structured scanner plan with pruned CDN/WAF tags.
- HardenedNucleiRunner / NucleiRunner: Hardened ephemeral container runner for Nuclei.
- FindingNormalizer: Ingestion, deduplication, and S3 evidence linkage.
"""
from pentefino_detection.normalizer import FindingNormalizer
from pentefino_detection.planner import (
    DetectionPlan,
    DetectionPlanner,
    EDGE_CDN_WAF_TAGS,
    GENERIC_BASELINE_TAGS,
)
from pentefino_detection.runner import HardenedNucleiRunner, NucleiRunner

__all__ = [
    "DetectionPlan",
    "DetectionPlanner",
    "EDGE_CDN_WAF_TAGS",
    "GENERIC_BASELINE_TAGS",
    "HardenedNucleiRunner",
    "NucleiRunner",
    "FindingNormalizer",
]
