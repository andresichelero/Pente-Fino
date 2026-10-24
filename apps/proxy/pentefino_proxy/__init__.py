"""
pentefino_proxy: Traffic Control Plane & Forward Egress Proxy for PenteFino.
"""
from .cloaking import CloakingEngine, MODERN_USER_AGENTS
from .evidence_tap import EvidenceRecord, EvidenceTap, compute_canonical_hash
from .rate_limiter import InMemoryTokenBucket, ValkeyRateLimiter
from .redactor import Redactor, redact_cookie_string, redact_set_cookie_string
from .s3_client import InMemoryS3Store, S3EvidenceClient
from .scope_guard import ScopeGuard, ScopeGuardError
from .server import ForwardProxyServer, ProxyResult

__all__ = [
    "ForwardProxyServer",
    "ProxyResult",
    "ScopeGuard",
    "ScopeGuardError",
    "ValkeyRateLimiter",
    "InMemoryTokenBucket",
    "CloakingEngine",
    "MODERN_USER_AGENTS",
    "Redactor",
    "redact_cookie_string",
    "redact_set_cookie_string",
    "S3EvidenceClient",
    "InMemoryS3Store",
    "EvidenceTap",
    "EvidenceRecord",
    "compute_canonical_hash",
]
