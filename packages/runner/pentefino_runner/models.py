"""Alias for config module models."""
from pentefino_runner.config import (
    DEFAULT_HTTP_PROXY,
    DEFAULT_NETWORK,
    ENV_NETWORK_VAR,
    FALLBACK_NETWORK,
    RunConfig,
    RunResult,
    VolumeMount,
)

__all__ = [
    "VolumeMount",
    "RunConfig",
    "RunResult",
    "DEFAULT_NETWORK",
    "FALLBACK_NETWORK",
    "ENV_NETWORK_VAR",
    "DEFAULT_HTTP_PROXY",
]
