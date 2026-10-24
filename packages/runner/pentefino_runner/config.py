"""Configuration models for pentefino_runner."""
from __future__ import annotations

import os
from typing import Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

DEFAULT_NETWORK: str = "pentefino_pentefino-net"
FALLBACK_NETWORK: str = "pentefino-net"
ENV_NETWORK_VAR: str = "PENTEFINO_DOCKER_NETWORK"
DEFAULT_HTTP_PROXY: str = "http://pentefino_proxy:8080"


class VolumeMount(BaseModel):
    """Specification for a container volume bind mount."""

    model_config = ConfigDict(frozen=True)

    host_path: str
    container_path: str
    mode: str = "ro"  # Read-only by default for security


class RunConfig(BaseModel):
    """Configuration for an ephemeral scanner container run."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    image: str
    command: List[str] = Field(default_factory=list)
    entrypoint: Optional[List[str]] = None

    # Isolation & Identity
    container_name: Optional[str] = None
    user: Optional[str] = None

    # Hardening Defaults (Strict Sandboxing)
    read_only: bool = True
    tmpfs: Dict[str, str] = Field(
        default_factory=lambda: {"/tmp": "rw,noexec,nosuid,size=64m"}
    )
    cap_drop: List[str] = Field(
        default_factory=lambda: ["ALL"]
    )
    security_opt: List[str] = Field(
        default_factory=lambda: ["no-new-privileges:true"]
    )
    init: bool = True

    # Resource Limits
    cpus: float = 1.0
    memory: str = "512m"
    pids_limit: int = 128

    # Network Containment & Egress Proxy
    network: Optional[str] = Field(
        default_factory=lambda: os.getenv(ENV_NETWORK_VAR, DEFAULT_NETWORK)
    )
    http_proxy: Optional[str] = DEFAULT_HTTP_PROXY
    https_proxy: Optional[str] = DEFAULT_HTTP_PROXY
    env: Dict[str, str] = Field(default_factory=dict)

    # Mounts & Volumes
    volumes: List[VolumeMount] = Field(default_factory=list)

    # Execution Lifecycle
    timeout_seconds: float = 300.0
    working_dir: Optional[str] = None


class RunResult(BaseModel):
    """Result of an ephemeral container run."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float = 0.0
    timed_out: bool = False
    container_name: str = ""
    command_executed: List[str] = Field(default_factory=list)

    @property
    def is_success(self) -> bool:
        """Returns True if process terminated with exit code 0 and did not time out."""
        return self.exit_code == 0 and not self.timed_out

    def check_returncode(self) -> None:
        """Raise ContainerExecutionError if exit_code is non-zero."""
        if self.exit_code != 0:
            from pentefino_runner.exceptions import ContainerExecutionError

            raise ContainerExecutionError(
                f"Container '{self.container_name}' failed with exit code {self.exit_code}: {self.stderr.strip()}",
                exit_code=self.exit_code,
                stdout=self.stdout,
                stderr=self.stderr,
                container_name=self.container_name,
            )
