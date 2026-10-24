"""Docker and Podman CLI command builder for pentefino_runner."""
from __future__ import annotations

import os
from typing import List, Optional

from pentefino_runner.config import (
    DEFAULT_NETWORK,
    ENV_NETWORK_VAR,
    FALLBACK_NETWORK,
    RunConfig,
)


class DockerCommandBuilder:
    """Builds hardened, deterministic CLI argument lists for docker or podman."""

    def __init__(
        self,
        engine_bin: str = "docker",
        default_network: str = DEFAULT_NETWORK,
        fallback_network: str = FALLBACK_NETWORK,
    ):
        self.engine_bin = engine_bin
        self.default_network = default_network
        self.fallback_network = fallback_network

    def resolve_network(
        self,
        requested_network: Optional[str] = None,
        use_fallback: bool = False,
    ) -> str:
        """Resolve docker network prioritizing env override, then explicit request, then default/fallback."""
        env_network = os.getenv(ENV_NETWORK_VAR)
        if env_network:
            return env_network
        if requested_network and requested_network != self.default_network:
            return requested_network
        if use_fallback:
            return self.fallback_network
        return requested_network or self.default_network

    def build_run_command(
        self,
        config: RunConfig,
        use_network_fallback: bool = False,
    ) -> List[str]:
        """Build the full CLI command for docker/podman run."""
        cmd: List[str] = [self.engine_bin, "run", "--rm"]

        # Container Name
        if config.container_name:
            cmd.extend(["--name", config.container_name])

        # Init Process Reaper
        if config.init:
            cmd.append("--init")

        # Network Isolation
        network = self.resolve_network(config.network, use_fallback=use_network_fallback)
        if network:
            cmd.extend(["--network", network])

        # Proxy Egress Routing (upper and lower case for maximum scanner compatibility)
        if config.http_proxy:
            cmd.extend(["-e", f"HTTP_PROXY={config.http_proxy}"])
            cmd.extend(["-e", f"http_proxy={config.http_proxy}"])
        if config.https_proxy:
            cmd.extend(["-e", f"HTTPS_PROXY={config.https_proxy}"])
            cmd.extend(["-e", f"https_proxy={config.https_proxy}"])

        # Custom Environment Variables
        for key, val in sorted(config.env.items()):
            cmd.extend(["-e", f"{key}={val}"])

        # Security & Hardening Flags
        if config.read_only:
            cmd.append("--read-only")

        for mount_path, opts in sorted(config.tmpfs.items()):
            cmd.extend(["--tmpfs", f"{mount_path}:{opts}"])

        for cap in config.cap_drop:
            cmd.extend(["--cap-drop", cap])

        for opt in config.security_opt:
            cmd.extend(["--security-opt", opt])

        if config.user:
            cmd.extend(["--user", config.user])

        # Resource Constraints
        if config.cpus > 0:
            cmd.extend(["--cpus", str(config.cpus)])
        if config.memory:
            cmd.extend(["--memory", config.memory])
        if config.pids_limit > 0:
            cmd.extend(["--pids-limit", str(config.pids_limit)])

        # Volume Mounts
        for vol in config.volumes:
            cmd.extend(["-v", f"{vol.host_path}:{vol.container_path}:{vol.mode}"])

        # Working Directory
        if config.working_dir:
            cmd.extend(["-w", config.working_dir])

        # Entrypoint Override
        extra_entrypoint_args: List[str] = []
        if config.entrypoint:
            cmd.extend(["--entrypoint", config.entrypoint[0]])
            if len(config.entrypoint) > 1:
                extra_entrypoint_args = config.entrypoint[1:]

        # Container Image (Tag or pinned SHA256 digest)
        cmd.append(config.image)

        # Extra Entrypoint Args + Scanner Arguments
        if extra_entrypoint_args:
            cmd.extend(extra_entrypoint_args)
        if config.command:
            cmd.extend(config.command)

        return cmd
