"""Hardened Nuclei Runner executing targeted scans inside ephemeral disposable containers.

Enforces zero-trust sandboxing (--read-only, --cap-drop ALL, tmpfs), network egress routing
through pentefino_proxy:8080, and surgical template execution by passing ONLY the
explicitly selected template paths via -t.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from pentefino_detection.planner import DetectionPlan
from pentefino_runner import (
    DEFAULT_HTTP_PROXY,
    DEFAULT_NETWORK,
    EphemeralRunner,
    RunConfig,
    RunResult,
    VolumeMount,
)

DEFAULT_NUCLEI_IMAGE: str = "projectdiscovery/nuclei:v3.3.5"


class HardenedNucleiRunner:
    """Executes Nuclei in a hardened ephemeral container via pentefino_runner."""

    def __init__(
        self,
        runner: EphemeralRunner,
        templates_host_dir: str | Path = "storage/templates/nuclei-templates",
        templates_container_dir: str = "/templates",
        nuclei_image: str = DEFAULT_NUCLEI_IMAGE,
        proxy_url: str = DEFAULT_HTTP_PROXY,
        network: str = DEFAULT_NETWORK,
        timeout_seconds: float = 300.0,
        rate_limit: int = 1,
    ):
        self.runner = runner
        self.templates_host_dir = Path(templates_host_dir)
        self.templates_container_dir = templates_container_dir.rstrip("/")
        self.nuclei_image = nuclei_image
        self.proxy_url = proxy_url
        self.network = network
        self.timeout_seconds = timeout_seconds
        self.rate_limit = rate_limit

    def build_run_config(
        self,
        plan: DetectionPlan,
        target_url: str | None = None,
        rate_limit: int | None = None,
    ) -> RunConfig:
        """Constructs hardened RunConfig with ONLY selected template paths passed via -t."""
        target = target_url or plan.target_url
        rl_val = str(rate_limit if rate_limit is not None else self.rate_limit)

        # Base Nuclei arguments
        command: list[str] = [
            "-u",
            target,
            "-jsonl",
            "-irr",
            "-o",
            "/tmp/nuclei_output.json",
            "-silent",
            "-stats=false",
            "-no-interactsh",
            "-rate-limit",
            rl_val,
            "-concurrency",
            "1",
        ]

        # Surgical template passing: ONLY pass the specific template paths selected by planner
        template_paths = list(plan.selected_template_paths)
        if not template_paths and plan.selected_template_ids:
            for tid in plan.selected_template_ids:
                suffix = tid if tid.endswith((".yaml", ".yml")) else f"{tid}.yaml"
                template_paths.append(f"{self.templates_container_dir}/{suffix}")

        for path in template_paths:
            command.extend(["-t", path])

        # Ephemeral container configuration with strict sandboxing
        return RunConfig(
            image=self.nuclei_image,
            command=command,
            network=self.network,
            http_proxy=self.proxy_url,
            https_proxy=self.proxy_url,
            read_only=True,
            tmpfs={"/tmp": "rw,noexec,nosuid,size=64m"},
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            cpus=1.0,
            memory="512m",
            pids_limit=128,
            timeout_seconds=self.timeout_seconds,
            volumes=[
                VolumeMount(
                    host_path=str(self.templates_host_dir),
                    container_path=self.templates_container_dir,
                    mode="ro",
                )
            ],
        )

    async def execute_scan(
        self,
        plan: DetectionPlan,
        target_url: str | None = None,
        timeout_seconds: float | None = None,
        rate_limit: int | None = None,
        on_finding: Callable[[dict[str, Any]], None] | None = None,
    ) -> list[dict[str, Any]]:
        """Executes targeted Nuclei container scan and returns parsed JSON findings."""
        # Fast exit if no templates were selected
        if not plan.selected_template_ids and not plan.selected_template_paths:
            return []

        config = self.build_run_config(plan, target_url=target_url, rate_limit=rate_limit)
        if timeout_seconds is not None:
            config.timeout_seconds = timeout_seconds

        collected_stdout: list[str] = []

        def handle_stdout(line: str) -> None:
            collected_stdout.append(line)
            if on_finding:
                line_str = line.strip()
                if line_str.startswith("{") and line_str.endswith("}"):
                    try:
                        parsed = json.loads(line_str)
                        if isinstance(parsed, dict) and "template-id" in parsed:
                            on_finding(parsed)
                    except Exception:
                        pass

        result: RunResult = await self.runner.run(
            config,
            on_stdout=handle_stdout,
        )

        # Parse findings from stdout stream
        raw_stdout = result.stdout or "".join(collected_stdout)
        findings: list[dict[str, Any]] = []

        for line in raw_stdout.splitlines():
            line_str = line.strip()
            if not line_str or not line_str.startswith("{"):
                continue
            try:
                data = json.loads(line_str)
                if isinstance(data, dict):
                    findings.append(data)
            except json.JSONDecodeError:
                continue

        return findings


# Alias for compatibility with PROJECT.md contract
NucleiRunner = HardenedNucleiRunner
