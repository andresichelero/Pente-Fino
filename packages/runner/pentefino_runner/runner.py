"""Ephemeral container runner executing commands asynchronously."""
from __future__ import annotations

import asyncio
import shutil
import time
import uuid
from typing import Callable, Optional

from pentefino_runner.builder import DockerCommandBuilder
from pentefino_runner.config import RunConfig, RunResult
from pentefino_runner.exceptions import (
    ContainerEngineNotFoundError,
    ContainerTimeoutError,
)


STREAM_LINE_BUFFER_LIMIT = 4 * 1024 * 1024  # 4MB line buffer for large scanner outputs


class EphemeralRunner:
    """Manages asynchronous lifecycle of hardened ephemeral scanner containers."""

    def __init__(
        self,
        engine: Optional[str] = None,
        builder: Optional[DockerCommandBuilder] = None,
    ):
        self.engine_bin = engine or self._detect_engine()
        self.builder = builder or DockerCommandBuilder(engine_bin=self.engine_bin)

    @staticmethod
    def _detect_engine() -> str:
        """Locate docker or podman on PATH, defaulting to docker."""
        for candidate in ("docker", "podman"):
            if shutil.which(candidate):
                return candidate
        return "docker"

    async def _cleanup_orphaned_container(self, container_name: str) -> None:
        """Forcefully remove orphaned container using <engine> rm -f."""
        try:
            rm_proc = await asyncio.create_subprocess_exec(
                self.engine_bin,
                "rm",
                "-f",
                container_name,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(rm_proc.wait(), timeout=5.0)
        except Exception:
            pass

    async def run(
        self,
        config: RunConfig,
        on_stdout: Optional[Callable[[str], None]] = None,
        on_stderr: Optional[Callable[[str], None]] = None,
        *,
        stdout_callback: Optional[Callable[[str], None]] = None,
        stderr_callback: Optional[Callable[[str], None]] = None,
        check: bool = False,
        raise_on_timeout: bool = True,
    ) -> RunResult:
        """Execute a container run asynchronously with non-blocking streaming and timeout enforcement."""
        cb_stdout = on_stdout or stdout_callback
        cb_stderr = on_stderr or stderr_callback

        if not config.container_name:
            config.container_name = f"pentefino_run_{uuid.uuid4().hex[:12]}"

        cmd = self.builder.build_run_command(config)
        start_time = time.monotonic()

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=STREAM_LINE_BUFFER_LIMIT,
            )
        except FileNotFoundError as err:
            raise ContainerEngineNotFoundError(
                f"Container engine binary '{self.engine_bin}' not found on PATH."
            ) from err

        stdout_chunks: list[str] = []
        stderr_chunks: list[str] = []

        async def _read_stream(
            stream: Optional[asyncio.StreamReader],
            collector: list[str],
            cb: Optional[Callable[[str], None]],
        ) -> None:
            if stream is None:
                return
            while True:
                line_bytes = await stream.readline()
                if not line_bytes:
                    break
                line = line_bytes.decode("utf-8", errors="replace")
                collector.append(line)
                if cb:
                    try:
                        cb(line)
                    except Exception:
                        pass

        read_tasks = asyncio.gather(
            _read_stream(proc.stdout, stdout_chunks, cb_stdout),
            _read_stream(proc.stderr, stderr_chunks, cb_stderr),
        )

        try:
            await asyncio.wait_for(
                asyncio.gather(proc.wait(), read_tasks),
                timeout=config.timeout_seconds,
            )
            timed_out = False
        except asyncio.TimeoutError:
            timed_out = True
            # Force container cleanup
            await self._cleanup_orphaned_container(config.container_name)

            # Terminate host CLI process
            try:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=2.0)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
            except (ProcessLookupError, OSError):
                pass

            try:
                await asyncio.wait_for(read_tasks, timeout=1.0)
            except (asyncio.TimeoutError, Exception):
                pass

            if raise_on_timeout:
                raise ContainerTimeoutError(
                    f"Container execution timed out after {config.timeout_seconds}s (container={config.container_name})",
                    container_name=config.container_name,
                    timeout_seconds=config.timeout_seconds,
                    partial_stdout="".join(stdout_chunks),
                    partial_stderr="".join(stderr_chunks),
                )

        duration = time.monotonic() - start_time
        result = RunResult(
            exit_code=proc.returncode if proc.returncode is not None else -1,
            stdout="".join(stdout_chunks),
            stderr="".join(stderr_chunks),
            duration_seconds=duration,
            timed_out=timed_out,
            container_name=config.container_name,
            command_executed=cmd,
        )

        if check:
            result.check_returncode()

        return result


# Ergonomic alias
EphemeralContainerRunner = EphemeralRunner
