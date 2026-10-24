"""Unit and mock integration tests for pentefino_runner."""
from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest

from pentefino_runner.builder import DockerCommandBuilder
from pentefino_runner.config import (
    DEFAULT_HTTP_PROXY,
    ENV_NETWORK_VAR,
    FALLBACK_NETWORK,
    RunConfig,
    VolumeMount,
)
from pentefino_runner.exceptions import (
    ContainerEngineNotFoundError,
    ContainerExecutionError,
    ContainerTimeoutError,
)
from pentefino_runner.runner import EphemeralContainerRunner, EphemeralRunner


class MockStreamReader(asyncio.StreamReader):
    """Async stream reader populated with pre-buffered byte data."""

    def __init__(self, data: bytes):
        super().__init__()
        self.feed_data(data)
        self.feed_eof()


class MockProcess:
    """Mock asyncio subprocess representing a container execution."""

    def __init__(
        self,
        returncode: int = 0,
        stdout_data: bytes = b"",
        stderr_data: bytes = b"",
        delay: float = 0.0,
    ):
        self.returncode = returncode
        self.stdout = MockStreamReader(stdout_data)
        self.stderr = MockStreamReader(stderr_data)
        self.delay = delay
        self.terminated = False
        self.killed = False
        self._exit_event = asyncio.Event()

    async def wait(self) -> int:
        if self.delay > 0:
            try:
                await asyncio.wait_for(self._exit_event.wait(), timeout=self.delay)
            except asyncio.TimeoutError:
                pass
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self._exit_event.set()

    def kill(self) -> None:
        self.killed = True
        self._exit_event.set()


# ==============================================================================
# 1. DockerCommandBuilder Unit Tests
# ==============================================================================


def test_command_builder_default_hardening_flags():
    """Verify builder produces all mandatory security hardening flags by default."""
    builder = DockerCommandBuilder()
    config = RunConfig(
        image="projectdiscovery/subfinder:v2.6.6",
        command=["-d", "example.com", "-silent"],
    )

    cmd = builder.build_run_command(config)

    # Core CLI invocation
    assert cmd[0:3] == ["docker", "run", "--rm"]
    assert "--init" in cmd

    # Hardening flags
    assert "--read-only" in cmd
    assert "--tmpfs" in cmd
    tmpfs_idx = cmd.index("--tmpfs")
    assert cmd[tmpfs_idx + 1] == "/tmp:rw,noexec,nosuid,size=64m"
    assert "--cap-drop" in cmd
    cap_idx = cmd.index("--cap-drop")
    assert cmd[cap_idx + 1] == "ALL"
    assert "--security-opt" in cmd
    sec_idx = cmd.index("--security-opt")
    assert cmd[sec_idx + 1] == "no-new-privileges:true"

    # Network containment
    assert "--network" in cmd
    net_idx = cmd.index("--network")
    assert cmd[net_idx + 1] == "pentefino_pentefino-net"

    # Proxy environment variables (both upper and lower case)
    assert "-e" in cmd
    assert f"HTTP_PROXY={DEFAULT_HTTP_PROXY}" in cmd
    assert f"http_proxy={DEFAULT_HTTP_PROXY}" in cmd
    assert f"HTTPS_PROXY={DEFAULT_HTTP_PROXY}" in cmd
    assert f"https_proxy={DEFAULT_HTTP_PROXY}" in cmd

    # Resource limits
    assert "--cpus" in cmd
    cpu_idx = cmd.index("--cpus")
    assert cmd[cpu_idx + 1] == "1.0"

    assert "--memory" in cmd
    mem_idx = cmd.index("--memory")
    assert cmd[mem_idx + 1] == "512m"

    assert "--pids-limit" in cmd
    pids_idx = cmd.index("--pids-limit")
    assert cmd[pids_idx + 1] == "128"

    # Image and command position
    img_idx = cmd.index("projectdiscovery/subfinder:v2.6.6")
    assert cmd[img_idx + 1 :] == ["-d", "example.com", "-silent"]


def test_command_builder_network_env_override(monkeypatch):
    """Verify PENTEFINO_DOCKER_NETWORK environment variable overrides network default."""
    monkeypatch.setenv(ENV_NETWORK_VAR, "custom_pentefino_bridge")
    builder = DockerCommandBuilder()
    config = RunConfig(image="projectdiscovery/dnsx:v1.2.1")

    cmd = builder.build_run_command(config)
    net_idx = cmd.index("--network")
    assert cmd[net_idx + 1] == "custom_pentefino_bridge"


def test_command_builder_network_fallback():
    """Verify network fallback mechanism returns pentefino-net."""
    builder = DockerCommandBuilder()
    resolved = builder.resolve_network(None, use_fallback=True)
    assert resolved == FALLBACK_NETWORK

    config = RunConfig(image="projectdiscovery/httpx:v1.6.8")
    cmd = builder.build_run_command(config, use_network_fallback=True)
    net_idx = cmd.index("--network")
    assert cmd[net_idx + 1] == "pentefino-net"


def test_command_builder_custom_network_explicit():
    """Verify explicit network parameter in RunConfig is respected."""
    builder = DockerCommandBuilder()
    config = RunConfig(image="alpine:latest", network="isolated_sandbox_net")

    cmd = builder.build_run_command(config)
    net_idx = cmd.index("--network")
    assert cmd[net_idx + 1] == "isolated_sandbox_net"


def test_command_builder_proxy_override_and_disable():
    """Verify custom proxy URLs and disabling proxy variables."""
    builder = DockerCommandBuilder()

    # Custom proxy
    config_custom = RunConfig(
        image="alpine:latest",
        http_proxy="http://custom_proxy:3128",
        https_proxy="http://custom_proxy:3128",
    )
    cmd_custom = builder.build_run_command(config_custom)
    assert "HTTP_PROXY=http://custom_proxy:3128" in cmd_custom
    assert "HTTPS_PROXY=http://custom_proxy:3128" in cmd_custom

    # Disabled proxy
    config_none = RunConfig(image="alpine:latest", http_proxy=None, https_proxy=None)
    cmd_none = builder.build_run_command(config_none)
    for token in cmd_none:
        assert "HTTP_PROXY=" not in token
        assert "HTTPS_PROXY=" not in token


def test_command_builder_custom_resource_limits():
    """Verify custom CPU, memory, and PID limits are encoded."""
    builder = DockerCommandBuilder()
    config = RunConfig(
        image="alpine:latest",
        cpus=2.5,
        memory="1g",
        pids_limit=256,
    )
    cmd = builder.build_run_command(config)
    assert cmd[cmd.index("--cpus") + 1] == "2.5"
    assert cmd[cmd.index("--memory") + 1] == "1g"
    assert cmd[cmd.index("--pids-limit") + 1] == "256"


def test_command_builder_volume_mounts_ro():
    """Verify read-only volume bindings are properly formatted."""
    builder = DockerCommandBuilder()
    config = RunConfig(
        image="projectdiscovery/nuclei:v3.3.5",
        volumes=[
            VolumeMount(
                host_path="/opt/pentefino/wordlists",
                container_path="/data/wordlists",
                mode="ro",
            ),
            VolumeMount(
                host_path="/opt/pentefino/templates",
                container_path="/templates",
                mode="ro",
            ),
        ],
    )
    cmd = builder.build_run_command(config)
    assert "-v" in cmd
    assert "/opt/pentefino/wordlists:/data/wordlists:ro" in cmd
    assert "/opt/pentefino/templates:/templates:ro" in cmd


def test_command_builder_user_and_working_dir():
    """Verify non-root user and working directory settings."""
    builder = DockerCommandBuilder()
    config = RunConfig(
        image="alpine:latest",
        user="1000:1000",
        working_dir="/home/pentefino",
    )
    cmd = builder.build_run_command(config)
    assert cmd[cmd.index("--user") + 1] == "1000:1000"
    assert cmd[cmd.index("-w") + 1] == "/home/pentefino"


def test_command_builder_custom_env_sorted():
    """Verify arbitrary custom environment variables are injected in sorted order."""
    builder = DockerCommandBuilder()
    config = RunConfig(
        image="alpine:latest",
        env={"SUBFINDER_PROVIDER_CONFIG": "/config.yaml", "DEBUG": "true"},
    )
    cmd = builder.build_run_command(config)
    assert "DEBUG=true" in cmd
    assert "SUBFINDER_PROVIDER_CONFIG=/config.yaml" in cmd


def test_command_builder_podman_engine():
    """Verify command builder generates podman invocations when configured."""
    builder = DockerCommandBuilder(engine_bin="podman")
    config = RunConfig(image="alpine:latest")
    cmd = builder.build_run_command(config)
    assert cmd[0:3] == ["podman", "run", "--rm"]


def test_command_builder_pinned_sha256_digest():
    """Verify immutable sha256 pinned container image digests are preserved."""
    digest_img = "projectdiscovery/subfinder@sha256:7f9b8c6a1e3d548b209e2cf948c27e85c18408a28f73a628a556b6b79c3d4a21"
    builder = DockerCommandBuilder()
    config = RunConfig(image=digest_img)
    cmd = builder.build_run_command(config)
    assert digest_img in cmd


def test_command_builder_entrypoint_and_args():
    """Verify entrypoint overrides are placed before image and extra entrypoint args after."""
    builder = DockerCommandBuilder()
    config = RunConfig(
        image="alpine:latest",
        entrypoint=["/bin/sh", "-c"],
        command=["echo pentefino"],
    )
    cmd = builder.build_run_command(config)
    assert cmd[cmd.index("--entrypoint") + 1] == "/bin/sh"
    img_idx = cmd.index("alpine:latest")
    assert cmd[img_idx + 1] == "-c"
    assert cmd[img_idx + 2] == "echo pentefino"


# ==============================================================================
# 2. EphemeralRunner Async Execution & Lifecycle Tests (Mock Subprocess)
# ==============================================================================


@pytest.mark.asyncio
async def test_runner_successful_execution():
    """Verify successful container execution returns RunResult with streams and exit code 0."""
    runner = EphemeralRunner(engine="docker")
    config = RunConfig(
        image="projectdiscovery/subfinder:v2.6.6",
        command=["-d", "example.com"],
        container_name="test_subfinder_01",
    )

    mock_proc = MockProcess(
        returncode=0,
        stdout_data=b"sub1.example.com\nsub2.example.com\n",
        stderr_data=b"[INF] Enumeration finished\n",
    )

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
        result = await runner.run(config)

    assert result.is_success is True
    assert result.exit_code == 0
    assert result.stdout == "sub1.example.com\nsub2.example.com\n"
    assert result.stderr == "[INF] Enumeration finished\n"
    assert result.timed_out is False
    assert result.container_name == "test_subfinder_01"
    assert result.duration_seconds >= 0.0

    # Ensure check_returncode() does not raise
    result.check_returncode()

    # Ensure create_subprocess_exec was called with correct command
    mock_exec.assert_called_once()
    called_cmd = mock_exec.call_args[0]
    assert called_cmd[0:3] == ("docker", "run", "--rm")
    assert "--name" in called_cmd
    assert "test_subfinder_01" in called_cmd


@pytest.mark.asyncio
async def test_runner_streaming_callbacks():
    """Verify stdout and stderr callbacks receive streamed lines non-blocking in real time."""
    runner = EphemeralRunner(engine="docker")
    config = RunConfig(image="alpine:latest")

    mock_proc = MockProcess(
        returncode=0,
        stdout_data=b"live.example.com [200]\nadmin.example.com [403]\n",
        stderr_data=b"warning: slow dns\n",
    )

    stdout_received: list[str] = []
    stderr_received: list[str] = []

    def on_stdout(line: str) -> None:
        stdout_received.append(line)

    def on_stderr(line: str) -> None:
        stderr_received.append(line)

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await runner.run(
            config,
            on_stdout=on_stdout,
            on_stderr=on_stderr,
        )

    assert result.is_success is True
    assert stdout_received == ["live.example.com [200]\n", "admin.example.com [403]\n"]
    assert stderr_received == ["warning: slow dns\n"]


@pytest.mark.asyncio
async def test_runner_kwargs_callbacks_compatibility():
    """Verify stdout_callback and stderr_callback keyword arguments work as aliases."""
    runner = EphemeralRunner(engine="docker")
    config = RunConfig(image="alpine:latest")

    mock_proc = MockProcess(
        returncode=0,
        stdout_data=b"chunk1\n",
        stderr_data=b"err1\n",
    )

    out_chunks = []
    err_chunks = []

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await runner.run(
            config,
            stdout_callback=lambda line: out_chunks.append(line),
            stderr_callback=lambda line: err_chunks.append(line),
        )

    assert result.is_success is True
    assert out_chunks == ["chunk1\n"]
    assert err_chunks == ["err1\n"]


@pytest.mark.asyncio
async def test_runner_non_zero_exit_code():
    """Verify non-zero exit code is recorded and check_returncode() raises ContainerExecutionError."""
    runner = EphemeralRunner(engine="docker")
    config = RunConfig(image="alpine:latest", container_name="fail_test_container")

    mock_proc = MockProcess(
        returncode=1,
        stdout_data=b"",
        stderr_data=b"Error: invalid flag provided\n",
    )

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        result = await runner.run(config)

    assert result.is_success is False
    assert result.exit_code == 1
    assert "Error: invalid flag provided" in result.stderr

    with pytest.raises(ContainerExecutionError) as exc_info:
        result.check_returncode()

    assert exc_info.value.exit_code == 1
    assert exc_info.value.container_name == "fail_test_container"
    assert "Error: invalid flag provided" in exc_info.value.stderr


@pytest.mark.asyncio
async def test_runner_check_kwarg_raises_immediately():
    """Verify check=True argument causes run() to raise ContainerExecutionError immediately."""
    runner = EphemeralRunner(engine="docker")
    config = RunConfig(image="alpine:latest")

    mock_proc = MockProcess(returncode=2, stderr_data=b"Fatal error\n")

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        with pytest.raises(ContainerExecutionError) as exc_info:
            await runner.run(config, check=True)

    assert exc_info.value.exit_code == 2


@pytest.mark.asyncio
async def test_runner_timeout_enforcement_and_docker_cleanup():
    """Verify timeout triggers process termination, docker rm -f cleanup, and ContainerTimeoutError."""
    runner = EphemeralRunner(engine="docker")
    config = RunConfig(
        image="alpine:latest",
        container_name="timeout_victim_container",
        timeout_seconds=0.05,
    )

    hanging_proc = MockProcess(
        returncode=0,
        stdout_data=b"starting scan...\n",
        stderr_data=b"",
        delay=10.0,  # Delays much longer than 0.05s timeout
    )
    cleanup_proc = MockProcess(returncode=0)

    exec_calls = []

    async def mock_subprocess_exec(*args, **kwargs):
        exec_calls.append(args)
        if len(exec_calls) == 1:
            return hanging_proc
        return cleanup_proc

    with patch("asyncio.create_subprocess_exec", side_effect=mock_subprocess_exec):
        with pytest.raises(ContainerTimeoutError) as exc_info:
            await runner.run(config)

    # Verify ContainerTimeoutError attributes
    assert exc_info.value.container_name == "timeout_victim_container"
    assert exc_info.value.timeout_seconds == 0.05
    assert exc_info.value.partial_stdout == "starting scan...\n"

    # Verify process termination was called
    assert hanging_proc.terminated is True or hanging_proc.killed is True

    # Verify docker rm -f was invoked for cleanup
    assert len(exec_calls) >= 2
    rm_call = exec_calls[1]
    assert rm_call == ("docker", "rm", "-f", "timeout_victim_container")


@pytest.mark.asyncio
async def test_runner_timeout_without_raising():
    """Verify raise_on_timeout=False returns RunResult with timed_out=True."""
    runner = EphemeralRunner(engine="docker")
    config = RunConfig(
        image="alpine:latest",
        container_name="no_raise_timeout_container",
        timeout_seconds=0.05,
    )

    hanging_proc = MockProcess(returncode=0, delay=10.0)
    cleanup_proc = MockProcess(returncode=0)

    exec_calls = []

    async def mock_subprocess_exec(*args, **kwargs):
        exec_calls.append(args)
        if len(exec_calls) == 1:
            return hanging_proc
        return cleanup_proc

    with patch("asyncio.create_subprocess_exec", side_effect=mock_subprocess_exec):
        result = await runner.run(config, raise_on_timeout=False)

    assert result.timed_out is True
    assert result.is_success is False
    assert result.container_name == "no_raise_timeout_container"


@pytest.mark.asyncio
async def test_runner_auto_generates_container_name():
    """Verify runner automatically generates pentefino_run_<hex> container name if not provided."""
    runner = EphemeralRunner(engine="docker")
    config = RunConfig(image="alpine:latest", container_name=None)

    mock_proc = MockProcess(returncode=0)

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
        result = await runner.run(config)

    assert result.container_name.startswith("pentefino_run_")
    assert len(result.container_name) > 15
    called_cmd = mock_exec.call_args[0]
    assert "--name" in called_cmd
    assert called_cmd[called_cmd.index("--name") + 1] == result.container_name


@pytest.mark.asyncio
async def test_runner_binary_not_found_raises_engine_not_found():
    """Verify FileNotFoundError during execution raises ContainerEngineNotFoundError."""
    runner = EphemeralRunner(engine="non_existent_engine_bin_123")
    config = RunConfig(image="alpine:latest")

    with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError("not found")):
        with pytest.raises(ContainerEngineNotFoundError) as exc_info:
            await runner.run(config)

    assert "non_existent_engine_bin_123" in str(exc_info.value)


@pytest.mark.asyncio
async def test_runner_cleanup_failure_resilience():
    """Verify runner handles failure of docker rm -f gracefully without masking timeout error."""
    runner = EphemeralRunner(engine="docker")
    config = RunConfig(image="alpine:latest", timeout_seconds=0.05)

    hanging_proc = MockProcess(returncode=0, delay=10.0)

    exec_calls = 0

    async def mock_subprocess_exec(*args, **kwargs):
        nonlocal exec_calls
        exec_calls += 1
        if exec_calls == 1:
            return hanging_proc
        raise OSError("Engine communication error during cleanup")

    with patch("asyncio.create_subprocess_exec", side_effect=mock_subprocess_exec):
        with pytest.raises(ContainerTimeoutError):
            await runner.run(config)


def test_alias_exports():
    """Verify EphemeralContainerRunner is an alias of EphemeralRunner."""
    assert EphemeralContainerRunner is EphemeralRunner
