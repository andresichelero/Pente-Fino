"""Exceptions for pentefino_runner."""
from __future__ import annotations


class RunnerError(Exception):
    """Base exception for all runner errors."""

    pass


class ContainerEngineNotFoundError(RunnerError):
    """Raised when neither docker nor podman is found on system PATH."""

    pass


class ContainerExecutionError(RunnerError):
    """Raised when a container process exits with a non-zero exit code."""

    def __init__(
        self,
        message: str,
        exit_code: int,
        stdout: str = "",
        stderr: str = "",
        container_name: str = "",
    ):
        super().__init__(message)
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.container_name = container_name


class ContainerTimeoutError(RunnerError):
    """Raised when a container run exceeds its timeout limit."""

    def __init__(
        self,
        message: str,
        container_name: str = "",
        timeout_seconds: float = 0.0,
        partial_stdout: str = "",
        partial_stderr: str = "",
    ):
        super().__init__(message)
        self.container_name = container_name
        self.timeout_seconds = timeout_seconds
        self.partial_stdout = partial_stdout
        self.partial_stderr = partial_stderr
