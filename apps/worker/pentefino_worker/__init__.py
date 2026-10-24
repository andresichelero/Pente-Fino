"""PenteFino Asynchronous Worker Package.

Provides:
- ScanTaskWorker: Processes queued scan_run and recon_run tasks with strict scope enforcement.
"""
from pentefino_worker.amqp_consumer import (
    AmqpWorkerDaemon,
    TrackedEphemeralRunner,
    WorkerTelemetryPublisher,
    setup_amqp_topology,
)
from pentefino_worker.cancellation import (
    ActiveContainerRegistry,
    ActiveJobInfo,
    default_container_registry,
)
from pentefino_worker.consumer import (
    IntelTaskJob,
    ReconTaskJob,
    ScanTaskJob,
    ScanTaskWorker,
)
from pentefino_worker.publisher import (
    AmqpTaskPublisher,
    default_publisher,
)

__all__ = [
    "ActiveContainerRegistry",
    "ActiveJobInfo",
    "AmqpTaskPublisher",
    "AmqpWorkerDaemon",
    "IntelTaskJob",
    "ReconTaskJob",
    "ScanTaskJob",
    "ScanTaskWorker",
    "TrackedEphemeralRunner",
    "WorkerTelemetryPublisher",
    "default_container_registry",
    "default_publisher",
    "setup_amqp_topology",
]

