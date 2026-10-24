"""CLI entrypoint for the PenteFino Egress Forward Proxy Server."""
from __future__ import annotations

import asyncio
import logging
import os
import signal

from pentefino_proxy.server import ForwardProxyServer


async def _main() -> None:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    host = os.getenv("PENTEFINO_PROXY_HOST", "0.0.0.0")
    port = int(os.getenv("PENTEFINO_PROXY_PORT", "8080"))
    valkey_url = os.getenv("VALKEY_URL", "redis://127.0.0.1:6379/0")
    env_class = os.getenv("PENTEFINO_ENV_CLASS", "bounty")

    server = ForwardProxyServer(
        host=host,
        port=port,
        valkey_url=valkey_url,
        environment_class=env_class,
    )
    await server.start()

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            pass

    try:
        await stop_event.wait()
    finally:
        await server.stop()


if __name__ == "__main__":
    asyncio.run(_main())
