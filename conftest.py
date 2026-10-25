"""Repository-wide pytest setup, applied before any test module imports the apps."""
from __future__ import annotations

import os

# In-process proxies built by the tests must not write into the live dashboard counters.
os.environ["PENTEFINO_PROXY_METRICS"] = "0"
# Starlette's TestClient reports its peer as "testclient"; treat it like loopback so the
# fail-closed auth (no PENTEFINO_API_KEY -> loopback only) still admits the test suite.
os.environ["PENTEFINO_TRUSTED_CLIENTS"] = "127.0.0.1,::1,localhost,testclient"
os.environ.pop("PENTEFINO_API_KEY", None)
