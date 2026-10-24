from __future__ import annotations

import asyncio
import logging
import math
import time
from typing import Any, Dict, Optional, Tuple, Union

try:
    import redis.asyncio as aioredis
except ImportError:
    try:
        import valkey.asyncio as aioredis  # type: ignore
    except ImportError:
        aioredis = None  # type: ignore

logger = logging.getLogger("pentefino.proxy.rate_limiter")

# Atomic Hierarchical Token Bucket Lua Script for Valkey / Redis
# Supports micro-spacing via deficit token reservation
LUA_TOKEN_BUCKET_SCRIPT = """
local now_arr = redis.call('TIME')
local now_us = tonumber(now_arr[1]) * 1000000 + tonumber(now_arr[2])

local function get_tokens(key, rate, capacity)
    local data = redis.call('HMGET', key, 'tokens', 'last_us')
    local tokens = tonumber(data[1])
    local last_us = tonumber(data[2])

    if not tokens or not last_us then
        tokens = capacity
        last_us = now_us
    else
        local elapsed_sec = (now_us - last_us) / 1000000.0
        if elapsed_sec > 0 then
            tokens = math.min(capacity, tokens + elapsed_sec * rate)
            last_us = now_us
        end
    end
    return tokens, last_us
end

local host_rate = tonumber(ARGV[1])
local host_cap = tonumber(ARGV[2])
local prog_rate = tonumber(ARGV[3])
local prog_cap = tonumber(ARGV[4])
local cost = tonumber(ARGV[5])

local host_tokens, _ = get_tokens(KEYS[1], host_rate, host_cap)
local prog_tokens, _ = get_tokens(KEYS[2], prog_rate, prog_cap)

local wait_host = 0.0
if host_tokens < cost then
    wait_host = (cost - host_tokens) / host_rate
end

local wait_prog = 0.0
if prog_tokens < cost then
    wait_prog = (cost - prog_tokens) / prog_rate
end

local max_wait = math.max(wait_host, wait_prog)

-- Deduct cost to reserve execution slot atomically (deficit / smooth queuing)
local new_host_tokens = host_tokens - cost
local new_prog_tokens = prog_tokens - cost

redis.call('HMSET', KEYS[1], 'tokens', tostring(new_host_tokens), 'last_us', tostring(now_us))
redis.call('EXPIRE', KEYS[1], 3600)
redis.call('HMSET', KEYS[2], 'tokens', tostring(new_prog_tokens), 'last_us', tostring(now_us))
redis.call('EXPIRE', KEYS[2], 3600)

local wait_ms = math.ceil(max_wait * 1000)
return {wait_ms > 0 and 0 or 1, wait_ms}
"""


class InMemoryTokenBucket:
    """Thread/Task-safe in-memory hierarchical token bucket for isolated test environments."""

    def __init__(self):
        self._lock = asyncio.Lock()
        self._buckets: Dict[str, Tuple[float, float]] = {}  # key -> (tokens, last_time_sec)
        self._backoffs: Dict[str, float] = {}  # host -> expire_timestamp

    async def acquire(
        self,
        host_key: str,
        prog_key: str,
        host_rate: float,
        host_cap: float,
        prog_rate: float,
        prog_cap: float,
        cost: float = 1.0,
    ) -> float:
        async with self._lock:
            now = time.monotonic()

            def update_bucket(key: str, rate: float, cap: float) -> float:
                if key not in self._buckets:
                    tokens = cap
                else:
                    tok, last_t = self._buckets[key]
                    elapsed = max(0.0, now - last_t)
                    tokens = min(cap, tok + elapsed * rate)
                return tokens

            host_tokens = update_bucket(host_key, host_rate, host_cap)
            prog_tokens = update_bucket(prog_key, prog_rate, prog_cap)

            wait_host = max(0.0, (cost - host_tokens) / host_rate) if host_tokens < cost else 0.0
            wait_prog = max(0.0, (cost - prog_tokens) / prog_rate) if prog_tokens < cost else 0.0
            max_wait = max(wait_host, wait_prog)

            # Deduct cost and save
            self._buckets[host_key] = (host_tokens - cost, now)
            self._buckets[prog_key] = (prog_tokens - cost, now)

            return max_wait

    def set_backoff(self, host: str, duration: float) -> None:
        self._backoffs[host] = time.monotonic() + duration

    def get_backoff(self, host: str) -> float:
        if host in self._backoffs:
            remaining = self._backoffs[host] - time.monotonic()
            if remaining > 0:
                return remaining
            del self._backoffs[host]
        return 0.0

    def reset(self) -> None:
        self._buckets.clear()
        self._backoffs.clear()


class ValkeyRateLimiter:
    """
    Hierarchical distributed token bucket rate limiter backed by Valkey / Redis.
    Enforces per-host (default 0.5 req/s) and per-program (default 2.0 req/s) quotas.
    Micro-spaces concurrent requests seamlessly using asyncio.sleep.
    """

    DEFAULT_HOST_RATE = 0.5  # 1 request every 2.0s
    DEFAULT_HOST_BURST = 1.0
    DEFAULT_PROG_RATE = 2.0  # 4 requests every 2.0s (1 req every 0.5s)
    DEFAULT_PROG_BURST = 4.0

    def __init__(
        self,
        valkey_url: str = "redis://127.0.0.1:6379/0",
        host_rate: float = DEFAULT_HOST_RATE,
        host_capacity: float = DEFAULT_HOST_BURST,
        prog_rate: float = DEFAULT_PROG_RATE,
        prog_capacity: float = DEFAULT_PROG_BURST,
        use_in_memory: bool = False,
    ):
        self.valkey_url = valkey_url
        self.host_rate = float(host_rate)
        self.host_capacity = float(host_capacity)
        self.prog_rate = float(prog_rate)
        self.prog_capacity = float(prog_capacity)
        self.use_in_memory = use_in_memory

        self._redis = None
        self._lua_sha = None
        self._in_memory_bucket = InMemoryTokenBucket()

    async def _get_redis(self):
        if self.use_in_memory:
            return None
        if self._redis is None and aioredis is not None:
            try:
                self._redis = aioredis.from_url(
                    self.valkey_url,
                    decode_responses=True,
                    socket_connect_timeout=2.0,
                )
                # Verify connection
                await self._redis.ping()
            except Exception as e:
                logger.warning("Valkey connection failed (%s); falling back to in-memory rate limiter", e)
                self.use_in_memory = True
                self._redis = None
        return self._redis

    async def acquire_lease(
        self,
        host: str,
        program_id: Union[str, Any] = "global",
        cost: float = 1.0,
        sleep: bool = True,
    ) -> float:
        """
        Acquires a token bucket lease for (program_id, host).
        Returns the delay in seconds that was or should be waited.
        If sleep=True, suspends execution via asyncio.sleep(wait_seconds).
        """
        host_clean = host.lower().split(":")[0].strip()
        prog_clean = str(program_id).strip()

        # Check circuit-breaker reactive backoff (e.g. 429 Retry-After)
        backoff_sec = await self.get_backoff(host_clean)
        if backoff_sec > 0:
            logger.info("Host %s in reactive backoff for %.2fs", host_clean, backoff_sec)
            if sleep:
                await asyncio.sleep(backoff_sec)

        host_key = f"rl:tb:host:{prog_clean}:{host_clean}"
        prog_key = f"rl:tb:prog:{prog_clean}"

        redis_client = await self._get_redis()
        wait_seconds = 0.0

        if redis_client is not None:
            try:
                result = await redis_client.eval(
                    LUA_TOKEN_BUCKET_SCRIPT,
                    2,
                    host_key,
                    prog_key,
                    self.host_rate,
                    self.host_capacity,
                    self.prog_rate,
                    self.prog_capacity,
                    cost,
                )
                # result is [status, wait_ms]
                wait_ms = result[1] if result and len(result) > 1 else 0
                wait_seconds = max(0.0, wait_ms / 1000.0)
            except Exception as e:
                logger.warning("Valkey eval failed (%s); falling back to in-memory bucket", e)
                wait_seconds = await self._in_memory_bucket.acquire(
                    host_key, prog_key,
                    self.host_rate, self.host_capacity,
                    self.prog_rate, self.prog_capacity,
                    cost,
                )
        else:
            wait_seconds = await self._in_memory_bucket.acquire(
                host_key, prog_key,
                self.host_rate, self.host_capacity,
                self.prog_rate, self.prog_capacity,
                cost,
            )

        if sleep and wait_seconds > 0:
            logger.debug("Micro-spacing request to %s: sleeping %.3fs", host_clean, wait_seconds)
            await asyncio.sleep(wait_seconds)

        return wait_seconds

    async def set_backoff(self, host: str, duration_seconds: float) -> None:
        """Sets a reactive backoff key when target responds with HTTP 429."""
        host_clean = host.lower().split(":")[0].strip()
        duration = max(1.0, float(duration_seconds))
        redis_client = await self._get_redis()
        if redis_client is not None:
            try:
                await redis_client.set(f"rl:backoff:{host_clean}", "1", ex=int(math.ceil(duration)))
                return
            except Exception:
                pass
        self._in_memory_bucket.set_backoff(host_clean, duration)

    async def get_backoff(self, host: str) -> float:
        """Checks if target host is currently in reactive backoff."""
        host_clean = host.lower().split(":")[0].strip()
        redis_client = await self._get_redis()
        if redis_client is not None:
            try:
                ttl = await redis_client.ttl(f"rl:backoff:{host_clean}")
                return max(0.0, float(ttl)) if ttl and ttl > 0 else 0.0
            except Exception:
                pass
        return self._in_memory_bucket.get_backoff(host_clean)

    async def reset(self, host: Optional[str] = None, program_id: Optional[str] = None) -> None:
        """Resets rate limiting state (useful in test teardown)."""
        self._in_memory_bucket.reset()
        redis_client = await self._get_redis()
        if redis_client is not None:
            try:
                if host and program_id:
                    await redis_client.delete(f"rl:tb:host:{program_id}:{host}")
                elif program_id:
                    await redis_client.delete(f"rl:tb:prog:{program_id}")
                else:
                    keys = await redis_client.keys("rl:tb:*")
                    if keys:
                        await redis_client.delete(*keys)
            except Exception:
                pass

    async def close(self) -> None:
        """Closes the underlying Redis connection pool."""
        if self._redis is not None:
            try:
                await self._redis.aclose()
            except Exception:
                pass
            self._redis = None
