from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Dict, Tuple

import redis.asyncio as redis


class RedisIdempotencyStore:
    def __init__(self, redis_url: str | None = None) -> None:
        self.redis_url = redis_url or os.getenv("REDIS_URL", "redis://redis:6379/0")
        self._redis = redis.from_url(self.redis_url, decode_responses=True)
        self.ttl_seconds = 60 * 10

    def make_key(self, key: str, fingerprint: str) -> str:
        combined = f"{key}:{fingerprint}"
        hash_key = hashlib.sha256(combined.encode()).hexdigest()[:16]
        return f"idem:{hash_key}"

    async def get(self, key: str) -> Tuple[int, Dict[str, Any]] | None:
        data = await self._redis.get(key)
        if not data:
            return None
        try:
            parsed = json.loads(data)
            return parsed["status_code"], parsed["payload"]
        except (json.JSONDecodeError, KeyError):
            return None

    async def set(self, key: str, status_code: int, payload: Dict[str, Any]) -> None:
        data = json.dumps({"status_code": status_code, "payload": payload})
        await self._redis.setex(key, self.ttl_seconds, data)

    async def close(self) -> None:
        await self._redis.close()


# Fallback in-memory store for development
class InMemoryIdempotencyStore:
    def __init__(self) -> None:
        self._store: Dict[str, Tuple[float, int, Dict[str, Any]]] = {}
        self.ttl_seconds = 60 * 10

    def make_key(self, key: str, fingerprint: str) -> str:
        combined = f"{key}:{fingerprint}"
        hash_key = hashlib.sha256(combined.encode()).hexdigest()[:16]
        return f"idem:{hash_key}"

    async def get(self, key: str) -> Tuple[int, Dict[str, Any]] | None:
        import time
        now = time.time()
        item = self._store.get(key)
        if not item:
            return None
        ts, status_code, payload = item
        if now - ts > self.ttl_seconds:
            self._store.pop(key, None)
            return None
        return status_code, payload

    async def set(self, key: str, status_code: int, payload: Dict[str, Any]) -> None:
        import time
        self._store[key] = (time.time(), status_code, payload)

    async def close(self) -> None:
        pass


# Use Redis in production, in-memory for development
USE_REDIS = os.getenv("USE_REDIS", "false").lower() == "true"
store = RedisIdempotencyStore() if USE_REDIS else InMemoryIdempotencyStore()

