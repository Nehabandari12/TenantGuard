"""Agent memory with a mem0-shaped API (add / search keyed by user_id).

`MemoryStore` is the raw store: namespaces in Redis, cosine search in Python.
`TenantScopedMemory` is the TenantGuard wrapper: the namespace is always
"tenant:user" from the verified Principal, callers cannot pick one, and a call
with no Principal raises. The same wrapper shape applies to mem0 itself
(`Memory.add(..., user_id=f"{tenant}:{user}")`); mem0 was left optional because it
needs its own LLM and vector store config.
"""

import json
import math
import time

import redis

from tenantguard.identity import require_principal

_PREFIX = "tg:mem:"


def _cos(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a)) or 1.0
    nb = math.sqrt(sum(y * y for y in b)) or 1.0
    return dot / (na * nb)


class MemoryStore:
    def __init__(self, redis_client: redis.Redis, embed) -> None:
        self._r = redis_client
        self._embed = embed

    def add(self, text: str, *, user_id: str) -> dict:
        item = {"text": text, "user_id": user_id, "ts": time.time(), "vector": self._embed(text)}
        self._r.rpush(_PREFIX + user_id, json.dumps(item))
        return {"text": text, "user_id": user_id}

    def search(self, query: str, *, user_id: str | None, limit: int = 3, min_score: float = 0.0) -> list[dict]:
        """user_id=None searches every namespace (how an unscoped memory store behaves)."""
        keys = [_PREFIX + user_id] if user_id is not None else list(self._r.scan_iter(_PREFIX + "*"))
        qv = self._embed(query)
        scored = []
        for key in keys:
            for raw in self._r.lrange(key, 0, -1):
                item = json.loads(raw)
                scored.append((_cos(qv, item["vector"]), item))
        scored.sort(key=lambda p: p[0], reverse=True)
        return [{"text": it["text"], "user_id": it["user_id"], "score": round(s, 4)} for s, it in scored[:limit] if s >= min_score]

    def clear(self) -> None:
        for key in self._r.scan_iter(_PREFIX + "*"):
            self._r.delete(key)


class TenantScopedMemory:
    def __init__(self, store: MemoryStore) -> None:
        self._store = store

    @staticmethod
    def _namespace() -> str:
        return require_principal().subject  # "tenant:user"

    def add(self, text: str) -> dict:
        return self._store.add(text, user_id=self._namespace())

    def search(self, query: str, limit: int = 3) -> list[dict]:
        return self._store.search(query, user_id=self._namespace(), limit=limit)
