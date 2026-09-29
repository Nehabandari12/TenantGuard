"""Agent memory per mode.

B0: memories are written per username but searched across everyone (no scoping at all).
B1/B2: scoped by username only. Usernames repeat across companies (every tenant has an
       "alice"), so Acme's alice and Initech's alice share one memory.
B3: tenantguard.memory.TenantScopedMemory, namespace "tenant:user", unscoped calls raise.
"""

from functools import lru_cache

import redis

from app import config
from app.config import Mode
from app.embeddings import embed
from tenantguard.identity import Principal
from tenantguard.memory import MemoryStore, TenantScopedMemory


@lru_cache(maxsize=1)
def store() -> MemoryStore:
    return MemoryStore(redis.Redis.from_url(config.REDIS_URL), embed)


def search(principal: Principal, query: str, limit: int = 3) -> list[dict]:
    if config.GUARDS.tenantguard:
        return TenantScopedMemory(store()).search(query, limit=limit)
    user_id = None if config.MODE is Mode.B0 else principal.username
    return store().search(query, user_id=user_id, limit=limit)


def add(principal: Principal, text: str) -> dict:
    if config.GUARDS.tenantguard:
        return TenantScopedMemory(store()).add(text)
    return store().add(text, user_id=principal.username)
