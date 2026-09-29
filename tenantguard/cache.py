"""Tenant-scoped semantic cache on RedisVL.

A semantic cache collapses near-identical questions onto one entry, so without a
tenant key two companies asking "what is our refund policy?" share an answer.
This wrapper always writes a tenant_id tag and always filters on it at lookup
(the per-user tag-filter recipe from the RedisVL cache guide, with tenant_id).
The tenant comes from the verified Principal; a call without one raises.
"""

from redisvl.extensions.cache.llm import SemanticCache
from redisvl.query.filter import Tag

from tenantguard import TenantContextError
from tenantguard.identity import require_principal


class TenantScopedCache:
    def __init__(self, *, redis_url: str, vectorizer, distance_threshold: float, name: str = "tg_cache_scoped") -> None:
        self._cache = SemanticCache(
            name=name,
            redis_url=redis_url,
            vectorizer=vectorizer,
            distance_threshold=distance_threshold,
            filterable_fields=[{"name": "tenant_id", "type": "tag"}],
        )

    def check(self, prompt: str) -> dict | None:
        principal = require_principal()
        hits = self._cache.check(prompt=prompt, num_results=1, filter_expression=Tag("tenant_id") == principal.tenant_id)
        if hits and hits[0].get("tenant_id") != principal.tenant_id:
            # Belt and braces: never return an entry whose stored tag disagrees.
            raise TenantContextError("cache returned an entry for another tenant")
        return hits[0] if hits else None

    def store(self, prompt: str, response: str, metadata: dict | None = None) -> str:
        principal = require_principal()
        return self._cache.store(prompt=prompt, response=response, metadata=metadata or {}, filters={"tenant_id": principal.tenant_id})

    def clear(self) -> None:
        self._cache.clear()
