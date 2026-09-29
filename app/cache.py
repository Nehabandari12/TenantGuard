"""Semantic cache for /ask. B0-B2: one global RedisVL cache keyed only by the question
(what most tutorials build). B3: tenantguard.cache.TenantScopedCache."""

from functools import lru_cache

from redisvl.extensions.cache.llm import SemanticCache
from redisvl.utils.vectorize import CustomVectorizer

from app import config
from app.embeddings import embed
from tenantguard.cache import TenantScopedCache


class LegacyCache:
    def __init__(self, vectorizer) -> None:
        self._cache = SemanticCache(name="tg_cache_legacy", redis_url=config.REDIS_URL, vectorizer=vectorizer,
                                    distance_threshold=config.CACHE_DISTANCE_THRESHOLD)

    def check(self, prompt: str) -> dict | None:
        hits = self._cache.check(prompt=prompt, num_results=1)
        return hits[0] if hits else None

    def store(self, prompt: str, response: str, metadata: dict | None = None) -> str:
        return self._cache.store(prompt=prompt, response=response, metadata=metadata or {})

    def clear(self) -> None:
        self._cache.clear()


@lru_cache(maxsize=1)
def get_cache():
    vectorizer = CustomVectorizer(embed=embed)
    if config.GUARDS.tenantguard:
        return TenantScopedCache(redis_url=config.REDIS_URL, vectorizer=vectorizer, distance_threshold=config.CACHE_DISTANCE_THRESHOLD)
    return LegacyCache(vectorizer)
