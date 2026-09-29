"""Local embeddings. bge-small-en-v1.5 via fastembed (ONNX, no torch) when available,
otherwise a deterministic hashing-trick embedder so the whole loop runs offline.

The hashing embedder is only lexical, but the seed corpus uses near-duplicate documents
across tenants, so lexical similarity is enough to reproduce cross-tenant retrieval.
"""

import hashlib
import math
import re
from functools import lru_cache

from app import config

_TOKEN = re.compile(r"[a-z0-9]+")


class HashEmbedder:
    name = "hash-384"

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [self._one(t) for t in texts]

    def _one(self, text: str) -> list[float]:
        vec = [0.0] * config.EMBED_DIM
        tokens = _TOKEN.findall(text.lower())
        for tok in tokens + [a + "_" + b for a, b in zip(tokens, tokens[1:])]:
            h = int.from_bytes(hashlib.blake2b(tok.encode(), digest_size=8).digest(), "big")
            vec[h % config.EMBED_DIM] += 1.0 if (h >> 63) & 1 else -1.0
        norm = math.sqrt(sum(v * v for v in vec)) or 1.0
        return [v / norm for v in vec]


class FastEmbedder:
    name = "BAAI/bge-small-en-v1.5"

    def __init__(self) -> None:
        from fastembed import TextEmbedding

        self._model = TextEmbedding(self.name)

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [v.tolist() for v in self._model.embed(texts)]


@lru_cache(maxsize=1)
def embedder():
    if config.EMBEDDER == "hash":
        return HashEmbedder()
    try:
        return FastEmbedder()
    except Exception:
        if config.EMBEDDER == "fastembed":
            raise
        return HashEmbedder()


def embed(text: str) -> list[float]:
    return embedder().embed([text])[0]


def embed_many(texts: list[str]) -> list[list[float]]:
    return embedder().embed(texts)
