"""What produced a run: code revision, package versions, model, data seed and machine.

Stored in the meta of every results file the benchmark writes, so a number can be traced to the
exact setup behind it. Collected at the end of a run, when the services have been up and the corpus
is seeded.
"""

import importlib.metadata
import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import httpx
import redis

from app import config
from app.seed import SEED

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ("fastapi", "starlette", "uvicorn", "mcp", "psycopg", "pgvector", "redis", "redisvl", "pyjwt", "httpx",
            "numpy", "fastembed", "onnxruntime", "presidio-analyzer", "spacy", "torch", "transformers")


def _git(*args: str) -> str | None:
    try:
        out = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() if out.returncode == 0 else None


def _version(package: str) -> str | None:
    try:
        return importlib.metadata.version(package)
    except importlib.metadata.PackageNotFoundError:
        return None


def _ollama_digest() -> str | None:
    """The weights behind LLM_MODEL. A tag like qwen3:4b can be re-pointed; the digest can't."""
    try:
        models = httpx.get(config.OLLAMA_URL + "/api/tags", timeout=5).json()["models"]
    except (httpx.HTTPError, ValueError, KeyError):
        return None
    return next((m.get("digest") for m in models if config.LLM_MODEL in (m.get("name"), m.get("model"))), None)


def _seeded_embedder() -> str | None:
    """The embedder app.seed used for the corpus (the app refuses to start with a different one)."""
    try:
        return (redis.Redis.from_url(config.REDIS_URL).get("tg:embedder") or b"").decode() or None
    except redis.RedisError:
        return None


def environment() -> dict:
    status = _git("status", "--porcelain", "--untracked-files=no")
    llm: dict = {"provider": config.LLM_PROVIDER}
    if config.LLM_PROVIDER == "ollama":
        llm |= {"model": config.LLM_MODEL, "digest": _ollama_digest(), "temperature": config.OLLAMA_TEMPERATURE,
                "seed": config.OLLAMA_SEED, "think": config.OLLAMA_THINK, "num_ctx": config.OLLAMA_NUM_CTX,
                "num_predict": config.OLLAMA_NUM_PREDICT}
    elif config.LLM_PROVIDER != "mock":
        llm["model"] = config.LLM_MODEL
    return {
        "recorded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "commit": _git("rev-parse", "HEAD"),
        "uncommitted_changes": None if status is None else bool(status),
        "python": platform.python_version(),
        "packages": {p: v for p in PACKAGES if (v := _version(p))},
        "llm": llm,
        "embedder": _seeded_embedder(),
        "data_seed": SEED,
        "os": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor() or None,
        "cpu_count": os.cpu_count(),
    }
