"""All runtime settings, read once from the environment.

GUARD_MODE picks the baseline. Every other flag is derived from it in `guards()`,
so the four modes run the same code against the same attacks.
"""

import os
from dataclasses import dataclass
from enum import StrEnum


class Mode(StrEnum):
    B0 = "B0"  # no protection
    B1 = "B1"  # tenant filter in app code (the typical tutorial fix)
    B2 = "B2"  # B1 + input prompt-injection firewall
    B3 = "B3"  # TenantGuard


@dataclass(frozen=True)
class Guards:
    app_tenant_filter: bool  # WHERE tenant_id = ... in app SQL (B1+)
    input_firewall: bool     # scan user input for injection (B2 only)
    tenantguard: bool        # identity, RLS, scoped cache/memory, MCP auth, scoped logs (B3)
    egress: bool             # outbound checks on answers, tool args, links, logs (B3)
    egress_canary: bool      # the canary part of egress; off for the "B3 without canary check" run


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


MODE = Mode(_env("GUARD_MODE", "B0").upper())

# "benchmark" (default): the local experiment. Any mode runs, with the public demo keys below, because
# B0-B2 exist to be attacked. "protected": refuse to start unless protected_problems() is empty.
ENV = _env("TG_ENV", "benchmark").lower()

# Host ports of the docker compose services. Windows sometimes reserves 55432 (`netsh interface ipv4
# show excludedportrange protocol=tcp`); set TG_PG_PORT for both compose and the app to move it.
# 127.0.0.1, not localhost: compose binds IPv4 loopback only, and on Windows "localhost" tries ::1 first.
_PG_PORT = _env("TG_PG_PORT", "55432")
_REDIS_PORT = _env("TG_REDIS_PORT", "56379")

DATABASE_URL = _env("DATABASE_URL", f"postgresql://tg_app:app-local-only@127.0.0.1:{_PG_PORT}/tenantguard")
OWNER_DATABASE_URL = _env("OWNER_DATABASE_URL", f"postgresql://tg_owner:owner-local-only@127.0.0.1:{_PG_PORT}/tenantguard")
REDIS_URL = _env("REDIS_URL", f"redis://127.0.0.1:{_REDIS_PORT}/0")

APP_URL = _env("APP_URL", "http://127.0.0.1:8000")
MCP_URL = _env("MCP_URL", "http://127.0.0.1:8001/mcp")

# Synthetic demo secrets. Two separate keys so a login token can never double as an MCP token in B3.
JWT_SECRET = _env("JWT_SECRET", "local-dev-login-signing-key-change-me")
MCP_JWT_SECRET = _env("MCP_JWT_SECRET", "local-dev-mcp-signing-key-change-me")
# Every signing key that appears in this repository; TG_ENV=protected refuses all of them.
PUBLIC_DEMO_KEYS = frozenset({"local-dev-login-signing-key-change-me", "local-dev-mcp-signing-key-change-me",
                              "change-me-login-key-at-least-32-bytes-long", "change-me-mcp-key-at-least-32-bytes-long"})
JWT_ISSUER = "tenantguard-app"
LOGIN_AUDIENCE = "tenantguard-app"
MCP_AUDIENCE = _env("MCP_AUDIENCE", MCP_URL)
MCP_TOKEN_TTL_SECONDS = int(_env("MCP_TOKEN_TTL_SECONDS", "60"))

# LLM: "ollama" (local, default), "mock" (offline, deterministic, worst-case obedient) or "anthropic".
# There is no automatic fallback between providers: if Ollama is down, requests fail loudly.
LLM_PROVIDER = _env("LLM_PROVIDER", "ollama")
LLM_MODEL = _env("LLM_MODEL", "qwen3:4b")
LLM_MAX_TOOL_ROUNDS = int(_env("LLM_MAX_TOOL_ROUNDS", "6"))
# Paid APIs are disabled unless explicitly allowed; LLM_PROVIDER=anthropic refuses to start otherwise.
ALLOW_PAID_LLM = _env("TG_ALLOW_PAID_LLM", "0") == "1"

OLLAMA_URL = _env("OLLAMA_URL", "http://127.0.0.1:11434")
# qwen3:4b in Ollama always reasons; think=true keeps that in a separate field instead of the answer.
OLLAMA_THINK = _env("OLLAMA_THINK", "1") == "1"
OLLAMA_NUM_CTX = int(_env("OLLAMA_NUM_CTX", "8192"))
# Cap on generated tokens per call (reasoning included). Without it one runaway reasoning chain on CPU
# can take many minutes per call, times up to LLM_MAX_TOOL_ROUNDS calls per agent request.
OLLAMA_NUM_PREDICT = int(_env("OLLAMA_NUM_PREDICT", "2048"))
OLLAMA_TIMEOUT_SECONDS = float(_env("OLLAMA_TIMEOUT_SECONDS", "600"))
# Fixed sampling for the app's model and the judge, so repeated runs are comparable.
OLLAMA_TEMPERATURE = 0
OLLAMA_SEED = 0

# Embeddings: "auto" uses fastembed bge-small-en-v1.5 if installed, else the hashing embedder.
EMBEDDER = _env("EMBEDDER", "auto")
EMBED_DIM = 384

# B2's input firewall: "heuristic" (keyword filter) or "promptguard" (Llama Prompt Guard 2, needs the gated model).
FIREWALL = _env("TG_FIREWALL", "heuristic")

CACHE_DISTANCE_THRESHOLD = float(_env("CACHE_DISTANCE_THRESHOLD", "0.15"))
TOP_K = 5

ALLOWED_LINK_DOMAINS = tuple(
    d.strip().lower() for d in _env("ALLOWED_LINK_DOMAINS", "docs.tenantguard.local,support.tenantguard.local").split(",") if d.strip()
)

TENANTS = ("acme", "globex", "initech")


def guards(mode: Mode = MODE) -> Guards:
    egress_canary = _env("TG_EGRESS_CANARY", "1") != "0"
    return Guards(
        app_tenant_filter=mode in (Mode.B1, Mode.B2, Mode.B3),
        input_firewall=mode is Mode.B2,
        tenantguard=mode is Mode.B3,
        egress=mode is Mode.B3,
        egress_canary=mode is Mode.B3 and egress_canary,
    )


GUARDS = guards()


def protected_problems() -> list[str]:
    """Settings that make this process unfit to serve real tenants. TG_ENV=protected refuses to start
    while any remain. An empty list means the known-unsafe settings are gone, not that the app is
    production-ready: see SECURITY.md for what the demo login still lacks."""
    problems = []
    if MODE is not Mode.B3:
        problems.append(f"GUARD_MODE={MODE.value} is a deliberately vulnerable benchmark baseline; only B3 isolates tenants")
    elif not GUARDS.egress_canary:
        problems.append("TG_EGRESS_CANARY=0 is a benchmark ablation; protected runs keep the egress canary check")
    for name, key in (("JWT_SECRET", JWT_SECRET), ("MCP_JWT_SECRET", MCP_JWT_SECRET)):
        if key in PUBLIC_DEMO_KEYS or len(key.encode()) < 32:
            problems.append(f"{name} is a public demo key or shorter than 32 bytes")
    if JWT_SECRET == MCP_JWT_SECRET:
        problems.append("JWT_SECRET and MCP_JWT_SECRET must differ, or a login token could pass as an MCP token")
    if "app-local-only" in DATABASE_URL:
        problems.append("DATABASE_URL uses the tg_app password published in sql/001_init.sql")
    return problems


def check_startup() -> None:
    """Called by the app and the MCP server before they serve anything."""
    if ENV not in ("benchmark", "protected"):
        raise RuntimeError(f"TG_ENV={ENV!r}: expected 'benchmark' or 'protected'")
    if ENV == "protected" and (problems := protected_problems()):
        raise RuntimeError("TG_ENV=protected refuses to start: " + "; ".join(problems))
