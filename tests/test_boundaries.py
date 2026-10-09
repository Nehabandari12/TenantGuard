"""Trust-boundary tests that need no Docker: identity at the HTTP edge, MCP tokens, tenant-scoped cache
and memory, the database role check, the protected startup profile and where new runs are written."""

import asyncio
import fnmatch
import os
import time

import jwt
import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from app import config
from attacks import provenance
from tenantguard import TenantContextError
from tenantguard.cache import TenantScopedCache
from tenantguard.db import assert_safe_role, tenant_transaction
from tenantguard.identity import IdentityMiddleware, Principal, bind_principal, issue_login_token, require_principal
from tenantguard.mcp_auth import TenantTokenVerifier, mint_mcp_token, principal_from_mcp_request
from tenantguard.memory import MemoryStore, TenantScopedMemory

ACME = Principal("acme", "alice")
GLOBEX = Principal("globex", "alice")  # same username, other company


def login_claims(**overrides) -> dict:
    now = int(time.time())
    claims = {"iss": config.JWT_ISSUER, "aud": config.LOGIN_AUDIENCE, "sub": "alice", "tid": "acme",
              "role": "member", "iat": now, "exp": now + 600}
    claims.update(overrides)
    return {k: v for k, v in claims.items() if v is not None}


# ---- identity at the HTTP edge ------------------------------------------------------------

@pytest.fixture
def client():
    def whoami(_request):
        return JSONResponse({"tenant": require_principal().tenant_id})

    def health(_request):
        return JSONResponse({"ok": True})

    app = Starlette(routes=[Route("/whoami", whoami), Route("/health", health)])
    app.add_middleware(IdentityMiddleware)
    return TestClient(app)


def bearer(token: str, **headers) -> dict:
    return {"Authorization": f"Bearer {token}", **headers}


def test_verified_token_sets_the_tenant(client):
    r = client.get("/whoami", headers=bearer(issue_login_token(ACME)))
    assert r.status_code == 200 and r.json() == {"tenant": "acme"}


def test_missing_bearer_is_refused(client):
    assert client.get("/whoami").status_code == 401
    assert client.get("/whoami", headers={"Authorization": "Basic YWNtZTphbGljZQ=="}).status_code == 401


@pytest.mark.parametrize("claims", [
    login_claims(exp=int(time.time()) - 5),            # expired
    login_claims(aud=config.MCP_AUDIENCE),             # meant for another audience
    login_claims(iss="someone-else"),                  # another issuer
    login_claims(tid=None),                            # no tenant claim
], ids=["expired", "wrong-audience", "wrong-issuer", "no-tenant"])
def test_invalid_login_tokens_are_refused(client, claims):
    token = jwt.encode(claims, config.JWT_SECRET, algorithm="HS256")
    assert client.get("/whoami", headers=bearer(token)).status_code == 401


def test_mcp_token_cannot_be_used_as_a_login_token(client):
    assert client.get("/whoami", headers=bearer(mint_mcp_token(ACME))).status_code == 401


def test_tenant_header_cannot_switch_tenants(client):
    token = issue_login_token(ACME)
    r = client.get("/whoami", headers=bearer(token, **{"X-Tenant-ID": "globex"}))
    assert r.status_code == 403 and r.json()["detail"] == "tenant mismatch"
    # Naming your own tenant is harmless and still resolves to the token's tenant.
    assert client.get("/whoami", headers=bearer(token, **{"X-Tenant-ID": "acme"})).json() == {"tenant": "acme"}


def test_public_paths_carry_no_tenant(client):
    assert client.get("/health").status_code == 200


# ---- MCP tokens ---------------------------------------------------------------------------

def mcp_claims(**overrides) -> dict:
    now = int(time.time())
    claims = {"iss": config.JWT_ISSUER, "aud": config.MCP_AUDIENCE, "sub": "acme:alice", "tid": "acme", "usr": "alice",
              "scope": "tools", "iat": now, "exp": now + 60}
    claims.update(overrides)
    return claims


@pytest.mark.parametrize("claims,key", [
    (mcp_claims(aud="http://127.0.0.1:9999/mcp"), config.MCP_JWT_SECRET),   # minted for another server
    (mcp_claims(), config.JWT_SECRET),                                     # signed with the login key
    (mcp_claims(sub="globex:alice"), config.MCP_JWT_SECRET),               # subject disagrees with tenant
], ids=["other-audience", "login-key", "subject-tenant-mismatch"])
def test_mcp_verifier_rejects(claims, key):
    assert asyncio.run(TenantTokenVerifier().verify_token(jwt.encode(claims, key, algorithm="HS256"))) is None


def test_mcp_tool_without_a_verified_token_fails_closed():
    with pytest.raises(TenantContextError):
        principal_from_mcp_request()


# ---- tenant-scoped memory and cache -------------------------------------------------------

class FakeRedis:
    """The three list operations MemoryStore uses."""

    def __init__(self) -> None:
        self.lists: dict[str, list[bytes]] = {}

    def rpush(self, key: str, value: str) -> None:
        self.lists.setdefault(key, []).append(value.encode())

    def lrange(self, key, start: int, end: int) -> list[bytes]:
        return list(self.lists.get(key.decode() if isinstance(key, bytes) else key, []))

    def scan_iter(self, pattern: str):
        return [k.encode() for k in self.lists if fnmatch.fnmatch(k, pattern)]


def toy_embed(text: str) -> list[float]:
    return [float(text.count(c)) for c in "aeiou"] + [1.0]


def test_memory_is_namespaced_by_tenant_and_user():
    store = MemoryStore(FakeRedis(), toy_embed)
    memory = TenantScopedMemory(store)
    with bind_principal(ACME):
        memory.add("Our escalation contact is ACME-7F3A9C")
        assert [m["text"] for m in memory.search("escalation contact")] == ["Our escalation contact is ACME-7F3A9C"]
    with bind_principal(GLOBEX):  # same username in another company sees nothing
        assert memory.search("escalation contact") == []
    # The unscoped store (B0-B2) is what crosses tenants.
    assert store.search("escalation contact", user_id=None)[0]["user_id"] == "acme:alice"


def test_memory_without_a_tenant_fails_closed():
    memory = TenantScopedMemory(MemoryStore(FakeRedis(), toy_embed))
    with pytest.raises(TenantContextError):
        memory.add("anything")
    with pytest.raises(TenantContextError):
        memory.search("anything")


class FakeSemanticCache:
    def __init__(self, hit: dict | None = None) -> None:
        self.hit, self.checks, self.stores = hit, [], []

    def check(self, prompt, num_results, filter_expression):
        self.checks.append(str(filter_expression))
        return [self.hit] if self.hit else []

    def store(self, prompt, response, metadata, filters):
        self.stores.append(filters)
        return "key"


def scoped_cache(fake: FakeSemanticCache) -> TenantScopedCache:
    cache = TenantScopedCache.__new__(TenantScopedCache)  # skip RedisVL setup; only the wrapper is under test
    cache._cache = fake
    return cache


def test_cache_always_filters_and_tags_by_the_verified_tenant():
    fake = FakeSemanticCache()
    cache = scoped_cache(fake)
    with bind_principal(ACME):
        assert cache.check("what is our restocking fee?") is None
        cache.store("what is our restocking fee?", "15%")
    assert fake.checks == ["@tenant_id:{acme}"] and fake.stores == [{"tenant_id": "acme"}]


def test_cache_refuses_an_entry_tagged_for_another_tenant():
    cache = scoped_cache(FakeSemanticCache(hit={"response": "15%", "tenant_id": "globex"}))
    with bind_principal(ACME), pytest.raises(TenantContextError):
        cache.check("what is our restocking fee?")


def test_cache_without_a_tenant_fails_closed():
    cache = scoped_cache(FakeSemanticCache())
    with pytest.raises(TenantContextError):
        cache.check("q")
    with pytest.raises(TenantContextError):
        cache.store("q", "a")


# ---- database role and tenant transactions ------------------------------------------------

class FakeRoleConn:
    def __init__(self, superuser: bool, bypassrls: bool) -> None:
        self.row = (superuser, bypassrls)

    def execute(self, _sql):
        return self

    def fetchone(self):
        return self.row


@pytest.mark.parametrize("superuser,bypassrls", [(True, False), (False, True)])
def test_app_refuses_roles_that_skip_rls(superuser, bypassrls):
    with pytest.raises(RuntimeError, match="bypasses row-level security"):
        assert_safe_role(FakeRoleConn(superuser, bypassrls))


def test_plain_role_is_accepted():
    assert_safe_role(FakeRoleConn(False, False))


def test_tenant_transaction_needs_a_verified_tenant_before_touching_the_pool():
    with pytest.raises(TenantContextError):
        with tenant_transaction(pool=None):  # type: ignore[arg-type]
            pass


# ---- startup profile ----------------------------------------------------------------------

STRONG = {"JWT_SECRET": "x" * 40, "MCP_JWT_SECRET": "y" * 40,
          "DATABASE_URL": "postgresql://tg_app:rotated-password@db.internal:5432/tenantguard"}


def configure(monkeypatch, env: str, mode: config.Mode, **values) -> None:
    monkeypatch.setattr(config, "ENV", env)
    monkeypatch.setattr(config, "MODE", mode)
    monkeypatch.setattr(config, "GUARDS", config.guards(mode))
    for name, value in values.items():
        monkeypatch.setattr(config, name, value)


def test_benchmark_profile_runs_vulnerable_baselines(monkeypatch):
    configure(monkeypatch, "benchmark", config.Mode.B0)
    config.check_startup()  # the experiment needs B0-B2 to start with the demo settings


def test_protected_profile_refuses_baselines_and_demo_settings(monkeypatch):
    configure(monkeypatch, "protected", config.Mode.B1)
    with pytest.raises(RuntimeError) as exc:
        config.check_startup()
    message = str(exc.value)
    assert "GUARD_MODE=B1" in message and "JWT_SECRET is a public demo key" in message and "sql/001_init.sql" in message


def test_protected_profile_refuses_shared_signing_keys(monkeypatch):
    configure(monkeypatch, "protected", config.Mode.B3, **{**STRONG, "MCP_JWT_SECRET": STRONG["JWT_SECRET"]})
    assert config.protected_problems() == ["JWT_SECRET and MCP_JWT_SECRET must differ, or a login token could pass as an MCP token"]


def test_protected_profile_starts_with_b3_and_real_settings(monkeypatch):
    configure(monkeypatch, "protected", config.Mode.B3, **STRONG)
    config.check_startup()


def test_unknown_profile_is_refused(monkeypatch):
    configure(monkeypatch, "prod", config.Mode.B3, **STRONG)
    with pytest.raises(RuntimeError, match="TG_ENV"):
        config.check_startup()


# ---- benchmark output ---------------------------------------------------------------------

@pytest.mark.skipif(bool(os.environ.get("TG_RESULTS_DIR")), reason="TG_RESULTS_DIR is set explicitly")
def test_new_runs_do_not_write_into_the_published_results():
    from attacks.run import RESULTS, ROOT

    assert RESULTS.parent == ROOT / "runs"


def test_run_environment_records_code_packages_and_seed(monkeypatch):
    monkeypatch.setattr(config, "LLM_PROVIDER", "mock")
    monkeypatch.setattr(provenance, "_seeded_embedder", lambda: "hash-384")
    env = provenance.environment()
    assert env["llm"] == {"provider": "mock"} and env["embedder"] == "hash-384"
    assert env["data_seed"] == provenance.SEED and env["packages"]["fastapi"] and env["python"]
    assert env["commit"] is None or len(env["commit"]) == 40
