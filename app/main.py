"""The target SaaS: /login /ask /agent /support/logs.

Run: GUARD_MODE=B0 uvicorn app.main:app --port 8000
The same code serves all four modes; app.config.GUARDS decides which protections run.
"""

from contextlib import asynccontextmanager

import redis
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app import agent, auth, config, db, logs, rag
from app.embeddings import embedder
from app.llm import get_llm
from baselines import firewall
from tenantguard import TenantContextError, tracing
from tenantguard.egress import Egress
from tenantguard.identity import IdentityMiddleware, Principal, issue_login_token

state: dict = {}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    db.open_pool()
    state["redis"] = redis.Redis.from_url(config.REDIS_URL)
    codes = db.tenant_codes()
    with db.pool.connection() as conn:
        state["tenant_names"] = dict(conn.execute("SELECT tenant_id, name FROM tg.tenants").fetchall())
    state["egress"] = Egress(codes, config.ALLOWED_LINK_DOMAINS, canary_check=config.GUARDS.egress_canary)
    get_llm()  # fail at startup, not on the first request, if the LLM provider is unavailable
    if config.GUARDS.input_firewall:
        firewall.load()
    seeded_with = (state["redis"].get("tg:embedder") or b"").decode()
    if seeded_with and seeded_with != embedder().name:
        raise RuntimeError(f"corpus was embedded with {seeded_with} but the app would use {embedder().name}")
    yield
    db.pool.close()


app = FastAPI(title="TenantGuard target app", lifespan=lifespan)
if config.GUARDS.tenantguard:
    app.add_middleware(IdentityMiddleware)


@app.exception_handler(TenantContextError)
async def tenant_context_error(_request: Request, exc: TenantContextError):
    return JSONResponse({"detail": f"tenant isolation: {exc}"}, status_code=403)


class LoginIn(BaseModel):
    tenant: str
    username: str
    password: str


class AskIn(BaseModel):
    question: str


class AgentIn(BaseModel):
    message: str


def _finish(principal: Principal, request_id: str, body: dict) -> JSONResponse:
    tracing.record("final_output", body)
    tracing.flush(state["redis"], request_id, principal.tenant_id)
    return JSONResponse({**body, "request_id": request_id}, headers={"X-Request-ID": request_id})


def _firewall(text: str) -> firewall.Verdict | None:
    if not config.GUARDS.input_firewall:
        return None
    verdict = firewall.scan(text)
    tracing.record("firewall", {"flagged": verdict.flagged, "backend": verdict.backend, "reason": verdict.reason})
    return verdict if verdict.flagged else None


@app.get("/health")
def health():
    return {"mode": config.MODE.value, "guards": config.GUARDS.__dict__, "embedder": embedder().name,
            "llm": get_llm().name, "llm_model": config.LLM_MODEL if get_llm().name != "mock" else None,
            "paid_llm_allowed": config.ALLOW_PAID_LLM, "firewall": firewall.backend_name() if config.GUARDS.input_firewall else None}


@app.post("/login")
def login(body: LoginIn):
    principal = auth.login(body.tenant, body.username, body.password)
    return {"token": issue_login_token(principal), "tenant": principal.tenant_id, "role": principal.role}


@app.post("/ask")
def ask(body: AskIn, principal: Principal = Depends(auth.get_principal)):
    rid = tracing.start()
    name = state["tenant_names"].get(principal.tenant_id, principal.tenant_id)
    if (v := _firewall(body.question)) is not None:
        return _finish(principal, rid, {"answer": "Request blocked by input firewall.", "sources": [], "blocked": v.backend})
    result = rag.ask(principal, name, body.question)
    answer = result["answer"]
    if config.GUARDS.egress:
        verdict = state["egress"].check_answer(answer + "\n" + "\n".join(s["title"] for s in result["sources"]), principal)
        if verdict.blocked:
            tracing.record("egress_block", [f.__dict__ for f in verdict.findings])
            result["sources"] = []
            answer = verdict.text
        else:
            answer = state["egress"].check_answer(answer, principal).text
    if not result["cached"]:
        rag.remember(body.question, answer, result["sources"])
    logs.write(principal, "/ask", f"Q: {body.question}\nA: {answer}", state["egress"])
    tracing.record("llm_usage", result["usage"])
    return _finish(principal, rid, {"answer": answer, "sources": result["sources"], "cached": result["cached"]})


@app.post("/agent")
async def run_agent(body: AgentIn, request: Request, principal: Principal = Depends(auth.get_principal)):
    rid = tracing.start()
    name = state["tenant_names"].get(principal.tenant_id, principal.tenant_id)
    if (v := _firewall(body.message)) is not None:
        return _finish(principal, rid, {"answer": "Request blocked by input firewall.", "tool_calls": [], "blocked": v.backend})
    login_token = request.headers.get("authorization", "")[7:] or None
    result = await agent.run(principal, name, body.message, login_token, state["egress"])
    answer = result["answer"]
    if config.GUARDS.egress:
        verdict = state["egress"].check_answer(answer, principal)
        if verdict.blocked:
            tracing.record("egress_block", [f.__dict__ for f in verdict.findings])
        answer = verdict.text
    agent.remember(principal, body.message, answer)
    logs.write(principal, "/agent", f"U: {body.message}\nA: {answer}\nTools: {result['tool_calls']}", state["egress"])
    tracing.record("llm_usage", result["usage"])
    return _finish(principal, rid, {"answer": answer, "tool_calls": result["tool_calls"]})


@app.get("/support/logs")
def support_logs(tenant: str | None = None, limit: int = 50, principal: Principal = Depends(auth.get_principal)):
    rid = tracing.start()
    try:
        rows = logs.read(principal, tenant, limit)
    except HTTPException:
        tracing.flush(state["redis"], rid, principal.tenant_id)
        raise
    return _finish(principal, rid, {"logs": rows})
