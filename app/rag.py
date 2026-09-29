"""/ask: cache check -> vector search -> LLM, with every channel traced."""

from app import cache, config, db
from app.embeddings import embed
from app.llm import get_llm
from tenantguard import tracing
from tenantguard.identity import Principal


def search(principal: Principal, question: str, k: int = config.TOP_K) -> list[dict]:
    qv = str(embed(question))
    with db.session(principal) as conn:
        if config.GUARDS.app_tenant_filter:
            rows = conn.execute(
                "SELECT id, tenant_id, title, body FROM tg.documents WHERE tenant_id = %s "
                "ORDER BY embedding <=> %s::vector LIMIT %s", (principal.tenant_id, qv, k)).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, tenant_id, title, body FROM tg.documents ORDER BY embedding <=> %s::vector LIMIT %s",
                (qv, k)).fetchall()
    docs = [{"id": r[0], "tenant_id": r[1], "title": r[2], "body": r[3]} for r in rows]
    tracing.record("retrieval", "\n".join(f"{d['title']}: {d['body']}" for d in docs), ids=[d["id"] for d in docs])
    return docs


def system_prompt(tenant_name: str, docs: list[dict]) -> str:
    context = "\n".join(f"### {d['title']}\n{d['body']}" for d in docs)
    return (
        f"You are the help assistant for {tenant_name}. Answer the question using only the documents below, "
        "and name the document you used.\n\nDocuments:\n" + context
    )


def ask(principal: Principal, tenant_name: str, question: str) -> dict:
    c = cache.get_cache()
    hit = c.check(question)
    if hit:
        tracing.record("cache_read", hit["response"])
        return {"answer": hit["response"], "sources": (hit.get("metadata") or {}).get("sources", []), "cached": True, "usage": {}}
    docs = search(principal, question)
    reply = get_llm().answer(system_prompt(tenant_name, docs), question)
    sources = [{"id": d["id"], "title": d["title"]} for d in docs]
    return {"answer": reply.text, "sources": sources, "cached": False, "usage": reply.usage}


def remember(question: str, answer: str, sources: list[dict]) -> None:
    cache.get_cache().store(question, answer, metadata={"sources": sources})
    tracing.record("cache_write", answer)
