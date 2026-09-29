"""Per-request trace of every channel an output can leave through.

Channels follow AgentLeak's model (final_output, tool_call, tool_response, shared memory, log)
extended with the RAG-specific ones: retrieval, cache_read/cache_write, memory_read/memory_write.
Output-only audits look at final_output; the detector scores all of them.

Events are buffered in a contextvar and flushed to Redis (tg:trace:<request_id>, 1h TTL) so the
attack harness can read them. If opentelemetry is installed, each event is also added to the
current span with a tenant.id attribute (send it to Langfuse or any OTLP backend).
"""

import contextvars
import json
import time
import uuid

import redis

_events: contextvars.ContextVar[list | None] = contextvars.ContextVar("tg_trace", default=None)
TRACE_TTL_SECONDS = 3600

try:  # optional
    from opentelemetry import trace as _otel

    _tracer = _otel.get_tracer("tenantguard")
except Exception:  # pragma: no cover
    _otel = None
    _tracer = None


def start() -> str:
    _events.set([])
    return uuid.uuid4().hex


def record(channel: str, content, **meta) -> None:
    events = _events.get()
    if events is None:
        return
    events.append({"channel": channel, "content": content if isinstance(content, str) else json.dumps(content, default=str), "meta": meta, "ts": time.time()})
    if _otel is not None:
        span = _otel.get_current_span()
        if span.is_recording():
            span.add_event(f"tg.{channel}", {k: str(v) for k, v in meta.items()})


def events() -> list[dict]:
    return list(_events.get() or [])


def flush(r: redis.Redis, request_id: str, tenant_id: str | None) -> None:
    evs = _events.get() or []
    if evs:
        key = f"tg:trace:{request_id}"
        r.rpush(key, *[json.dumps({**e, "tenant_id": tenant_id}) for e in evs])
        r.expire(key, TRACE_TTL_SECONDS)
    _events.set(None)


def read(r: redis.Redis, request_id: str) -> list[dict]:
    return [json.loads(x) for x in r.lrange(f"tg:trace:{request_id}", 0, -1)]
