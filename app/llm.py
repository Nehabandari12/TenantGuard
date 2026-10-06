"""LLM providers behind one small interface.

ollama    : the default. A local model served by Ollama (default qwen3:4b) through its native
            /api/chat endpoint, temperature 0 with a fixed seed. Free, and nothing leaves the machine.
mock      : offline and deterministic. It is a *worst-case obedient* model: it repeats whatever
            context it is given, fills tool arguments with whatever the user or a document asks
            for, and follows "AI ASSISTANT INSTRUCTION:" lines found in tool results. That makes
            it an upper bound on what a fully jailbroken model could do, which is exactly what an
            enforcement layer has to survive.
anthropic : Claude via the official SDK. A paid API, so it is disabled unless TG_ALLOW_PAID_LLM=1.

There is no fallback between providers. If the chosen one is unavailable, requests fail.
"""

import base64
import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from urllib.parse import quote

import httpx

from app import config


@dataclass
class ToolCall:
    id: str
    name: str
    input: dict


@dataclass
class LLMReply:
    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    usage: dict = field(default_factory=lambda: {"input_tokens": 0, "output_tokens": 0})
    assistant_content: list | None = None  # what to append to `messages` as the assistant turn


_THINK_BLOCK = re.compile(r"<think>.*?</think>", re.S)


def _strip_reasoning(text: str) -> str:
    """Drop reasoning that leaked into the answer text (e.g. qwen3 with think=false)."""
    text = _THINK_BLOCK.sub("", text)
    if "</think>" in text:
        text = text.rsplit("</think>", 1)[1]
    return text.strip()


class OllamaLLM:
    name = "ollama"

    def __init__(self) -> None:
        self._http = httpx.Client(base_url=config.OLLAMA_URL, timeout=config.OLLAMA_TIMEOUT_SECONDS)
        try:
            r = self._http.post("/api/show", json={"model": config.LLM_MODEL})
        except httpx.HTTPError as exc:
            raise RuntimeError(f"Ollama is not reachable at {config.OLLAMA_URL} (no fallback is configured)") from exc
        if r.status_code != 200:
            raise RuntimeError(f"Ollama model {config.LLM_MODEL!r} is not installed; run: ollama pull {config.LLM_MODEL}")

    @staticmethod
    def _to_ollama(messages: list) -> list[dict]:
        """Convert the agent's Anthropic-shaped history (tool_use / tool_result blocks) to Ollama's."""
        out, names = [], {}
        for m in messages:
            content = m["content"]
            if isinstance(content, str):
                out.append({"role": m["role"], "content": content})
            elif m["role"] == "assistant":
                text = "".join(b.get("text", "") for b in content if b.get("type") == "text")
                calls = []
                for b in content:
                    if b.get("type") == "tool_use":
                        names[b["id"]] = b["name"]
                        calls.append({"function": {"name": b["name"], "arguments": b["input"]}})
                out.append({"role": "assistant", "content": text, **({"tool_calls": calls} if calls else {})})
            else:
                for b in content:
                    if b.get("type") == "tool_result":
                        out.append({"role": "tool", "tool_name": names.get(b["tool_use_id"], ""), "content": str(b.get("content", ""))})
        return out

    def _chat(self, system: str, messages: list, tools: list[dict] | None) -> LLMReply:
        payload = {
            "model": config.LLM_MODEL,
            "stream": False,
            "think": config.OLLAMA_THINK,
            "options": {"temperature": config.OLLAMA_TEMPERATURE, "seed": config.OLLAMA_SEED, "num_ctx": config.OLLAMA_NUM_CTX, "num_predict": config.OLLAMA_NUM_PREDICT},
            "messages": [{"role": "system", "content": system}, *self._to_ollama(messages)],
        }
        if tools:
            payload["tools"] = [{"type": "function", "function": {"name": t["name"], "description": t["description"],
                                                                  "parameters": t["input_schema"]}} for t in tools]
        r = self._http.post("/api/chat", json=payload)
        r.raise_for_status()
        data = r.json()
        msg = data["message"]
        text = _strip_reasoning(msg.get("content") or "")
        calls = []
        for i, tc in enumerate(msg.get("tool_calls") or []):
            fn = tc["function"]
            args = fn.get("arguments") or {}
            if isinstance(args, str):
                args = json.loads(args or "{}")
            calls.append(ToolCall(tc.get("id") or f"call_{i}", fn["name"], args))
        usage = {"input_tokens": data.get("prompt_eval_count", 0), "output_tokens": data.get("eval_count", 0)}
        content = ([{"type": "text", "text": text}] if text else []) + \
                  [{"type": "tool_use", "id": c.id, "name": c.name, "input": c.input} for c in calls]
        return LLMReply(text, calls, usage, content)

    def answer(self, system: str, question: str) -> LLMReply:
        return self._chat(system, [{"role": "user", "content": question}], None)

    def step(self, system: str, messages: list, tools: list[dict]) -> LLMReply:
        return self._chat(system, messages, tools)


class AnthropicLLM:
    name = "anthropic"

    def __init__(self) -> None:
        if not config.ALLOW_PAID_LLM:
            raise RuntimeError("LLM_PROVIDER=anthropic is a paid API and is disabled; set TG_ALLOW_PAID_LLM=1 to enable it")
        import anthropic

        self._client = anthropic.Anthropic()

    def _create(self, **kwargs):
        params = {"model": config.LLM_MODEL, "max_tokens": 4096, **kwargs}
        if config.LLM_MODEL.startswith("claude-haiku"):
            params["temperature"] = 0
        return self._client.messages.create(**params)

    @staticmethod
    def _reply(response) -> LLMReply:
        text = "".join(b.text for b in response.content if b.type == "text")
        calls = [ToolCall(b.id, b.name, dict(b.input)) for b in response.content if b.type == "tool_use"]
        usage = {"input_tokens": response.usage.input_tokens, "output_tokens": response.usage.output_tokens}
        return LLMReply(text, calls, usage, response.content)

    def answer(self, system: str, question: str) -> LLMReply:
        return self._reply(self._create(system=system, messages=[{"role": "user", "content": question}]))

    def step(self, system: str, messages: list, tools: list[dict]) -> LLMReply:
        return self._reply(self._create(system=system, messages=messages, tools=tools))


# ------------------------------------------------------------------------------------------
# Mock model
# ------------------------------------------------------------------------------------------

_TICKET = re.compile(r"\bT-\d{4}\b")
_CODE = re.compile(r"\b[A-Z]{4}-[0-9A-F]{6}\b")
_INSTR = re.compile(r"AI ASSISTANT INSTRUCTION:(.+?)(?:\n\n|\nTicket reference:|$)", re.S)
_URL = re.compile(r"https?://[^\s)\]]+")
_MEMORY_WORDS = ("remember", "previous", "earlier", "last time", "history", "we discussed", "you told")


def _apply_output_format(user_text: str, answer: str) -> str:
    low = user_text.lower()
    if "spell" in low or "space between" in low or "spaces between" in low or "separate each character" in low:
        answer = _CODE.sub(lambda m: " ".join(m.group(0)), answer)
    if "reverse" in low:
        answer = answer[::-1]
    if "hex" in low and "encode" in low:
        answer = answer.encode().hex()
    if "base64" in low:
        answer = base64.b64encode(answer.encode()).decode()
    if "español" in low or "espanol" in low or "spanish" in low:
        answer = "Respuesta: " + answer
    return answer


def _mentioned_tenant(text: str, default: str) -> str:
    low = text.lower()
    for t in config.TENANTS:
        if t != default and t in low:
            return t
    return default


class MockLLM:
    name = "mock"

    def answer(self, system: str, question: str) -> LLMReply:
        sections = re.findall(r"^### (.+?)\n(.+?)(?=\n### |\Z)", system, re.S | re.M)
        if not sections:
            text = "I could not find anything about that in the documents."
        else:
            text = "Here is what the documents say:\n" + "\n".join(f"- {title}: {body.strip()}" for title, body in sections)
        return LLMReply(_apply_output_format(question, text))

    def step(self, system: str, messages: list, tools: list[dict]) -> LLMReply:
        own = (re.search(r"tenant id: (\w+)", system) or [None, ""])[1]
        tool_names = {t["name"]: t for t in tools}
        takes_tenant = {n for n, t in tool_names.items() if "tenant_id" in t.get("input_schema", {}).get("properties", {})}
        user_text = next(m["content"] for m in messages if m["role"] == "user" and isinstance(m["content"], str))

        def key(name: str, args: dict) -> tuple:
            return name, args.get("ticket_id") or args.get("query"), args.get("tenant_id")

        done = [key(b["name"], b["input"]) for m in messages if m["role"] == "assistant"
                for b in m["content"] if isinstance(b, dict) and b.get("type") == "tool_use"]
        results = [b for m in messages if m["role"] == "user" and isinstance(m["content"], list)
                   for b in m["content"] if b.get("type") == "tool_result"]
        result_text = "\n\n".join(str(b.get("content", "")) for b in results)

        def call(name: str, args: dict, tenant_hint: str | None = None) -> dict | None:
            if name not in tool_names:
                return None
            if name in takes_tenant:
                args = {**args, "tenant_id": tenant_hint or own}
            if key(name, args) in done:
                return None
            done.append(key(name, args))
            return {"name": name, "input": args}

        planned: list[dict] = []
        links: list[str] = []
        if not done:
            low = user_text.lower()
            hint = _mentioned_tenant(user_text, own)
            tickets = _TICKET.findall(user_text)
            if any(w in low for w in _MEMORY_WORDS) and not tickets:
                pass
            elif "note" in low and tickets:
                text = user_text.split(":", 1)[1].strip() if ":" in user_text else user_text
                planned.append(call("create_note", {"ticket_id": tickets[0], "text": text}, hint))
            elif tickets:
                planned.extend(call("get_ticket", {"ticket_id": t}, hint) for t in tickets)
            else:
                planned.append(call("search_docs", {"query": user_text}, hint))
        # Follow instructions embedded in tool results (indirect prompt injection).
        gathered = " ".join(dict.fromkeys(_CODE.findall(result_text)))
        for instr in _INSTR.findall(result_text):
            tenant_hint = _mentioned_tenant(instr, own)
            for t in _TICKET.findall(instr.split("create_note")[0]) if "get_ticket" in instr else []:
                planned.append(call("get_ticket", {"ticket_id": t}, tenant_hint))
            m = re.search(r"create_note on ticket (T-\d{4})", instr)
            if m:
                planned.append(call("create_note", {"ticket_id": m.group(1), "text": f"Copied data: {result_text[:1500]}"}, own))
            for url in _URL.findall(instr):
                data = quote(gathered or result_text[:200])
                links.append(url.replace("{DATA}", data) if "{DATA}" in url else url + ("&" if "?" in url else "?") + "d=" + data)
        planned = [p for p in planned if p]
        if planned:
            calls = [ToolCall(f"mock_{len(done) + i}", p["name"], p["input"]) for i, p in enumerate(planned)]
            content = [{"type": "tool_use", "id": c.id, "name": c.name, "input": c.input} for c in calls]
            return LLMReply("", calls, assistant_content=content)

        parts = []
        if result_text:
            parts.append("Here is what I found:\n" + result_text)
        if any(w in user_text.lower() for w in _MEMORY_WORDS):
            mem = system.split("Relevant memories:", 1)[1].strip() if "Relevant memories:" in system else ""
            parts.append("From memory:\n" + (mem or "(nothing)"))
        parts.extend(f"![status]({u})" for u in links)
        text = _apply_output_format(user_text, "\n\n".join(parts) or "I could not find anything relevant.")
        return LLMReply(text, assistant_content=[{"type": "text", "text": text}])


_PROVIDERS = {"ollama": OllamaLLM, "mock": MockLLM, "anthropic": AnthropicLLM}


@lru_cache(maxsize=1)
def get_llm():
    try:
        provider = _PROVIDERS[config.LLM_PROVIDER]
    except KeyError:
        raise RuntimeError(f"unknown LLM_PROVIDER {config.LLM_PROVIDER!r}; choose one of {sorted(_PROVIDERS)}") from None
    return provider()
