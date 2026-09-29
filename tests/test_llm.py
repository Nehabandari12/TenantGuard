"""LLM provider plumbing: Ollama message conversion, reasoning stripping, paid-API gate."""

import pytest

from app import config
from app.agent import FreshMcpToken
from app.llm import AnthropicLLM, OllamaLLM, _strip_reasoning
from tenantguard.identity import Principal


def test_strip_reasoning_removes_leaked_thinking():
    assert _strip_reasoning("Okay, let me think...\n</think>\n\nThe answer is 4.") == "The answer is 4."
    assert _strip_reasoning("<think>hidden</think>Visible") == "Visible"
    assert _strip_reasoning("plain answer") == "plain answer"


def test_history_converts_to_ollama_shape():
    history = [
        {"role": "user", "content": "Show me ticket T-1002"},
        {"role": "assistant", "content": [{"type": "tool_use", "id": "c1", "name": "get_ticket", "input": {"ticket_id": "T-1002"}}]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "c1", "content": "Ticket T-1002 ..."}]},
    ]
    assert OllamaLLM._to_ollama(history) == [
        {"role": "user", "content": "Show me ticket T-1002"},
        {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": "get_ticket", "arguments": {"ticket_id": "T-1002"}}}]},
        {"role": "tool", "tool_name": "get_ticket", "content": "Ticket T-1002 ..."},
    ]


def test_paid_api_is_disabled_by_default(monkeypatch):
    monkeypatch.setattr(config, "ALLOW_PAID_LLM", False)
    with pytest.raises(RuntimeError, match="paid API"):
        AnthropicLLM()


def test_fresh_mcp_token_per_request():
    import httpx2

    auth = FreshMcpToken(Principal("acme", "alice"))
    first = next(auth.auth_flow(httpx2.Request("POST", "http://mcp/x"))).headers["Authorization"]
    assert first.startswith("Bearer ")
