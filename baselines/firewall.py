"""B2 input firewall: scan the user's input for prompt injection before it reaches the app.

Backends, picked with TG_FIREWALL and recorded in every result, so runs on different backends are never
mixed up (there is no fallback between them):
  heuristic    a keyword filter (the default; needs nothing)
  promptguard  Llama Prompt Guard 2 86M, the classifier behind LlamaFirewall's PromptGuard scanner, run
               directly through transformers. Needs `pip install -e ".[firewall]"` and Hugging Face access
               to the gated model. The llamafirewall package itself also pulls in CodeShield and scanners
               B2 doesn't use.

Either way it only sees the *user input*, not retrieved documents or tool results, which is how input
guardrails are usually deployed and why B2 misses indirect injection.

    python -m baselines.firewall      # score every user input the benchmark sends with the chosen backend
"""

import re
from dataclasses import dataclass
from functools import lru_cache

from app import config

_HEURISTICS = [
    r"ignore (all |any )?(previous|prior|above) (instructions|rules)",
    r"disregard (the |your )?(system|previous)",
    r"you are now", r"developer mode", r"jailbreak", r"system prompt",
    r"act as (an? )?(admin|administrator|root|support)",
    r"(other|another|all) (tenants?|compan(y|ies)|customers?)'?s? (data|documents|tickets)",
    r"maintenance mode", r"dump (the |all )?(index|database|documents)",
    r"print (all|every) (document|record|ticket)",
]
_PATTERN = re.compile("|".join(_HEURISTICS), re.IGNORECASE)

PROMPT_GUARD = "meta-llama/Llama-Prompt-Guard-2-86M"
PROMPT_GUARD_THRESHOLD = 0.5  # the model's own decision boundary (argmax of the two classes)
_SEGMENT_TOKENS = 512         # the model's context; longer inputs are scored per segment, max wins


@dataclass
class Verdict:
    flagged: bool
    backend: str
    reason: str = ""


def backend_name() -> str:
    if config.FIREWALL not in ("heuristic", "promptguard"):
        raise RuntimeError(f"unknown TG_FIREWALL {config.FIREWALL!r}; choose heuristic or promptguard")
    return config.FIREWALL


@lru_cache(maxsize=1)
def _prompt_guard():
    try:
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
    except ImportError as exc:
        raise RuntimeError('TG_FIREWALL=promptguard needs pip install -e ".[firewall]"') from exc
    tokenizer = AutoTokenizer.from_pretrained(PROMPT_GUARD)
    model = AutoModelForSequenceClassification.from_pretrained(PROMPT_GUARD).eval()
    return torch, tokenizer, model


def prompt_guard_score(text: str) -> float:
    """Probability that `text` tries to override instructions (class 1 of Prompt Guard 2)."""
    torch, tokenizer, model = _prompt_guard()
    ids = tokenizer(text, add_special_tokens=False)["input_ids"] or [tokenizer.unk_token_id]
    step = _SEGMENT_TOKENS - 2
    best = 0.0
    with torch.no_grad():
        for start in range(0, len(ids), step):
            segment = [tokenizer.cls_token_id, *ids[start:start + step], tokenizer.sep_token_id]
            logits = model(input_ids=torch.tensor([segment])).logits
            best = max(best, torch.softmax(logits, dim=-1)[0, 1].item())
    return best


def load() -> None:
    """Load the backend at startup, so a missing model fails the start rather than the first request."""
    if backend_name() == "promptguard":
        _prompt_guard()


def scan(text: str) -> Verdict:
    if backend_name() == "promptguard":
        p = prompt_guard_score(text)
        return Verdict(p >= PROMPT_GUARD_THRESHOLD, "promptguard", f"p={p:.3f}")
    m = _PATTERN.search(text)
    return Verdict(bool(m), "heuristic", m.group(0) if m else "")


def benchmark_inputs() -> list[tuple[str, str]]:
    """(source, text) for every user input the benchmark sends: scored and setup steps, eval questions,
    agent tasks."""
    import yaml

    from app.seed import build
    from attacks.run import ROOT
    from eval.run_eval import agent_task_list

    inputs = []
    for case in yaml.safe_load((ROOT / "attacks" / "cases.yaml").read_text(encoding="utf-8")):
        for step in case.get("setup", []) + case["steps"]:
            if "text" in step:
                inputs.append((case["id"], step["text"]))
    data = build()
    inputs += [("eval", f"What is the {d['aspect']} in our {d['topic']}?") for d in data["docs"]]
    inputs += [("agent", t["question"]) for t in agent_task_list(data["docs"], data["tickets"], 3)]
    return inputs


def main() -> None:
    load()
    results = [(src, text, scan(text)) for src, text in benchmark_inputs()]
    flagged = [r for r in results if r[2].flagged]
    print(f"{backend_name()}: flagged {len(flagged)} of {len(results)} benchmark inputs")
    for src, text, v in flagged:
        print(f"  {src:13} {v.reason:10} {text[:90]}")
    if backend_name() == "promptguard":
        for src, text, v in sorted(results, key=lambda r: -float(r[2].reason[2:]))[:5]:
            print(f"  highest: {v.reason}  {src:13} {text[:80]}")


if __name__ == "__main__":
    main()
