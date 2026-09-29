"""B2 input firewall: scan the user's input for prompt injection before it reaches the app.

Backend order:
  1. LlamaFirewall with the PromptGuard scanner (needs `pip install llamafirewall` and
     Hugging Face access to Llama Prompt Guard 2 - request it early, it is gated).
  2. A keyword heuristic, used when LlamaFirewall is unavailable. Results record which
     backend ran, so a heuristic-backed B2 row is never passed off as LlamaFirewall.

Either way it only sees the *user input*, not retrieved documents or tool results,
which is how input guardrails are usually deployed and why B2 misses indirect injection.
"""

import re
from dataclasses import dataclass
from functools import lru_cache

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


@dataclass
class Verdict:
    flagged: bool
    backend: str
    reason: str = ""


@lru_cache(maxsize=1)
def _llamafirewall():
    try:
        from llamafirewall import LlamaFirewall, Role, ScannerType, UserMessage

        fw = LlamaFirewall(scanners={Role.USER: [ScannerType.PROMPT_GUARD]})
        return fw, UserMessage
    except Exception:
        return None


def backend_name() -> str:
    return "llamafirewall-promptguard" if _llamafirewall() else "heuristic"


def scan(text: str) -> Verdict:
    lf = _llamafirewall()
    if lf is not None:
        fw, user_message = lf
        result = fw.scan(user_message(content=text))
        flagged = str(getattr(result, "decision", "")).upper().endswith("BLOCK")
        return Verdict(flagged, "llamafirewall-promptguard", str(getattr(result, "reason", "")))
    m = _PATTERN.search(text)
    return Verdict(bool(m), "heuristic", m.group(0) if m else "")
