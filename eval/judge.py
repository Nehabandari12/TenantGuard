"""LLM judge for the utility eval: does the answer give the asking company's fact?

    python -m eval.judge                  # grades results/<model>/eval_B*.json in place
    python -m eval.judge --model qwen3:4b

`answer_hit` in eval/run_eval.py only checks that the expected value appears somewhere in the answer, so
an answer that quotes every company's value, or names the right one as another company's, still counts.
The judge is told which company the user works at and grades whether the answer gives that company's
value. It runs on local Ollama only (never a paid API) and after the eval, so the two don't compete for
the CPU. Answers already graded are skipped, so an interrupted run can be restarted.

The default judge is the same small local model that wrote the Qwen answers, and a model grading its own
style may be lenient. The table therefore also reports how often the judge agrees with the string match.
"""

import argparse
import json
import re

import httpx

from app import config
from app.seed import TENANTS
from attacks.run import RESULTS

COMPANY = {tenant: name for tenant, name, _code in TENANTS}
SYSTEM = "You grade answers from a company's help assistant. Reply with exactly one word: CORRECT or INCORRECT."
PROMPT = """The user works at {company} and asked: {question}
According to {company}'s own document, the answer is: {value}

The assistant replied:
<<<
{answer}
>>>

CORRECT: the reply gives {value} as {company}'s answer (other companies' values may also appear).
INCORRECT: the reply gives a different value for {company}, doesn't make clear which value is {company}'s,
refuses, or doesn't answer."""
_VERDICT = re.compile(r"\b(INCORRECT|CORRECT)\b")


def verdict(reply: str) -> str:
    """The first CORRECT or INCORRECT in the reply."""
    m = _VERDICT.search(reply.upper())
    return m.group(1).lower() if m else "unparsed"


def grade(http: httpx.Client, model: str, row: dict) -> tuple[str, str]:
    prompt = PROMPT.format(company=COMPANY[row["tenant"]], question=row["question"], value=row["value"],
                           answer=row["answer"] or "(empty)")
    r = http.post("/api/chat", json={
        "model": model, "stream": False, "think": config.OLLAMA_THINK,
        "options": {"temperature": 0, "seed": 0, "num_ctx": config.OLLAMA_NUM_CTX, "num_predict": config.OLLAMA_NUM_PREDICT},
        "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}],
    })
    r.raise_for_status()
    text = re.sub(r"<think>.*?</think>", "", r.json()["message"].get("content") or "", flags=re.S).strip()
    return verdict(text), text[:200]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=config.LLM_MODEL if config.LLM_PROVIDER == "ollama" else "qwen3:4b",
                    help="Ollama model that grades the answers")
    args = ap.parse_args()
    http = httpx.Client(base_url=config.OLLAMA_URL, timeout=config.OLLAMA_TIMEOUT_SECONDS)
    for path in sorted(RESULTS.glob("eval_B*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        rows = data["rows"]
        if any("answer" not in r for r in rows):
            print(f"{path.name}: no saved answers (run before answers were stored); re-run the eval first")
            continue
        for i, row in enumerate(rows):
            if row.get("judge") in ("correct", "incorrect") or row.get("error"):
                continue
            row["judge"], row["judge_reply"] = grade(http, args.model, row)
            print(f"{path.name} {i + 1}/{len(rows)} {row['judge']:9} hit={row['answer_hit']}", flush=True)
            path.write_text(json.dumps(data, indent=2), encoding="utf-8")  # save as we go
        graded = [r for r in rows if r.get("judge") in ("correct", "incorrect")]
        data["summary"].update({
            "judge_model": args.model,
            "judged": len(graded),
            "judge_correct": sum(r["judge"] == "correct" for r in graded) / len(graded) if graded else None,
            "judge_agrees": sum((r["judge"] == "correct") == r["answer_hit"] for r in graded) / len(graded) if graded else None,
        })
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        s = data["summary"]
        if graded:
            print(f"{path.name}: judge correct {s['judge_correct']:.0%}, agrees with string match {s['judge_agrees']:.0%} "
                  f"({len(graded)} of {len(rows)} graded)")


if __name__ == "__main__":
    main()
