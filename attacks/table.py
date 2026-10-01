"""Build results/<llm>/RESULTS.md from that folder's <mode>.json and eval_<mode>.json.

    python -m attacks.table                   # current LLM_PROVIDER / LLM_MODEL
    LLM_PROVIDER=mock python -m attacks.table
"""

import json

from attacks.run import RESULTS

ROUTES = [("search", "LLM08"), ("cache", "LLM08"), ("memory", "ASI06"), ("tools", "ASI02/ASI03"),
          ("injection", "LLM01/ASI01"), ("logs", "LLM02"), ("ALL", "")]
LABELS = {"B0": "B0 no protection", "B1": "B1 app tenant filter", "B2": "B2 B1 + keyword firewall",
          "B2_promptguard": "B2 with Prompt Guard 2", "B3": "B3 TenantGuard", "B3_nocanary": "B3 without egress canary check"}


def pct(n: int, d: int) -> str:
    return f"{n / d:.0%}" if d else "-"


def main() -> None:
    runs = {label: json.loads((RESULTS / f"{label}.json").read_text(encoding="utf-8"))
            for label in LABELS if (RESULTS / f"{label}.json").exists()}
    lines = ["# Results", ""]
    if runs:
        meta = next(iter(runs.values()))["meta"]
        reps = {LABELS[l]: r["meta"]["repeats"] for l, r in runs.items()}
        rep_text = (str(meta["repeats"]) if len(set(reps.values())) == 1
                    else ", ".join(f"{k} {v}" for k, v in reps.items()))
        lines += [f"LLM: `{meta['llm']}`{' / ' + meta['llm_model'] if meta.get('llm_model') else ''}, "
                  f"repeats per check: {rep_text}. Cell = leak rate over all runs, answers-only / all-channels.", ""]
        lines.append("| Route | OWASP | " + " | ".join(LABELS[l] for l in runs) + " |")
        lines.append("|---|---|" + "---|" * len(runs))
        for route, owasp in ROUTES:
            cells = []
            for run in runs.values():
                s = run["summary"].get(route)
                cells.append(f"{pct(s['leak_answer'], s['runs'])} / {pct(s['leak_any'], s['runs'])}" if s else "-")
            lines.append(f"| {'**all**' if route == 'ALL' else route} | {owasp} | " + " | ".join(cells) + " |")
        unstable = {}
        for label, run in runs.items():
            outcomes: dict[str, set] = {}
            for rec in run["records"]:
                if not rec.get("error"):
                    outcomes.setdefault(rec["id"], set()).add(rec["leak_any"])
            if run["meta"]["repeats"] > 1:
                unstable[LABELS[label]] = sorted(i for i, o in outcomes.items() if len(o) > 1)
        if unstable:
            lines += ["", "Checks whose all-channels outcome changed between repeats: "
                      + "; ".join(f"{k}: {len(v)}" + (f" ({', '.join(v)})" if v else "") for k, v in unstable.items()) + "."]
        errored = {LABELS[l]: r["summary"]["ALL"].get("errors", 0) for l, r in runs.items() if r["summary"]["ALL"].get("errors")}
        if errored:
            lines += ["", "Checks that errored (timed out; counted as runs but not as leaks, so they could hide one): "
                      + ", ".join(f"{k}: {v}" for k, v in errored.items()) + "."]
        b2 = runs.get("B2", {}).get("summary", {}).get("ALL")
        if b2:
            hidden = b2["leak_any"] - b2["leak_answer"]
            lines += ["", f"Hidden leaks in B2 (caught by all-channels scoring, missed by answers-only): "
                          f"{hidden} of {b2['runs']} runs ({pct(hidden, b2['runs'])})."]
    evals = {m: json.loads((RESULTS / f"eval_{m}.json").read_text(encoding="utf-8"))["summary"]
             for m in ("B0", "B1", "B2", "B2_promptguard", "B3") if (RESULTS / f"eval_{m}.json").exists()}
    if evals:
        judged = any(s.get("judge_correct") is not None for s in evals.values())
        lines += ["", "## Utility (normal questions)", "",
                  "| Mode | Questions | Recall@5 | Answer hit | " + ("Judge: correct | Judge agrees with hit | " if judged else "")
                  + "Wrong blocks | p50 ms | p95 ms | Tokens in/out | USD |",
                  "|---|---|---|---|" + ("---|---|" if judged else "") + "---|---|---|---|---|"]
        for m, s in evals.items():
            judge = (f"{pct(round(s['judge_correct'] * s['judged']), s['judged'])} | {pct(round(s['judge_agrees'] * s['judged']), s['judged'])} | "
                     if s.get("judge_correct") is not None else "- | - | ") if judged else ""
            lines.append(f"| {m} | {s['questions']} | {s['recall_at_5']:.0%} | {s['answer_hit']:.0%} | {judge}{s['wrong_block']:.0%} | "
                         f"{s['p50_ms']:.0f} | {s['p95_ms']:.0f} | {s['input_tokens']}/{s['output_tokens']} | {s['usd']:.4f} |")
        eval_errors = {m: s.get("errors", 0) + (s.get("agent") or {}).get("errors", 0) for m, s in evals.items()}
        if any(eval_errors.values()):
            lines += ["", "Eval rows that hit a server error (left out of the rates above): "
                      + ", ".join(f"{m}: {v}" for m, v in eval_errors.items() if v) + "."]
        if judged:
            model = next(s["judge_model"] for s in evals.values() if s.get("judge_model"))
            lines += ["", f"Answer hit: the expected value appears in the answer. Judge: `{model}` (local) decides whether the "
                          "answer gives the asking company's value."]
    agent = {m: s["agent"] for m, s in evals.items() if s.get("agent")}
    if agent:
        lines += ["", "## Agent tasks on the tenant's own data", "",
                  "| Mode | Tasks | Done | Read a ticket | Search | Add a note | Wrong blocks | Tool errors | p50 ms |",
                  "|---|---|---|---|---|---|---|---|---|"]
        for m, a in agent.items():
            k = a["by_kind"]
            lines.append(f"| {m} | {a['tasks']} | {a['done']:.0%} | {k['ticket']:.0%} | {k['search']:.0%} | {k['note']:.0%} | "
                         f"{a['wrong_block']:.0%} | {a['tool_error']:.0%} | {a['p50_ms']:.0f} |")
    (RESULTS / "RESULTS.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
