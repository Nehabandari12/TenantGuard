"""Build results/<llm>/RESULTS.md from that folder's <mode>.json and eval_<mode>.json.

    python -m attacks.table                   # current LLM_PROVIDER / LLM_MODEL
    LLM_PROVIDER=mock python -m attacks.table
"""

import json

from attacks.run import RESULTS

ROUTES = [("search", "LLM08"), ("cache", "LLM08"), ("memory", "ASI06"), ("tools", "ASI02/ASI03"),
          ("injection", "LLM01/ASI01"), ("logs", "LLM02"), ("ALL", "")]
LABELS = {"B0": "B0 no protection", "B1": "B1 app tenant filter", "B2": "B2 B1 + input firewall",
          "B3": "B3 TenantGuard", "B3_nocanary": "B3 without egress canary check"}


def pct(n: int, d: int) -> str:
    return f"{n / d:.0%}" if d else "-"


def main() -> None:
    runs = {label: json.loads((RESULTS / f"{label}.json").read_text(encoding="utf-8"))
            for label in LABELS if (RESULTS / f"{label}.json").exists()}
    lines = ["# Results", ""]
    if runs:
        meta = next(iter(runs.values()))["meta"]
        lines += [f"LLM: `{meta['llm']}`{' / ' + meta['llm_model'] if meta.get('llm_model') else ''}, "
                  f"repeats per case: {meta['repeats']}. Cell = leak rate, answers-only / all-channels.", ""]
        lines.append("| Route | OWASP | " + " | ".join(LABELS[l] for l in runs) + " |")
        lines.append("|---|---|" + "---|" * len(runs))
        for route, owasp in ROUTES:
            cells = []
            for run in runs.values():
                s = run["summary"].get(route)
                cells.append(f"{pct(s['leak_answer'], s['runs'])} / {pct(s['leak_any'], s['runs'])}" if s else "-")
            lines.append(f"| {'**all**' if route == 'ALL' else route} | {owasp} | " + " | ".join(cells) + " |")
        b2 = runs.get("B2", {}).get("summary", {}).get("ALL")
        if b2:
            hidden = b2["leak_any"] - b2["leak_answer"]
            lines += ["", f"Hidden leaks in B2 (caught by all-channels scoring, missed by answers-only): "
                          f"{hidden} of {b2['runs']} runs ({pct(hidden, b2['runs'])})."]
    evals = {m: json.loads((RESULTS / f"eval_{m}.json").read_text(encoding="utf-8"))["summary"]
             for m in ("B0", "B1", "B2", "B3") if (RESULTS / f"eval_{m}.json").exists()}
    if evals:
        lines += ["", "## Utility (normal questions)", "",
                  "| Mode | Questions | Recall@5 | Answer hit | Wrong blocks | p50 ms | p95 ms | Tokens in/out | USD |",
                  "|---|---|---|---|---|---|---|---|---|"]
        for m, s in evals.items():
            lines.append(f"| {m} | {s['questions']} | {s['recall_at_5']:.0%} | {s['answer_hit']:.0%} | {s['wrong_block']:.0%} | "
                         f"{s['p50_ms']:.0f} | {s['p95_ms']:.0f} | {s['input_tokens']}/{s['output_tokens']} | {s['usd']:.4f} |")
    (RESULTS / "RESULTS.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
