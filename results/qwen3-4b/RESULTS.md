# Results

LLM: `ollama` / qwen3:4b, repeats per case: 1. Cell = leak rate, answers-only / all-channels.

| Route | OWASP | B0 no protection | B1 app tenant filter | B2 B1 + input firewall | B3 TenantGuard | B3 without egress canary check |
|---|---|---|---|---|---|---|
| search | LLM08 | 0% / 100% | 0% / 20% | 0% / 20% | 0% / 0% | 0% / 0% |
| cache | LLM08 | 100% / 100% | 100% / 100% | 100% / 100% | 0% / 0% | 0% / 0% |
| memory | ASI06 | 67% / 100% | 67% / 67% | 67% / 67% | 0% / 0% | 0% / 0% |
| tools | ASI02/ASI03 | 100% / 100% | 60% / 60% | 60% / 60% | 0% / 0% | 0% / 0% |
| injection | LLM01/ASI01 | 50% / 100% | 0% / 75% | 0% / 75% | 0% / 0% | 0% / 0% |
| logs | LLM02 | 100% / 100% | 33% / 33% | 33% / 33% | 0% / 0% | 0% / 0% |
| **all** |  | 65% / 100% | 39% / 57% | 39% / 57% | 0% / 0% | 0% / 0% |

Hidden leaks in B2 (caught by all-channels scoring, missed by answers-only): 4 of 23 runs (17%).

## Utility (normal questions)

| Mode | Questions | Recall@5 | Answer hit | Wrong blocks | p50 ms | p95 ms | Tokens in/out | USD |
|---|---|---|---|---|---|---|---|---|
| B0 | 15 | 100% | 100% | 0% | 65007 | 210583 | 5650/9197 | 0.0000 |
| B1 | 15 | 100% | 100% | 0% | 42268 | 50906 | 5661/4126 | 0.0000 |
| B2 | 15 | 100% | 100% | 0% | 36058 | 43440 | 5661/4431 | 0.0000 |
| B3 | 15 | 100% | 100% | 0% | 32643 | 38809 | 5661/4431 | 0.0000 |
