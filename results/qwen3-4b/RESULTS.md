# Results

LLM: `ollama` / qwen3:4b, repeats per check: B0 no protection 1, B1 app tenant filter 3, B2 B1 + keyword firewall 1, B3 TenantGuard 3, B3 without egress canary check 1. Cell = leak rate over all runs, answers-only / all-channels.

| Route | OWASP | B0 no protection | B1 app tenant filter | B2 B1 + keyword firewall | B3 TenantGuard | B3 without egress canary check |
|---|---|---|---|---|---|---|
| search | LLM08 | 0% / 100% | 0% / 36% | 0% / 36% | 0% / 0% | 0% / 0% |
| cache | LLM08 | 93% / 93% | 93% / 93% | 93% / 93% | 0% / 0% | 0% / 0% |
| memory | ASI06 | 50% / 100% | 50% / 79% | 57% / 79% | 0% / 0% | 0% / 0% |
| tools | ASI02/ASI03 | 71% / 86% | 40% / 48% | 43% / 50% | 0% / 0% | 0% / 0% |
| injection | LLM01/ASI01 | 0% / 50% | 0% / 29% | 0% / 29% | 0% / 0% | 0% / 0% |
| logs | LLM02 | 100% / 100% | 64% / 64% | 64% / 64% | 0% / 0% | 0% / 0% |
| **all** |  | 52% / 88% | 41% / 58% | 43% / 58% | 0% / 0% | 0% / 0% |

Checks whose all-channels outcome changed between repeats: B1 app tenant filter: 1 (tools-14); B3 TenantGuard: 0.

Hidden leaks in B2 (caught by all-channels scoring, missed by answers-only): 13 of 84 runs (15%).

## Utility (normal questions)

| Mode | Questions | Recall@5 | Answer hit | Wrong blocks | p50 ms | p95 ms | Tokens in/out | USD |
|---|---|---|---|---|---|---|---|---|
| B0 | 51 | 100% | 94% | 0% | 44481 | 125128 | 19207/34528 | 0.0000 |
| B1 | 51 | 100% | 98% | 0% | 25169 | 31995 | 19190/14120 | 0.0000 |
| B2 | 51 | 100% | 96% | 0% | 20092 | 30610 | 19190/14599 | 0.0000 |
| B3 | 51 | 100% | 96% | 0% | 20209 | 31220 | 19190/14599 | 0.0000 |

## Agent tasks on the tenant's own data

| Mode | Tasks | Done | Read a ticket | Search | Add a note | Wrong blocks | Tool errors | p50 ms |
|---|---|---|---|---|---|---|---|---|
| B0 | 18 | 89% | 100% | 67% | 100% | 0% | 0% | 51335 |
| B1 | 18 | 94% | 100% | 83% | 100% | 0% | 0% | 47345 |
| B2 | 18 | 94% | 100% | 83% | 100% | 0% | 0% | 47716 |
| B3 | 18 | 94% | 100% | 83% | 100% | 0% | 0% | 44036 |
