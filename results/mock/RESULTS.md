# Results

LLM: `mock`, repeats per check: 1. Cell = leak rate over all runs, answers-only / all-channels.

| Route | OWASP | B0 no protection | B1 app tenant filter | B2 B1 + keyword firewall | B2 with Prompt Guard 2 | B3 TenantGuard | B3 without egress canary check |
|---|---|---|---|---|---|---|---|
| search | LLM08 | 100% / 100% | 36% / 36% | 36% / 36% | 36% / 36% | 0% / 0% | 0% / 0% |
| cache | LLM08 | 100% / 100% | 100% / 100% | 100% / 100% | 100% / 100% | 0% / 0% | 0% / 0% |
| memory | ASI06 | 93% / 100% | 64% / 79% | 64% / 79% | 64% / 79% | 0% / 0% | 0% / 0% |
| tools | ASI02/ASI03 | 86% / 100% | 57% / 71% | 57% / 71% | 57% / 71% | 0% / 0% | 0% / 0% |
| injection | LLM01/ASI01 | 43% / 100% | 43% / 71% | 43% / 71% | 43% / 71% | 0% / 0% | 0% / 0% |
| logs | LLM02 | 100% / 100% | 64% / 64% | 64% / 64% | 64% / 64% | 0% / 0% | 0% / 0% |
| **all** |  | 87% / 100% | 61% / 70% | 61% / 70% | 61% / 70% | 0% / 0% | 0% / 0% |

Hidden leaks in B2 (caught by all-channels scoring, missed by answers-only): 8 of 84 runs (10%).

## Utility (normal questions)

| Mode | Questions | Recall@5 | Answer hit | Wrong blocks | p50 ms | p95 ms | Tokens in/out | USD |
|---|---|---|---|---|---|---|---|---|
| B0 | 60 | 100% | 100% | 0% | 74 | 115 | 0/0 | 0.0000 |
| B1 | 60 | 100% | 100% | 0% | 81 | 101 | 0/0 | 0.0000 |
| B2 | 60 | 100% | 100% | 0% | 81 | 129 | 0/0 | 0.0000 |
| B2_promptguard | 60 | 100% | 100% | 0% | 425 | 510 | 0/0 | 0.0000 |
| B3 | 60 | 100% | 100% | 0% | 105 | 136 | 0/0 | 0.0000 |

## Agent tasks on the tenant's own data

| Mode | Tasks | Done | Read a ticket | Search | Add a note | Wrong blocks | Tool errors | p50 ms |
|---|---|---|---|---|---|---|---|---|
| B0 | 27 | 100% | 100% | 100% | 100% | 0% | 0% | 113 |
| B1 | 27 | 100% | 100% | 100% | 100% | 0% | 0% | 167 |
| B2 | 27 | 100% | 100% | 100% | 100% | 0% | 0% | 124 |
| B2_promptguard | 27 | 100% | 100% | 100% | 100% | 0% | 0% | 448 |
| B3 | 27 | 100% | 100% | 100% | 100% | 0% | 0% | 162 |
