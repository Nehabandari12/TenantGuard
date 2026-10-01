# Results

LLM: `mock`, repeats per check: 1. Cell = leak rate over all runs, answers-only / all-channels.

| Route | OWASP | B0 no protection | B1 app tenant filter | B2 B1 + keyword firewall | B2 with Prompt Guard 2 | B3 TenantGuard | B3 without egress canary check |
|---|---|---|---|---|---|---|---|
| search | LLM08 | 100% / 100% | 31% / 31% | 31% / 31% | 31% / 31% | 0% / 0% | 0% / 0% |
| cache | LLM08 | 100% / 100% | 100% / 100% | 100% / 100% | 100% / 100% | 0% / 0% | 0% / 0% |
| memory | ASI06 | 92% / 100% | 62% / 77% | 62% / 77% | 62% / 77% | 0% / 0% | 0% / 0% |
| tools | ASI02/ASI03 | 85% / 100% | 54% / 69% | 54% / 69% | 54% / 69% | 0% / 0% | 0% / 0% |
| injection | LLM01/ASI01 | 38% / 100% | 38% / 69% | 38% / 69% | 38% / 69% | 0% / 0% | 0% / 0% |
| logs | LLM02 | 100% / 100% | 62% / 62% | 62% / 62% | 62% / 62% | 0% / 0% | 0% / 0% |
| **all** |  | 86% / 100% | 58% / 68% | 58% / 68% | 58% / 68% | 0% / 0% | 0% / 0% |

Hidden leaks in B2 (caught by all-channels scoring, missed by answers-only): 8 of 78 runs (10%).

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
