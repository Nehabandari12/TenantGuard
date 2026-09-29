# Results

LLM: `mock`, repeats per case: 1. Cell = leak rate, answers-only / all-channels.

| Route | OWASP | B0 no protection | B1 app tenant filter | B2 B1 + input firewall | B3 TenantGuard | B3 without egress canary check |
|---|---|---|---|---|---|---|
| search | LLM08 | 100% / 100% | 20% / 20% | 20% / 20% | 0% / 0% | 0% / 0% |
| cache | LLM08 | 100% / 100% | 100% / 100% | 100% / 100% | 0% / 0% | 0% / 0% |
| memory | ASI06 | 100% / 100% | 67% / 67% | 67% / 67% | 0% / 0% | 0% / 0% |
| tools | ASI02/ASI03 | 100% / 100% | 60% / 60% | 60% / 60% | 0% / 0% | 0% / 0% |
| injection | LLM01/ASI01 | 50% / 100% | 50% / 75% | 50% / 75% | 0% / 0% | 0% / 0% |
| logs | LLM02 | 100% / 100% | 33% / 33% | 33% / 33% | 0% / 0% | 0% / 0% |
| **all** |  | 91% / 100% | 52% / 57% | 52% / 57% | 0% / 0% | 0% / 0% |

Hidden leaks in B2 (caught by all-channels scoring, missed by answers-only): 1 of 23 runs (4%).

## Utility (normal questions)

| Mode | Questions | Recall@5 | Answer hit | Wrong blocks | p50 ms | p95 ms | Tokens in/out | USD |
|---|---|---|---|---|---|---|---|---|
| B0 | 60 | 100% | 100% | 0% | 101 | 167 | 0/0 | 0.0000 |
| B1 | 60 | 100% | 100% | 0% | 98 | 182 | 0/0 | 0.0000 |
| B2 | 60 | 100% | 100% | 0% | 96 | 157 | 0/0 | 0.0000 |
| B3 | 60 | 100% | 100% | 0% | 162 | 259 | 0/0 | 0.0000 |
