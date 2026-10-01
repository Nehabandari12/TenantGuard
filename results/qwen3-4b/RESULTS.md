# Results

LLM: `ollama` / qwen3:4b, repeats per check: 1. Cell = leak rate over all runs, answers-only / all-channels.

| Route | OWASP | B0 no protection | B1 app tenant filter | B2 B1 + keyword firewall | B3 TenantGuard | B3 without egress canary check |
|---|---|---|---|---|---|---|
| search | LLM08 | 8% / 100% | 0% / 31% | 0% / 31% | 0% / 0% | 0% / 0% |
| cache | LLM08 | 100% / 100% | 100% / 100% | 100% / 100% | 0% / 0% | 0% / 0% |
| memory | ASI06 | 54% / 100% | 62% / 77% | 62% / 77% | 0% / 0% | 0% / 0% |
| tools | ASI02/ASI03 | 85% / 100% | 46% / 54% | 46% / 54% | 0% / 0% | 0% / 0% |
| injection | LLM01/ASI01 | 15% / 69% | 0% / 38% | 0% / 38% | 0% / 0% | 0% / 0% |
| logs | LLM02 | 100% / 100% | 62% / 62% | 62% / 62% | 0% / 0% | 0% / 0% |
| **all** |  | 60% / 95% | 45% / 60% | 45% / 60% | 0% / 0% | 0% / 0% |

Hidden leaks in B2 (caught by all-channels scoring, missed by answers-only): 12 of 78 runs (15%).

## Utility (normal questions)

| Mode | Questions | Recall@5 | Answer hit | Judge: correct | Judge agrees with hit | Wrong blocks | p50 ms | p95 ms | Tokens in/out | USD |
|---|---|---|---|---|---|---|---|---|---|---|
| B0 | 15 | 100% | 100% | 100% | 100% | 0% | 42277 | 128517 | 5650/9666 | 0.0000 |
| B1 | 15 | 100% | 100% | 100% | 100% | 0% | 30913 | 37865 | 5661/4087 | 0.0000 |
| B2 | 15 | 100% | 100% | 100% | 100% | 0% | 28193 | 35340 | 5661/4470 | 0.0000 |
| B3 | 15 | 100% | 100% | 100% | 100% | 0% | 29155 | 35262 | 5661/4470 | 0.0000 |

Answer hit: the expected value appears in the answer. Judge: `qwen3:4b` (local) decides whether the answer gives the asking company's value.

## Agent tasks on the tenant's own data

| Mode | Tasks | Done | Read a ticket | Search | Add a note | Wrong blocks | Tool errors | p50 ms |
|---|---|---|---|---|---|---|---|---|
| B0 | 9 | 100% | 100% | 100% | 100% | 0% | 0% | 62471 |
| B1 | 9 | 89% | 67% | 100% | 100% | 0% | 11% | 73490 |
| B2 | 9 | 100% | 100% | 100% | 100% | 0% | 0% | 63783 |
| B3 | 9 | 100% | 100% | 100% | 100% | 0% | 0% | 53003 |
