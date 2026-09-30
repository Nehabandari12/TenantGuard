# TenantGuard

[![CI](https://github.com/Nehabandari12/TenantGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/Nehabandari12/TenantGuard/actions/workflows/ci.yml)

An enforcement layer that stops one company's data from reaching another company in a multi-tenant
LLM app, plus a benchmark that measures it. The same app runs in four modes against the same checks:

| Mode | What protects tenants |
|---|---|
| B0 | nothing |
| B1 | a `WHERE tenant_id = …` filter in app code (the usual tutorial fix) |
| B2 | B1 + an input prompt-injection firewall |
| B3 | **TenantGuard**: verified identity, FORCE RLS, tenant-scoped cache and memory, audience-bound MCP tokens, outbound checks |

A leak is a canary (e.g. `GLBX-4A1F0C`) showing up where its owner tenant can't see it. The detector checks
**every output channel**, not only the final answer: retrieval, cache, memory, tool calls and results, logs,
external URLs, and notes written into another tenant's records. It matches after undoing base64, hex,
URL-encoding, reversal and inserted separators.

## Results (23 checks per mode)

Leak rate, answers-only / all-channels, for two models: a real one (**Qwen3 4B**, local through Ollama) and an
offline **mock** that obeys any instruction it sees (the worst case). No check errored or timed out in either
run. Full tables: [results/qwen3-4b/RESULTS.md](results/qwen3-4b/RESULTS.md), [results/mock/RESULTS.md](results/mock/RESULTS.md).

**Qwen3 4B**

| Route | OWASP | B0 | B1 | B2 | B3 | B3, egress canary check off |
|---|---|---|---|---|---|---|
| search | LLM08 | 0% / 100% | 0% / 20% | 0% / 20% | 0% / 0% | 0% / 0% |
| cache | LLM08 | 100% / 100% | 100% / 100% | 100% / 100% | 0% / 0% | 0% / 0% |
| memory | ASI06 | 67% / 100% | 67% / 67% | 67% / 67% | 0% / 0% | 0% / 0% |
| tools | ASI02/ASI03 | 100% / 100% | 60% / 60% | 60% / 60% | 0% / 0% | 0% / 0% |
| injection | LLM01/ASI01 | 50% / 100% | 0% / 75% | 0% / 75% | 0% / 0% | 0% / 0% |
| logs | LLM02 | 100% / 100% | 33% / 33% | 33% / 33% | 0% / 0% | 0% / 0% |
| **all** | | 65% / 100% | 39% / 57% | 39% / 57% | **0% / 0%** | **0% / 0%** |

**Mock model (worst-case obedient)**

| Route | OWASP | B0 | B1 | B2 | B3 | B3, egress canary check off |
|---|---|---|---|---|---|---|
| search | LLM08 | 100% / 100% | 20% / 20% | 20% / 20% | 0% / 0% | 0% / 0% |
| cache | LLM08 | 100% / 100% | 100% / 100% | 100% / 100% | 0% / 0% | 0% / 0% |
| memory | ASI06 | 100% / 100% | 67% / 67% | 67% / 67% | 0% / 0% | 0% / 0% |
| tools | ASI02/ASI03 | 100% / 100% | 60% / 60% | 60% / 60% | 0% / 0% | 0% / 0% |
| injection | LLM01/ASI01 | 50% / 100% | 50% / 75% | 50% / 75% | 0% / 0% | 0% / 0% |
| logs | LLM02 | 100% / 100% | 33% / 33% | 33% / 33% | 0% / 0% | 0% / 0% |
| **all** | | 91% / 100% | 52% / 57% | 52% / 57% | **0% / 0%** | **0% / 0%** |

What the two runs show:

- **B3 held at 0% on both models**, and still 0% with the egress canary check turned off, so the protection
  comes from making other tenants' data unreachable, not from egress recognising canaries.
- **The tutorial fix (B1) still leaks in 57% of checks on both models**, through the semantic cache, memory
  keyed by usernames that repeat across companies, tools that trust a model-supplied `tenant_id`, and the
  log viewer's tenant switch. The input firewall (B2) changed nothing.
- **A real model hides leaks from answer-only audits.** Qwen rephrases instead of repeating reference codes.
  In B0 its search answers looked clean (0%) while every one of them had pulled other companies' documents
  into context (100%). Across B0, 35% of checks leak somewhere other than the answer, against 9% for the mock.
- **Normal use is unaffected.** Every mode answered every utility question correctly: Qwen 15 per mode, mock
  60 per mode, 100% recall@5, 0 wrong blocks. The guard overhead, measured on the mock where the LLM costs
  nothing, is about 40-60 ms at p50. Qwen's latencies (33-65 s at p50 on CPU) are dominated by inference and
  by how loaded the machine was, so they don't compare modes.
- **Unprotected retrieval costs compute too.** With other companies' near-duplicate documents in context,
  Qwen produced about twice as many output tokens in B0 (9,197 vs 4,126-4,431 in B1-B3, over 15 questions).

Read these numbers with the [limitations](#limitations) in mind: 23 checks so far (the target is ~80),
and one repeat per check.

## How it works

```
 client ──JWT──> FastAPI app ──────────────> Postgres (pgvector, FORCE RLS)
                  │ identity middleware          ▲ set_config('app.tenant_id', t, true)
                  │ tenant-tagged cache (Redis)  │ per transaction, role tg_app
                  │ tenant:user memory (Redis)   │
                  │ egress checks ───────────────┤
                  └──60 s aud-bound token──> MCP server (tenant from token only)
```

- **Identity** ([tenantguard/identity.py](tenantguard/identity.py)): the tenant comes only from a verified JWT, never from the body, a header or the model.
- **Postgres** ([tenantguard/db.py](tenantguard/db.py), [sql/001_init.sql](sql/001_init.sql)): ENABLE + FORCE RLS, a fail-closed policy function, `set_config(..., true)` inside an explicit transaction, `hnsw.iterative_scan` so filtered search still returns a full top 5, and a startup check that refuses superuser or BYPASSRLS roles.
- **Cache** ([tenantguard/cache.py](tenantguard/cache.py)): RedisVL `SemanticCache` that always stores and always filters a `tenant_id` tag.
- **Memory** ([tenantguard/memory.py](tenantguard/memory.py)): namespace is always `tenant:user`, and a call without a verified tenant raises.
- **MCP** ([tenantguard/mcp_auth.py](tenantguard/mcp_auth.py)): no token passthrough. Each request gets a freshly minted, 60 s token whose audience is the MCP server, and tools have no tenant argument. The mcp 2.x SDK binds each session to the token's subject (`tenant:user`).
- **Egress** ([tenantguard/egress.py](tenantguard/egress.py)): blocks foreign canaries after decoding, redacts secrets and PII (Presidio), and allows links only to approved domains, on answers, tool arguments and log lines.

Why each piece is built this way, how leaks are scored, and the bugs found along the way:
[docs/DESIGN.md](docs/DESIGN.md).

## Setup

Needs Docker, Python 3.12, [uv](https://docs.astral.sh/uv/) and [Ollama](https://ollama.com) with Qwen3 4B.

```bash
ollama pull qwen3:4b                                          # the default LLM; runs locally, no API key
docker compose up -d
uv venv --python 3.12 .venv && uv pip install --python .venv -e ".[embed,pii,dev]"
.venv/Scripts/python -m spacy download en_core_web_sm        # Presidio model (bin/ on macOS/Linux)
.venv/Scripts/python -m app.seed                              # 3 companies, 150 docs, 60 tickets, 222 canaries
.venv/Scripts/python -m pytest -q                             # 27 unit tests
.venv/Scripts/python -m attacks.bench                         # everything below, resumable; writes results/<model>/
```

`attacks.bench` runs B0-B3, B3 without the egress canary check, the utility eval and the results table.
Each step skips if it has already finished and otherwise resumes from its last saved check, so after a crash
or reboot you just run it again. Progress is in `results/<model>/progress.log`. Individual steps:
`python -m attacks.run --mode B1`, `python -m eval.run_eval --mode B3 --per-tenant 5`, `python -m attacks.table`.

**LLM choice.** The default is local Ollama `qwen3:4b` at temperature 0 with a fixed seed. Nothing is sent to
a paid API, and there is no fallback between providers: if Ollama is down, the app refuses to start.
Settings are in [.env.example](.env.example).

| `LLM_PROVIDER` | Model | Cost | Notes |
|---|---|---|---|
| `ollama` (default) | `LLM_MODEL=qwen3:4b` | free, local | about 1 min per request on CPU |
| `mock` | built-in | free, offline | deterministic, worst-case obedient; the full suite runs in about 1 minute |
| `anthropic` | `claude-haiku-4-5` | paid | **disabled**: refuses to start unless `TG_ALLOW_PAID_LLM=1` |

Each LLM writes to its own folder (`results/mock/`, `results/qwen3-4b/`). Local and mock runs use 1 repeat
per check by default; pass `--repeats 3` to measure run-to-run variation.

## Limitations

- The mock follows any instruction in its context, so it's an upper bound on model misbehaviour, not a
  realistic model. Qwen3 4B is a real but small model; a larger model may follow planted instructions more
  or less often.
- Each check ran once. Qwen at temperature 0 with a fixed seed is close to, but not exactly, repeatable on
  CPU, so `--repeats 3` would give a better estimate of the B0-B2 rates. The B3 zeros don't depend on the
  model's behaviour.
- Canary detection undercounts leaks that a model paraphrases. Provenance rules cover the cache, memory and
  log viewer, and all-channels scoring catches paraphrase on retrieval and tool results. Answers-only
  numbers for a real model are therefore a lower bound.
- On a CPU-only machine Qwen3 4B takes about a minute per request, so the Qwen utility eval uses 15
  questions per mode instead of 60.
- There are 23 checks (3-5 per route) against a target of ~80, and no encoded/translated variants of
  inputs yet. The detector and egress *do* decode base64/hex/URL/reversed/split output.
- B2 used the keyword-heuristic fallback because LlamaFirewall was not installed (it needs gated Hugging
  Face access to Llama Prompt Guard 2). The input firewall caught none of these checks, because none rely
  on jailbreak phrasing and it never sees retrieved tickets.
- B3 scoring 0% even with the egress canary check off shows the protection comes from the access layer.
  Egress still matters for the injection route: link stripping is what stops a tenant's own data from
  leaving through a URL.
- "Answer hit" is a string match on the expected fact, not an LLM judge.
- Synthetic data only.

## Credits

All code here is written for this project; no files were copied. Design ideas came from:
[Sectum AI](https://github.com/sectum-ai/sectum-ai) (Apache-2.0: hard + secret canary types, MCP check classes,
"explicit deny, not empty success"), [AgentLeak](https://github.com/yagobski/agentleak) (MIT: output-channel model),
and, as ideas only because they carry no license, [tenantvault-zero-trust-rag](https://github.com/RitwijParmar/tenantvault-zero-trust-rag)
(fail-closed tenant function), [ai-tenant-leak-test](https://github.com/bluntlycoded/ai-tenant-leak-test)
("verify ingest first" precheck, check categories) and [multi-tenant-rag](https://github.com/Mehta-Amit-Codes/multi-tenant-rag)
(skeleton shape, and a live example of the superuser-bypasses-RLS trap). Details in [docs/DESIGN.md](docs/DESIGN.md#prior-work).
