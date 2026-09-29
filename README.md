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

## Results (mock LLM, 23 checks per mode)

Leak rate, answers-only / all-channels. Full table: [results/mock/RESULTS.md](results/mock/RESULTS.md).
A run against the local Qwen3 4B model is in progress; its table goes to `results/qwen3-4b/RESULTS.md`.

| Route | OWASP | B0 | B1 | B2 | B3 | B3, egress canary check off |
|---|---|---|---|---|---|---|
| search | LLM08 | 100% / 100% | 20% / 20% | 20% / 20% | 0% / 0% | 0% / 0% |
| cache | LLM08 | 100% / 100% | 100% / 100% | 100% / 100% | 0% / 0% | 0% / 0% |
| memory | ASI06 | 100% / 100% | 67% / 67% | 67% / 67% | 0% / 0% | 0% / 0% |
| tools | ASI02/ASI03 | 100% / 100% | 60% / 60% | 60% / 60% | 0% / 0% | 0% / 0% |
| injection | LLM01/ASI01 | 50% / 100% | 50% / 75% | 50% / 75% | 0% / 0% | 0% / 0% |
| logs | LLM02 | 100% / 100% | 33% / 33% | 33% / 33% | 0% / 0% | 0% / 0% |
| **all** | | 91% / 100% | 52% / 57% | 52% / 57% | **0% / 0%** | **0% / 0%** |

Normal use is unaffected: on 60 generated questions every mode has 100% recall@5 and 0 wrong blocks;
B3 adds about 40-60 ms at p50.

Read these numbers with the [limitations](#limitations) in mind: the mock model is deterministic and
worst-case obedient, and there are 23 checks so far (the target is ~80).

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

- The table above uses the offline mock model. It follows any instruction in its context, so it's an upper
  bound on model misbehaviour, not a realistic model. The Qwen3 4B run is the realistic (small, local) counterpart.
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
