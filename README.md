# TenantGuard

[![CI](https://github.com/Nehabandari12/TenantGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/Nehabandari12/TenantGuard/actions/workflows/ci.yml)

An enforcement layer that stops one company's data from reaching another company in a multi-tenant
LLM app, plus a benchmark that measures it. The same app runs in four modes against the same checks:

| Mode | What protects tenants |
|---|---|
| B0 | nothing |
| B1 | a `WHERE tenant_id = …` filter in app code (the usual tutorial fix) |
| B2 | B1 + an input prompt-injection firewall: a keyword filter, or Llama Prompt Guard 2 |
| B3 | **TenantGuard**: verified identity, FORCE RLS, tenant-scoped cache and memory, audience-bound MCP tokens, outbound checks |

A leak is a canary (e.g. `GLBX-4A1F0C`) showing up where its owner tenant can't see it. The detector checks
**every output channel**, not only the final answer: retrieval, cache, memory, tool calls and results, logs,
external URLs, and notes written into another tenant's records. It matches after undoing base64, hex,
URL-encoding, reversal and inserted separators.

## Why this matters

Each of these happened or was demonstrated in public, and each matches a route the checks cover. They are
here for the pattern; nothing below claims TenantGuard would have stopped any of them as those systems
were built.

| When | What happened | Route here |
|---|---|---|
| Mar 2023 | **ChatGPT.** A bug in the Redis client library (redis-py) let some users see titles from other users' chat histories. For 1.2% of Plus subscribers active during a nine-hour window, another user could see their name, email, payment address and the last four digits of their card. ([BleepingComputer](https://www.bleepingcomputer.com/news/security/openai-chatgpt-payment-data-leak-caused-by-open-source-bug/), [Help Net Security](https://www.helpnetsecurity.com/2023/03/27/chatgpt-data-leak/)) | cache: a shared store hands one user's entry to another |
| Aug 2024 | **Slack AI.** PromptArmor showed that a message posted in a public channel could make Slack AI pull data from a private channel the attacker wasn't in and render it inside a link for the victim to click. Slack first called it intended behaviour. ([PromptArmor](https://promptarmor.com/resources/data-exfiltration-from-slack-ai-via-indirect-prompt-injection)) | injection, with data leaving through a link |
| May-Jun 2025 | **Asana MCP server.** A logic flaw in the MCP server Asana launched on May 1 let users of one organization see some data from other organizations. Asana found it on June 4 and took the server offline until June 17. ([BleepingComputer](https://bleepingcomputer.com/news/security/asana-warns-mcp-ai-feature-exposed-customer-data-to-other-orgs/)) | tools: an MCP server crossing tenants |
| Jun 2025 | **EchoLeak, Microsoft 365 Copilot** (CVE-2025-32711). Aim Security showed that a crafted email, once Copilot retrieved it, could make Copilot pull data from the user's context and send it out through URLs, with no click needed. Microsoft fixed it; there is no evidence it was exploited. ([The Hacker News](https://thehackernews.com/2025/06/zero-click-ai-vulnerability-exposes.html)) | injection, with data leaving through a URL |
| Jul 2025 | **Supabase MCP** (demonstrated on a test setup). General Analysis filed a support ticket containing instructions. A developer's coding agent, connected through MCP with the `service_role` key, which bypasses row-level security, read a private tokens table and wrote it back into the ticket thread. ([General Analysis](https://www.generalanalysis.com/blog/supabase-mcp-blog)) | injection through a support ticket, plus a role that skips RLS |

## Results

Two models: an offline **mock** that obeys any instruction it sees (the worst case), and a real one
(**Qwen3 4B**, local through Ollama). The mock ran all 84 checks (14 per route) in a fresh run on 2 Oct 2026.
Qwen ran the first 78; the six encoded-reply checks were added afterwards and ran on the mock only. Qwen's B1
ran three times. Leak rate, answers-only / all-channels. No check errored. Full tables:
[results/qwen3-4b/RESULTS.md](results/qwen3-4b/RESULTS.md), [results/mock/RESULTS.md](results/mock/RESULTS.md).

**Qwen3 4B, 78 checks**

| Route | OWASP | B0 | B1 (3 runs) | B2, keyword filter | B3 | B3, egress canary check off |
|---|---|---|---|---|---|---|
| search | LLM08 | 8% / 100% | 0% / 31% | 0% / 31% | 0% / 0% | 0% / 0% |
| cache | LLM08 | 100% / 100% | 100% / 100% | 100% / 100% | 0% / 0% | 0% / 0% |
| memory | ASI06 | 54% / 100% | 56% / 77% | 62% / 77% | 0% / 0% | 0% / 0% |
| tools | ASI02/ASI03 | 85% / 100% | 41% / 49% | 46% / 54% | 0% / 0% | 0% / 0% |
| injection | LLM01/ASI01 | 15% / 69% | 0% / 33% | 0% / 38% | 0% / 0% | 0% / 0% |
| logs | LLM02 | 100% / 100% | 62% / 62% | 62% / 62% | 0% / 0% | 0% / 0% |
| **all** | | 60% / 95% | 43% / 59% | 45% / 60% | **0% / 0%** | **0% / 0%** |

**Mock model (worst-case obedient), 84 checks**

| Route | OWASP | B0 | B1 | B2, keyword filter | B2, Prompt Guard 2 | B3 | B3, egress canary check off |
|---|---|---|---|---|---|---|---|
| search | LLM08 | 100% / 100% | 36% / 36% | 36% / 36% | 36% / 36% | 0% / 0% | 0% / 0% |
| cache | LLM08 | 100% / 100% | 100% / 100% | 100% / 100% | 100% / 100% | 0% / 0% | 0% / 0% |
| memory | ASI06 | 93% / 100% | 64% / 79% | 64% / 79% | 64% / 79% | 0% / 0% | 0% / 0% |
| tools | ASI02/ASI03 | 86% / 100% | 57% / 71% | 57% / 71% | 57% / 71% | 0% / 0% | 0% / 0% |
| injection | LLM01/ASI01 | 43% / 100% | 43% / 71% | 43% / 71% | 43% / 71% | 0% / 0% | 0% / 0% |
| logs | LLM02 | 100% / 100% | 64% / 64% | 64% / 64% | 64% / 64% | 0% / 0% | 0% / 0% |
| **all** | | 87% / 100% | 61% / 70% | 61% / 70% | 61% / 70% | **0% / 0%** | **0% / 0%** |

What the runs show:

- **B3 held at 0% on every check, on both models**, and still 0% with the egress canary check turned off,
  so the protection comes from making other tenants' data unreachable, not from egress recognising canaries.
  Every B3 outcome is an explicit denial (403, an MCP token refused with HTTP 401, "not found or not
  accessible") or the caller's own data.
- **The tutorial fix (B1) still leaks in 59% of runs on Qwen and 70% on the mock**, through the semantic
  cache, memory keyed by usernames that repeat across companies, tools that trust a model-supplied
  `tenant_id`, the tenant-switch header and the log viewer's `?tenant=` parameter. It does stop plain ID
  guessing and unauthenticated tool calls. Across Qwen's three B1 runs only 2 of 78 checks changed outcome.
- **Input firewalls don't see these attacks.** Neither B2 firewall changed a single result. Llama Prompt
  Guard 2 86M scores an obvious "ignore your previous instructions" at 0.999, yet flagged none of the 286
  inputs the benchmark sends (highest score 0.18). The cross-tenant requests read like ordinary ones ("show
  me ticket T-1005", a header, a `?tenant=` parameter), and planted instructions arrive in tool results,
  which an input firewall never looks at.
- **A real model hides leaks from answer-only audits.** Qwen rephrases instead of repeating reference codes.
  In B0 its search answers looked clean (8%) while all of them had pulled other companies' documents into
  context (100%). 35% of Qwen's B0 checks and 16% of its B1 runs leak only somewhere other than the answer:
  retrieval, tool results, memory, a note in another tenant's ticket, or an outside link.
- **Encoded replies don't hide a leak.** Six checks ask for the reply in base64, spaced out or reversed. On
  the mock all six leak in B0 and B1 and are caught only because the detector decodes them; B3 holds.
- **How the user asks decides whether a real model obeys planted text.** Asked to "handle" a poisoned ticket,
  Qwen followed its instructions. Asked to summarize it, explain it or reply to it, it didn't, even in B0
  (the only 4 of 78 checks that didn't leak there). The mock follows them every time, which is why it's the
  upper bound.
- **Normal use is unaffected.** On 51 normal questions per mode Qwen had 100% recall@5 and 0 wrong blocks in
  every mode, and B3's answers were identical to B2's, which has no TenantGuard at all. The string match
  scored 96-98% in B1-B3, and every miss there was wording, not a wrong fact ("1 hour" for the seed's
  "1 hours", "Customer Success Manager" without "the"). In B0 (94%) two answers came back empty: with other
  companies' documents in context, Qwen spent its whole token budget reasoning. Agent tasks on the tenant's
  own data: reading a ticket and adding a note worked every time in every mode, and searches matched in 83%
  (B1-B3), the misses again being wording. The
  mock answered all 60 questions and did all 27 agent tasks in every mode. On the mock, where the LLM costs
  nothing, TenantGuard adds about 25 ms at p50 to `/ask` (105 vs 81 ms) and nothing measurable to
  `/agent`; Prompt Guard 2 adds about 340 ms on CPU.
- **Unprotected retrieval costs compute too.** With other companies' near-duplicate documents in context,
  Qwen produced 2.4 times as many output tokens in B0 (34,528 vs 14,120-14,599 in B1-B3, over 51 questions).

Read these numbers with the [limitations](#limitations) in mind.

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
- **Postgres** ([tenantguard/db.py](tenantguard/db.py), [sql/001_init.sql](sql/001_init.sql)): ENABLE + FORCE RLS, a fail-closed policy function, `set_config(..., true)` inside an explicit transaction, `hnsw.iterative_scan` so filtered search still returns a full top 5, and a startup check that refuses superuser or BYPASSRLS roles. [tenantguard/rls_audit.py](tenantguard/rls_audit.py) audits all of this against a live database, and CI runs it on a freshly built one.
- **Cache** ([tenantguard/cache.py](tenantguard/cache.py)): RedisVL `SemanticCache` that always stores and always filters a `tenant_id` tag.
- **Memory** ([tenantguard/memory.py](tenantguard/memory.py)): namespace is always `tenant:user`, and a call without a verified tenant raises.
- **MCP** ([tenantguard/mcp_auth.py](tenantguard/mcp_auth.py)): no token passthrough. Each request gets a freshly minted, 60 s token whose audience is the MCP server, and tools have no tenant argument. The mcp 2.x SDK binds each session to the token's subject (`tenant:user`).
- **Egress** ([tenantguard/egress.py](tenantguard/egress.py)): blocks other tenants' canaries after decoding in answers and tool arguments, removes links to unapproved domains from answers and refuses tool calls that carry one, redacts secrets in answers and logs, and redacts PII (Presidio) in log lines. Answers keep the tenant's own customer details on purpose: they belong to that tenant.

Why each piece is built this way, how leaks are scored, and the bugs found along the way:
[docs/DESIGN.md](docs/DESIGN.md).

## Setup

Needs Docker, Python 3.12, [uv](https://docs.astral.sh/uv/) and [Ollama](https://ollama.com) with Qwen3 4B.

One command does all of the below except the benchmark: `powershell -ExecutionPolicy Bypass -File scripts\setup.ps1`
on Windows, `bash scripts/setup.sh` on macOS and Linux (`-SkipModel` / `--skip-model` to skip pulling Qwen).
Step by step:

```bash
ollama pull qwen3:4b                                          # the default LLM; runs locally, no API key
docker compose up -d
uv venv --python 3.12 .venv && uv pip install --python .venv -e ".[embed,pii,dev]"
.venv/Scripts/python -m spacy download en_core_web_sm        # Presidio model (bin/ on macOS/Linux)
.venv/Scripts/python -m app.seed                              # 3 companies, 150 docs, 60 tickets, 222 canaries
.venv/Scripts/python -m pytest -q                             # 34 unit tests
.venv/Scripts/python -m tenantguard.admin rls on && .venv/Scripts/python -m tenantguard.rls_audit   # RLS audit (B3 state)
.venv/Scripts/python -m attacks.bench                         # everything below, resumable; writes results/<model>/
```

`attacks.bench` runs B0-B3, B3 without the egress canary check, the utility eval and the results table.
Each step picks up where its saved results end: after a crash or reboot, or after new checks are added to
`attacks/cases.yaml`, you just run it again and only the missing checks run. Progress is in `results/<model>/progress.log`. Individual steps:
`python -m attacks.run --mode B1`, `python -m eval.run_eval --mode B3 --per-tenant 5`, `python -m attacks.table`.

**Demo.** `python -m attacks.demo` runs four of the checks (a tool asked for another tenant's ticket, a shared
cache, planted instructions, the log viewer) in B0 and then B3, and prints what each user got back and the
detector's verdict. About 30 seconds on the mock; add `--real` for the configured LLM. It writes no results.

**B2 with Llama Prompt Guard 2.** Request access to
[meta-llama/Llama-Prompt-Guard-2-86M](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M) and log in
with `hf auth login`, then `uv pip install --python .venv -e ".[firewall]"`. `python -m attacks.bench --promptguard`
adds the B2 run with it, and `TG_FIREWALL=promptguard python -m baselines.firewall` scores every input the
benchmark sends.

**LLM choice.** The default is local Ollama `qwen3:4b` at temperature 0 with a fixed seed. Nothing is sent to
a paid API, and there is no fallback between providers: if Ollama is down, the app refuses to start.
Settings are in [.env.example](.env.example).

| `LLM_PROVIDER` | Model | Cost | Notes |
|---|---|---|---|
| `ollama` (default) | `LLM_MODEL=qwen3:4b` | free, local | about 1 min per request on CPU |
| `mock` | built-in | free, offline | deterministic, worst-case obedient; a few minutes per mode |
| `anthropic` | `claude-haiku-4-5` | paid | **disabled**: refuses to start unless `TG_ALLOW_PAID_LLM=1` |

Each LLM writes to its own folder (`results/mock/`, `results/qwen3-4b/`). Local and mock runs use 1 repeat
per check by default; pass `--repeats 3` to measure run-to-run variation.

## Limitations

- The mock follows any instruction in its context, so it's an upper bound on model misbehaviour, not a
  realistic model. Qwen3 4B is a real but small model; a larger model may follow planted instructions more
  or less often.
- On Qwen only B1 ran three times (2 of 78 checks changed outcome between runs); the other modes ran once.
  The B3 zeros don't depend on the model's behaviour, and the mock confirms them on all 84 checks.
- Canary detection undercounts leaks that a model paraphrases. Provenance rules cover the cache, memory and
  log viewer, and all-channels scoring catches paraphrase on retrieval and tool results. Answers-only
  numbers for a real model are therefore a lower bound.
- On a CPU-only machine Qwen3 4B takes about a minute per request, so Qwen ran 78 of the 84 checks, and
  its utility eval uses 51 questions and 18 agent tasks per mode (the mock: 60 and 27).
- There are no encoded or translated copies of the attack inputs. Neither input firewall caught even the
  plain inputs, and B3 doesn't read the input to decide isolation, so they would change no result (see
  [docs/DESIGN.md](docs/DESIGN.md#decided-against)). The detector and egress do decode base64, hex, URL,
  reversed and split output.
- B2 with Prompt Guard 2 ran on the mock only. It flags none of the inputs, so on Qwen it would take exactly
  the path the keyword-filter B2 took. The model runs directly through transformers; the llamafirewall
  package, which wraps it, also pulls in scanners B2 doesn't use.
- B3 scoring 0% even with the egress canary check off shows the protection comes from the access layer.
  Egress still matters for the injection route: link stripping is what stops a tenant's own data from
  leaving through a URL.
- The LLM judge is the same small model that wrote the answers. In an earlier 15-question run it graded
  all 60 answers and agreed with the string match on every one, and it rejects the right number credited to
  the wrong company. On this CPU it needs about three minutes per answer, so the 51-question set is scored
  by string match, and every miss was read: wording in B1-B3, two empty answers in B0. A stronger judge would
  be a better check.
- Synthetic data only.

## Credits

All code here is written for this project; no files were copied. Design ideas came from:
[Sectum AI](https://github.com/sectum-ai/sectum-ai) (Apache-2.0: hard + secret canary types, MCP check classes,
"explicit deny, not empty success"), [AgentLeak](https://github.com/yagobski/agentleak) (MIT: output-channel model),
and, as ideas only because they carry no license, [tenantvault-zero-trust-rag](https://github.com/RitwijParmar/tenantvault-zero-trust-rag)
(fail-closed tenant function), [ai-tenant-leak-test](https://github.com/bluntlycoded/ai-tenant-leak-test)
("verify ingest first" precheck, check categories) and [multi-tenant-rag](https://github.com/Mehta-Amit-Codes/multi-tenant-rag)
(skeleton shape, and a live example of the superuser-bypasses-RLS trap). Details in [docs/DESIGN.md](docs/DESIGN.md#prior-work).
