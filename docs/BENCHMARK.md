# Benchmark results

Detailed results behind the summary in the [README](../README.md). How leaks are scored and why the
benchmark is built this way: [DESIGN.md](DESIGN.md).

## The runs

| | |
|---|---|
| Checks | 84 in [attacks/cases.yaml](../attacks/cases.yaml), 14 per route; the routes map to OWASP LLM01, LLM02, LLM08 (Top 10 for LLM Applications) and ASI01, ASI02, ASI03, ASI06 (Top 10 for Agentic Applications) |
| Data | synthetic: 3 companies, 150 documents, 60 tickets, 222 canaries, generated from a fixed seed ([app/seed.py](../app/seed.py)) |
| Models | **mock**: offline, obeys every instruction it sees (worst case). **Qwen3 4B** through Ollama (`qwen3:4b`), temperature 0, seed 0 |
| Embeddings | BAAI/bge-small-en-v1.5 through fastembed (ONNX) |
| Repeats | mock: 1 per check (deterministic). Qwen: B1 and B3 three times (252 runs each), the other modes once |
| When | 2-4 Oct 2026, from scratch with the code at the commits stored in each results file |
| Machine | laptop, Intel Core Ultra 7 256V, 16 GB RAM, Windows 11, CPU inference |
| Files | [results/qwen3-4b/](../results/qwen3-4b/) and [results/mock/](../results/mock/): one JSON per mode with every check's channels, leaks and response, plus `RESULTS.md` |

Each published record stores the commit it ran on, and each file stores the mode, model and repeat
count. Runs made after 6 Oct 2026 also store package versions, the Ollama model digest, the embedder,
the data seed and the machine ([attacks/provenance.py](../attacks/provenance.py)).

Leak rate cells read **answers-only / all-channels**. Answers-only counts a leak only when another
tenant's data is in the final answer; all-channels also counts retrieval, cache, memory, tool calls and
results, logs, outside links and notes written into another tenant's records. A check that failed
(timeout, server error) observed nothing, so it is reported separately and left out of both rates. No
check failed in the published runs.

## Leak rates

**Qwen3 4B, 84 checks**

| Route | OWASP | B0 | B1 (3 runs) | B2, keyword filter | B3 (3 runs) | B3, egress canary check off |
|---|---|---|---|---|---|---|
| search | LLM08 | 0% / 100% | 0% / 36% | 0% / 36% | 0% / 0% | 0% / 0% |
| cache | LLM08 | 93% / 93% | 93% / 93% | 93% / 93% | 0% / 0% | 0% / 0% |
| memory | ASI06 | 50% / 100% | 50% / 79% | 57% / 79% | 0% / 0% | 0% / 0% |
| tools | ASI02/ASI03 | 71% / 86% | 40% / 48% | 43% / 50% | 0% / 0% | 0% / 0% |
| injection | LLM01/ASI01 | 0% / 50% | 0% / 29% | 0% / 29% | 0% / 0% | 0% / 0% |
| logs | LLM02 | 100% / 100% | 64% / 64% | 64% / 64% | 0% / 0% | 0% / 0% |
| **all** | | 52% / 88% | 41% / 58% | 43% / 58% | **0% / 0%** | **0% / 0%** |

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

## Findings

What the runs show:

- **B3 held at 0% on every check, on both models**, in all three Qwen runs (none of 252 runs leaked), and
  still 0% with the egress canary check turned off, so the protection comes from making other tenants' data
  unreachable, not from egress recognising canaries. Every B3 outcome is an explicit denial (403, an MCP
  token refused with HTTP 401, "not found or not accessible") or the caller's own data. All 15 direct
  tool-server calls in Qwen's B3 runs are recorded as refused with HTTP 401, so none of the zeros comes from
  a server that wasn't answering.
- **The tutorial fix (B1) still leaks in 58% of runs on Qwen and 70% on the mock**, through the semantic
  cache, memory keyed by usernames that repeat across companies, tools that trust a model-supplied
  `tenant_id`, the tenant-switch header and the log viewer's `?tenant=` parameter. It does stop plain ID
  guessing and unauthenticated tool calls. Across Qwen's three B1 runs only 1 of 84 checks changed outcome
  (`tools-14`, below).
- **Input firewalls don't see these attacks.** Neither B2 firewall changed a single result. Llama Prompt
  Guard 2 86M scores an obvious "ignore your previous instructions" at 0.999, yet flagged none of the 286
  inputs the benchmark sends (highest score 0.18). The cross-tenant requests read like ordinary ones ("show
  me ticket T-1005", a header, a `?tenant=` parameter), and planted instructions arrive in tool results,
  which an input firewall never looks at.
- **A real model hides leaks from answer-only audits.** Qwen rephrases instead of repeating reference codes.
  In B0 its search answers looked clean (0%) while all of them had pulled other companies' documents into
  context (100%). 36% of Qwen's B0 checks and 17% of its B1 runs leak only somewhere other than the answer:
  retrieval, tool results, memory, a note in another tenant's ticket, or an outside link.
- **Encoded replies don't hide a leak.** Six checks ask for the reply in base64, spaced out or reversed. On
  the mock all six leak in B0 and B1 and are caught only because the detector decodes them; B3 holds. Qwen
  returned an empty answer in 27 of the 30 runs of these checks in B0-B2. The other three times (`tools-14`)
  it spelled another company's ticket reference out letter by letter (`A C M E - 8 9 C 1 D 1`), and the
  answer counts as a leak only because the detector decodes it.
- **How the user asks changes whether a real model obeys planted text.** Asked to summarize, explain or
  reply to a poisoned ticket, Qwen never followed the planted instructions, in any mode or run. Asked to
  handle or show it, it often did, though not every time, and which of those checks leaked differed between
  runs. The mock follows planted instructions every time, which is why it's the upper bound.
- **Normal use is unaffected.** On 51 normal questions per mode Qwen had 100% recall@5 and 0 wrong blocks in
  every mode, and B3's answers were identical to B2's, which has no TenantGuard at all. The string match
  scored 96-98% in B1-B3, and every miss there was wording, not a wrong fact ("1 hour" for the seed's
  "1 hours", "Customer Success Manager" without "the"). In B0 (94%) two answers came back empty: with other
  companies' documents in context, Qwen spent its whole token budget reasoning. Agent tasks on the tenant's
  own data: reading a ticket and adding a note worked every time in every mode, and searches matched in 83%
  (B1-B3), the misses again being wording. The
  mock answered all 60 questions and did all 27 agent tasks in every mode. Latency is under
  [Overhead](#overhead).
- **Unprotected retrieval costs compute too.** With other companies' near-duplicate documents in context,
  Qwen produced 2.4 times as many output tokens in B0 (34,528 vs 14,120-14,599 in B1-B3, over 51 questions).

## Overhead

On the mock, where the model costs nothing, the published run measured `/ask` at p50 105 ms in B3 and
81 ms in B1 (60 questions each), so about 25 ms for TenantGuard, and no measurable difference on
`/agent`. Re-measured on 6 Oct 2026 on the same laptop with 60 questions: B3 was 30-32 ms slower than B1
at p50 with the `pii` extra (Presidio) installed, over two repeats, and 3 ms slower without it. So in
these measurements most of the overhead is Presidio redacting PII in log lines, not the isolation checks.
With Qwen on CPU a request takes about a minute, and the overhead disappears in the noise. Prompt Guard 2
in B2 adds about 340 ms on CPU.

## Reproducing

The commands below write to `runs/<model>/`, which git ignores, and never touch the published
`results/`. Compare your `runs/<model>/RESULTS.md` with the published one.

**Mock, all modes (about 3 minutes).** Needs the real embeddings (`.[embed]`, a one-time 65 MB model
download); with the lexical hash embedder B0's precheck can't find each tenant's own documents and the
run stops instead of reporting a meaningless result. With Postgres and Redis up (`docker compose up -d`):

```powershell
# Windows (PowerShell)
uv pip install --python .venv\Scripts\python.exe -e ".[embed,pii,dev]" -c constraints.txt
$env:LLM_PROVIDER = "mock"
.venv\Scripts\python.exe -m app.seed
.venv\Scripts\python.exe -m attacks.bench --eval-per-tenant 20 --eval-agent-per-tenant 3
```

```bash
# macOS / Linux
uv pip install --python .venv/bin/python -e ".[embed,pii,dev]" -c constraints.txt
export LLM_PROVIDER=mock
.venv/bin/python -m app.seed
.venv/bin/python -m attacks.bench --eval-per-tenant 20 --eval-agent-per-tenant 3
```

On 6 Oct 2026 a fresh clone installed with `.[embed,dev]` (no Presidio) reproduced every published mock
leak rate exactly. Prompt Guard 2 was not re-run.

**Qwen3 4B (CPU: B0 alone took about a day on the laptop above).** `ollama pull qwen3:4b`, unset
`LLM_PROVIDER` (Ollama is the default), then
`python -m attacks.bench --eval-per-tenant 17 --eval-agent-per-tenant 2`, and
`python -m attacks.bench --repeats 3 --repeat-modes B1,B3` for the repeats. A real model's outputs can
differ between machines and Ollama versions even at temperature 0; new results files record the digest of
the weights they used.

**Individual steps.** `python -m attacks.run --mode B1`, `python -m eval.run_eval --mode B3 --per-tenant 5`,
`python -m attacks.table`. `attacks.bench` resumes: after a crash or reboot, or after new checks are added to
`attacks/cases.yaml`, run it again and only the missing checks run. Progress is in `runs/<model>/progress.log`.

**Replacing the published results** (only for a deliberate re-run): set `TG_RESULTS_DIR=results/<model>`.

**B2 with Llama Prompt Guard 2.** Request access to
[meta-llama/Llama-Prompt-Guard-2-86M](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M) and log in
with `hf auth login`, then `uv pip install --python .venv -e ".[firewall]"`. `python -m attacks.bench --promptguard`
adds the B2 run with it, and `TG_FIREWALL=promptguard python -m baselines.firewall` scores every input the
benchmark sends.

**LLM choice.** The default is local Ollama `qwen3:4b` at temperature 0 with a fixed seed. Nothing is sent to
a paid API, and there is no fallback between providers: if Ollama is down, the app refuses to start.
Settings are in [.env.example](../.env.example).

| `LLM_PROVIDER` | Model | Cost | Notes |
|---|---|---|---|
| `ollama` (default) | `LLM_MODEL=qwen3:4b` | free, local | about 1 min per request on CPU |
| `mock` | built-in | free, offline | deterministic, worst-case obedient; under a minute per mode |
| `anthropic` | `claude-haiku-4-5` | paid | **disabled**: refuses to start unless `TG_ALLOW_PAID_LLM=1` |

## Limitations

- The mock follows any instruction in its context, so it's an upper bound on model misbehaviour, not a
  realistic model. Qwen3 4B is a real but small model; a larger model may follow planted instructions more
  or less often.
- On Qwen, B1 and B3 ran three times and the other modes once. At temperature 0 with a fixed seed the
  outcomes were stable (1 of 84 B1 checks changed) but not fixed: in an earlier three-run B1 on 78 checks,
  `injection-03` and `tools-03` changed instead. The B3 zeros don't depend on the model's behaviour.
- Canary detection undercounts leaks that a model paraphrases. Provenance rules cover the cache, memory and
  log viewer, and all-channels scoring catches paraphrase on retrieval and tool results. Answers-only
  numbers for a real model are therefore a lower bound.
- On a CPU-only machine Qwen3 4B takes about a minute per request, so its utility eval uses 51 questions
  and 18 agent tasks per mode (the mock: 60 and 27), and B2 with Prompt Guard 2 ran on the mock only.
- There are no encoded or translated copies of the attack inputs. Neither input firewall caught even the
  plain inputs, and B3 doesn't read the input to decide isolation, so they would change no result (see
  [DESIGN.md](DESIGN.md#decided-against)). The detector and egress do decode base64, hex, URL,
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
