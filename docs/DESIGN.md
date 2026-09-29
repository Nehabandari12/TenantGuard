# Design notes

Why TenantGuard is built the way it is, what broke while building it, and where the ideas came from.
Setup and headline results are in the [README](../README.md).

## Threat model

Several companies (tenants) share one LLM app: one Postgres database, one Redis, one MCP tool server, one
model. A leak is any of tenant A's data reaching a user of tenant B, through any channel: the answer, the
retrieved context, a cache hit, a memory recall, a tool call or its result, a log line, a URL the answer
makes the client fetch, or a note written into B's records.

The attacker is an authenticated user of another tenant, or text planted in data the model reads (a
support ticket with instructions in it). The model is treated as untrusted. It can be talked into
anything, so no protection may depend on it behaving. That is why the default benchmark model is a mock
that follows every instruction it sees.

## Decisions

**One app, four modes.** `GUARD_MODE` becomes a `Guards` record in `app/config.py`, and every mode
difference reads from it. B0-B3 run the same code against the same checks. The runner restarts the app and
the MCP server for each mode.

**Two database roles.** `tg_owner` owns the tables. `tg_app` is a plain login: not the owner, not a
superuser, `NOBYPASSRLS`. Superusers and BYPASSRLS roles skip row-level security even with FORCE, and
FORCE only extends RLS to the owner, so connecting as anything else turns RLS off without any error. The
app checks its own role at startup and refuses to run if it could bypass RLS (`assert_safe_role`). The
Docker superuser only runs the init script.

**Policies always exist; B3 turns enforcement on.** `python -m tenantguard.admin rls on|off` flips
ENABLE + FORCE as the owner. B0-B2 stand in for apps without RLS, and the app role is the same in every mode.

**Fail closed.** `tg_current_tenant()` raises when `app.tenant_id` isn't set, so a query that forgot to
set the tenant errors instead of quietly returning zero rows. Unscoped cache and memory calls raise
`TenantContextError` the same way.

**Tenant context per transaction.** Each unit of work is one explicit transaction that starts with
`set_config('app.tenant_id', t, true)` and `SET LOCAL hnsw.iterative_scan = relaxed_order`. The `true`
makes the setting transaction-local, so a pooled connection can't carry one tenant's context into the next
request, and the pool's reset hook runs `RESET ALL` as a second line of defence. Iterative scan
(pgvector >= 0.8) keeps walking the HNSW graph until LIMIT rows survive the RLS filter. Without it,
filtered search returns fewer than top-k when most neighbours belong to other tenants.

**Identity from the token only.** The tenant comes from a verified JWT (HS256 pinned; `iss`, `aud`, `exp`
required), stored in a contextvar by a pure ASGI middleware. Request bodies, headers and model output never
set it. A mismatched `X-Tenant-ID` header gets a 403 instead of being ignored, so probing is visible.

**No token passthrough to MCP.** B1/B2 forward the login JWT and trust a `tenant_id` argument that the
model fills in. B3 mints a separate token signed with a different key: `aud` is the MCP server, `sub` is
`tenant:user`, the TTL is 60 s, and a new one is minted for every HTTP request. The audience is checked
twice (our verifier and the SDK's `validate_token_resource`). Tools have no tenant parameter at all. The
mcp 2.x SDK binds each session to the token subject, so a session ID replayed by another user is refused.
Cross-tenant lookups raise an explicit `ToolError` ("not found or not accessible") instead of returning
an empty success.

**Foreign keys bypass RLS.** A note could point at another tenant's ticket through the foreign key alone,
so B3's `create_note` looks the ticket up through RLS first.

**Egress knows the canaries, so B3 is also measured without that check.** Egress blocks foreign canaries
(after decoding), redacts secrets and PII, and strips links to unapproved domains. The canary check shares
knowledge with the detector, so the benchmark also runs B3 with it off (`TG_EGRESS_CANARY=0`). B3 stays at
0% that way, which shows the isolation comes from the access layer. Link stripping still matters: it stops
a tenant's *own* data from leaving through an injected image URL.

**Worst-case mock model.** `MockLLM` repeats its context, fills tool arguments with whatever the user or a
document names, and follows `AI ASSISTANT INSTRUCTION:` lines in tool results. It is deterministic, runs
the whole suite in about a minute, and is an upper bound on model misbehaviour.

**Embeddings.** `BAAI/bge-small-en-v1.5` through fastembed (ONNX, no torch), with a deterministic hashing
embedder as the fallback. The seed records which embedder built the corpus, and the app refuses to start
with a different one. Mixed embedders make retrieval meaningless without raising any error.

**Memory.** A small Redis store with a mem0-shaped API instead of mem0 itself, which needs its own LLM and
vector-store config. The per-mode bugs are realistic: B0 searches everyone's memory, and B1/B2 key it by
username, which collides across companies (every tenant has an `alice`).

## What counts as a leak

Ground truth is `tg.canary_registry`, which only the owner role can read, so the detector never relies on
what the app or egress believe. The seed plants two kinds of canary: hard tokens (`GLBX-4A1F0C`) and
secret-shaped ones (AKIA key IDs, SSNs in the never-issued 9xx range).

Every channel in the request trace is matched after decoding (standard and URL-safe base64, hex,
URL-encoding, ROT13, reversal) and after removing separators, so `G L B X - 4 A 1 F 0 C` still matches.
The detector and egress share `tenantguard/decode.py`.

Each mode gets two scores. **Answers-only** looks at the final response, **all-channels** at everything.
The gap is what an output-only audit misses. On the mock model, injection in B0 is 50% answers-only and
100% all-channels.

Canaries alone undercount leaks from a real model, because it paraphrases. Two more rules cover that:

- A cache or memory read that replays text another tenant's session produced during the case setup is a
  leak, and so is an answer that repeats it.
- A log-viewer response that returns rows tagged with another tenant is a leak.

Neither rule can fire on a correctly scoped store, because those channels only ever hold the session's own
entries.

The runner won't score a mode until every tenant has retrieved its own canary (`precheck`). Otherwise a
broken ingest would produce a 0% that looks like perfect isolation.

## Bugs found along the way

| Bug | How it showed up | Fix |
|---|---|---|
| The mock agent looped forever on `create_note`: its arguments grew each round, so dedupe never matched | Reading the code before the first run | Dedupe on tool name + target |
| MCP 2.x reports a plain `ValueError` as a generic "Error executing tool" | B3 smoke test | Raise the SDK's `ToolError` with an explicit message |
| `tools-04` passed in B0 only because a required argument was missing | Reading B0 results | The case passes the caller's own tenant, so it really tests the lookup |
| A base64-encoded canary slipped past the detector and egress. An 11-char canary encodes to 15 chars + `=`, and the decoder only tried runs of 16+ | Unit test | Minimum token length lowered to 12, all modes re-run |
| Direct MCP denials surfaced as an opaque `ExceptionGroup` | Reading B3 results | Unwrap to the innermost error |
| With a slow local model, B3's 60 s MCP token expired partway through a tool loop. The later calls failed, which would have *looked* like protection | First Qwen run | Mint a fresh token per HTTP request instead of stretching the TTL |
| Qwen3 4B always reasons. With `think:false` the reasoning lands in the answer text, where the detector scores it | First Qwen request | `think:true` (reasoning goes to a separate field and is dropped), plus stripping any leaked `<think>` text |
| The precheck required the canary in the answer text, which only the mock repeats | Qwen run stopped at "globex cannot retrieve its own documents" | The precheck reads the retrieval channel |
| B0 cache checks scored "ok" although Initech was served Acme's cached answer, because the paraphrased answer had no canary | Interrupted Qwen run | Provenance rule (above) |
| Login tokens (1 h) expired during a B0 run of over an hour. Setup requests got 401 and wrote no logs, so three log checks scored "no leak" | B0 logs at 0% on Qwen vs 100% on the mock | Tokens are refreshed after 30 min, and a setup step that doesn't return 200 raises `SetupFailed` instead of being scored |
| The log viewer returned other tenants' rows with no canary in them | B0 logs after the token fix | Rows tagged with another tenant count as a leak |
| Long runs died with the terminal session, and a reboot also stopped Docker | First Qwen run, 9 checks into B0 | Runs save after every check and take `--resume`. `attacks/bench.py` runs every step, skips finished ones and logs to a file, so it can run detached |
| One B3 agent request ran past the harness's 30-minute timeout (unbounded reasoning, up to 6 model calls), and the run crashed | B3 `injection-02` on Qwen | `OLLAMA_NUM_PREDICT=2048` caps each call; calls under the cap are unchanged at temperature 0 with a fixed seed. The step timeout is now derived from rounds × LLM timeout, so it outlasts anything the app can take. A scored step that times out or returns 5xx is recorded as an *error*, shown in the summary and table, and retried on resume. It is never scored as a pass |

The expired-token bug is the instructive one: a harness failure that produced exactly the number you want
to see. Setup failures now stop the run.

## Running a real model

Local Qwen3 4B through Ollama, temperature 0, fixed seed, 1 repeat per check. On CPU (about 14 tokens/s,
with roughly 300 reasoning tokens per call) `/ask` takes about a minute and a one-tool `/agent` call a bit
more, so the full benchmark takes hours. The Qwen utility eval therefore uses 15 questions per mode instead
of 60. Paid APIs stay off unless `TG_ALLOW_PAID_LLM=1`, and there is no fallback between providers.

Something only the real model showed: in B0, Qwen's answer used only Initech's document, but the
response's source list still named Globex's and Acme's documents. An answers-only audit would call that clean.

## Prior work

No code was copied from any of these. The permissively licensed ones would have allowed it with
attribution, but it wasn't needed. From the unlicensed ones only the ideas were taken.

| Project | License | What it contributed |
|---|---|---|
| [sectum-ai/sectum-ai](https://github.com/sectum-ai/sectum-ai) | Apache-2.0 | Hard vs secret canaries. MCP check classes (confused deputy, token passthrough, cross-server, tool-description injection). Cross-tenant fetches must be an explicit deny, not an empty success |
| [yagobski/agentleak](https://github.com/yagobski/agentleak) | MIT | The output-channel model (final output, tool call, tool response, memory, log), extended here with retrieval and cache channels |
| [RitwijParmar/tenantvault-zero-trust-rag](https://github.com/RitwijParmar/tenantvault-zero-trust-rag) | none | Fail-closed tenant function, FORCE RLS, non-owner API role |
| [bluntlycoded/ai-tenant-leak-test](https://github.com/bluntlycoded/ai-tenant-leak-test) | none | Verify ingest before trusting a clean run; check categories |
| [Mehta-Amit-Codes/multi-tenant-rag](https://github.com/Mehta-Amit-Codes/multi-tenant-rag) | none | Skeleton shape. Also a live example of the main trap: it connects as the Docker superuser, so its RLS never applies |
| [modelcontextprotocol/python-sdk](https://github.com/modelcontextprotocol/python-sdk) | MIT | Dependency (mcp 2.2): `TokenVerifier`, `validate_token_resource`, per-session owner binding |
| [redis/redis-vl-python](https://github.com/redis/redis-vl-python) | MIT | Dependency (redisvl 0.27): `SemanticCache` with a `tenant_id` tag filter |

## Not done yet

- 23 checks (3-5 per route). The target is about 13 per route, and the case format and runner already
  support more.
- Input-side variants (base64, split and translated copies of each attack). Output-side decoding exists
  and is tested.
- B2 ran on the keyword heuristic, because LlamaFirewall needs gated access to Llama Prompt Guard 2.
- Answer quality is a string match on the expected fact, not an LLM judge.
- Qwen runs with `--repeats 3` to measure run-to-run variation.
- An RLS policy check in CI (for example rlsgrid).
- A reviewer agent that approves each tool call.
