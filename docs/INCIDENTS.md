# Public incidents behind the checks

Several of TenantGuard's attack routes mirror failures that happened, or were demonstrated, in public.
Each one below matches a route the checks cover. They are here for the pattern; nothing below claims
TenantGuard would have stopped any of them as those systems were built.

| When | What happened | Route here |
|---|---|---|
| Mar 2023 | **ChatGPT.** A bug in the Redis client library (redis-py) let some users see titles from other users' chat histories. For 1.2% of Plus subscribers active during a nine-hour window, another user could see their name, email, payment address and the last four digits of their card. ([BleepingComputer](https://www.bleepingcomputer.com/news/security/openai-chatgpt-payment-data-leak-caused-by-open-source-bug/), [Help Net Security](https://www.helpnetsecurity.com/2023/03/27/chatgpt-data-leak/)) | cache: a shared store hands one user's entry to another |
| Aug 2024 | **Slack AI.** PromptArmor showed that a message posted in a public channel could make Slack AI pull data from a private channel the attacker wasn't in and render it inside a link for the victim to click. Slack first called it intended behaviour. ([PromptArmor](https://promptarmor.com/resources/data-exfiltration-from-slack-ai-via-indirect-prompt-injection)) | injection, with data leaving through a link |
| May-Jun 2025 | **Asana MCP server.** A logic flaw in the MCP server Asana launched on May 1 let users of one organization see some data from other organizations. Asana found it on June 4 and took the server offline until June 17. ([BleepingComputer](https://bleepingcomputer.com/news/security/asana-warns-mcp-ai-feature-exposed-customer-data-to-other-orgs/)) | tools: an MCP server crossing tenants |
| Jun 2025 | **EchoLeak, Microsoft 365 Copilot** (CVE-2025-32711). Aim Security showed that a crafted email, once Copilot retrieved it, could make Copilot pull data from the user's context and send it out through URLs, with no click needed. Microsoft fixed it; there is no evidence it was exploited. ([The Hacker News](https://thehackernews.com/2025/06/zero-click-ai-vulnerability-exposes.html)) | injection, with data leaving through a URL |
| Jul 2025 | **Supabase MCP** (demonstrated on a test setup). General Analysis filed a support ticket containing instructions. A developer's coding agent, connected through MCP with the `service_role` key, which bypasses row-level security, read a private tokens table and wrote it back into the ticket thread. ([General Analysis](https://www.generalanalysis.com/blog/supabase-mcp-blog)) | injection through a support ticket, plus a role that skips RLS |

The checks themselves are in [attacks/cases.yaml](../attacks/cases.yaml); how each route is scored is in
[DESIGN.md](DESIGN.md#what-counts-as-a-leak).
