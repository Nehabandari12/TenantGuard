"""TenantGuard: tenant-isolation enforcement for multi-tenant LLM apps.

Layers (each module is independently usable):
  identity   verified JWT -> Principal in a contextvar; nothing reads tenant from the body or the model
  db         Postgres transactions pinned to a tenant with set_config(..., true) under FORCE RLS
  cache      RedisVL SemanticCache that always stores and filters a tenant_id tag
  memory     agent memory namespaced tenant:user; unscoped calls raise
  mcp_auth   audience-bound, short-lived MCP tokens; tenant comes from the token only
  egress     outbound checks: foreign canaries (after decoding), secrets/PII, link allowlist
  tracing    per-request trace of every output channel (+ optional OpenTelemetry)
"""


class TenantContextError(RuntimeError):
    """Raised when tenant-scoped work is attempted without a verified tenant."""
