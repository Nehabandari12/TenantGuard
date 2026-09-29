"""Application logs and the support-staff log viewer.

B0: every log line stored verbatim; /support/logs returns all tenants unless ?tenant= is given.
B1/B2: viewer defaults to the caller's tenant but honours ?tenant= ("support can switch tenant").
B3: lines are tenant-tagged under FORCE RLS and redacted by egress before they are written;
    the viewer can only ever see the caller's tenant, and asking for another is a 403.
"""

from fastapi import HTTPException

from app import config, db
from app.config import Mode
from tenantguard import tracing
from tenantguard.identity import Principal


def write(principal: Principal, route: str, message: str, egress=None) -> None:
    if config.GUARDS.egress and egress is not None:
        message = egress.redact_for_log(message, principal)
    with db.session(principal) as conn:
        conn.execute("INSERT INTO tg.app_logs (tenant_id, username, route, message) VALUES (%s, %s, %s, %s)",
                     (principal.tenant_id, principal.username, route, message))
    tracing.record("log", message, route=route)


def read(principal: Principal, tenant: str | None, limit: int) -> list[dict]:
    if principal.role != "support":
        raise HTTPException(403, "support role required")
    limit = max(1, min(limit, 200))
    if config.GUARDS.tenantguard:
        if tenant and tenant != principal.tenant_id:
            raise HTTPException(403, "tenant mismatch")
        tenant = principal.tenant_id
    elif config.MODE is not Mode.B0:
        tenant = tenant or principal.tenant_id
    with db.session(principal) as conn:
        rows = conn.execute(
            "SELECT id, tenant_id, username, route, message FROM tg.app_logs "
            "WHERE (%(t)s::text IS NULL OR tenant_id = %(t)s) ORDER BY id DESC LIMIT %(n)s",
            {"t": tenant, "n": limit},
        ).fetchall()
    return [{"id": r[0], "tenant_id": r[1], "username": r[2], "route": r[3], "message": r[4]} for r in rows]
