"""Postgres sessions pinned to one tenant.

Every unit of work is one explicit transaction that starts with
    SELECT set_config('app.tenant_id', <tenant>, true)
`true` makes the setting transaction-local, so it dies at COMMIT/ROLLBACK and a pooled
connection can never carry tenant A's context into tenant B's request. (SET LOCAL would
do the same but cannot take a bind parameter; plain SET would outlive the transaction.)

The tables use ENABLE + FORCE ROW LEVEL SECURITY with a fail-closed policy, and the app
connects as a non-owner, non-superuser role, so a forgotten WHERE clause cannot leak.
Compare: fastapi-rls (same SET LOCAL-in-transaction idea), tenantvault-zero-trust-rag.
"""

from collections.abc import Iterator
from contextlib import contextmanager

import psycopg
from psycopg_pool import ConnectionPool

from tenantguard.identity import Principal, require_principal


def scrub(conn: psycopg.Connection) -> None:
    """Pool reset hook: drop any session-level setting before a connection is reused."""
    conn.execute("RESET ALL")


@contextmanager
def tenant_transaction(pool: ConnectionPool, principal: Principal | None = None) -> Iterator[psycopg.Connection]:
    principal = principal or require_principal()
    with pool.connection() as conn:
        with conn.transaction():
            conn.execute("SELECT set_config('app.tenant_id', %s, true)", (principal.tenant_id,))
            # pgvector >= 0.8: keep scanning the HNSW graph until LIMIT rows survive the RLS
            # filter, instead of returning fewer than top-k when most neighbours are foreign.
            conn.execute("SET LOCAL hnsw.iterative_scan = relaxed_order")
            yield conn


RLS_TABLES = ("documents", "tickets", "notes", "app_logs")


def set_rls(owner_conn: psycopg.Connection, enabled: bool) -> None:
    """Toggle enforcement of the (always-defined) policies. Must run as the table owner."""
    for table in RLS_TABLES:
        if enabled:
            owner_conn.execute(f"ALTER TABLE tg.{table} ENABLE ROW LEVEL SECURITY")
            owner_conn.execute(f"ALTER TABLE tg.{table} FORCE ROW LEVEL SECURITY")
        else:
            owner_conn.execute(f"ALTER TABLE tg.{table} NO FORCE ROW LEVEL SECURITY")
            owner_conn.execute(f"ALTER TABLE tg.{table} DISABLE ROW LEVEL SECURITY")


def rls_status(conn: psycopg.Connection) -> dict[str, tuple[bool, bool]]:
    rows = conn.execute(
        "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class "
        "WHERE relnamespace = 'tg'::regnamespace AND relname = ANY(%s)",
        (list(RLS_TABLES),),
    ).fetchall()
    return {name: (enabled, forced) for name, enabled, forced in rows}


def assert_safe_role(conn: psycopg.Connection) -> None:
    """Refuse to run as a role that silently skips RLS (superuser or BYPASSRLS)."""
    superuser, bypass = conn.execute(
        "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"
    ).fetchone()
    if superuser or bypass:
        raise RuntimeError("app is connected as a role that bypasses row-level security")
