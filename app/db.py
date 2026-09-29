"""Connection pool for the app and the MCP server. Always the plain tg_app role.

`session(principal)` is the single entry point for SQL: in B3 it is a TenantGuard
tenant transaction (set_config + FORCE RLS); in B0-B2 it is a plain transaction and
isolation is whatever the query's WHERE clause does.
"""

from collections.abc import Iterator
from contextlib import contextmanager

import psycopg
from psycopg_pool import ConnectionPool

from app import config
from tenantguard.db import assert_safe_role, scrub, tenant_transaction
from tenantguard.identity import Principal

pool = ConnectionPool(config.DATABASE_URL, min_size=1, max_size=10, kwargs={"autocommit": True}, reset=scrub, open=False)


def open_pool() -> None:
    pool.open(wait=True)
    with pool.connection() as conn:
        assert_safe_role(conn)


@contextmanager
def session(principal: Principal) -> Iterator[psycopg.Connection]:
    if config.GUARDS.tenantguard:
        with tenant_transaction(pool, principal) as conn:
            yield conn
    else:
        with pool.connection() as conn, conn.transaction():
            yield conn


def tenant_codes() -> dict[str, str]:
    with pool.connection() as conn:
        return dict(conn.execute("SELECT tenant_id, code FROM tg.tenants").fetchall())
