"""The RLS audit against a real, seeded database. Opt-in with TG_DB_TESTS=1 (CI sets it).

They are opt-in because the fixture switches RLS enforcement on, which would change a benchmark
running against the same database. Each broken configuration is created inside a transaction
on the owner connection, audited through that same connection, and rolled back.
"""

import os
from contextlib import contextmanager

import psycopg
import pytest

from app import config
from tenantguard.db import rls_status, set_rls
from tenantguard.rls_audit import audit, catalog_checks

pytestmark = pytest.mark.skipif(os.environ.get("TG_DB_TESTS") != "1",
                                reason="database tests are opt-in: TG_DB_TESTS=1 (they switch RLS enforcement)")


@pytest.fixture(scope="module")
def conns():
    owner = psycopg.connect(config.OWNER_DATABASE_URL, autocommit=True)
    app = psycopg.connect(config.DATABASE_URL, autocommit=True)
    before = rls_status(owner)
    set_rls(owner, True)
    yield owner, app
    for table, (enabled, forced) in before.items():
        owner.execute(f"ALTER TABLE tg.{table} {'ENABLE' if enabled else 'DISABLE'} ROW LEVEL SECURITY")
        owner.execute(f"ALTER TABLE tg.{table} {'FORCE' if forced else 'NO FORCE'} ROW LEVEL SECURITY")
    owner.close()
    app.close()


def failures(checks) -> set[str]:
    return {c.name for c in checks if not c.ok}


@contextmanager
def broken(owner, *statements):
    """Apply `statements` as the owner, yield the catalog checks that see them, then roll back."""
    with owner.transaction():
        for sql in statements:
            owner.execute(sql)
        yield failures(catalog_checks(owner, "tg_app"))
        raise psycopg.Rollback()


def test_seeded_database_passes(conns):
    owner, app = conns
    assert failures(audit(owner, app)) == set()


def test_extra_permissive_policy_is_flagged(conns):
    with broken(conns[0], "CREATE POLICY open_read ON tg.documents FOR SELECT USING (true)") as failed:
        assert failed == {"documents: every permissive policy is the tenant fence"}


def test_fence_widened_with_or_is_flagged(conns):
    with broken(conns[0], "ALTER POLICY tenant_fence ON tg.tickets USING (tenant_id = tg_current_tenant() OR status = 'open')") as failed:
        assert failed == {"tickets: every permissive policy is the tenant fence"}


def test_rls_not_forced_is_flagged(conns):
    with broken(conns[0], "ALTER TABLE tg.notes NO FORCE ROW LEVEL SECURITY") as failed:
        assert failed == {"notes: RLS enabled and forced"}


def test_view_running_as_owner_is_flagged(conns):
    with broken(conns[0], "CREATE VIEW tg.all_tickets AS SELECT * FROM tg.tickets",
                "GRANT SELECT ON tg.all_tickets TO tg_app") as failed:
        assert failed == {"no view readable by tg_app runs with its owner's rights"}
    with broken(conns[0], "CREATE VIEW tg.all_tickets WITH (security_invoker = true) AS SELECT * FROM tg.tickets",
                "GRANT SELECT ON tg.all_tickets TO tg_app") as failed:
        assert failed == set()


def test_security_definer_function_is_flagged(conns):
    fn = ("CREATE FUNCTION tg.ticket_count() RETURNS bigint LANGUAGE sql SECURITY DEFINER "
          "AS 'SELECT count(*) FROM tg.tickets'")
    with broken(conns[0], fn, "GRANT EXECUTE ON FUNCTION tg.ticket_count() TO tg_app") as failed:
        assert failed == {"no SECURITY DEFINER function is executable by tg_app"}


def test_registry_grant_is_flagged(conns):
    with broken(conns[0], "GRANT SELECT ON tg.canary_registry TO tg_app") as failed:
        # Once readable it is also an unfenced tenant table, so it fails those checks too.
        assert failed == {"canary_registry: tg_app has no privilege on it", "canary_registry: RLS enabled and forced",
                          "canary_registry: every permissive policy is the tenant fence"}


def test_live_checks_see_the_leak_when_enforcement_is_off(conns):
    owner, app = conns
    set_rls(owner, False)
    try:
        failed = failures(audit(owner, app))
    finally:
        set_rls(owner, True)
    assert "documents as acme: no other tenant's rows" in failed
    assert "tickets: reading with no tenant set raises" in failed
    assert "notes: acme cannot write a row for globex" in failed
