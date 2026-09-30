"""Audit that Postgres row-level security really keeps tenants apart.

    python -m tenantguard.rls_audit        # prints every check, exits 1 if any fails

Run it with enforcement on (`python -m tenantguard.admin rls on`, the B3 state). CI builds a fresh
database from sql/, seeds it, turns enforcement on and runs this on every push.

Catalog checks, as the table owner:
  * the app role is not a superuser, has no BYPASSRLS, and owns no table (directly or through a role
    it is a member of). Any of those makes Postgres skip RLS without an error.
  * every table the app role can read that has a tenant_id column has RLS enabled and forced,
    unless it is listed in UNSCOPED with the reason.
  * every permissive policy on those tables is exactly the tenant fence, in USING and WITH CHECK.
    Permissive policies are OR-ed, so one extra `USING (true)` opens the whole table.
  * the app role has no privilege on the owner-only tables (the canary registry).
  * no view the app role can read runs with its owner's rights (a view bypasses RLS unless it has
    security_invoker), and no SECURITY DEFINER function is executable by the app role.
Live checks, as the app role:
  * with no tenant set, reading or writing a scoped table raises instead of returning zero rows.
  * with a tenant set, no scoped table returns another tenant's rows, and the tenant's own rows
    are visible (a policy that hides everything would otherwise pass).
  * an insert for another tenant is refused and the same insert for its own tenant is accepted
    (both rolled back).
  * the tenant setting does not outlive its transaction.
"""

import re
import sys
from dataclasses import dataclass

import psycopg

from app import config

SCHEMA = "tg"
# Tables with a tenant_id column that the app role reads without RLS, on purpose.
UNSCOPED = {
    "tenants": "the tenant directory (ids, names, canary prefixes); the app shows every tenant's name",
    "app_users": "/login looks the user up before any tenant is known",
}
OWNER_ONLY = ("canary_registry",)
# The only policy expression the audit accepts. Anything else needs a human to look at it.
FENCE = re.compile(r"^\(*tenant_id\s*=\s*(tg\.)?tg_current_tenant\(\)\)*$")
# Inserts for the write checks. A writable scoped table without one fails the audit, so a new
# table can't skip the check unnoticed. %(tenant)s is the row's tenant, %(ticket)s one of its tickets.
WRITE_PROBES = {
    "notes": "INSERT INTO tg.notes (tenant_id, ticket_id, author, body) VALUES (%(tenant)s, %(ticket)s, 'rls-audit', 'probe')",
    "app_logs": "INSERT INTO tg.app_logs (tenant_id, username, route, message) VALUES (%(tenant)s, 'rls-audit', '/rls-audit', 'probe')",
}
_SYSTEM_SCHEMAS = ("pg_catalog", "information_schema", "pg_toast")


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""


# ---------------------------------------------------------------- catalog

def scoped_tables(owner: psycopg.Connection, app_role: str) -> list[str]:
    rows = owner.execute(
        "SELECT c.relname FROM pg_class c JOIN pg_attribute a ON a.attrelid = c.oid "
        "WHERE c.relnamespace = %s::regnamespace AND c.relkind IN ('r', 'p') "
        "AND a.attname = 'tenant_id' AND NOT a.attisdropped "
        "AND has_table_privilege(%s::name, c.oid, 'SELECT') ORDER BY c.relname",
        (SCHEMA, app_role)).fetchall()
    return [r[0] for r in rows if r[0] not in UNSCOPED]


def _fenced(expr: str | None) -> bool:
    return expr is not None and bool(FENCE.match(re.sub(r"\s+", " ", expr).strip()))


def catalog_checks(owner: psycopg.Connection, app_role: str) -> list[Check]:
    checks = []
    superuser, bypass = owner.execute(
        "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = %s", (app_role,)).fetchone()
    checks.append(Check(f"{app_role} is not a superuser and has no BYPASSRLS", not superuser and not bypass,
                        f"rolsuper={superuser}, rolbypassrls={bypass}"))
    owned = [r[0] for r in owner.execute(
        "SELECT c.relname FROM pg_class c WHERE c.relnamespace = %s::regnamespace AND c.relkind IN ('r', 'p', 'v', 'm') "
        "AND pg_has_role(%s::name, c.relowner, 'MEMBER') ORDER BY 1", (SCHEMA, app_role)).fetchall()]
    checks.append(Check(f"{app_role} owns no table, directly or through role membership", not owned,
                        "owns " + ", ".join(owned)))

    tables = scoped_tables(owner, app_role)
    status = dict((r[0], (r[1], r[2])) for r in owner.execute(
        "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class "
        "WHERE relnamespace = %s::regnamespace AND relname = ANY(%s)", (SCHEMA, tables)).fetchall())
    policies = owner.execute(
        "SELECT tablename, policyname, cmd, qual, with_check FROM pg_policies "
        "WHERE schemaname = %s AND permissive = 'PERMISSIVE' AND (roles && ARRAY['public', %s]::name[])",
        (SCHEMA, app_role)).fetchall()
    for table in tables:
        enabled, forced = status[table]
        checks.append(Check(f"{table}: RLS enabled and forced", enabled and forced, f"enabled={enabled}, forced={forced}"))
        mine = [p for p in policies if p[0] == table]
        bad = []
        for _table, name, cmd, qual, with_check in mine:
            # With no WITH CHECK, Postgres checks new rows against USING instead.
            reads_ok = cmd == "INSERT" or _fenced(qual)
            writes_ok = cmd in ("SELECT", "DELETE") or _fenced(with_check if with_check is not None else qual)
            if not (reads_ok and writes_ok):
                bad.append(f"{name} ({cmd}): USING {qual}, WITH CHECK {with_check}")
        checks.append(Check(f"{table}: every permissive policy is the tenant fence", bool(mine) and not bad,
                            "; ".join(bad) or "no policy"))
    for table in OWNER_ONLY:
        granted = owner.execute(
            "SELECT has_table_privilege(%s::name, %s::regclass, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')",
            (app_role, f"{SCHEMA}.{table}")).fetchone()[0]
        checks.append(Check(f"{table}: {app_role} has no privilege on it", not granted))

    views = []
    for schema, name, kind, options in owner.execute(
            "SELECT n.nspname, c.relname, c.relkind, c.reloptions FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE c.relkind IN ('v', 'm') AND n.nspname <> ALL(%s) AND has_table_privilege(%s::name, c.oid, 'SELECT')",
            (list(_SYSTEM_SCHEMAS), app_role)).fetchall():
        invoker = any(o.lower() in ("security_invoker=true", "security_invoker=on", "security_invoker=1") for o in options or [])
        if kind == "m" or not invoker:
            views.append(f"{schema}.{name}")
    checks.append(Check(f"no view readable by {app_role} runs with its owner's rights", not views, ", ".join(views)))
    definers = [f"{r[0]}.{r[1]}" for r in owner.execute(
        "SELECT n.nspname, p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
        "WHERE p.prosecdef AND n.nspname <> ALL(%s) AND has_function_privilege(%s::name, p.oid, 'EXECUTE') "
        "AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e')",
        (list(_SYSTEM_SCHEMAS), app_role)).fetchall()]
    checks.append(Check(f"no SECURITY DEFINER function is executable by {app_role}", not definers, ", ".join(definers)))
    return checks


# ---------------------------------------------------------------- live

def _attempt(conn: psycopg.Connection, sql: str, params=None, tenant: str | None = None) -> tuple[list | None, Exception | None]:
    """Run one statement in its own transaction and always roll it back. Returns (rows, error)."""
    rows = None
    try:
        with conn.transaction():
            if tenant is not None:
                conn.execute("SELECT set_config('app.tenant_id', %s, true)", (tenant,))
            cur = conn.execute(sql, params)
            rows = cur.fetchall() if cur.description else []
            raise psycopg.Rollback()
    except psycopg.Error as exc:
        return None, exc
    return rows, None


def _owner_counts(owner: psycopg.Connection, table: str, tenants: list[str]) -> dict[str, int]:
    """Rows per tenant as the owner. FORCE applies RLS to the owner too, so visit each tenant."""
    counts = {}
    for t in tenants:
        rows, err = _attempt(owner, f"SELECT count(*) FROM {SCHEMA}.{table} WHERE tenant_id = %s", (t,), tenant=t)
        counts[t] = rows[0][0] if err is None else 0
    return counts


def live_checks(owner: psycopg.Connection, app: psycopg.Connection, app_role: str) -> list[Check]:
    checks = []
    tenants = [r[0] for r in owner.execute(f"SELECT tenant_id FROM {SCHEMA}.tenants ORDER BY 1").fetchall()]
    if len(tenants) < 2:
        return [Check("live checks need at least two seeded tenants", False, f"found {tenants}")]
    tickets = {}
    for t in tenants:
        rows, _ = _attempt(owner, f"SELECT id FROM {SCHEMA}.tickets WHERE tenant_id = %s ORDER BY id LIMIT 1", (t,), tenant=t)
        tickets[t] = rows[0][0] if rows else None

    for table in scoped_tables(owner, app_role):
        counts = _owner_counts(owner, table, tenants)
        if sum(counts.values()):
            rows, err = _attempt(app, f"SELECT count(*) FROM {SCHEMA}.{table}")
            checks.append(Check(f"{table}: reading with no tenant set raises", err is not None,
                                f"returned {rows[0][0] if rows else rows} rows instead of an error"))
        for t in tenants:
            rows, err = _attempt(app, f"SELECT count(*) FILTER (WHERE tenant_id IS DISTINCT FROM %s), count(*) FROM {SCHEMA}.{table}",
                                 (t,), tenant=t)
            if err is not None:
                checks.append(Check(f"{table} as {t}: readable", False, str(err).strip()))
                continue
            foreign, total = rows[0]
            checks.append(Check(f"{table} as {t}: no other tenant's rows", foreign == 0, f"{foreign} foreign rows visible"))
            if counts[t]:
                checks.append(Check(f"{table} as {t}: sees all of its own rows", total - foreign == counts[t],
                                    f"{total - foreign} of {counts[t]} visible"))

        writable = app.execute("SELECT has_table_privilege(%s::name, %s::regclass, 'INSERT')",
                               (app_role, f"{SCHEMA}.{table}")).fetchone()[0]
        if not writable:
            continue
        probe = WRITE_PROBES.get(table)
        if probe is None:
            checks.append(Check(f"{table}: has a write probe", False, "add one to WRITE_PROBES"))
            continue
        own, other = tenants[0], tenants[1]
        _, err = _attempt(app, probe, {"tenant": own, "ticket": tickets[own]})
        checks.append(Check(f"{table}: writing with no tenant set raises", err is not None, "the insert succeeded"))
        _, err = _attempt(app, probe, {"tenant": other, "ticket": tickets[other]}, tenant=own)
        checks.append(Check(f"{table}: {own} cannot write a row for {other}", err is not None, "the insert succeeded"))
        _, err = _attempt(app, probe, {"tenant": own, "ticket": tickets[own]}, tenant=own)
        checks.append(Check(f"{table}: {own} can write its own row", err is None, str(err).strip() if err else ""))

    with app.transaction():
        app.execute("SELECT set_config('app.tenant_id', %s, true)", (tenants[0],))
    leftover = app.execute("SELECT current_setting('app.tenant_id', true)").fetchone()[0]
    checks.append(Check("the tenant setting ends with its transaction", not leftover, f"still set to {leftover!r}"))
    return checks


def audit(owner: psycopg.Connection, app: psycopg.Connection) -> list[Check]:
    app_role = app.execute("SELECT current_user").fetchone()[0]
    return catalog_checks(owner, app_role) + live_checks(owner, app, app_role)


def main() -> int:
    with psycopg.connect(config.OWNER_DATABASE_URL, autocommit=True) as owner, \
            psycopg.connect(config.DATABASE_URL, autocommit=True) as app:
        checks = audit(owner, app)
    for c in checks:
        print(f"{'PASS' if c.ok else 'FAIL'}  {c.name}" + ("" if c.ok or not c.detail else f"  ({c.detail})"))
    failed = sum(not c.ok for c in checks)
    print(f"\n{len(checks) - failed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
