-- TenantGuard database bootstrap. Runs once, as the bootstrap superuser, from docker-entrypoint-initdb.d.
--
-- Two roles, per the plan:
--   tg_owner : owns every table and runs migrations/seed/admin toggles. Not a superuser.
--   tg_app   : what the app and the MCP server connect as. Not owner, not superuser, NOBYPASSRLS.
-- Superusers and BYPASSRLS roles skip row-level security entirely, even with FORCE, and FORCE only
-- extends RLS to the table owner. So the only safe shape is "app connects as a plain role".

CREATE EXTENSION IF NOT EXISTS vector;

CREATE ROLE tg_owner LOGIN PASSWORD 'owner-local-only' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE ROLE tg_app   LOGIN PASSWORD 'app-local-only'   NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOINHERIT;

GRANT CONNECT ON DATABASE tenantguard TO tg_owner, tg_app;
CREATE SCHEMA tg AUTHORIZATION tg_owner;
ALTER ROLE tg_owner SET search_path = tg, public;
ALTER ROLE tg_app   SET search_path = tg, public;

SET ROLE tg_owner;
SET search_path = tg, public;

-- Fail-closed tenant accessor (pattern from tenantvault-zero-trust-rag's app.require_tenant(),
-- re-implemented here). A query that reaches an RLS-protected table with no tenant context
-- raises instead of silently returning zero rows, so a missing set_config() is loud.
CREATE FUNCTION tg_current_tenant() RETURNS text
LANGUAGE plpgsql STABLE AS $$
DECLARE
  t text := current_setting('app.tenant_id', true);
BEGIN
  IF t IS NULL OR t = '' THEN
    RAISE EXCEPTION 'tenantguard: no tenant context set' USING ERRCODE = '42501';
  END IF;
  RETURN t;
END;
$$;

CREATE TABLE tenants (
  tenant_id text PRIMARY KEY,
  name      text NOT NULL,
  code      text NOT NULL UNIQUE          -- canary prefix, e.g. ACME
);

-- Login table. Not tenant-scoped data: /login must read it before the tenant is known.
CREATE TABLE app_users (
  tenant_id     text NOT NULL REFERENCES tenants(tenant_id),
  username      text NOT NULL,
  role          text NOT NULL CHECK (role IN ('member', 'support')),
  password_hash text NOT NULL,
  PRIMARY KEY (tenant_id, username)
);

CREATE TABLE documents (
  id        bigserial PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES tenants(tenant_id),
  title     text NOT NULL,
  topic     text NOT NULL,
  body      text NOT NULL,
  canary    text NOT NULL UNIQUE,
  embedding vector(384) NOT NULL
);
CREATE INDEX documents_embedding_hnsw ON documents USING hnsw (embedding vector_cosine_ops);
CREATE INDEX documents_tenant ON documents (tenant_id);

-- Guessable IDs on purpose (T-1001, T-2001, ...): the IDOR target.
CREATE TABLE tickets (
  id             text PRIMARY KEY,
  tenant_id      text NOT NULL REFERENCES tenants(tenant_id),
  subject        text NOT NULL,
  body           text NOT NULL,
  customer_email text NOT NULL,
  canary         text NOT NULL UNIQUE,
  status         text NOT NULL DEFAULT 'open'
);
CREATE INDEX tickets_tenant ON tickets (tenant_id);

CREATE TABLE notes (
  id         bigserial PRIMARY KEY,
  tenant_id  text NOT NULL REFERENCES tenants(tenant_id),
  ticket_id  text NOT NULL REFERENCES tickets(id),
  author     text NOT NULL,
  body       text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX notes_ticket ON notes (ticket_id);

CREATE TABLE app_logs (
  id         bigserial PRIMARY KEY,
  tenant_id  text,                         -- legacy modes may leave it NULL
  username   text,
  route      text NOT NULL,
  message    text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Ground truth for the attack detector. Never granted to tg_app.
CREATE TABLE canary_registry (
  canary      text PRIMARY KEY,
  tenant_id   text NOT NULL REFERENCES tenants(tenant_id),
  kind        text NOT NULL CHECK (kind IN ('hard', 'secret')),
  record_type text NOT NULL,
  record_id   text NOT NULL
);

-- Policies are always defined; whether they are enforced is the per-mode toggle
-- (python -m tenantguard.admin rls on|off, run as tg_owner). USING filters reads,
-- WITH CHECK stops writes that would land a row in another tenant.
CREATE POLICY tenant_fence ON documents USING (tenant_id = tg_current_tenant()) WITH CHECK (tenant_id = tg_current_tenant());
CREATE POLICY tenant_fence ON tickets   USING (tenant_id = tg_current_tenant()) WITH CHECK (tenant_id = tg_current_tenant());
CREATE POLICY tenant_fence ON notes     USING (tenant_id = tg_current_tenant()) WITH CHECK (tenant_id = tg_current_tenant());
CREATE POLICY tenant_fence ON app_logs  USING (tenant_id = tg_current_tenant()) WITH CHECK (tenant_id = tg_current_tenant());

RESET ROLE;

REVOKE ALL ON SCHEMA tg FROM PUBLIC;
GRANT USAGE ON SCHEMA tg TO tg_app;
GRANT SELECT ON tg.tenants, tg.app_users TO tg_app;
GRANT SELECT ON tg.documents, tg.tickets TO tg_app;
GRANT SELECT, INSERT ON tg.notes, tg.app_logs TO tg_app;
GRANT USAGE ON SEQUENCE tg.notes_id_seq, tg.app_logs_id_seq TO tg_app;
GRANT EXECUTE ON FUNCTION tg.tg_current_tenant() TO tg_app;
