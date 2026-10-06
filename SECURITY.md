# Security notes

TenantGuard is a solo research and demonstration project. It has not been deployed for real users,
independently reviewed, penetration-tested by a third party, or certified. The benchmark reports
leaks *observed* on 84 checks against synthetic data; zero observed leaks is not a proof that no
leak exists.

## What runs where

| Piece | Trust boundary it enforces | Where it is checked |
|---|---|---|
| Identity middleware | tenant comes from a verified login JWT only; `X-Tenant-ID` for another tenant gets 403 | [tests/test_boundaries.py](tests/test_boundaries.py) |
| Postgres | `FORCE ROW LEVEL SECURITY`, app role `tg_app` is not owner, superuser or `BYPASSRLS`, tenant set per transaction | [tenantguard/rls_audit.py](tenantguard/rls_audit.py), run in CI on a fresh database |
| Redis cache and memory | cache entries tagged and filtered by tenant; memory keyed `tenant:user`; no tenant means an exception | unit tests |
| MCP server | 60 s token minted per request, audience = the MCP server, separate signing key, no tenant argument on tools | unit tests, benchmark `tools` route |
| Egress | other tenants' canaries (decoded), unapproved links, secrets in answers and logs | unit tests, benchmark `injection` route |

## The baselines are vulnerable on purpose

`GUARD_MODE` B0, B1 and B2 exist to be attacked: B0 has no isolation, B1 trusts a model-supplied
`tenant_id` and the tenant-switch header, B2 only adds an input filter. `app/config.py` defaults to
B0 because the benchmark harness sets the mode itself. Never expose a B0-B2 process to a network.

`docker-compose.yml` binds Postgres and Redis to `127.0.0.1` for that reason.

## Public demo values

Everything below is published in this repository and is synthetic. Treat any process using one of
them as untrusted:

- Postgres bootstrap superuser `postgres` / `postgres` (compose only; the app never connects as it)
- `tg_owner` / `owner-local-only` and `tg_app` / `app-local-only` (`sql/001_init.sql`)
- JWT signing keys in `app/config.py` and `.env.example`
- the seeded users' password `demo` (`app/seed.py`)

## `TG_ENV=protected`

The default `TG_ENV=benchmark` starts any mode with the demo values, which the experiment needs.
`TG_ENV=protected` makes the app and the MCP server refuse to start unless:

- the mode is B3 and the egress canary check is on,
- `JWT_SECRET` and `MCP_JWT_SECRET` are not demo values, are at least 32 bytes and differ,
- `DATABASE_URL` does not use the published `tg_app` password (`ALTER ROLE tg_app PASSWORD ...` first).

Passing these checks removes known-unsafe settings. It does not make the demo production-ready.
What the demo still lacks:

- **Login.** Passwords are unsalted SHA-256 of `tenant:user:password`, there is no rate limiting or
  lockout, and login tokens are HS256 with a shared key, valid for an hour, with no revocation. A real
  deployment would use an identity provider (OIDC) and verify its asymmetric signatures.
- **Transport.** No TLS anywhere; uvicorn serves plain HTTP.
- **Secrets.** Read from environment variables; there is no secret manager or key rotation.
- **Operations.** Single node, no backups, no audit trail beyond `tg.app_logs`, no monitoring.

## Dependencies

`constraints.txt` pins every package to the version in the environment that produced the published
results, resolved for all platforms. CI and the setup scripts install through it.

The dependency audit workflow checks those pins against the PyPI advisory database on every push and
weekly. It ignores three advisories, all in `cryptography` 48.0.1:

| Advisory | Issue |
|---|---|
| PYSEC-2026-3552 (CVE-2026-69247) | PKCS#7 EnvelopedData decryption timing oracle |
| PYSEC-2026-3553 (CVE-2026-69249) | exponential X.509 path building |
| PYSEC-2026-3554 (CVE-2026-69248) | wildcard names escape X.509 name constraints |

Why they are ignored: all three are fixed in `cryptography` 49 and 50, but the only package that needs `cryptography`,
`presidio-anonymizer` (the optional `pii` extra), requires `cryptography<49` in its latest release
(2.2.364). TenantGuard uses Presidio only to redact text and never decrypts PKCS#7 or validates X.509
certificates through `cryptography`. Remove the exceptions when a Presidio release allows 49 or later.

To refresh the pins (for example monthly, or for an advisory):

```bash
uv pip compile pyproject.toml --all-extras --universal --python-version 3.12 --no-annotate -o constraints.txt
```

then run the unit tests, the RLS audit and the mock benchmark, and note in the commit that the
published results were produced with the previous pins. Dependabot keeps the workflow actions current.

## Reporting

Please open a GitHub issue. This is a personal project without a support commitment.
