"""Who is calling. B3 uses TenantGuard's verified contextvar; B0-B2 use the legacy path.

The legacy path verifies the JWT signature but then honours an X-Tenant-ID header,
the "tenant switcher" pattern admin and support UIs often add. That header is how an
authenticated user of one company asks to act as another.
"""

import hashlib

import jwt
from fastapi import HTTPException, Request

from app import config, db
from tenantguard.identity import Principal, require_principal


def login(tenant: str, username: str, password: str) -> Principal:
    digest = hashlib.sha256(f"{tenant}:{username}:{password}".encode()).hexdigest()
    with db.pool.connection() as conn:
        row = conn.execute(
            "SELECT role FROM tg.app_users WHERE tenant_id = %s AND username = %s AND password_hash = %s",
            (tenant, username, digest),
        ).fetchone()
    if row is None:
        raise HTTPException(401, "bad credentials")
    return Principal(tenant_id=tenant, username=username, role=row[0])


def bearer(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(401, "missing bearer token")
    return auth[7:].strip()


def get_principal(request: Request) -> Principal:
    if config.GUARDS.tenantguard:
        return require_principal()
    try:
        claims = jwt.decode(bearer(request), config.JWT_SECRET, algorithms=["HS256"], options={"verify_aud": False})
    except jwt.PyJWTError as exc:
        raise HTTPException(401, f"invalid token: {exc}") from exc
    tenant = request.headers.get("x-tenant-id") or claims["tid"]
    return Principal(tenant_id=tenant, username=claims["sub"], role=claims.get("role", "member"))
