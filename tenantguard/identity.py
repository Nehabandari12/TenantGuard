"""Identity: the tenant comes from a verified login token and nowhere else.

The middleware verifies the JWT (algorithm pinned, signature, issuer, audience, expiry),
builds a Principal, and stores it in a contextvar for the lifetime of the request.
Request bodies, headers like X-Tenant-ID, and model output never set the tenant.
"""

import contextvars
import time
from contextlib import contextmanager
from dataclasses import dataclass

import jwt
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from app import config
from tenantguard import TenantContextError


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    username: str
    role: str = "member"

    @property
    def subject(self) -> str:
        return f"{self.tenant_id}:{self.username}"


_current: contextvars.ContextVar[Principal | None] = contextvars.ContextVar("tg_principal", default=None)


def current_principal() -> Principal | None:
    return _current.get()


def require_principal() -> Principal:
    principal = _current.get()
    if principal is None:
        raise TenantContextError("no verified tenant in context")
    return principal


@contextmanager
def bind_principal(principal: Principal):
    token = _current.set(principal)
    try:
        yield principal
    finally:
        _current.reset(token)


def issue_login_token(principal: Principal, ttl_seconds: int = 3600) -> str:
    now = int(time.time())
    claims = {
        "iss": config.JWT_ISSUER,
        "aud": config.LOGIN_AUDIENCE,
        "sub": principal.username,
        "tid": principal.tenant_id,
        "role": principal.role,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    return jwt.encode(claims, config.JWT_SECRET, algorithm="HS256")


def verify_login_token(token: str) -> Principal:
    claims = jwt.decode(
        token,
        config.JWT_SECRET,
        algorithms=["HS256"],
        audience=config.LOGIN_AUDIENCE,
        issuer=config.JWT_ISSUER,
        options={"require": ["exp", "iss", "aud", "sub", "tid"]},
    )
    return Principal(tenant_id=claims["tid"], username=claims["sub"], role=claims.get("role", "member"))


class IdentityMiddleware:
    """Pure ASGI middleware so the contextvar is set in the same context the endpoint runs in."""

    def __init__(self, app: ASGIApp, public_paths: tuple[str, ...] = ("/login", "/health")) -> None:
        self.app = app
        self.public_paths = public_paths

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["path"] in self.public_paths:
            await self.app(scope, receive, send)
            return
        headers = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
        auth = headers.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            await JSONResponse({"detail": "missing bearer token"}, status_code=401)(scope, receive, send)
            return
        try:
            principal = verify_login_token(auth[7:].strip())
        except jwt.PyJWTError as exc:
            await JSONResponse({"detail": f"invalid token: {exc}"}, status_code=401)(scope, receive, send)
            return
        # An explicit deny (403) rather than silently ignoring the header, so probing is visible.
        claimed = headers.get("x-tenant-id")
        if claimed and claimed != principal.tenant_id:
            await JSONResponse({"detail": "tenant mismatch"}, status_code=403)(scope, receive, send)
            return
        with bind_principal(principal):
            await self.app(scope, receive, send)
