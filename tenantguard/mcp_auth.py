"""MCP authorization for B3.

The app never forwards the user's login token (no token passthrough). For each agent
request it mints a separate short-lived token signed with a different key, whose
audience is exactly the MCP server. The MCP server:
  * rejects any token whose aud is not itself (checked here AND by the SDK's
    validate_token_resource, so a login token or a token for another server fails twice),
  * takes the tenant from the token's claims, never from tool arguments,
  * runs its queries through tenantguard.db.tenant_transaction,
  * gets per-session owner binding from the SDK: mcp>=2 ties each session ID to the
    token's (client_id, iss, sub), and we set sub = "tenant:user", so a session ID
    replayed by a different user or tenant is refused. (In mcp 1.x this needed a fork,
    e.g. andylim-duo/python-sdk; 2.x ships it.)
"""

import time

import jwt
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken, TokenVerifier

from app import config
from tenantguard import TenantContextError
from tenantguard.identity import Principal

CLIENT_ID = "tenantguard-app"
SCOPE = "tools"


def mint_mcp_token(principal: Principal, ttl_seconds: int | None = None) -> str:
    now = int(time.time())
    claims = {
        "iss": config.JWT_ISSUER,
        "aud": config.MCP_AUDIENCE,
        "sub": principal.subject,
        "tid": principal.tenant_id,
        "usr": principal.username,
        "role": principal.role,
        "scope": SCOPE,
        "iat": now,
        "exp": now + (ttl_seconds or config.MCP_TOKEN_TTL_SECONDS),
    }
    return jwt.encode(claims, config.MCP_JWT_SECRET, algorithm="HS256")


class TenantTokenVerifier(TokenVerifier):
    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            claims = jwt.decode(
                token,
                config.MCP_JWT_SECRET,
                algorithms=["HS256"],
                audience=config.MCP_AUDIENCE,
                issuer=config.JWT_ISSUER,
                options={"require": ["exp", "iss", "aud", "sub", "tid", "usr"]},
            )
        except jwt.PyJWTError:
            return None
        if claims["sub"] != f"{claims['tid']}:{claims['usr']}":
            return None
        return AccessToken(
            token=token,
            client_id=CLIENT_ID,
            scopes=claims.get("scope", "").split(),
            expires_at=claims["exp"],
            resource=claims["aud"],
            subject=claims["sub"],
            claims={"iss": claims["iss"], "tid": claims["tid"], "usr": claims["usr"], "role": claims.get("role", "member")},
        )


def principal_from_mcp_request() -> Principal:
    token = get_access_token()
    if token is None or not token.claims:
        raise TenantContextError("MCP call without a verified token")
    return Principal(tenant_id=token.claims["tid"], username=token.claims["usr"], role=token.claims.get("role", "member"))
