"""MCP server with three tools: search_docs, get_ticket, create_note.

Run: GUARD_MODE=B0 uvicorn mcp_server.server:app --port 8001   (endpoint: /mcp)

B0     no auth. Tools take tenant_id from the model; search ignores it, get_ticket is a plain
       lookup by guessable ID (IDOR), create_note writes into any ticket.
B1/B2  accepts the user's login JWT (token passthrough: any token the app signed is good).
       Tools filter by the tenant_id *argument*, which the model (or an injected
       instruction) can set to another tenant.
B3     TenantGuard: audience-bound MCP token, tenant from the token only, no tenant_id
       parameter exists, every query runs under FORCE RLS, cross-tenant lookups get an
       explicit error rather than an empty success.
"""

import jwt
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from app import config, db
from app.config import Mode
from app.embeddings import embed
from tenantguard.identity import Principal
from tenantguard.mcp_auth import SCOPE, TenantTokenVerifier, principal_from_mcp_request


class PassthroughVerifier(TokenVerifier):
    """Legacy: trusts any login token the app signed, whatever its audience."""

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            claims = jwt.decode(token, config.JWT_SECRET, algorithms=["HS256"], options={"verify_aud": False})
        except jwt.PyJWTError:
            return None
        return AccessToken(token=token, client_id="legacy", scopes=[SCOPE], expires_at=claims.get("exp"),
                           subject=claims["sub"], claims={"tid": claims["tid"], "usr": claims["sub"]})


def _format_ticket(row, notes) -> str:
    text = f"Ticket {row[0]} [{row[1]}] {row[2]}\n{row[3]}"
    if notes:
        text += "\nNotes:\n" + "\n".join(f"- {n[0]}: {n[1]}" for n in notes)
    return text


def _format_docs(rows) -> str:
    return "\n\n".join(f"{r[0]}: {r[1]}" for r in rows) or "No documents found."


def _search(principal: Principal, query: str, tenant_filter: str | None) -> str:
    qv = str(embed(query))
    with db.session(principal) as conn:
        if tenant_filter is None:
            rows = conn.execute("SELECT title, body FROM tg.documents ORDER BY embedding <=> %s::vector LIMIT 3", (qv,)).fetchall()
        else:
            rows = conn.execute("SELECT title, body FROM tg.documents WHERE tenant_id = %s ORDER BY embedding <=> %s::vector LIMIT 3",
                                (tenant_filter, qv)).fetchall()
    return _format_docs(rows)


def _ticket(principal: Principal, ticket_id: str, tenant_filter: str | None) -> str | None:
    with db.session(principal) as conn:
        if tenant_filter is None:
            row = conn.execute("SELECT id, tenant_id, subject, body FROM tg.tickets WHERE id = %s", (ticket_id,)).fetchone()
        else:
            row = conn.execute("SELECT id, tenant_id, subject, body FROM tg.tickets WHERE id = %s AND tenant_id = %s",
                               (ticket_id, tenant_filter)).fetchone()
        if row is None:
            return None
        notes = conn.execute("SELECT author, body FROM tg.notes WHERE ticket_id = %s ORDER BY id", (ticket_id,)).fetchall()
    return _format_ticket(row, notes)


def _note(principal: Principal, ticket_id: str, text: str, tenant_filter: str | None) -> str | None:
    with db.session(principal) as conn:
        if tenant_filter is None:
            row = conn.execute("SELECT tenant_id FROM tg.tickets WHERE id = %s", (ticket_id,)).fetchone()
        else:
            row = conn.execute("SELECT tenant_id FROM tg.tickets WHERE id = %s AND tenant_id = %s", (ticket_id, tenant_filter)).fetchone()
        if row is None:
            return None
        # Legacy writes the note under the ticket's tenant; B3 under the caller's (and RLS WITH CHECK
        # refuses anything else). Postgres FK checks bypass RLS, which is why B3 also looks the
        # ticket up through RLS first instead of relying on the foreign key.
        owner = principal.tenant_id if config.GUARDS.tenantguard else row[0]
        conn.execute("INSERT INTO tg.notes (tenant_id, ticket_id, author, body) VALUES (%s, %s, %s, %s)",
                     (owner, ticket_id, principal.username, text))
    return f"Note added to {ticket_id}."


def build() -> MCPServer:
    if config.GUARDS.tenantguard:
        server = MCPServer(
            "tenantguard-tools",
            token_verifier=TenantTokenVerifier(),
            auth=AuthSettings(issuer_url=config.APP_URL, resource_server_url=config.MCP_URL,
                              validate_token_resource=True, required_scopes=[SCOPE]),
        )

        @server.tool()
        def search_docs(query: str) -> str:
            """Search this company's knowledge base."""
            principal = principal_from_mcp_request()
            return _search(principal, query, principal.tenant_id)

        @server.tool()
        def get_ticket(ticket_id: str) -> str:
            """Fetch a support ticket (with its notes) by ID, e.g. T-1001."""
            principal = principal_from_mcp_request()
            text = _ticket(principal, ticket_id, principal.tenant_id)
            if text is None:
                raise ToolError(f"ticket {ticket_id} not found or not accessible")
            return text

        @server.tool()
        def create_note(ticket_id: str, text: str) -> str:
            """Add an internal note to a support ticket."""
            principal = principal_from_mcp_request()
            result = _note(principal, ticket_id, text, principal.tenant_id)
            if result is None:
                raise ToolError(f"ticket {ticket_id} not found or not accessible")
            return result

        return server

    if config.MODE is Mode.B0:
        server = MCPServer("tenantguard-tools")
    else:
        server = MCPServer(
            "tenantguard-tools",
            token_verifier=PassthroughVerifier(),
            auth=AuthSettings(issuer_url=config.APP_URL, resource_server_url=config.MCP_URL,
                              validate_token_resource=False, required_scopes=[SCOPE]),
        )
    filtered = config.GUARDS.app_tenant_filter

    def caller(tenant_id: str) -> Principal:
        return Principal(tenant_id=tenant_id, username="agent")

    @server.tool()
    def search_docs(query: str, tenant_id: str) -> str:
        """Search a company's knowledge base. tenant_id selects the company."""
        return _search(caller(tenant_id), query, tenant_id if filtered else None)

    @server.tool()
    def get_ticket(ticket_id: str, tenant_id: str) -> str:
        """Fetch a support ticket (with its notes) by ID, e.g. T-1001."""
        text = _ticket(caller(tenant_id), ticket_id, tenant_id if filtered else None)
        if text is None:
            raise ToolError(f"ticket {ticket_id} not found")
        return text

    @server.tool()
    def create_note(ticket_id: str, text: str, tenant_id: str) -> str:
        """Add an internal note to a support ticket."""
        result = _note(caller(tenant_id), ticket_id, text, tenant_id if filtered else None)
        if result is None:
            raise ToolError(f"ticket {ticket_id} not found")
        return result

    return server


config.check_startup()
server = build()
db.open_pool()
app = server.streamable_http_app(host="127.0.0.1")
