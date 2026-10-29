"""A real HTTP MCP server with its own OAuth server that rotates refresh tokens like Bytebase or Metabase."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import secrets
from urllib.parse import urlencode

from aiohttp import web


class FakeUpstream:
    def __init__(self) -> None:
        self.clients: dict[str, str] = {}
        self.codes: dict[str, dict] = {}
        self.access: set[str] = set()
        self.refresh: set[str] = set()
        self.refresh_calls = 0
        self.token_failure: str | None = None  # "server_error", "invalid_grant" or "invalid_client"
        self.token_delay = 0.0
        self.reject_all = False
        self.publishes_mcpd = False  # serve /clients/mcpd and accept it as a client id
        self.mcp_requests: list[dict] = []
        self.sse_gate = asyncio.Event()
        self.runner: web.AppRunner | None = None
        self.base = ""

    async def start(self) -> None:
        app = web.Application()
        app.router.add_post("/mcp", self.mcp)
        app.router.add_get("/.well-known/oauth-protected-resource/mcp", self.resource_metadata)
        app.router.add_get("/.well-known/oauth-authorization-server", self.server_metadata)
        app.router.add_post("/register", self.register)
        app.router.add_get("/clients/mcpd", self.mcpd_document)
        app.router.add_get("/authorize", self.authorize)
        app.router.add_post("/token", self.token)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await site.start()
        self.base = f"http://127.0.0.1:{self.runner.addresses[0][1]}"

    async def stop(self) -> None:
        await self.runner.cleanup()

    def expire_access(self) -> None:
        self.access.clear()

    def pair(self) -> dict:
        access, refresh = secrets.token_hex(8), secrets.token_hex(8)
        self.access.add(access)
        self.refresh.add(refresh)
        return {"access_token": access, "refresh_token": refresh, "expires_in": 3600, "token_type": "Bearer"}

    async def mcp(self, request: web.Request) -> web.StreamResponse:
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        body = await request.json()
        self.mcp_requests.append(
            {"headers": dict(request.headers), "body": body, "query": request.query_string}
        )
        if token not in self.access or self.reject_all:
            return web.json_response(
                {"error": "invalid_token"},
                status=401,
                headers={
                    "WWW-Authenticate": f'Bearer resource_metadata="{self.base}/.well-known/oauth-protected-resource/mcp", scope="mcp"'
                },
            )
        if body.get("method") == "stream":
            response = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
            await response.prepare(request)
            await response.write(b'data: {"n": 1}\n\n')
            await self.sse_gate.wait()
            await response.write(b'data: {"n": 2}\n\n')
            await response.write_eof()
            return response
        return web.json_response(
            {"jsonrpc": "2.0", "id": body.get("id"), "result": {"echo": body}},
            headers={"Mcp-Session-Id": "session-1"},
        )

    async def resource_metadata(self, _request: web.Request) -> web.Response:
        return web.json_response(
            {
                "resource": f"{self.base}/mcp",
                "authorization_servers": [self.base],
                "scopes_supported": ["mcp"],
            }
        )

    async def server_metadata(self, _request: web.Request) -> web.Response:
        return web.json_response(
            {
                "issuer": self.base,
                "authorization_endpoint": f"{self.base}/authorize",
                "token_endpoint": f"{self.base}/token",
                "registration_endpoint": f"{self.base}/register",
                "code_challenge_methods_supported": ["S256"],
                "client_id_metadata_document_supported": self.publishes_mcpd,
            }
        )

    async def mcpd_document(self, _request: web.Request) -> web.Response:
        if not self.publishes_mcpd:
            return web.Response(status=404)
        client_id = f"{self.base}/clients/mcpd"
        return web.json_response(
            {
                "client_id": client_id,
                "client_name": "mcpd",
                "redirect_uris": ["http://localhost:8790/callback"],
            }
        )

    async def register(self, request: web.Request) -> web.Response:
        body = await request.json()
        client_id = secrets.token_hex(6)
        self.clients[client_id] = body["redirect_uris"][0]
        return web.json_response({"client_id": client_id, "token_endpoint_auth_method": "none"}, status=201)

    async def authorize(self, request: web.Request) -> web.Response:
        q = request.query
        published = (
            self.publishes_mcpd
            and q["client_id"] == f"{self.base}/clients/mcpd"
            and q["redirect_uri"].startswith("http://localhost:")
        )
        if (not published and self.clients.get(q["client_id"]) != q["redirect_uri"]) or q[
            "code_challenge_method"
        ] != "S256":
            return web.Response(status=400, text="bad authorize request")
        code = secrets.token_hex(6)
        self.codes[code] = {
            "client_id": q["client_id"],
            "challenge": q["code_challenge"],
            "resource": q["resource"],
        }
        raise web.HTTPFound(f"{q['redirect_uri']}?{urlencode({'code': code, 'state': q['state']})}")

    async def token(self, request: web.Request) -> web.Response:
        form = await request.post()
        if form["grant_type"] == "authorization_code":
            grant = self.codes.pop(form["code"], None)
            digest = hashlib.sha256(form["code_verifier"].encode()).digest()
            challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
            if grant is None or grant["challenge"] != challenge or grant["client_id"] != form["client_id"]:
                return web.json_response({"error": "invalid_grant"}, status=400)
            return web.json_response(self.pair())
        self.refresh_calls += 1
        await asyncio.sleep(0.05 + self.token_delay)  # widen the window two unserialized refreshes race in
        if self.token_failure == "server_error":
            return web.json_response({"error": "server_error"}, status=503)
        if self.token_failure == "invalid_client":
            return web.json_response({"error": "invalid_client"}, status=401)
        old = form["refresh_token"]
        if self.token_failure == "invalid_grant" or old not in self.refresh:
            return web.json_response({"error": "invalid_grant"}, status=400)
        self.refresh.discard(old)
        return web.json_response(self.pair())
