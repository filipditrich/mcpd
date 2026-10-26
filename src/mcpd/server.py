"""The daemon: sole owner of upstream tokens, and a pass-through proxy for local MCP clients."""

from __future__ import annotations

import asyncio
import hmac
import html
import json
import logging
import os
import secrets
import signal
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

import aiohttp
from aiohttp import web

from . import oauth
from .config import Config, Paths, client_token, write_private

log = logging.getLogger("mcpd")

TOKEN_HEADER = "X-Mcpd-Token"
MAX_BODY = 32 * 1024 * 1024
LOGIN_TTL_S = 600
REFRESH_EARLY_S = 60
MAINTAIN_EVERY_S = 60
MAINTAIN_AHEAD_S = 600
RETRY_AFTER_S = 20
HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
DROP_REQUEST = HOP | {"host", "authorization", "content-length", "accept-encoding", "cookie", "origin"}
DROP_RESPONSE = HOP | {"content-length", "content-encoding", "www-authenticate", "set-cookie"}


class NeedsLogin(Exception):
    pass


class Unavailable(Exception):
    pass


class Store:
    """tokens.json, written only by the daemon, replaced atomically on every change."""

    def __init__(self, path: Path):
        self.path = path
        try:
            self.data: dict[str, dict] = json.loads(path.read_text())
        except FileNotFoundError:
            self.data = {}
        except ValueError:
            # Keep the damaged file for inspection instead of crash-looping under launchd.
            aside = path.with_name(f"{path.name}.corrupt-{int(time.time())}")
            path.rename(aside)
            log.error("unreadable %s moved to %s; every upstream needs login", path.name, aside.name)
            self.data = {}

    def get(self, name: str) -> dict:
        return dict(self.data.get(name) or {})

    def put(self, name: str, record: dict) -> None:
        self.data[name] = record
        write_private(self.path, json.dumps(self.data, indent=1, sort_keys=True).encode())


@dataclass
class Pending:
    name: str
    verifier: str
    auth: dict
    client: dict
    created: float


class Daemon:
    def __init__(self, config: Config, paths: Paths, *, host: str = "127.0.0.1"):
        self.config = config
        self.paths = paths
        self.host = host
        self.port = config.port
        self.store = Store(paths.tokens)
        self.secret = client_token(paths)
        self.locks: defaultdict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self.pending: dict[str, Pending] = {}
        self.failed_at: dict[str, float] = {}
        self.session: aiohttp.ClientSession | None = None
        self.runner: web.AppRunner | None = None
        self.maintainer: asyncio.Task | None = None

    # lifecycle

    async def start(self) -> None:
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=None, sock_connect=15),
            headers={"User-Agent": "mcpd/0.1"},
        )
        self.runner = web.AppRunner(self.app(), access_log=None, handler_cancellation=True)
        await self.runner.setup()
        site = web.TCPSite(self.runner, self.host, self.port)
        await site.start()
        self.port = self.runner.addresses[0][1]
        if self.host == "127.0.0.1" and self.config.port:
            # Browsers may resolve the localhost callback to ::1 first.
            try:
                await web.TCPSite(self.runner, "::1", self.port).start()
            except OSError:
                pass
        self.maintainer = asyncio.create_task(self.maintain())
        log.info("listening on %s:%s with %d upstreams", self.host, self.port, len(self.config.upstreams))

    async def stop(self) -> None:
        if self.maintainer:
            self.maintainer.cancel()
        if self.runner:
            await self.runner.cleanup()
        if self.session:
            await self.session.close()

    def app(self) -> web.Application:
        app = web.Application(client_max_size=MAX_BODY, middlewares=[self.guard])
        app.router.add_get("/callback", self.callback)
        app.router.add_get("/_mcpd/status", self.status_route)
        app.router.add_post("/_mcpd/login/{name}", self.login_route)
        app.router.add_post("/_mcpd/logout/{name}", self.logout_route)
        app.router.add_route("*", "/{name}", self.proxy)
        return app

    @web.middleware
    async def guard(self, request: web.Request, handler):
        # A web page can reach 127.0.0.1 through DNS rebinding; it cannot fake Host or add our header.
        if request.host not in {f"{h}:{self.port}" for h in ("127.0.0.1", "localhost", "[::1]")}:
            return web.json_response({"error": "forbidden_host"}, status=403)
        if not (request.method == "GET" and request.path == "/callback"):
            given = request.headers.get(TOKEN_HEADER, "")
            if not hmac.compare_digest(given.encode(), self.secret.encode()):
                return web.json_response({"error": "mcpd_token_required"}, status=401)
        return await handler(request)

    # tokens

    def record(self, name: str) -> dict:
        record = self.store.get(name)
        return record if record.get("url") == self.config.upstreams[name] else {}

    def update(self, name: str, **fields) -> None:
        record = self.record(name) or {"url": self.config.upstreams[name]}
        record.update(fields, updated_at=time.time())
        self.store.put(name, record)

    def needs_login(self, name: str, reason: str, *, forget_client: bool = False) -> NeedsLogin:
        """Only for a dead grant; call with the upstream's lock held."""
        log.warning("%s needs login: %s", name, reason)
        fields = {"client": None} if forget_client else {}
        self.update(name, tokens=None, state="needs_login", error=reason, **fields)
        return NeedsLogin(reason)

    async def access_token(self, name: str) -> str:
        record = self.record(name)
        tokens = record.get("tokens")
        if not tokens or record.get("state") == "needs_login":
            raise NeedsLogin(record.get("error") or "Not logged in")
        expires_at = tokens.get("expires_at")
        if expires_at and expires_at - REFRESH_EARLY_S <= time.time():
            try:
                await self.refresh(name, tokens["access_token"])
            except Unavailable:
                if expires_at <= time.time():
                    raise
                return tokens["access_token"]  # still valid for a few seconds
            tokens = self.record(name)["tokens"]
        return tokens["access_token"]

    async def refresh(self, name: str, stale: str) -> None:
        # Shielded: a client hanging up must not cancel a refresh between rotation and persisting it.
        await asyncio.shield(self.refresh_locked(name, stale))

    async def refresh_locked(self, name: str, stale: str) -> None:
        """One refresh per upstream at a time; callers holding an older token reuse the result."""
        async with self.locks[name]:
            record = self.record(name)
            tokens = record.get("tokens")
            if not tokens:
                raise NeedsLogin(record.get("error") or "Not logged in")
            if tokens["access_token"] != stale:
                return
            if not tokens.get("refresh_token"):
                raise self.needs_login(name, "Server issued no refresh token")
            if time.time() - self.failed_at.get(name, 0) < RETRY_AFTER_S:
                # Waiters behind a failed refresh fail fast instead of each hitting the endpoint.
                raise Unavailable(record.get("error") or "Refresh failed recently")
            try:
                fresh = await oauth.refresh(
                    self.session, record["auth"], record["client"], tokens["refresh_token"]
                )
            except oauth.OAuthError as exc:
                if exc.permanent:
                    dead_client = exc.code in ("invalid_client", "unauthorized_client")
                    raise self.needs_login(
                        name, f"Refresh rejected ({exc.code})", forget_client=dead_client
                    ) from exc
                log.warning("%s refresh failed, keeping tokens: %s", name, exc)
                self.failed_at[name] = time.time()
                self.update(name, state="error", error=str(exc))
                raise Unavailable(str(exc)) from exc
            self.failed_at.pop(name, None)
            fresh["refresh_token"] = fresh.get("refresh_token") or tokens["refresh_token"]
            # Persist before any request uses it, so a rotated refresh token is never lost.
            self.update(name, tokens=fresh, state="ok", error=None, refreshed_at=time.time())
            log.info("%s refreshed", name)

    async def maintain(self) -> None:
        """Refreshes ahead of expiry so idle upstreams stay logged in."""
        while True:
            for name in self.config.upstreams:
                record = self.record(name)
                tokens = record.get("tokens") or {}
                expires_at = tokens.get("expires_at")
                if record.get("state") == "needs_login" or not expires_at:
                    continue
                if expires_at - MAINTAIN_AHEAD_S <= time.time():
                    try:
                        await self.refresh(name, tokens["access_token"])
                    except (NeedsLogin, Unavailable):
                        pass
                    except Exception:
                        log.exception("%s background refresh crashed", name)
            await asyncio.sleep(MAINTAIN_EVERY_S)

    # proxy

    async def proxy(self, request: web.Request) -> web.StreamResponse:
        name = request.match_info["name"]
        url = self.config.upstreams.get(name)
        if url is None:
            return web.json_response({"error": "unknown_upstream", "upstream": name}, status=404)
        body = await request.read()
        headers = {
            k: v for k, v in request.headers.items() if k.lower() not in DROP_REQUEST | {"x-mcpd-token"}
        }
        try:
            for attempt in (1, 2):
                token = await self.access_token(name)
                try:
                    upstream = await self.session.request(
                        request.method,
                        url + (f"?{request.query_string}" if request.query_string else ""),
                        headers=headers | {"Authorization": f"Bearer {token}"},
                        data=body or None,
                        allow_redirects=False,
                    )
                except (aiohttp.ClientError, TimeoutError) as exc:
                    return web.json_response(
                        {"error": "upstream_unreachable", "message": type(exc).__name__}, status=502
                    )
                if upstream.status != 401:
                    return await self.relay(request, upstream)
                upstream.release()
                if attempt == 1:
                    await self.refresh(name, token)
        except NeedsLogin as exc:
            return self.login_required(name, str(exc))
        except Unavailable as exc:
            return web.json_response({"error": "refresh_unavailable", "message": str(exc)}, status=502)
        # A 401 right after a refresh may be scope- or server-specific; never discard the
        # refresh token for it. A dead grant shows up as a permanent refresh error instead.
        return web.json_response(
            {"error": "upstream_rejected_token", "message": f"{name} rejected a freshly refreshed token"},
            status=502,
        )

    def login_required(self, name: str, reason: str) -> web.Response:
        # 503, not 401: a 401 would send the client into its own OAuth flow against mcpd.
        message = f"mcpd: {name} needs login ({reason}). Run `mcpd login {name}` or use Switchboard."
        return web.json_response(
            {"error": "login_required", "upstream": name, "message": message}, status=503
        )

    async def relay(self, request: web.Request, upstream: aiohttp.ClientResponse) -> web.StreamResponse:
        response = web.StreamResponse(status=upstream.status, reason=upstream.reason)
        for key, value in upstream.headers.items():
            if key.lower() not in DROP_RESPONSE:
                response.headers.add(key, value)
        try:
            await response.prepare(request)
            async for chunk in upstream.content.iter_any():
                await response.write(chunk)
            await response.write_eof()
        finally:
            upstream.release()
        return response

    # login

    @property
    def redirect_uri(self) -> str:
        return f"http://localhost:{self.port}/callback"

    async def begin_login(self, name: str) -> str:
        auth = await oauth.discover(self.session, self.config.upstreams[name])
        client = self.record(name).get("client") or {}
        if (
            client.get("registration_endpoint") != auth["registration_endpoint"]
            or client.get("redirect_uri") != self.redirect_uri
        ):
            client = await oauth.register(self.session, auth, self.redirect_uri)
        now = time.time()
        self.pending = {k: p for k, p in self.pending.items() if now - p.created < LOGIN_TTL_S}
        state = secrets.token_urlsafe(24)
        verifier, challenge = oauth.pkce()
        self.pending[state] = Pending(name, verifier, auth, client, now)
        return oauth.authorize_url(auth, client, state=state, challenge=challenge)

    async def callback(self, request: web.Request) -> web.Response:
        pending = self.pending.pop(request.query.get("state", ""), None)
        if pending is None or time.time() - pending.created >= LOGIN_TTL_S:
            return page("Login link expired", "Start the login again from Switchboard or `mcpd login`.", 400)
        if "error" in request.query or "code" not in request.query:
            reason = request.query.get("error_description") or request.query.get("error") or "no code"
            return page(f"{pending.name}: login failed", reason, 400)
        try:
            tokens = await oauth.exchange(
                self.session,
                pending.auth,
                pending.client,
                code=request.query["code"],
                verifier=pending.verifier,
            )
        except oauth.OAuthError as exc:
            return page(f"{pending.name}: login failed", str(exc), 502)
        async with self.locks[pending.name]:
            self.update(
                pending.name,
                auth=pending.auth,
                client=pending.client,
                tokens=tokens,
                state="ok",
                error=None,
                login_at=time.time(),
            )
        log.info("%s logged in", pending.name)
        return page(
            f"{pending.name}: logged in", "You can close this tab. Every agent session shares this login."
        )

    # control

    def status(self) -> dict:
        upstreams = []
        for name, url in self.config.upstreams.items():
            record = self.record(name)
            tokens = record.get("tokens") or {}
            upstreams.append(
                {
                    "name": name,
                    "url": url,
                    "local_url": f"http://127.0.0.1:{self.port}/{name}",
                    "state": record.get("state") if record.get("state") and tokens else "needs_login",
                    "error": record.get("error"),
                    "expires_at": tokens.get("expires_at"),
                    "refreshable": bool(tokens.get("refresh_token")),
                    "login_at": record.get("login_at"),
                    "refreshed_at": record.get("refreshed_at"),
                }
            )
        return {
            "schema_version": 1,
            "daemon": "running",
            "pid": os.getpid(),
            "port": self.port,
            "checked_at": time.time(),
            "upstreams": upstreams,
        }

    async def status_route(self, _request: web.Request) -> web.Response:
        return web.json_response(self.status())

    async def login_route(self, request: web.Request) -> web.Response:
        name = request.match_info["name"]
        if name not in self.config.upstreams:
            return web.json_response({"error": "unknown_upstream"}, status=404)
        try:
            url = await self.begin_login(name)
        except oauth.OAuthError as exc:
            return web.json_response({"error": "login_unavailable", "message": str(exc)}, status=502)
        return web.json_response({"url": url})

    async def logout_route(self, request: web.Request) -> web.Response:
        name = request.match_info["name"]
        if name not in self.config.upstreams:
            return web.json_response({"error": "unknown_upstream"}, status=404)
        async with self.locks[name]:
            self.update(name, tokens=None, state="needs_login", error="Logged out")
        return web.json_response({"ok": True})


def page(title: str, text: str, status: int = 200) -> web.Response:
    body = (
        "<!doctype html><meta charset=utf-8><title>mcpd</title>"
        "<body style='font:16px system-ui;margin:4rem auto;max-width:36rem'>"
        f"<h1 style='font-size:1.4rem'>{html.escape(title)}</h1><p>{html.escape(text)}</p>"
    )
    return web.Response(text=body, content_type="text/html", status=status)


async def serve(config: Config, paths: Paths) -> None:
    daemon = Daemon(config, paths)
    await daemon.start()
    stopping = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        # launchd stops with SIGTERM; let in-flight refreshes persist before exiting.
        loop.add_signal_handler(sig, stopping.set)
    try:
        await stopping.wait()
    finally:
        await daemon.stop()
