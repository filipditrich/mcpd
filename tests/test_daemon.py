from __future__ import annotations

import asyncio
import json
import stat
import time

import aiohttp
import pytest
from fake_upstream import FakeUpstream

from mcpd import oauth, server
from mcpd.config import Config, Paths
from mcpd.server import TOKEN_HEADER, Daemon


@pytest.fixture
async def upstream():
    fake = FakeUpstream()
    await fake.start()
    yield fake
    fake.sse_gate.set()
    await fake.stop()


@pytest.fixture
def paths(tmp_path):
    return Paths(tmp_path / "config.toml", tmp_path / "state")


@pytest.fixture
async def http():
    async with aiohttp.ClientSession() as session:
        yield session


async def started(upstream: FakeUpstream, paths: Paths) -> Daemon:
    daemon = Daemon(Config(0, {"fake": f"{upstream.base}/mcp"}), paths)
    await daemon.start()
    return daemon


async def login(daemon: Daemon, http: aiohttp.ClientSession) -> None:
    url = await daemon.begin_login("fake")
    async with http.get(url) as response:  # follows /authorize → mcpd /callback
        assert response.status == 200, await response.text()


async def call(daemon: Daemon, http: aiohttp.ClientSession, body: dict, **headers) -> aiohttp.ClientResponse:
    headers = {TOKEN_HEADER: daemon.secret, "Accept": "application/json, text/event-stream"} | headers
    return await http.post(f"http://127.0.0.1:{daemon.port}/fake", json=body, headers=headers)


@pytest.fixture
async def daemon(upstream, paths, http):
    d = await started(upstream, paths)
    await login(d, http)
    yield d
    upstream.sse_gate.set()
    await d.stop()


async def test_login_discovers_registers_and_stores_tokens_privately(daemon, upstream, paths, http):
    # Catches: broken discovery/PKCE (fake verifies the S256 challenge), tokens not persisted, loose file mode.
    response = await call(daemon, http, {"jsonrpc": "2.0", "id": 7, "method": "ping"})
    assert response.status == 200
    assert (await response.json())["result"]["echo"]["id"] == 7
    stored = json.loads(paths.tokens.read_text())["fake"]
    assert stored["tokens"]["access_token"] in upstream.access
    assert stat.S_IMODE(paths.tokens.stat().st_mode) == 0o600
    assert daemon.status()["upstreams"][0]["state"] == "ok"


async def test_concurrent_requests_share_one_rotating_refresh(daemon, upstream, http):
    # Catches: unserialized refresh. The second refresh would present a rotated-away token,
    # get invalid_grant and log the user out, exactly the multi-terminal failure.
    upstream.expire_access()
    responses = await asyncio.gather(
        *(call(daemon, http, {"jsonrpc": "2.0", "id": i, "method": "ping"}) for i in range(20))
    )
    assert [r.status for r in responses] == [200] * 20
    assert sorted([(await r.json())["result"]["echo"]["id"] for r in responses]) == list(range(20))
    assert upstream.refresh_calls == 1
    assert daemon.status()["upstreams"][0]["state"] == "ok"


async def test_rotated_refresh_token_survives_restart(daemon, upstream, paths, http):
    # Catches: a rotated refresh token kept only in memory; after a restart the old one is dead.
    upstream.expire_access()
    assert (await call(daemon, http, {"jsonrpc": "2.0", "id": 1, "method": "ping"})).status == 200
    await daemon.stop()
    upstream.expire_access()
    again = await started(upstream, paths)
    try:
        response = await call(again, http, {"jsonrpc": "2.0", "id": 2, "method": "ping"})
        assert response.status == 200
        assert upstream.refresh_calls == 2
    finally:
        await again.stop()


async def test_transient_refresh_failure_keeps_login(daemon, upstream, http, monkeypatch):
    monkeypatch.setattr(server, "RETRY_AFTER_S", 0)
    # Catches: treating a token-endpoint outage as a dead login and wiping the tokens.
    upstream.expire_access()
    upstream.token_failure = "server_error"
    failed = await call(daemon, http, {"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert failed.status == 502
    assert daemon.status()["upstreams"][0]["state"] == "error"
    upstream.token_failure = None
    recovered = await call(daemon, http, {"jsonrpc": "2.0", "id": 2, "method": "ping"})
    assert recovered.status == 200
    assert daemon.status()["upstreams"][0]["state"] == "ok"


async def test_rejected_refresh_asks_for_login_without_upstream_challenge(daemon, upstream, http):
    # Catches: forwarding the upstream 401 + WWW-Authenticate, which sends Claude Code into its own
    # OAuth flow against the real server and bypasses mcpd.
    upstream.expire_access()
    upstream.token_failure = "invalid_grant"
    response = await call(daemon, http, {"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert response.status == 503
    assert "WWW-Authenticate" not in response.headers
    assert (await response.json())["error"] == "login_required"
    assert daemon.status()["upstreams"][0]["state"] == "needs_login"


async def test_local_callers_need_the_token_and_a_local_host(daemon, upstream, http):
    # Catches: an open local proxy (any process or rebinding web page could use prod write tools).
    before = len(upstream.mcp_requests)
    no_token = await http.post(f"http://127.0.0.1:{daemon.port}/fake", json={"id": 1})
    assert no_token.status == 401
    rebinding = await call(daemon, http, {"id": 1}, Host=f"evil.example:{daemon.port}")
    assert rebinding.status == 403
    assert len(upstream.mcp_requests) == before


async def test_session_header_passes_through_and_local_token_does_not(daemon, upstream, http):
    # Catches: dropping Mcp-Session-Id (every call becomes a new session) or leaking the local secret.
    first = await call(daemon, http, {"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    session_id = first.headers["Mcp-Session-Id"]
    await call(daemon, http, {"jsonrpc": "2.0", "id": 2, "method": "ping"}, **{"Mcp-Session-Id": session_id})
    sent = upstream.mcp_requests[-1]["headers"]
    assert sent["Mcp-Session-Id"] == "session-1"
    assert TOKEN_HEADER not in sent
    assert (
        sent["Authorization"]
        == f"Bearer {json.loads(daemon.paths.tokens.read_text())['fake']['tokens']['access_token']}"
    )


async def test_event_stream_is_relayed_as_it_arrives(daemon, upstream, http):
    # Catches: buffering the whole response, which hangs long-lived MCP streams.
    response = await call(daemon, http, {"jsonrpc": "2.0", "id": 1, "method": "stream"})
    first = await asyncio.wait_for(response.content.readuntil(b"\n\n"), timeout=2)
    assert first == b'data: {"n": 1}\n\n'
    upstream.sse_gate.set()
    assert await asyncio.wait_for(response.content.read(), timeout=2) == b'data: {"n": 2}\n\n'


async def test_rejected_fresh_token_keeps_the_refresh_token(daemon, upstream, http):
    # Catches: discarding the whole login when the server answers 401 twice for a reason
    # unrelated to the grant (scope check, blip). Every session would need a browser login.
    upstream.reject_all = True
    rejected = await call(daemon, http, {"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert rejected.status == 502
    assert daemon.status()["upstreams"][0]["state"] != "needs_login"
    upstream.reject_all = False
    assert (await call(daemon, http, {"jsonrpc": "2.0", "id": 2, "method": "ping"})).status == 200


async def test_hung_token_endpoint_times_out_and_frees_the_upstream(daemon, upstream, http, monkeypatch):
    # Catches: a token endpoint that never answers holding the refresh lock, hanging every request.
    monkeypatch.setattr(oauth, "TIMEOUT", aiohttp.ClientTimeout(total=0.3))
    upstream.token_delay = 3
    upstream.expire_access()
    response = await asyncio.wait_for(call(daemon, http, {"jsonrpc": "2.0", "id": 1, "method": "ping"}), 2)
    assert response.status == 502
    assert not daemon.locks["fake"].locked()


async def test_waiters_behind_a_failed_refresh_fail_fast(daemon, upstream, http):
    # Catches: every queued request retrying the failing token endpoint in turn.
    upstream.expire_access()
    upstream.token_failure = "server_error"
    responses = await asyncio.gather(
        *(call(daemon, http, {"jsonrpc": "2.0", "id": i, "method": "ping"}) for i in range(10))
    )
    assert {r.status for r in responses} == {502}
    assert upstream.refresh_calls == 1


async def test_still_valid_token_is_used_when_early_refresh_fails(daemon, upstream, http):
    # Catches: failing requests during a token-endpoint outage although the access token still works.
    record = daemon.record("fake")
    daemon.update("fake", tokens=record["tokens"] | {"expires_at": time.time() + 30})
    upstream.token_failure = "server_error"
    assert (await call(daemon, http, {"jsonrpc": "2.0", "id": 1, "method": "ping"})).status == 200


async def test_dead_client_registration_is_replaced_on_next_login(daemon, upstream, http):
    # Catches: reusing a client the server deleted, so every later login fails the same way.
    upstream.expire_access()
    upstream.token_failure = "invalid_client"
    assert (await call(daemon, http, {"jsonrpc": "2.0", "id": 1, "method": "ping"})).status == 503
    upstream.token_failure = None
    await login(daemon, http)
    assert len(upstream.clients) == 2
    assert (await call(daemon, http, {"jsonrpc": "2.0", "id": 2, "method": "ping"})).status == 200


async def test_only_the_oauth_callback_skips_the_local_token(daemon, http):
    # Catches: a path-based exemption letting a web page POST to /callback without the secret.
    response = await http.post(f"http://127.0.0.1:{daemon.port}/callback", json={})
    assert response.status == 401


async def test_query_string_reaches_the_upstream(daemon, upstream, http):
    # Catches: dropping query parameters some MCP transports put on the endpoint URL.
    headers = {TOKEN_HEADER: daemon.secret, "Accept": "application/json, text/event-stream"}
    url = f"http://127.0.0.1:{daemon.port}/fake?sessionId=abc"
    assert (await http.post(url, json={"jsonrpc": "2.0", "id": 1}, headers=headers)).status == 200
    assert upstream.mcp_requests[-1]["query"] == "sessionId=abc"


async def test_unreadable_token_file_is_set_aside(upstream, paths):
    # Catches: a damaged tokens.json crash-looping the LaunchAgent.
    paths.state.mkdir(parents=True)
    paths.tokens.write_text("{not json")
    d = await started(upstream, paths)
    try:
        assert d.status()["upstreams"][0]["state"] == "needs_login"
        assert list(paths.state.glob("tokens.json.corrupt-*"))
    finally:
        await d.stop()
