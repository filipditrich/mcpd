<img src="assets/logo.svg" alt="" width="72" height="72">

# mcpd

**One login for remote MCP servers, shared by every agent session.** Log in to Bytebase, Metabase, Sentry or any other OAuth MCP server once. Every Claude Code terminal uses that login, and none of them can log the others out.

[![CI](https://github.com/filipditrich/mcpd/actions/workflows/ci.yml/badge.svg)](https://github.com/filipditrich/mcpd/actions/workflows/ci.yml)
![macOS](https://img.shields.io/badge/platform-macOS-lightgrey)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)
[![MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

```bash
uv tool install git+ssh://git@github.com/filipditrich/mcpd.git
mcpd import-claude && mcpd setup && mcpd login --needed && mcpd claude apply
```

## The problem

Claude Code keeps its own MCP connections in every session. Each session loads the OAuth tokens when it starts and refreshes them on its own.

Many servers rotate refresh tokens: every refresh returns a new refresh token and invalidates the old one. With a few terminals open, this happens about once an hour:

1. Terminal A refreshes and gets a new refresh token.
2. Terminal B still holds the old one. Its refresh fails with `invalid_grant`.
3. B drops the login, and every terminal asks you to log in to that server again.

It looks random because it depends on which terminal refreshes first.

## What mcpd does

1. **Owns every login.** One background process (a LaunchAgent) holds the tokens for all configured servers.
2. **Refreshes one at a time.** Each server has at most one refresh in flight. A rotated refresh token is saved before any request uses it. Requests that were waiting reuse the result.
3. **Keeps logins through outages.** Only a rejected grant or client ends a login. A token-endpoint error, timeout or network failure keeps the tokens, and mcpd retries after 20 seconds.
4. **Refreshes ahead of time.** Every minute it refreshes tokens that expire within ten minutes, so idle servers stay logged in.
5. **Stays out of the protocol.** Claude Code connects to `http://127.0.0.1:8790/<name>`. mcpd swaps in the real `Authorization` header and streams the response back, including `Mcp-Session-Id` and event streams. It never parses MCP, so server updates do not break it.

When a server needs a login, mcpd answers `503 login_required` with the command to run. It never passes the server's `401` through, because that would make Claude Code start its own login flow around mcpd.

## Install

Requirements: macOS, [uv](https://docs.astral.sh/uv/), Claude Code.

```bash
uv tool install git+ssh://git@github.com/filipditrich/mcpd.git   # ~/.local/bin/mcpd
mcpd import-claude      # copies your OAuth MCP servers from ~/.claude.json into the config
mcpd setup              # installs and starts ~/Library/LaunchAgents/com.filipditrich.mcpd.plist
mcpd login --needed     # one browser login per server
mcpd claude apply       # points Claude Code at mcpd, only for servers mcpd is logged in to
```

Then run `/mcp` → reconnect in open sessions, or restart them.

`import-claude` skips stdio servers and servers that authenticate with static `headers` or a `headersHelper`; those never need a login. To add a server by hand, put `name = "https://…"` under `[upstreams]` in `~/.config/mcpd/config.toml` and run `mcpd restart`.

### Update and uninstall

```bash
uv tool upgrade mcpd && mcpd restart
mcpd claude revert      # restores the original Claude Code entries
mcpd uninstall          # removes the LaunchAgent; config and tokens stay
```

## Using it

Normally you do nothing. When a server does need a login (a password change, a revoked grant, a session limit), Claude Code shows it as failed with:

```text
mcpd: bytebase needs login (Refresh rejected (invalid_grant)). Run `mcpd login bytebase` or use Switchboard.
```

Run `mcpd login bytebase`, finish the login in the browser, then `/mcp` → reconnect. Do not use `/mcp` → authenticate for a server that goes through mcpd: that logs Claude Code in directly, around mcpd.

Switchboard, my local service dashboard, shows the same state as an **MCP logins** row; its Log in action runs `mcpd login --needed`.

## Commands

| Command | What it does |
|---|---|
| `mcpd status [--json]` | Login state per server. Exit 0 all logged in, 2 some need attention, 3 the daemon is down. |
| `mcpd login NAME… \| --needed [--no-open] [--wait SECONDS]` | Starts browser logins. `--needed` takes every server that needs one; `--wait` blocks until they finish. |
| `mcpd logout NAME` | Forgets one server's tokens. |
| `mcpd claude apply [NAME…] [--dry-run]` | Points user-scope Claude Code entries at mcpd. Backs up each original entry once. |
| `mcpd claude revert [NAME…] [--dry-run]` | Restores the backed-up entries. |
| `mcpd import-claude [--dry-run]` | Adds OAuth HTTP servers from `~/.claude.json` to the config. |
| `mcpd setup [--dry-run]` | Installs and starts the LaunchAgent. |
| `mcpd restart` | Restarts the daemon, which reloads the config. |
| `mcpd uninstall` | Removes the LaunchAgent. |
| `mcpd logs [-n 80]` | Shows the daemon log: logins, refreshes and why any failed. |

`claude apply` and `claude revert` go through `claude mcp remove` and `claude mcp add-json`. They never edit `~/.claude.json` directly, because running sessions write that file too.

## How it works

Logging in follows the MCP authorization spec:

1. Discover the authorization server: the `401` challenge's `resource_metadata` (RFC 9728), then the server metadata (RFC 8414).
2. Get a client id. A server that supports client ID metadata documents and publishes one for mcpd at `{issuer origin}/clients/mcpd` is used with that document's URL as the client id; no registration. Otherwise mcpd registers a client dynamically (RFC 7591) as `mcpd`, with the redirect `http://localhost:8790/callback`.
3. Open the browser with PKCE (S256) and the `resource` parameter (RFC 8707).
4. Exchange the code at the callback and save the tokens.

How mcpd treats a failed refresh:

| Token endpoint answer | What happens |
|---|---|
| `invalid_grant`, `unsupported_grant_type` | The login is gone. The server shows `needs_login`. |
| `invalid_client`, `unauthorized_client` | The login and the client registration are gone. The next login registers a new client. |
| 5xx, timeout, network error, anything else | Tokens are kept. The server shows `error`. Requests fail fast for 20 seconds, then refresh again. An access token that has not expired yet keeps working. |

### Consent screens

A consent screen can only name an app it can verify. A registered client on a localhost redirect names itself, so servers show its name as unverified, or show "an app on this computer" when it gave none. A server that publishes mcpd's metadata document on its own domain proves the name instead: the NFCtron MCP host (`https://mcp.nfctron.com/clients/mcpd`) does, and its Hub consent screen shows **MCP Proxy (mcpd)** with this logo and a verified badge.

`mcpd logout <name>` also forgets the client registration, so the next login picks up a published document or registers again under the current name.

A server that answers `401` again right after a successful refresh gets a `502`; mcpd keeps the login, because such a `401` is usually a scope or server problem, not a dead grant.

## Files

| Path | Content |
|---|---|
| `~/.config/mcpd/config.toml` | `port` (default 8790) and `[upstreams]`. |
| `~/Library/Application Support/mcpd/tokens.json` | Client registrations and tokens. Mode 0600, replaced atomically. |
| `~/Library/Application Support/mcpd/client-token` | The secret local clients send as `X-Mcpd-Token`. |
| `~/Library/Application Support/mcpd/claude-backup.json` | Original Claude Code entries replaced by `claude apply`. |
| `~/Library/Application Support/mcpd/mcpd.log` | Daemon log. It never contains tokens. |

`MCPD_HOME` moves the config and state under one directory.

## Security

- The daemon listens on `127.0.0.1` and `::1` only.
- Every request except the OAuth callback needs `X-Mcpd-Token`. A web page cannot add that header to a cross-origin request.
- Requests whose `Host` is not `127.0.0.1`, `localhost` or `[::1]` on the mcpd port are refused, which blocks DNS rebinding.
- The callback accepts only a `state` that mcpd issued in the last ten minutes, and only once.
- Servers, and every endpoint they advertise, must use HTTPS.
- Tokens are in a 0600 file, like `gcloud` credentials, not in the Keychain. Any process running as you can read them, and `X-Mcpd-Token` is stored in plain text in `~/.claude.json`.

## Limits

- **Servers without dynamic client registration** (Slack's MCP, for example) only accept pre-approved apps. mcpd cannot log in to them.
- **claude.ai connectors** keep their login on Anthropic's side and refresh it there, so they do not have this problem. Manage them at claude.ai → Settings → Connectors.
- **Only user-scope entries** are switched. A project- or local-scope entry with the same name still wins in that project.

## Troubleshooting

**A session still asks for a login.** Run `mcpd status`. If the server is `ok`, that session still uses its old entry: run `/mcp` → reconnect. If it is `needs_login`, run `mcpd login NAME`. `mcpd logs` shows why the last refresh failed.

**`mcpd status` says the daemon is unavailable.** Run `mcpd setup`, then `mcpd logs`. A damaged `tokens.json` is moved aside as `tokens.json.corrupt-<time>` and every server then needs a login.

**A login page says the link expired.** Logins expire after ten minutes or after a daemon restart. Run `mcpd login NAME` again.

## Development

```bash
uv sync
uv run pytest -q
uv run ruff check src tests
```

The tests run the real daemon against a real local OAuth and MCP server (`tests/fake_upstream.py`). It rotates refresh tokens, verifies PKCE, and can be told to fail, hang or reject.

## License

[MIT](LICENSE)
