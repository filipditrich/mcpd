# mcpd

**One login owner for remote MCP servers, shared by every agent session.** Log in to Bytebase, Metabase or any OAuth MCP server once. Every Claude Code terminal uses that login, and none of them can log the others out.

## The problem

Claude Code keeps its own MCP connections in every session. Each session loads the OAuth tokens at startup and refreshes them on its own.

Many servers rotate refresh tokens: each refresh returns a new refresh token and invalidates the old one. Bytebase does this, and its access tokens last one hour. With several terminals open:

1. Terminal A refreshes and gets a new refresh token.
2. Terminal B still holds the old one. Its refresh fails with `invalid_grant`.
3. B drops the login, and every terminal has to log in to that server again.

## What mcpd does

1. **Owns every login.** A LaunchAgent daemon holds the tokens for all configured servers in `~/Library/Application Support/mcpd/tokens.json` (mode 0600).
2. **Refreshes one at a time.** Each server has one refresh in flight at most. A rotated refresh token is saved before any request uses it. Callers holding an older token reuse the result.
3. **Keeps logins through outages.** Only `invalid_grant`, `invalid_client`, `unauthorized_client` and `unsupported_grant_type` end a login. A token-endpoint error or network failure keeps the tokens and retries on the next request.
4. **Refreshes ahead of expiry.** Every minute it refreshes tokens that expire within ten minutes, so idle servers stay logged in.
5. **Proxies unchanged.** Claude Code connects to `http://127.0.0.1:8790/<name>`. mcpd replaces the `Authorization` header and streams the response back. It passes `Mcp-Session-Id` and event streams through and does not parse MCP.

When a server needs a login, mcpd answers `503 login_required` with the command to run. It never forwards the upstream `401`, so Claude Code does not start its own OAuth flow around mcpd.

## Install

Requirements: macOS, [uv](https://docs.astral.sh/uv/), Claude Code.

```bash
uv tool install ~/Work/tools/mcpd     # installs ~/.local/bin/mcpd
mcpd import-claude              # copies OAuth HTTP servers from ~/.claude.json into the config
mcpd setup                      # writes and loads ~/Library/LaunchAgents/com.filipditrich.mcpd.plist
mcpd login --needed             # opens one browser login per server
mcpd claude apply               # points Claude Code at mcpd, only for servers mcpd is logged in to
```

Then run `/mcp` → reconnect in open sessions, or restart them.

`import-claude` skips stdio servers and servers that authenticate with static `headers` or `headersHelper`. Those never need a login.

## Commands

| Command | What it does |
| --- | --- |
| `mcpd status [--json]` | Login state per server. Exit 0 = all logged in, 2 = some need attention, 3 = daemon down. |
| `mcpd login NAME… \| --needed [--no-open] [--wait SECONDS]` | Starts a browser login. `--wait` blocks until it completes. |
| `mcpd logout NAME` | Forgets one server's tokens. |
| `mcpd claude apply [NAME…] [--dry-run]` | Rewrites user-scope Claude Code entries to use mcpd. Backs up each original entry once. |
| `mcpd claude revert [NAME…] [--dry-run]` | Restores the backed-up entries. |
| `mcpd import-claude [--dry-run]` | Adds OAuth HTTP servers from `~/.claude.json` to the config. |
| `mcpd setup [--dry-run]` / `mcpd restart` / `mcpd uninstall` | Manages the LaunchAgent. `restart` reloads the config. |
| `mcpd logs [-n N]` | Shows the daemon log. |

`claude apply` and `claude revert` go through `claude mcp remove` and `claude mcp add-json`. They never edit `~/.claude.json` directly, because running sessions write that file too.

## Files

| Path | Content |
| --- | --- |
| `~/.config/mcpd/config.toml` | `port` and `[upstreams]` (`name = "https://…"`). |
| `~/Library/Application Support/mcpd/tokens.json` | Client registrations and tokens. 0600, replaced atomically. |
| `~/Library/Application Support/mcpd/client-token` | The secret local clients send as `X-Mcpd-Token`. |
| `~/Library/Application Support/mcpd/claude-backup.json` | Original Claude Code entries replaced by `claude apply`. |
| `~/Library/Application Support/mcpd/mcpd.log` | Daemon log: logins, refreshes, failures. No tokens. |

`MCPD_HOME` moves the config and state under one directory, for tests.

## Security

- The daemon listens on 127.0.0.1 and ::1 only.
- Every request except the OAuth callback needs `X-Mcpd-Token`. A web page cannot add that header to a cross-origin request.
- Requests whose `Host` is not `127.0.0.1`, `localhost` or `[::1]` on the mcpd port are refused, which blocks DNS rebinding.
- The callback accepts only a `state` that mcpd issued in the last ten minutes, and uses it once.
- Upstream URLs must use HTTPS.
- Tokens are stored in a 0600 file, like `gcloud` credentials, not in the Keychain. Any process running as you can read them.

## Development

```bash
uv sync
uv run pytest -q
uv run ruff check src tests
```

The tests run the real daemon against a real local OAuth + MCP server (`tests/fake_upstream.py`) that rotates refresh tokens and verifies PKCE.
