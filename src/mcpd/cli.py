from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import plistlib
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import __version__
from .config import Config, ConfigError, Paths, client_token, dump, load, validate_url, write_private
from .server import TOKEN_HEADER, serve

LABEL = "com.filipditrich.mcpd"
PLIST = Path.home() / "Library/LaunchAgents" / f"{LABEL}.plist"
CLAUDE_JSON = Path(os.environ.get("MCPD_CLAUDE_JSON", Path.home() / ".claude.json"))
EXIT_OK, EXIT_ERROR, EXIT_ATTENTION, EXIT_DAEMON = 0, 1, 2, 3


def control(paths: Paths, config: Config, method: str, path: str, timeout: float = 30) -> dict:
    request = urllib.request.Request(
        f"http://127.0.0.1:{config.port}{path}",
        method=method,
        headers={TOKEN_HEADER: client_token(paths)},
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=timeout) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read() or b"{}")
        except ValueError:
            body = {}
        raise SystemExit(f"mcpd: {body.get('message') or body.get('error') or exc}") from exc


def daemon_status(paths: Paths, config: Config) -> dict:
    try:
        return control(paths, config, "GET", "/_mcpd/status", timeout=5)
    except (OSError, ValueError):
        # The daemon is down; report what the token file says, marked as unavailable.
        try:
            stored = json.loads(paths.tokens.read_text())
        except (FileNotFoundError, ValueError):
            stored = {}
        upstreams = []
        for name, url in config.upstreams.items():
            record = stored.get(name) or {}
            same = record.get("url") == url and record.get("tokens")
            upstreams.append(
                {
                    "name": name,
                    "url": url,
                    "local_url": f"http://127.0.0.1:{config.port}/{name}",
                    "state": (record.get("state") or "needs_login") if same else "needs_login",
                    "error": record.get("error"),
                    "expires_at": (record.get("tokens") or {}).get("expires_at") if same else None,
                }
            )
        return {
            "schema_version": 1,
            "daemon": "unavailable",
            "port": config.port,
            "checked_at": time.time(),
            "upstreams": upstreams,
        }


def ago(ts: float | None) -> str:
    if not ts:
        return "-"
    delta = ts - time.time()
    minutes = abs(int(delta // 60))
    return f"in {minutes}m" if delta > 0 else f"{minutes}m ago"


def cmd_status(args: argparse.Namespace, paths: Paths) -> int:
    config = load(paths.config)
    status = daemon_status(paths, config)
    if args.json:
        print(json.dumps(status, indent=2))
    else:
        print(f"daemon {status['daemon']} · port {status['port']}")
        for u in status["upstreams"]:
            detail = u.get("error") or f"token expires {ago(u.get('expires_at'))}"
            print(f"  {u['name']:<28} {u['state']:<12} {detail}")
    if status["daemon"] != "running":
        return EXIT_DAEMON
    return EXIT_OK if all(u["state"] == "ok" for u in status["upstreams"]) else EXIT_ATTENTION


def cmd_login(args: argparse.Namespace, paths: Paths) -> int:
    config = load(paths.config)
    status = daemon_status(paths, config)
    if status["daemon"] != "running":
        print("mcpd: daemon not running; run `mcpd setup`", file=sys.stderr)
        return EXIT_DAEMON
    states = {u["name"]: u["state"] for u in status["upstreams"]}
    names = [n for n, s in states.items() if s == "needs_login"] if args.needed else args.names
    unknown = [n for n in names if n not in states]
    if unknown:
        print(f"mcpd: unknown upstream: {', '.join(unknown)}", file=sys.stderr)
        return EXIT_ERROR
    if not names:
        print("Every upstream is logged in.")
        return EXIT_OK
    started = time.time()
    for name in names:
        url = control(paths, config, "POST", f"/_mcpd/login/{name}")["url"]
        print(f"{name}: {url}")
        if not args.no_open:
            subprocess.run(["/usr/bin/open", url], check=False)
    if not args.wait:
        return EXIT_OK
    deadline = started + args.wait
    while time.time() < deadline:
        upstreams = {u["name"]: u for u in daemon_status(paths, config)["upstreams"]}
        if all(
            upstreams[n]["state"] == "ok" and (upstreams[n].get("login_at") or 0) >= started for n in names
        ):
            print("Logged in.")
            return EXIT_OK
        time.sleep(1)
    print("mcpd: timed out waiting for login", file=sys.stderr)
    return EXIT_ATTENTION


def cmd_logout(args: argparse.Namespace, paths: Paths) -> int:
    config = load(paths.config)
    control(paths, config, "POST", f"/_mcpd/logout/{args.name}")
    return EXIT_OK


def claude_servers() -> dict:
    return json.loads(CLAUDE_JSON.read_text()).get("mcpServers", {})


def is_local(entry: dict, config: Config) -> bool:
    return str(entry.get("url", "")).startswith(f"http://127.0.0.1:{config.port}/")


def cmd_import(args: argparse.Namespace, paths: Paths) -> int:
    """Adds user-scope Claude Code HTTP servers that log in with OAuth (no static headers)."""
    try:
        config = load(paths.config)
    except ConfigError:
        config = Config(8790, {})
    upstreams = dict(config.upstreams)
    for name, entry in claude_servers().items():
        if entry.get("type") != "http" or entry.get("headers") or entry.get("headersHelper"):
            continue
        if is_local(entry, config) or name in upstreams:
            continue
        try:
            validate_url(entry["url"])
        except ConfigError:
            continue
        upstreams[name] = entry["url"]
        print(f"  + {name} {entry['url']}")
    new = Config(config.port, upstreams)
    if args.dry_run:
        print(dump(new))
        return EXIT_OK
    write_private(paths.config, dump(new).encode())
    print(f"Wrote {paths.config}. Restart the daemon to load it: mcpd restart")
    return EXIT_OK


def claude(*args: str) -> None:
    exe = shutil.which("claude") or str(Path.home() / ".local/bin/claude")
    result = subprocess.run([exe, "mcp", *args], capture_output=True, text=True, check=False)
    if result.returncode:
        raise SystemExit(f"claude mcp {args[0]} failed: {(result.stderr or result.stdout).strip()}")


def cmd_claude_apply(args: argparse.Namespace, paths: Paths) -> int:
    """Points user-scope Claude Code entries at mcpd, only for upstreams mcpd is logged in to."""
    config = load(paths.config)
    status = daemon_status(paths, config)
    if status["daemon"] != "running":
        print("mcpd: daemon not running", file=sys.stderr)
        return EXIT_DAEMON
    states = {u["name"]: u["state"] for u in status["upstreams"]}
    servers = claude_servers()
    try:
        backup = json.loads(paths.claude_backup.read_text())
    except FileNotFoundError:
        backup = {}
    token = client_token(paths)
    code = EXIT_OK
    for name in args.names or list(config.upstreams):
        if name not in config.upstreams:
            print(f"  ! {name}: not an mcpd upstream")
            code = EXIT_ERROR
            continue
        entry = servers.get(name)
        if entry is not None and is_local(entry, config):
            print(f"  · {name}: already through mcpd")
            continue
        if states.get(name) != "ok":
            print(f"  ! {name}: skipped, mcpd is not logged in ({states.get(name)}); run `mcpd login {name}`")
            code = EXIT_ATTENTION
            continue
        local = {
            "type": "http",
            "url": f"http://127.0.0.1:{config.port}/{name}",
            "headers": {TOKEN_HEADER: token},
        }
        print(f"  ✓ {name} → {local['url']}")
        if args.dry_run:
            continue
        if entry is not None:
            backup.setdefault(name, entry)
            write_private(paths.claude_backup, json.dumps(backup, indent=1).encode())
            claude("remove", "-s", "user", name)
        claude("add-json", "-s", "user", name, json.dumps(local))
    if not args.dry_run:
        print("Run /mcp → reconnect, or restart sessions, to pick up the change.")
    return code


def cmd_claude_revert(args: argparse.Namespace, paths: Paths) -> int:
    config = load(paths.config)
    try:
        backup = json.loads(paths.claude_backup.read_text())
    except FileNotFoundError:
        backup = {}
    servers = claude_servers()
    for name in args.names or list(backup):
        if name not in backup:
            print(f"  ! {name}: no backup")
            continue
        print(f"  ✓ {name} → {backup[name].get('url')}")
        if args.dry_run:
            continue
        if name in servers and is_local(servers[name], config):
            claude("remove", "-s", "user", name)
        claude("add-json", "-s", "user", name, json.dumps(backup[name]))
        del backup[name]
        write_private(paths.claude_backup, json.dumps(backup, indent=1).encode())
    return EXIT_OK


def plist_bytes(paths: Paths) -> bytes:
    return plistlib.dumps(
        {
            "Label": LABEL,
            "ProgramArguments": [sys.executable, "-m", "mcpd", "serve"],
            "RunAtLoad": True,
            "KeepAlive": True,
            "ThrottleInterval": 10,
            "StandardOutPath": str(paths.log),
            "StandardErrorPath": str(paths.log),
        }
    )


def launchctl(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["/bin/launchctl", *args], capture_output=True, text=True, check=False)


def cmd_setup(args: argparse.Namespace, paths: Paths) -> int:
    load(paths.config)
    wanted = plist_bytes(paths)
    current = PLIST.read_bytes() if PLIST.exists() else None
    print(f"  {'·' if current == wanted else '✓'} {PLIST}")
    if args.dry_run:
        return EXIT_OK
    paths.state.mkdir(parents=True, exist_ok=True, mode=0o700)
    client_token(paths)
    target = f"gui/{os.getuid()}/{LABEL}"
    if current != wanted:
        PLIST.parent.mkdir(parents=True, exist_ok=True)
        PLIST.write_bytes(wanted)
        launchctl("bootout", target)
    if launchctl("print", target).returncode:
        result = launchctl("bootstrap", f"gui/{os.getuid()}", str(PLIST))
        if result.returncode:
            print(f"launchctl bootstrap failed: {result.stderr.strip()}", file=sys.stderr)
            return EXIT_ERROR
    return EXIT_OK


def cmd_restart(_args: argparse.Namespace, paths: Paths) -> int:
    load(paths.config)
    result = launchctl("kickstart", "-k", f"gui/{os.getuid()}/{LABEL}")
    if result.returncode:
        print(f"launchctl kickstart failed: {result.stderr.strip()}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_OK


def cmd_uninstall(_args: argparse.Namespace, _paths: Paths) -> int:
    launchctl("bootout", f"gui/{os.getuid()}/{LABEL}")
    PLIST.unlink(missing_ok=True)
    print(
        "Removed the LaunchAgent. Tokens and config stay; `mcpd claude revert` restores Claude Code entries."
    )
    return EXIT_OK


def cmd_logs(args: argparse.Namespace, paths: Paths) -> int:
    try:
        lines = paths.log.read_text(errors="replace").splitlines()
    except FileNotFoundError:
        lines = []
    print("\n".join(lines[-args.n :]))
    return EXIT_OK


def cmd_serve(_args: argparse.Namespace, paths: Paths) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    config = load(paths.config)
    asyncio.run(serve(config, paths))
    return EXIT_OK


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="mcpd", description="Shared login owner and proxy for remote MCPs")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("serve", help="run the daemon (launchd runs this)").set_defaults(fn=cmd_serve)
    p = sub.add_parser("status", help="show every upstream's login state")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_status)
    p = sub.add_parser("login", help="log in to upstreams in the browser")
    p.add_argument("names", nargs="*")
    p.add_argument("--needed", action="store_true", help="every upstream that needs a login")
    p.add_argument("--no-open", action="store_true", help="print the URL instead of opening it")
    p.add_argument("--wait", type=float, default=0, metavar="SECONDS", help="block until logged in")
    p.set_defaults(fn=cmd_login)
    p = sub.add_parser("logout", help="forget one upstream's tokens")
    p.add_argument("name")
    p.set_defaults(fn=cmd_logout)
    p = sub.add_parser("import-claude", help="add OAuth HTTP servers from ~/.claude.json to the config")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(fn=cmd_import)
    claude_cmd = sub.add_parser("claude", help="switch Claude Code user-scope entries to or from mcpd")
    claude_sub = claude_cmd.add_subparsers(dest="claude_command", required=True)
    for name, fn in (("apply", cmd_claude_apply), ("revert", cmd_claude_revert)):
        p = claude_sub.add_parser(name)
        p.add_argument("names", nargs="*")
        p.add_argument("--dry-run", action="store_true")
        p.set_defaults(fn=fn)
    p = sub.add_parser("setup", help="install and start the LaunchAgent")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(fn=cmd_setup)
    p = sub.add_parser("logs", help="show the daemon log")
    p.add_argument("-n", type=int, default=80)
    p.set_defaults(fn=cmd_logs)
    sub.add_parser("restart", help="restart the daemon (reloads config)").set_defaults(fn=cmd_restart)
    sub.add_parser("uninstall", help="remove the LaunchAgent").set_defaults(fn=cmd_uninstall)
    args = parser.parse_args(argv)
    if args.command == "login" and not args.names and not args.needed:
        parser.error("login needs upstream names or --needed")
    try:
        sys.exit(args.fn(args, Paths.default()))
    except ConfigError as exc:
        print(f"mcpd: {exc}", file=sys.stderr)
        sys.exit(4)
