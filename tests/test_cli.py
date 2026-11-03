from __future__ import annotations

import json
import logging

import pytest

from mcpd import cli
from mcpd.config import ConfigError, Paths, load, parse


def test_config_rejects_plaintext_remote_upstreams():
    # Catches: sending bearer tokens over plain HTTP to a remote host.
    with pytest.raises(ConfigError):
        parse('[upstreams]\nbytebase = "http://bytebase.example.com/mcp"\n')
    assert parse('[upstreams]\nlocal = "http://127.0.0.1:9/mcp"\n').upstreams == {
        "local": "http://127.0.0.1:9/mcp"
    }


def test_config_reserves_the_callback_route_name():
    # Catches: an upstream named "callback" sharing the token-exempt OAuth callback path.
    with pytest.raises(ConfigError):
        parse('[upstreams]\ncallback = "https://x.example.com/mcp"\n')


def test_import_takes_only_oauth_http_servers(tmp_path, monkeypatch):
    # Catches: importing servers that authenticate with static headers or run over stdio,
    # which mcpd would then try to log in to and break.
    claude_json = tmp_path / "claude.json"
    claude_json.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "bytebase": {"type": "http", "url": "https://bytebase.example.com/mcp"},
                    "keyed": {"type": "http", "url": "https://k.example.com/mcp", "headers": {"X-Key": "1"}},
                    "local": {"type": "stdio", "command": "x"},
                    "already": {"type": "http", "url": "http://127.0.0.1:8790/already"},
                }
            }
        )
    )
    monkeypatch.setattr(cli, "CLAUDE_JSON", claude_json)
    paths = Paths(tmp_path / "config.toml", tmp_path / "state")
    monkeypatch.setattr(Paths, "default", classmethod(lambda cls: paths))
    with pytest.raises(SystemExit) as done:
        cli.main(["import-claude"])
    assert done.value.code == 0
    assert load(paths.config).upstreams == {"bytebase": "https://bytebase.example.com/mcp"}


def test_daemon_log_rotates_instead_of_growing(tmp_path, monkeypatch):
    # Catches: an unbounded mcpd.log; the live one reached 394 MB of stream-cut tracebacks.
    monkeypatch.setattr(cli, "LOG_MAX_BYTES", 10_000)
    paths = Paths(tmp_path / "config.toml", tmp_path / "state")
    root = logging.getLogger()
    before = list(root.handlers)
    try:
        cli.log_to_file(paths)
        for i in range(1000):
            logging.getLogger("mcpd").warning("line %d %s", i, "x" * 60)
    finally:
        for handler in set(root.handlers) - set(before):
            root.removeHandler(handler)
            handler.close()
    assert paths.log.stat().st_size <= 10_000
    assert "line 999 " in paths.log.read_text()
    assert sum(f.stat().st_size for f in paths.state.glob("mcpd.log*")) < 50_000
