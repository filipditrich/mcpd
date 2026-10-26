from __future__ import annotations

import json
import os
import re
import secrets
import tomllib
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

DEFAULT_PORT = 8790
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Paths:
    config: Path
    state: Path

    @classmethod
    def default(cls) -> Paths:
        root = os.environ.get("MCPD_HOME")
        if root:
            base = Path(root).absolute()
            return cls(base / "config.toml", base / "state")
        home = Path.home()
        return cls(home / ".config/mcpd/config.toml", home / "Library/Application Support/mcpd")

    @property
    def tokens(self) -> Path:
        return self.state / "tokens.json"

    @property
    def client_token(self) -> Path:
        return self.state / "client-token"

    @property
    def claude_backup(self) -> Path:
        return self.state / "claude-backup.json"

    @property
    def log(self) -> Path:
        return self.state / "mcpd.log"


@dataclass(frozen=True)
class Config:
    port: int
    upstreams: dict[str, str]


def validate_url(url: str) -> None:
    parts = urlsplit(url)
    local = parts.hostname in LOCAL_HOSTS
    if parts.scheme != "https" and not (parts.scheme == "http" and local):
        raise ConfigError(f"{url}: upstreams must use https")
    if not parts.hostname or parts.username or parts.password or parts.fragment:
        raise ConfigError(f"{url}: invalid upstream URL")


def parse(text: str) -> Config:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"Invalid TOML: {exc}") from exc
    if set(data) - {"port", "upstreams"}:
        raise ConfigError("Expected only port and [upstreams]")
    port = data.get("port", DEFAULT_PORT)
    if type(port) is not int or not 0 <= port <= 65535:
        raise ConfigError("port must be an integer port")
    upstreams = data.get("upstreams", {})
    if not isinstance(upstreams, dict):
        raise ConfigError("[upstreams] must map names to URLs")
    for name, url in upstreams.items():
        if not NAME.fullmatch(name) or name.startswith("_") or name == "callback":
            raise ConfigError(f"Invalid upstream name: {name}")
        if not isinstance(url, str):
            raise ConfigError(f"{name}: URL must be a string")
        validate_url(url)
    return Config(port, dict(upstreams))


def load(path: Path) -> Config:
    try:
        return parse(path.read_text())
    except FileNotFoundError as exc:
        raise ConfigError(f"No config at {path}; run `mcpd import-claude`") from exc


def dump(config: Config) -> str:
    lines = [f"port = {config.port}", "", "[upstreams]"]
    lines += [f"{name} = {json.dumps(url)}" for name, url in sorted(config.upstreams.items())]
    return "\n".join(lines) + "\n"


def write_private(path: Path, data: bytes) -> None:
    """Atomic replace with 0600 permissions; the directory is 0700."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def client_token(paths: Paths) -> str:
    """Secret every local client sends as X-Mcpd-Token; created once."""
    try:
        token = paths.client_token.read_text().strip()
        if token:
            return token
    except FileNotFoundError:
        pass
    token = secrets.token_urlsafe(32)
    write_private(paths.client_token, token.encode())
    return token
