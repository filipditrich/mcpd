"""OAuth 2.1 client for MCP servers: discovery, dynamic registration, PKCE, code exchange, refresh."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import time
from urllib.parse import urlencode, urlsplit

import aiohttp

from .config import ConfigError, validate_url

ACCEPT = {"Accept": "application/json, text/event-stream"}
PROBE = {
    "jsonrpc": "2.0",
    "id": 0,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "mcpd", "version": "0.1.0"},
    },
}
TIMEOUT = aiohttp.ClientTimeout(total=30)
# Errors that mean the grant or client is gone; anything else is retried later with the tokens kept.
PERMANENT = {"invalid_grant", "invalid_client", "unauthorized_client", "unsupported_grant_type"}


class OAuthError(Exception):
    def __init__(self, message: str, *, permanent: bool, code: str | None = None):
        super().__init__(message)
        self.permanent = permanent
        self.code = code


def challenge_params(header: str) -> dict[str, str]:
    return {k.lower(): a or b for k, a, b in re.findall(r'(\w+)=(?:"([^"]*)"|([^\s,]+))', header)}


async def get_json(session: aiohttp.ClientSession, url: str) -> dict | None:
    try:
        async with session.get(url, headers={"Accept": "application/json"}, timeout=TIMEOUT) as r:
            if r.status != 200:
                return None
            data = await r.json(content_type=None)
            return data if isinstance(data, dict) else None
    except (aiohttp.ClientError, ValueError, TimeoutError):
        return None


def origin_and_path(url: str) -> tuple[str, str]:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}", parts.path.rstrip("/")


async def server_metadata(session: aiohttp.ClientSession, issuer: str) -> dict | None:
    origin, path = origin_and_path(issuer)
    candidates = [f"{origin}/.well-known/oauth-authorization-server{path}"]
    candidates.append(f"{origin}/.well-known/openid-configuration{path}")
    if path:
        candidates.append(f"{origin}{path}/.well-known/openid-configuration")
    for url in candidates:
        meta = await get_json(session, url)
        if meta and meta.get("authorization_endpoint") and meta.get("token_endpoint"):
            return meta
    return None


async def discover(session: aiohttp.ClientSession, url: str) -> dict:
    """Finds the authorization server for an MCP URL (RFC 9728 → RFC 8414, legacy fallback)."""
    try:
        async with session.post(url, json=PROBE, headers=ACCEPT, timeout=TIMEOUT) as r:
            challenge = r.headers.get("WWW-Authenticate", "") if r.status == 401 else ""
    except (aiohttp.ClientError, TimeoutError) as exc:
        raise OAuthError(f"Cannot reach {url}: {type(exc).__name__}", permanent=False) from exc
    params = challenge_params(challenge)
    origin, path = origin_and_path(url)
    candidates = [params["resource_metadata"]] if "resource_metadata" in params else []
    if path:
        candidates.append(f"{origin}/.well-known/oauth-protected-resource{path}")
    candidates.append(f"{origin}/.well-known/oauth-protected-resource")
    resource_meta = None
    for candidate in candidates:
        found = await get_json(session, candidate)
        if found and found.get("authorization_servers"):
            resource_meta = found
            break
    issuer = resource_meta["authorization_servers"][0] if resource_meta else origin
    meta = await server_metadata(session, issuer)
    if meta is None:
        if resource_meta:
            raise OAuthError(f"No authorization server metadata at {issuer}", permanent=False)
        meta = {
            "authorization_endpoint": f"{origin}/authorize",
            "token_endpoint": f"{origin}/token",
            "registration_endpoint": f"{origin}/register",
        }
    if not meta.get("registration_endpoint"):
        raise OAuthError(f"{issuer} does not support dynamic client registration", permanent=True)
    for key in ("authorization_endpoint", "token_endpoint", "registration_endpoint"):
        try:
            validate_url(meta[key])
        except ConfigError as exc:
            # Codes and refresh tokens must never travel in plain text, nor open odd URL schemes.
            raise OAuthError(f"Refusing {key}: {exc}", permanent=True) from exc
    scope = params.get("scope") or " ".join((resource_meta or {}).get("scopes_supported") or [])
    words = scope.split()
    if words and "offline_access" in (meta.get("scopes_supported") or []) and "offline_access" not in words:
        words.append("offline_access")
    return {
        "resource": (resource_meta or {}).get("resource") or url,
        "scope": " ".join(words),
        "authorization_endpoint": meta["authorization_endpoint"],
        "token_endpoint": meta["token_endpoint"],
        "registration_endpoint": meta["registration_endpoint"],
    }


async def register(session: aiohttp.ClientSession, auth: dict, redirect_uri: str) -> dict:
    body = {
        "client_name": "mcpd",
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }
    try:
        async with session.post(auth["registration_endpoint"], json=body, timeout=TIMEOUT) as r:
            data = await r.json(content_type=None)
            status = r.status
    except (aiohttp.ClientError, ValueError, TimeoutError) as exc:
        raise OAuthError(f"Client registration failed: {type(exc).__name__}", permanent=False) from exc
    if status not in (200, 201) or not isinstance(data, dict) or not data.get("client_id"):
        raise OAuthError(f"Client registration rejected (HTTP {status})", permanent=False)
    return {
        "client_id": data["client_id"],
        "client_secret": data.get("client_secret"),
        "auth_method": data.get("token_endpoint_auth_method") or "none",
        "redirect_uri": redirect_uri,
        "registration_endpoint": auth["registration_endpoint"],
    }


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def authorize_url(auth: dict, client: dict, *, state: str, challenge: str) -> str:
    query = {
        "response_type": "code",
        "client_id": client["client_id"],
        "redirect_uri": client["redirect_uri"],
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
        "resource": auth["resource"],
    }
    if auth.get("scope"):
        query["scope"] = auth["scope"]
    sep = "&" if "?" in auth["authorization_endpoint"] else "?"
    return auth["authorization_endpoint"] + sep + urlencode(query)


async def token_request(session: aiohttp.ClientSession, auth: dict, client: dict, form: dict) -> dict:
    form = dict(form, resource=auth["resource"])
    basic = None
    if client.get("client_secret") and client.get("auth_method") == "client_secret_basic":
        basic = aiohttp.BasicAuth(client["client_id"], client["client_secret"])
    else:
        form["client_id"] = client["client_id"]
        if client.get("client_secret"):
            form["client_secret"] = client["client_secret"]
    try:
        async with session.post(
            auth["token_endpoint"],
            data=form,
            auth=basic,
            headers={"Accept": "application/json"},
            timeout=TIMEOUT,
        ) as r:
            status = r.status
            text = await r.text()
    except (aiohttp.ClientError, TimeoutError) as exc:
        raise OAuthError(f"Token endpoint unreachable: {type(exc).__name__}", permanent=False) from exc
    try:
        data = json.loads(text)
    except ValueError:
        data = None
    if status == 200 and isinstance(data, dict) and data.get("access_token"):
        try:
            expires_at = time.time() + float(data["expires_in"]) if data.get("expires_in") else None
        except (TypeError, ValueError):
            expires_at = None
        return {
            "access_token": data["access_token"],
            "refresh_token": data.get("refresh_token"),
            "expires_at": expires_at,
        }
    code = data.get("error") if isinstance(data, dict) else None
    permanent = status in (400, 401) and code in PERMANENT
    raise OAuthError(
        f"Token request failed: HTTP {status} {code or ''}".strip(), permanent=permanent, code=code
    )


async def exchange(
    session: aiohttp.ClientSession, auth: dict, client: dict, *, code: str, verifier: str
) -> dict:
    return await token_request(
        session,
        auth,
        client,
        {
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": client["redirect_uri"],
        },
    )


async def refresh(session: aiohttp.ClientSession, auth: dict, client: dict, refresh_token: str) -> dict:
    return await token_request(
        session, auth, client, {"grant_type": "refresh_token", "refresh_token": refresh_token}
    )
