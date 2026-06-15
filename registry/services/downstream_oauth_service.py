"""Downstream OAuth discovery and DCR service."""

from __future__ import annotations

import ipaddress
import logging
import urllib.parse
from typing import Any

import httpx

from registry.repositories.documentdb.server_oauth_client_repository import ServerOAuthClientRepository
from registry.schemas.server_oauth_client_models import ServerOAuthClient
from registry.utils.credential_encryption import _get_fernet

logger = logging.getLogger(__name__)

_TIMEOUT = 10.0
_PRIVATE_HOSTS = {"localhost"}


def _decrypt_static_secret(ciphertext: str | None) -> str | None:
    if not ciphertext:
        return None
    fernet = _get_fernet()
    if not fernet:
        return None
    try:
        return fernet.decrypt(ciphertext.encode()).decode()
    except Exception:
        logger.warning("Failed to decrypt downstream static client_secret")
        return None


def _reject_ssrf(url: str) -> None:
    """Raise ValueError if the URL resolves to a private/loopback address."""
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    if host in _PRIVATE_HOSTS:
        raise ValueError(f"SSRF protection: private/loopback host rejected: {host}")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        raise ValueError(f"SSRF protection: private/loopback host rejected: {host}")


async def discover_as_metadata(proxy_pass_url: str) -> dict[str, Any]:
    """Discover AS metadata for an OAuth-protected MCP server.

    Discovery order (MCP spec + RFC 9728):
    1. Make an unauthenticated request to the resource URL and parse the
       `resource_metadata` field from the `WWW-Authenticate: Bearer` header
       on the 401 response.  This is the most reliable source.
    2. If the header is absent, construct the PRM URL per RFC 9728 §3:
         {scheme}://{host}/.well-known/oauth-protected-resource{path}
    3. Fetch the PRM document, walk the `authorization_servers` list, and
       fetch the AS metadata from the standard well-known endpoints.
    """
    prm_url: str | None = None

    # Step 1 — probe the resource endpoint and read WWW-Authenticate.
    try:
        _reject_ssrf(proxy_pass_url)
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            probe = await client.post(proxy_pass_url, content=b"{}")
        if probe.status_code == 401:
            www_auth = probe.headers.get("www-authenticate", "")
            prm_url = _parse_resource_metadata(www_auth)
            if prm_url:
                logger.debug("OAuth discovery: resource_metadata from WWW-Authenticate: %s", prm_url)
    except Exception as exc:
        logger.debug("OAuth discovery probe failed for %s: %s", proxy_pass_url, exc)

    # Step 2 — fall back to RFC 9728 URL construction.
    if not prm_url:
        parsed = urllib.parse.urlparse(proxy_pass_url.rstrip("/"))
        resource_path = parsed.path  # e.g. "/mcp"
        prm_url = f"{parsed.scheme}://{parsed.netloc}/.well-known/oauth-protected-resource{resource_path}"
        logger.debug("OAuth discovery: using RFC 9728 constructed PRM URL: %s", prm_url)

    # Step 3 — fetch PRM and walk to AS metadata.
    _reject_ssrf(prm_url)
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        prm_resp = await client.get(prm_url)
        prm_resp.raise_for_status()
        prm = prm_resp.json()

    as_urls: list[str] = prm.get("authorization_servers", [])
    if not as_urls:
        raise ValueError(f"No authorization_servers in PRM from {prm_url}")

    as_issuer = as_urls[0].rstrip("/")
    for well_known_path in (
        "/.well-known/oauth-authorization-server",
        "/.well-known/openid-configuration",
    ):
        as_meta_url = f"{as_issuer}{well_known_path}"
        try:
            _reject_ssrf(as_meta_url)
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                meta_resp = await client.get(as_meta_url)
                if meta_resp.status_code == 200:
                    return meta_resp.json()
        except Exception as exc:
            logger.debug("AS metadata fetch from %s failed: %s", as_meta_url, exc)

    raise ValueError(f"Could not fetch AS metadata from {as_issuer}")


def _parse_resource_metadata(www_authenticate: str) -> str | None:
    """Extract resource_metadata URL from a WWW-Authenticate: Bearer header.

    Header format (RFC 6750 / MCP spec):
      Bearer error="...", resource_metadata="https://..."
    """
    if not www_authenticate.lower().startswith("bearer"):
        return None
    import re
    match = re.search(r'resource_metadata\s*=\s*"([^"]+)"', www_authenticate, re.IGNORECASE)
    return match.group(1) if match else None


async def register_dcr_client(
    registration_endpoint: str,
    gateway_base_url: str,
    server_path: str,
    scopes: list[str],
) -> dict[str, Any]:
    """Perform RFC 7591 Dynamic Client Registration."""
    _reject_ssrf(registration_endpoint)
    redirect_uri = f"{gateway_base_url.rstrip('/')}/api/servers/{server_path}/downstream/callback"
    payload = {
        "client_name": f"MCP Gateway — {server_path}",
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_basic",
        "scope": " ".join(scopes) if scopes else "",
    }
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.post(registration_endpoint, json=payload)
        resp.raise_for_status()
        return resp.json()


async def resolve_client_for_server(
    server_path: str,
    proxy_pass_url: str,
    downstream_oauth_config: dict[str, Any],
    gateway_base_url: str,
    repo: ServerOAuthClientRepository,
) -> ServerOAuthClient:
    """Resolve or create the OAuth client for a downstream server."""
    existing = await repo.get(server_path)
    if existing:
        return existing

    auth_url = downstream_oauth_config.get("auth_url")
    token_url = downstream_oauth_config.get("token_url")
    scopes_supported = downstream_oauth_config.get("scopes", [])
    registration_endpoint = None

    if not auth_url or not token_url:
        as_meta = await discover_as_metadata(proxy_pass_url)
        auth_url = auth_url or as_meta.get("authorization_endpoint")
        token_url = token_url or as_meta.get("token_endpoint")
        scopes_supported = as_meta.get("scopes_supported", scopes_supported)
        registration_endpoint = as_meta.get("registration_endpoint")

    if not auth_url or not token_url:
        raise ValueError(f"Could not resolve auth/token endpoints for {server_path}")

    dcr_enabled = downstream_oauth_config.get("dcr_enabled", False)
    client_id = downstream_oauth_config.get("client_id")
    client_secret = _decrypt_static_secret(downstream_oauth_config.get("client_secret_encrypted"))
    registration_access_token: str | None = None
    via_dcr = False

    if dcr_enabled and registration_endpoint:
        scopes = downstream_oauth_config.get("scopes", [])
        dcr_result = await register_dcr_client(
            registration_endpoint,
            gateway_base_url,
            server_path,
            scopes,
        )
        client_id = dcr_result["client_id"]
        client_secret = dcr_result.get("client_secret")
        registration_access_token = dcr_result.get("registration_access_token")
        via_dcr = True
        logger.info("DCR completed for server %s, client_id=%s", server_path, client_id)

    if not client_id:
        raise ValueError(f"No client_id available for server {server_path}")

    await repo.upsert(
        server_path=server_path,
        client_id=client_id,
        client_secret=client_secret,
        token_endpoint=token_url,
        authorization_endpoint=auth_url,
        scopes_supported=scopes_supported,
        via_dcr=via_dcr,
        registration_access_token=registration_access_token,
    )
    resolved = await repo.get(server_path)
    if resolved is None:
        raise ValueError(f"Failed to persist OAuth client for {server_path}")
    return resolved
