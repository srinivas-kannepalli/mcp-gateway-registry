"""Downstream OAuth discovery and DCR service."""

from __future__ import annotations

import ipaddress
import logging
import re
import urllib.parse
from typing import Any

import httpx
from mcp.shared.auth import (
    OAuthClientInformationFull,
    OAuthClientMetadata,
    OAuthMetadata,
    ProtectedResourceMetadata,
)
from pydantic import ValidationError

from registry.repositories.documentdb.server_oauth_client_repository import ServerOAuthClientRepository
from registry.schemas.server_oauth_client_models import ServerOAuthClient
from registry.utils.credential_encryption import _get_fernet

logger = logging.getLogger(__name__)

_TIMEOUT = 10.0
_PRIVATE_HOSTS = {"localhost"}
_PREFERRED_AUTH_METHODS: tuple[str, ...] = (
    "client_secret_basic",
    "client_secret_post",
    "none",
)
_WELL_KNOWN_AS_PATHS: tuple[str, ...] = (
    "/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration",
)


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


def _parse_resource_metadata_url(www_authenticate: str) -> str | None:
    """Extract resource_metadata URL from WWW-Authenticate: Bearer header."""
    if not www_authenticate.lower().startswith("bearer"):
        return None

    match = re.search(
        r'resource_metadata\s*=\s*"([^"]+)"',
        www_authenticate,
        re.IGNORECASE,
    )
    return match.group(1) if match else None


def _select_token_auth_method(advertised: list[str]) -> str:
    """Pick the preferred token endpoint auth method from AS metadata."""
    for method in _PREFERRED_AUTH_METHODS:
        if method in advertised:
            return method
    return "none"


def _build_rfc9728_prm_url(resource_url: str) -> str:
    """Construct the RFC 9728 protected-resource metadata URL."""
    parsed = urllib.parse.urlparse(resource_url.rstrip("/"))
    return (
        f"{parsed.scheme}://{parsed.netloc}"
        f"/.well-known/oauth-protected-resource{parsed.path}"
    )


async def _fetch_json(
    client: httpx.AsyncClient,
    url: str,
) -> dict[str, Any]:
    """Fetch a JSON document and raise on HTTP failures."""
    _reject_ssrf(url)
    response = await client.get(url)
    response.raise_for_status()
    return response.json()


async def _discover_protected_resource_metadata(resource_url: str) -> ProtectedResourceMetadata:
    """Fetch and validate protected-resource metadata for a downstream server.

    Args:
        resource_url: Downstream protected resource URL.

    Returns:
        Validated protected-resource metadata.

    Raises:
        httpx.HTTPError: If the PRM fetch fails.
        ValidationError: If the PRM payload is invalid.
    """
    _reject_ssrf(resource_url)
    prm_url: str | None = None

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        try:
            probe = await client.post(resource_url, content=b"{}")
        except httpx.HTTPError as exc:
            logger.debug("OAuth discovery probe failed for %s: %s", resource_url, exc)
        else:
            if probe.status_code == 401:
                prm_url = _parse_resource_metadata_url(
                    probe.headers.get("www-authenticate", ""),
                )

        resolved_prm_url = prm_url or _build_rfc9728_prm_url(resource_url)
        prm_payload = await _fetch_json(client, resolved_prm_url)

    return ProtectedResourceMetadata.model_validate(prm_payload)


async def _discover_as_metadata(issuer_url: str) -> OAuthMetadata:
    """Fetch and validate OAuth authorization server metadata.

    Args:
        issuer_url: OAuth issuer base URL.

    Returns:
        Validated OAuth authorization server metadata.

    Raises:
        ValueError: If no well-known metadata document can be loaded.
    """
    issuer = issuer_url.rstrip("/")

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        for well_known_path in _WELL_KNOWN_AS_PATHS:
            metadata_url = f"{issuer}{well_known_path}"
            try:
                _reject_ssrf(metadata_url)
                response = await client.get(metadata_url)
            except httpx.HTTPError as exc:
                logger.debug("AS metadata fetch failed for %s: %s", metadata_url, exc)
                continue

            if response.status_code != 200:
                logger.debug(
                    "AS metadata fetch returned %s for %s",
                    response.status_code,
                    metadata_url,
                )
                continue

            try:
                metadata = OAuthMetadata.model_validate(response.json())
            except ValidationError as exc:
                logger.debug("AS metadata validation failed for %s: %s", metadata_url, exc)
                continue

            logger.info("Discovered AS metadata via %s", well_known_path)
            return metadata

    raise ValueError(f"Could not fetch AS metadata from {issuer}")


async def discover_as_metadata(proxy_pass_url: str) -> OAuthMetadata:
    """Discover OAuth authorization server metadata for a downstream resource.

    Args:
        proxy_pass_url: Downstream protected resource URL.

    Returns:
        Validated OAuth authorization server metadata.

    Raises:
        ValueError: If the protected resource does not advertise an authorization server.
    """
    try:
        prm = await _discover_protected_resource_metadata(proxy_pass_url)
    except ValidationError as exc:
        if "authorization_servers" in str(exc):
            raise ValueError(f"No authorization_servers in PRM from {proxy_pass_url}") from exc
        raise

    if not prm.authorization_servers:
        raise ValueError(f"No authorization_servers in PRM from {proxy_pass_url}")

    issuer = str(prm.authorization_servers[0]).rstrip("/")
    return await _discover_as_metadata(issuer)


async def register_dcr_client(
    as_metadata: OAuthMetadata,
    gateway_base_url: str,
    server_path: str,
    scopes: list[str],
) -> OAuthClientInformationFull:
    """Register an OAuth client with the downstream authorization server.

    Args:
        as_metadata: Validated authorization server metadata.
        gateway_base_url: Gateway base URL used to build the callback URI.
        server_path: Downstream server path.
        scopes: Requested scopes for the downstream server.

    Returns:
        Validated client information returned by DCR.

    Raises:
        ValueError: If the AS does not expose a registration endpoint.
        httpx.HTTPError: If the DCR request fails.
        ValidationError: If the DCR payload is invalid.
    """
    if not as_metadata.registration_endpoint:
        raise ValueError("Authorization server does not expose registration_endpoint")

    auth_method = _select_token_auth_method(
        list(as_metadata.token_endpoint_auth_methods_supported or []),
    )
    redirect_uri = (
        f"{gateway_base_url.rstrip('/')}/api/servers/"
        f"{server_path.lstrip('/')}/downstream/callback"
    )
    metadata = OAuthClientMetadata(
        redirect_uris=[redirect_uri],
        token_endpoint_auth_method=auth_method,  # type: ignore[arg-type]
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        client_name=f"MCP Gateway - {server_path}",
        scope=" ".join(scopes) if scopes else None,
    )
    payload = metadata.model_dump(mode="json", exclude_none=True)

    registration_endpoint = str(as_metadata.registration_endpoint)
    _reject_ssrf(registration_endpoint)
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        response = await client.post(registration_endpoint, json=payload)
        response.raise_for_status()
        response_payload = response.json()
        client_information = OAuthClientInformationFull.model_validate(response_payload)
        registration_access_token = response_payload.get("registration_access_token")
        if registration_access_token is not None:
            object.__setattr__(
                client_information,
                "registration_access_token",
                registration_access_token,
            )
        return client_information


async def resolve_client_for_server(
    server_path: str,
    proxy_pass_url: str,
    downstream_oauth_config: dict[str, Any],
    gateway_base_url: str,
    repo: ServerOAuthClientRepository,
) -> ServerOAuthClient:
    """Resolve or create the OAuth client for a downstream server.

    Args:
        server_path: Registry server path.
        proxy_pass_url: Downstream proxy URL used for discovery.
        downstream_oauth_config: Downstream OAuth configuration.
        gateway_base_url: Gateway base URL used to build callback URIs.
        repo: Repository used to cache OAuth clients.

    Returns:
        Persisted downstream OAuth client.

    Raises:
        ValueError: If the client cannot be resolved or persisted.
    """
    existing = await repo.get(server_path)
    if existing:
        return existing

    auth_url = downstream_oauth_config.get("auth_url")
    token_url = downstream_oauth_config.get("token_url")
    scopes_supported = list(downstream_oauth_config.get("scopes", []))
    client_id = downstream_oauth_config.get("client_id")
    client_secret = _decrypt_static_secret(
        downstream_oauth_config.get("client_secret_encrypted"),
    )
    registration_access_token: str | None = None
    token_endpoint_auth_method = "none"
    via_dcr = False
    as_metadata: OAuthMetadata | None = None

    if not auth_url or not token_url:
        as_metadata = await discover_as_metadata(proxy_pass_url)
        auth_url = auth_url or str(as_metadata.authorization_endpoint)
        token_url = token_url or str(as_metadata.token_endpoint)
        if as_metadata.scopes_supported:
            scopes_supported = list(as_metadata.scopes_supported)

    if not auth_url or not token_url:
        raise ValueError(f"Could not resolve auth/token endpoints for {server_path}")

    dcr_enabled = bool(downstream_oauth_config.get("dcr_enabled", False))
    if dcr_enabled and as_metadata and as_metadata.registration_endpoint:
        dcr_client = await register_dcr_client(
            as_metadata=as_metadata,
            gateway_base_url=gateway_base_url,
            server_path=server_path,
            scopes=list(downstream_oauth_config.get("scopes", [])),
        )
        client_id = dcr_client.client_id
        token_endpoint_auth_method = dcr_client.token_endpoint_auth_method or "none"
        if token_endpoint_auth_method == "none":
            client_secret = None
        else:
            client_secret = dcr_client.client_secret
        registration_access_token = getattr(dcr_client, "registration_access_token", None)
        via_dcr = True

    if not client_id:
        raise ValueError(f"No client_id available for server {server_path}")

    await repo.upsert(
        server_path=server_path,
        client_id=client_id,
        client_secret=client_secret,
        token_endpoint=token_url,
        authorization_endpoint=auth_url,
        scopes_supported=scopes_supported,
        token_endpoint_auth_method=token_endpoint_auth_method,
        via_dcr=via_dcr,
        registration_access_token=registration_access_token,
    )
    resolved = await repo.get(server_path)
    if resolved is None:
        raise ValueError(f"Failed to persist OAuth client for {server_path}")
    return resolved
