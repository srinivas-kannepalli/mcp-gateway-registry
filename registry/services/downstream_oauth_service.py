"""Downstream OAuth discovery and DCR service."""

from __future__ import annotations

import ipaddress
import logging
import urllib.parse
from typing import Any

import httpx
from mcp.client.auth.utils import (
    build_oauth_authorization_server_metadata_discovery_urls,
    build_protected_resource_metadata_discovery_urls,
    create_client_registration_request,
    extract_resource_metadata_from_www_auth,
    handle_auth_metadata_response,
    handle_protected_resource_response,
)
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


def _select_token_auth_method(advertised: list[str]) -> str:
    """Pick the preferred token endpoint auth method from AS metadata."""
    for method in _PREFERRED_AUTH_METHODS:
        if method in advertised:
            return method
    return "none"


async def _discover_protected_resource_metadata(resource_url: str) -> ProtectedResourceMetadata:
    """Fetch and validate protected-resource metadata for a downstream server.

    Probes the resource endpoint to find the WWW-Authenticate header, then uses
    the SDK's ``build_protected_resource_metadata_discovery_urls`` helper to
    generate ordered candidate URLs (explicit from header → RFC 9728 fallback).

    Args:
        resource_url: Downstream protected resource URL.

    Returns:
        Validated protected-resource metadata.

    Raises:
        ValueError: If no valid PRM can be discovered.
    """
    _reject_ssrf(resource_url)
    www_auth_url: str | None = None

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        try:
            probe = await client.post(resource_url, content=b"{}")
            if probe.status_code == 401:
                www_auth_url = extract_resource_metadata_from_www_auth(probe)
        except httpx.HTTPError as exc:
            logger.debug("OAuth discovery probe failed for %s: %s", resource_url, exc)

        for url in build_protected_resource_metadata_discovery_urls(www_auth_url, resource_url):
            _reject_ssrf(url)
            try:
                response = await client.get(url)
                metadata = await handle_protected_resource_response(response)
                if metadata is not None:
                    return metadata
            except httpx.HTTPError as exc:
                logger.debug("PRM fetch failed for %s: %s", url, exc)

    raise ValueError(f"Could not discover protected-resource metadata for {resource_url}")


async def _discover_as_metadata(issuer_url: str) -> OAuthMetadata:
    """Fetch and validate OAuth authorization server metadata.

    Uses the SDK's ``build_oauth_authorization_server_metadata_discovery_urls``
    to generate ordered candidate URLs (RFC 8414 path-aware, OIDC fallbacks).

    Args:
        issuer_url: OAuth issuer base URL.

    Returns:
        Validated OAuth authorization server metadata.

    Raises:
        ValueError: If no well-known metadata document can be loaded.
    """
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        for url in build_oauth_authorization_server_metadata_discovery_urls(issuer_url, issuer_url):
            try:
                _reject_ssrf(url)
                response = await client.get(url)
                should_continue, metadata = await handle_auth_metadata_response(response)
                if metadata is not None:
                    logger.info("Discovered AS metadata via %s", url)
                    return metadata
                if not should_continue:
                    break
            except httpx.HTTPError as exc:
                logger.debug("AS metadata fetch failed for %s: %s", url, exc)

    raise ValueError(f"Could not fetch AS metadata from {issuer_url}")


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
    """Register an OAuth client with the downstream authorization server via DCR.

    Uses the SDK's ``create_client_registration_request`` to build the RFC 7591
    request, then parses the response manually to preserve the
    ``registration_access_token`` field (RFC 7592) which the SDK model omits.

    Args:
        as_metadata: Validated authorization server metadata.
        gateway_base_url: Gateway base URL used to build the callback URI.
        server_path: Downstream server path.
        scopes: Requested scopes for the downstream server.

    Returns:
        Validated client information returned by DCR, with
        ``registration_access_token`` set as an attribute when present.

    Raises:
        ValueError: If the AS does not expose a registration endpoint.
        httpx.HTTPError: If the DCR request fails.
        ValidationError: If the DCR response payload is invalid.
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
    client_metadata = OAuthClientMetadata(
        redirect_uris=[redirect_uri],
        token_endpoint_auth_method=auth_method,  # type: ignore[arg-type]
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        client_name=f"MCP Gateway - {server_path}",
        scope=" ".join(scopes) if scopes else None,
    )

    # SDK builds the request with correct serialisation (by_alias, exclude_none)
    auth_base_url = str(as_metadata.authorization_endpoint).rstrip("/").rsplit("/", 1)[0]
    request = create_client_registration_request(as_metadata, client_metadata, auth_base_url)
    _reject_ssrf(str(request.url))

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        response = await client.send(request)
        response.raise_for_status()
        response_payload = response.json()

    # Parse via SDK model for field validation, then attach registration_access_token
    # separately — OAuthClientInformationFull does not declare this RFC 7592 field.
    client_info = OAuthClientInformationFull.model_validate(response_payload)
    registration_access_token = response_payload.get("registration_access_token")
    if registration_access_token is not None:
        object.__setattr__(client_info, "registration_access_token", registration_access_token)

    return client_info


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
