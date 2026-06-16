"""Downstream OAuth flow endpoints."""

from __future__ import annotations

import base64
import logging
import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from mcp.client.auth import PKCEParameters
from mcp.client.auth.utils import get_client_metadata_scopes

from registry.auth.dependencies import enhanced_auth
from registry.repositories.factory import (
    get_downstream_consent_repository,
    get_downstream_oauth_state_repository,
    get_server_oauth_client_repository,
    get_user_server_token_repository,
)
from registry.repositories.documentdb.server_oauth_client_repository import _decrypt as _decrypt_client_secret
from registry.schemas.server_oauth_client_models import ServerOAuthClient
from registry.schemas.user_server_token_models import UserServerTokenCreate, UserServerTokenStatus
from registry.services.downstream_oauth_service import resolve_client_for_server
from registry.services.server_service import server_service

logger = logging.getLogger(__name__)

router = APIRouter(tags=["downstream-oauth"])

_token_repo = get_user_server_token_repository()
_client_repo = get_server_oauth_client_repository()
_consent_repo = get_downstream_consent_repository()
_state_repo = get_downstream_oauth_state_repository()


def _build_token_exchange_request(
    oauth_client: ServerOAuthClient,
    code: str,
    redirect_uri: str,
    code_verifier: str,
    resource_indicator: str,
) -> tuple[dict[str, Any], dict[str, str]]:
    """Build token exchange data and headers for the configured client auth method.

    Supported methods:
    - ``none``: PKCE only, no client credentials
    - ``client_secret_basic``: Basic auth header
    - ``client_secret_post``: client credentials in the form body

    Raises:
        ValueError: If the auth method is unsupported or required credentials are missing.
    """
    token_endpoint_auth_method = oauth_client.token_endpoint_auth_method or "none"
    data: dict[str, Any] = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    }
    # Only include resource if non-empty (some providers reject unknown params)
    if resource_indicator:
        data["resource"] = resource_indicator
    headers: dict[str, str] = {}

    if token_endpoint_auth_method == "none":
        data["client_id"] = oauth_client.client_id
        return data, headers

    client_secret = _decrypt_client_secret(oauth_client.client_secret_encrypted)
    if not client_secret:
        raise ValueError(
            f"Missing client_secret for token endpoint auth method {token_endpoint_auth_method}",
        )

    if token_endpoint_auth_method == "client_secret_basic":
        credentials = base64.b64encode(
            f"{oauth_client.client_id}:{client_secret}".encode(),
        ).decode()
        headers["Authorization"] = f"Basic {credentials}"
        # Also include client_id in the body — some servers (e.g. Miro) require it
        # in the request body even when using HTTP Basic authentication.
        data["client_id"] = oauth_client.client_id
        return data, headers

    if token_endpoint_auth_method == "client_secret_post":
        data["client_id"] = oauth_client.client_id
        data["client_secret"] = client_secret
        return data, headers

    if token_endpoint_auth_method in {"private_key_jwt", "client_secret_jwt"}:
        raise ValueError(
            f"Unsupported token endpoint auth method: {token_endpoint_auth_method}",
        )

    raise ValueError(f"Unknown token endpoint auth method: {token_endpoint_auth_method}")


def _normalize_path(path: str) -> str:
    return path if path.startswith("/") else f"/{path}"


def _get_proxy_url(server: dict[str, Any]) -> str:
    return server.get("proxy_pass_url") or server.get("mcp_endpoint") or ""


def _get_resource_indicator(server: dict[str, Any]) -> str:
    downstream_oauth = server.get("downstream_oauth", {})
    return downstream_oauth.get("resource_indicator") or _get_proxy_url(server)


async def _get_server_or_404(path: str) -> dict[str, Any]:
    normalized_path = _normalize_path(path)
    server = await server_service.get_server_info(normalized_path)
    if not server:
        raise HTTPException(status_code=404, detail=f"Server '{path}' not found")
    return server


@router.get("/servers/{path:path}/downstream/authorize")
async def downstream_authorize(
    path: str,
    request: Request,
    user_context: Annotated[dict[str, Any], Depends(enhanced_auth)],
) -> RedirectResponse:
    """Initiate downstream OAuth flow for the current user."""
    server = await _get_server_or_404(path)
    downstream_oauth = server.get("downstream_oauth", {})
    if downstream_oauth.get("downstream_auth_type", "none") != "oauth2":
        raise HTTPException(status_code=400, detail="Server does not require downstream OAuth")

    # Require at least auth_url+token_url OR a proxy_pass_url to discover them from.
    has_manual_endpoints = downstream_oauth.get("auth_url") and downstream_oauth.get("token_url")
    proxy_pass_url = _get_proxy_url(server)
    if not has_manual_endpoints and not proxy_pass_url:
        raise HTTPException(
            status_code=400,
            detail=(
                "Cannot initiate OAuth: server has no auth_url/token_url configured and no "
                "proxy_pass_url to auto-discover them from. Edit the server and add the "
                "Authorization URL and Token URL."
            ),
        )

    normalized_path = server.get("path", _normalize_path(path))
    username = user_context["username"]
    gateway_base_url = str(request.base_url).rstrip("/")
    try:
        oauth_client = await resolve_client_for_server(
            server_path=normalized_path,
            proxy_pass_url=proxy_pass_url,
            downstream_oauth_config=downstream_oauth,
            gateway_base_url=gateway_base_url,
            repo=_client_repo,
        )
    except ValueError as exc:
        logger.warning("OAuth client resolution failed for %s: %s", normalized_path, exc)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except httpx.HTTPStatusError as exc:
        logger.warning("HTTP error during OAuth setup for %s: %s", normalized_path, exc)
        raise HTTPException(
            status_code=502,
            detail=f"Upstream OAuth server returned an error: {exc.response.status_code}",
        ) from exc
    except httpx.RequestError as exc:
        logger.warning("Network error during OAuth setup for %s: %s", normalized_path, exc)
        raise HTTPException(
            status_code=502,
            detail="Could not reach the upstream OAuth server. Check the server URL.",
        ) from exc

    pkce = PKCEParameters.generate()
    state = secrets.token_urlsafe(32)
    await _state_repo.save(
        state,
        {
            "username": username,
            "server_path": normalized_path,
            "code_verifier": pkce.code_verifier,
        },
    )

    # Scope selection per MCP spec (§2.3.2):
    # 1. User-configured scopes (explicit intent)
    # 2. AS-advertised scopes_supported stored from discovery
    # 3. Omit scope parameter (let AS assign defaults)
    configured_scopes: list[str] = downstream_oauth.get("scopes") or []
    scope_str: str | None
    if configured_scopes:
        scope_str = " ".join(configured_scopes)
    else:
        # get_client_metadata_scopes selects per MCP spec priority; pass stored
        # scopes_supported as the AS metadata equivalent (no live re-fetch needed)
        scope_str = get_client_metadata_scopes(
            www_authenticate_scope=None,
            protected_resource_metadata=None,
            authorization_server_metadata=None,
        )
        if not scope_str and oauth_client.scopes_supported:
            scope_str = " ".join(oauth_client.scopes_supported)

    await _consent_repo.record_consent(username, normalized_path, configured_scopes)

    params: dict[str, str] = {
        "response_type": "code",
        "client_id": oauth_client.client_id,
        "redirect_uri": (
            f"{gateway_base_url}/api/servers/{normalized_path.lstrip('/')}/downstream/callback"
        ),
        "state": state,
        "code_challenge": pkce.code_challenge,
        "code_challenge_method": "S256",
    }
    if scope_str:
        params["scope"] = scope_str
    resource = _get_resource_indicator(server)
    if resource:
        params["resource"] = resource
    redirect_url = f"{oauth_client.authorization_endpoint}?{urlencode(params)}"
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_302_FOUND)


@router.get("/servers/{path:path}/downstream/callback")
async def downstream_callback(
    path: str,
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
) -> HTMLResponse:
    """Handle downstream callback, exchange code for tokens, and persist them."""
    if error:
        return HTMLResponse(f"<h2>Authorization failed</h2><p>{error}</p>", status_code=400)
    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing code or state")

    state_data = await _state_repo.consume(state)
    if not state_data:
        raise HTTPException(status_code=400, detail="Invalid or expired state")

    normalized_path = _normalize_path(path)
    if state_data["server_path"] != normalized_path:
        raise HTTPException(status_code=400, detail="State/path mismatch")

    server = await _get_server_or_404(normalized_path)
    oauth_client = await _client_repo.get(normalized_path)
    if not oauth_client:
        raise HTTPException(status_code=500, detail="OAuth client config missing")

    gateway_base_url = str(request.base_url).rstrip("/")
    redirect_uri = (
        f"{gateway_base_url}/api/servers/{normalized_path.lstrip('/')}/downstream/callback"
    )
    try:
        token_payload, token_headers = _build_token_exchange_request(
            oauth_client=oauth_client,
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=state_data["code_verifier"],
            resource_indicator=_get_resource_indicator(server),
        )
    except ValueError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            oauth_client.token_endpoint,
            data=token_payload,
            headers=token_headers,
        )
        if not resp.is_success:
            error_body = resp.text
            logger.error(
                "Token exchange failed for %s: status=%s body=%s",
                normalized_path,
                resp.status_code,
                error_body[:500],
            )
            # On 401/400 the DCR client registration has likely expired.
            # Purge it and redirect back to /authorize so the flow restarts
            # transparently (fresh DCR + new authorization request).
            if resp.status_code in (400, 401):
                try:
                    await _client_repo.delete(normalized_path)
                    logger.info(
                        "Purged stale DCR client for %s after token exchange %s — redirecting to re-authorize",
                        normalized_path,
                        resp.status_code,
                    )
                except Exception as purge_exc:
                    logger.warning("Failed to purge DCR client: %s", purge_exc)
                authorize_url = (
                    f"/api/servers/{normalized_path.lstrip('/')}/downstream/authorize"
                )
                return HTMLResponse(
                    f"<script>window.location.href = '{authorize_url}';</script>"
                    f"<p>Redirecting to re-authorize...</p>",
                    status_code=200,
                )
            return HTMLResponse(
                f"<h2>Authorization failed</h2>"
                f"<p>The authorization server returned an unexpected error "
                f"(HTTP {resp.status_code}): {error_body[:200]}</p>"
                f"<p>Please close this window and try again.</p>"
                f"<script>window.opener && window.opener.postMessage('oauth_error', '*');</script>",
                status_code=400,
            )
        token_data = resp.json()

    expires_at = None
    if "expires_in" in token_data:
        expires_at = datetime.now(UTC) + timedelta(seconds=int(token_data["expires_in"]))

    await _token_repo.upsert(
        UserServerTokenCreate(
            username=state_data["username"],
            server_path=normalized_path,
            access_token=token_data["access_token"],
            refresh_token=token_data.get("refresh_token"),
            expires_at=expires_at,
            token_type=token_data.get("token_type", "Bearer"),
            scope=token_data.get("scope"),
        )
    )

    logger.info(
        "Downstream OAuth token stored for user=%s server=%s",
        state_data["username"],
        normalized_path,
    )
    return HTMLResponse(
        "<h2>Connected!</h2><p>You can close this window.</p>"
        "<script>window.opener && window.opener.postMessage('oauth_complete', '*'); window.close();</script>"
    )


@router.get("/servers/{path:path}/downstream/token/status")
async def downstream_token_status(
    path: str,
    user_context: Annotated[dict[str, Any], Depends(enhanced_auth)],
) -> UserServerTokenStatus:
    """Return the downstream token status for the current user."""
    server = await _get_server_or_404(path)
    normalized_path = server.get("path", _normalize_path(path))
    token = await _token_repo.get(user_context["username"], normalized_path)
    if not token:
        return UserServerTokenStatus(server_path=normalized_path, has_token=False, is_expired=True)

    expired = await _token_repo.is_expired(user_context["username"], normalized_path)
    return UserServerTokenStatus(
        server_path=normalized_path,
        has_token=True,
        is_expired=expired,
        scope=token.scope,
        expires_at=token.expires_at,
    )


@router.delete("/servers/{path:path}/downstream/token", status_code=status.HTTP_204_NO_CONTENT)
async def downstream_token_revoke(
    path: str,
    user_context: Annotated[dict[str, Any], Depends(enhanced_auth)],
) -> None:
    """Delete the stored downstream token for the current user."""
    server = await _get_server_or_404(path)
    normalized_path = server.get("path", _normalize_path(path))
    username = user_context["username"]
    await _token_repo.delete(username, normalized_path)
    await _consent_repo.revoke_consent(username, normalized_path)
