"""Unit tests for downstream OAuth service helpers."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from mcp.client.auth.utils import extract_resource_metadata_from_www_auth
from mcp.shared.auth import OAuthClientInformationFull, OAuthMetadata, ProtectedResourceMetadata
from pydantic import ValidationError

from registry.schemas.server_oauth_client_models import ServerOAuthClient
from registry.services.downstream_oauth_service import (
    _discover_as_metadata,
    _discover_protected_resource_metadata,
    _reject_ssrf,
    _select_token_auth_method,
    discover_as_metadata,
    register_dcr_client,
    resolve_client_for_server,
)


def _response(
    status_code: int,
    payload: dict | None,
    method: str = "GET",
    url: str = "https://example.com",
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    request = httpx.Request(method, url)
    return httpx.Response(
        status_code=status_code,
        json=payload,
        headers=headers,
        request=request,
    )


@pytest.fixture
def mock_httpx_client() -> AsyncMock:
    with patch("registry.services.downstream_oauth_service.httpx.AsyncClient") as mock_client:
        instance = AsyncMock()
        mock_client.return_value.__aenter__ = AsyncMock(return_value=instance)
        mock_client.return_value.__aexit__ = AsyncMock(return_value=False)
        yield instance


def _oauth_metadata(**overrides: object) -> OAuthMetadata:
    payload: dict[str, object] = {
        "issuer": "https://auth.example.com",
        "authorization_endpoint": "https://auth.example.com/authorize",
        "token_endpoint": "https://auth.example.com/token",
    }
    payload.update(overrides)
    return OAuthMetadata.model_validate(payload)


def _oauth_client_info(**overrides: object) -> OAuthClientInformationFull:
    payload: dict[str, object] = {
        "client_id": "client-123",
        "client_secret": "secret-123",
        "redirect_uris": [
            "https://gateway.example.com/api/servers/jira/downstream/callback",
        ],
        "token_endpoint_auth_method": "client_secret_basic",
    }
    payload.update(overrides)
    return OAuthClientInformationFull.model_validate(payload)


class TestRejectSsrf:
    """Tests for SSRF guardrail."""

    def test_reject_localhost(self) -> None:
        with pytest.raises(ValueError, match="SSRF protection"):
            _reject_ssrf("http://localhost/path")

    def test_reject_private_ipv4(self) -> None:
        with pytest.raises(ValueError, match="SSRF protection"):
            _reject_ssrf("http://192.168.1.1/path")

    def test_reject_loopback(self) -> None:
        with pytest.raises(ValueError, match="SSRF protection"):
            _reject_ssrf("http://127.0.0.1/path")

    def test_allow_public_hostname(self) -> None:
        _reject_ssrf("https://atlassian.net/path")


class TestParseResourceMetadataUrl:
    """WWW-Authenticate header parsing is now delegated to the MCP SDK.

    These tests verify the SDK's ``extract_resource_metadata_from_www_auth``
    works correctly via a real httpx.Response so we catch any SDK API changes.
    """

    def _make_response(self, www_authenticate: str) -> httpx.Response:
        request = httpx.Request("POST", "https://resource.example.com/mcp")
        return httpx.Response(
            status_code=401,
            headers={"WWW-Authenticate": www_authenticate},
            request=request,
        )

    def test_extracts_url_from_bearer_header(self) -> None:
        response = self._make_response(
            'Bearer resource_metadata="https://resource.example.com/.well-known/oauth"'
        )
        assert (
            extract_resource_metadata_from_www_auth(response)
            == "https://resource.example.com/.well-known/oauth"
        )

    def test_returns_none_when_resource_metadata_absent(self) -> None:
        response = self._make_response('Bearer error="invalid_token"')
        assert extract_resource_metadata_from_www_auth(response) is None


class TestSelectTokenAuthMethod:
    """Tests for token endpoint authentication method selection."""

    def test_prefers_client_secret_basic(self) -> None:
        result = _select_token_auth_method(["none", "client_secret_basic"])

        assert result == "client_secret_basic"

    def test_falls_back_to_client_secret_post_when_basic_absent(self) -> None:
        result = _select_token_auth_method(["client_secret_post", "none"])

        assert result == "client_secret_post"

    def test_returns_none_when_only_none_advertised(self) -> None:
        result = _select_token_auth_method(["none"])

        assert result == "none"

    def test_returns_none_when_list_empty(self) -> None:
        result = _select_token_auth_method([])

        assert result == "none"

    def test_returns_none_when_unknown_method_only(self) -> None:
        result = _select_token_auth_method(["private_key_jwt"])

        assert result == "none"


class TestDiscoverProtectedResourceMetadata:
    """Tests for protected-resource metadata discovery."""

    async def test_uses_www_authenticate_resource_metadata_url(
        self,
        mock_httpx_client: AsyncMock,
    ) -> None:
        mock_httpx_client.post.return_value = _response(
            401,
            {"error": "invalid_token"},
            method="POST",
            url="https://resource.example.com/mcp",
            headers={
                "WWW-Authenticate": (
                    'Bearer resource_metadata="https://resource.example.com/custom-prm"'
                ),
            },
        )
        mock_httpx_client.get.return_value = _response(
            200,
            {
                "resource": "https://resource.example.com/mcp",
                "authorization_servers": ["https://auth.example.com"],
            },
            url="https://resource.example.com/custom-prm",
        )

        result = await _discover_protected_resource_metadata("https://resource.example.com/mcp")

        assert isinstance(result, ProtectedResourceMetadata)
        assert str(result.resource) == "https://resource.example.com/mcp"
        assert mock_httpx_client.get.await_args.args[0] == "https://resource.example.com/custom-prm"

    async def test_falls_back_to_rfc9728_url_construction_when_no_header(
        self,
        mock_httpx_client: AsyncMock,
    ) -> None:
        mock_httpx_client.post.return_value = _response(
            401,
            {"error": "invalid_token"},
            method="POST",
            url="https://resource.example.com/mcp",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        )
        mock_httpx_client.get.return_value = _response(
            200,
            {
                "resource": "https://resource.example.com/mcp",
                "authorization_servers": ["https://auth.example.com"],
            },
            url="https://resource.example.com/.well-known/oauth-protected-resource/mcp",
        )

        await _discover_protected_resource_metadata("https://resource.example.com/mcp")

        assert (
            mock_httpx_client.get.await_args.args[0]
            == "https://resource.example.com/.well-known/oauth-protected-resource/mcp"
        )

    async def test_falls_back_to_rfc9728_when_probe_returns_non_401(
        self,
        mock_httpx_client: AsyncMock,
    ) -> None:
        mock_httpx_client.post.return_value = _response(
            200,
            {"ok": True},
            method="POST",
            url="https://resource.example.com/mcp",
        )
        mock_httpx_client.get.return_value = _response(
            200,
            {
                "resource": "https://resource.example.com/mcp",
                "authorization_servers": ["https://auth.example.com"],
            },
            url="https://resource.example.com/.well-known/oauth-protected-resource/mcp",
        )

        await _discover_protected_resource_metadata("https://resource.example.com/mcp")

        assert (
            mock_httpx_client.get.await_args.args[0]
            == "https://resource.example.com/.well-known/oauth-protected-resource/mcp"
        )

    async def test_raises_on_prm_fetch_failure(self, mock_httpx_client: AsyncMock) -> None:
        mock_httpx_client.post.return_value = _response(
            200,
            {"ok": True},
            method="POST",
            url="https://resource.example.com/mcp",
        )
        failing_response = _response(
            500,
            {"error": "server_error"},
            url="https://resource.example.com/.well-known/oauth-protected-resource/mcp",
        )
        mock_httpx_client.get.return_value = failing_response

        with pytest.raises(ValueError, match="Could not discover protected-resource metadata"):
            await _discover_protected_resource_metadata("https://resource.example.com/mcp")


class TestDiscoverAsMetadata:
    """Tests for OAuth authorization server metadata discovery."""

    async def test_uses_oauth_authorization_server_well_known(
        self,
        mock_httpx_client: AsyncMock,
    ) -> None:
        mock_httpx_client.get.return_value = _response(
            200,
            {
                "issuer": "https://auth.example.com",
                "authorization_endpoint": "https://auth.example.com/authorize",
                "token_endpoint": "https://auth.example.com/token",
            },
            url="https://auth.example.com/.well-known/oauth-authorization-server",
        )

        result = await _discover_as_metadata("https://auth.example.com")

        assert isinstance(result, OAuthMetadata)
        assert str(result.authorization_endpoint) == "https://auth.example.com/authorize"
        assert (
            mock_httpx_client.get.await_args.args[0]
            == "https://auth.example.com/.well-known/oauth-authorization-server"
        )

    async def test_falls_back_to_openid_configuration(
        self,
        mock_httpx_client: AsyncMock,
    ) -> None:
        mock_httpx_client.get.side_effect = [
            _response(
                404,
                {"error": "not_found"},
                url="https://auth.example.com/.well-known/oauth-authorization-server",
            ),
            _response(
                200,
                {
                    "issuer": "https://auth.example.com",
                    "authorization_endpoint": "https://auth.example.com/authorize",
                    "token_endpoint": "https://auth.example.com/token",
                },
                url="https://auth.example.com/.well-known/openid-configuration",
            ),
        ]

        result = await _discover_as_metadata("https://auth.example.com")

        assert isinstance(result, OAuthMetadata)
        assert mock_httpx_client.get.await_count == 2

    async def test_raises_when_both_fail(self, mock_httpx_client: AsyncMock) -> None:
        mock_httpx_client.get.side_effect = [
            _response(
                404,
                {"error": "not_found"},
                url="https://auth.example.com/.well-known/oauth-authorization-server",
            ),
            _response(
                404,
                {"error": "not_found"},
                url="https://auth.example.com/.well-known/openid-configuration",
            ),
        ]

        with pytest.raises(ValueError, match="Could not fetch AS metadata"):
            await _discover_as_metadata("https://auth.example.com")

    async def test_validates_response_with_pydantic_model(
        self,
        mock_httpx_client: AsyncMock,
    ) -> None:
        mock_httpx_client.get.side_effect = [
            _response(
                200,
                {
                    "issuer": "https://auth.example.com",
                    "authorization_endpoint": "https://auth.example.com/authorize",
                },
                url="https://auth.example.com/.well-known/oauth-authorization-server",
            ),
            _response(
                404,
                {"error": "not_found"},
                url="https://auth.example.com/.well-known/openid-configuration",
            ),
        ]

        with pytest.raises(ValueError, match="Could not fetch AS metadata"):
            await _discover_as_metadata("https://auth.example.com")


class TestDiscoverAsMetadataFull:
    """Tests for the public protected-resource to AS metadata discovery pipeline."""

    async def test_full_pipeline_www_auth_to_as_metadata(
        self,
        mock_httpx_client: AsyncMock,
    ) -> None:
        mock_httpx_client.post.return_value = _response(
            401,
            {"error": "invalid_token"},
            method="POST",
            url="https://resource.example.com/mcp",
            headers={
                "WWW-Authenticate": (
                    'Bearer resource_metadata="https://resource.example.com/custom-prm"'
                ),
            },
        )
        mock_httpx_client.get.side_effect = [
            _response(
                200,
                {
                    "resource": "https://resource.example.com/mcp",
                    "authorization_servers": ["https://auth.example.com"],
                },
                url="https://resource.example.com/custom-prm",
            ),
            _response(
                200,
                {
                    "issuer": "https://auth.example.com",
                    "authorization_endpoint": "https://auth.example.com/authorize",
                    "token_endpoint": "https://auth.example.com/token",
                },
                url="https://auth.example.com/.well-known/oauth-authorization-server",
            ),
        ]

        result = await discover_as_metadata("https://resource.example.com/mcp")

        assert isinstance(result, OAuthMetadata)
        assert str(result.token_endpoint) == "https://auth.example.com/token"

    async def test_raises_when_prm_has_no_authorization_servers(
        self,
        mock_httpx_client: AsyncMock,
    ) -> None:
        mock_httpx_client.post.return_value = _response(
            401,
            {"error": "invalid_token"},
            method="POST",
            url="https://resource.example.com/mcp",
            headers={
                "WWW-Authenticate": (
                    'Bearer resource_metadata="https://resource.example.com/custom-prm"'
                ),
            },
        )
        mock_httpx_client.get.return_value = _response(
            200,
            {
                "resource": "https://resource.example.com/mcp",
                "authorization_servers": [],
            },
            url="https://resource.example.com/custom-prm",
        )

        with pytest.raises(ValueError, match="Could not discover protected-resource metadata"):
            await discover_as_metadata("https://resource.example.com/mcp")


class TestRegisterDcrClient:
    """Tests for dynamic client registration."""

    def _dcr_response(self, payload: dict) -> httpx.Response:
        """Build a mock DCR response via client.send()."""
        request = httpx.Request("POST", "https://auth.example.com/register")
        return httpx.Response(status_code=201, json=payload, request=request)

    def _sent_payload(self, mock_httpx_client: AsyncMock) -> dict:
        """Extract the JSON body from the request passed to client.send()."""
        sent_request: httpx.Request = mock_httpx_client.send.call_args.args[0]
        return json.loads(sent_request.content)

    async def test_selects_auth_method_from_as_metadata(self, mock_httpx_client: AsyncMock) -> None:
        mock_httpx_client.send.return_value = self._dcr_response(
            {
                "client_id": "client-123",
                "client_secret": "secret-123",
                "redirect_uris": [
                    "https://gateway.example.com/api/servers/jira/downstream/callback",
                ],
                "token_endpoint_auth_method": "client_secret_basic",
            }
        )

        await register_dcr_client(
            as_metadata=_oauth_metadata(
                registration_endpoint="https://auth.example.com/register",
                token_endpoint_auth_methods_supported=["none", "client_secret_basic"],
            ),
            gateway_base_url="https://gateway.example.com",
            server_path="/jira",
            scopes=["read"],
        )

        payload = self._sent_payload(mock_httpx_client)
        assert payload["token_endpoint_auth_method"] == "client_secret_basic"

    async def test_builds_correct_payload_with_scopes(self, mock_httpx_client: AsyncMock) -> None:
        mock_httpx_client.send.return_value = self._dcr_response(
            {
                "client_id": "client-123",
                "client_secret": "secret-123",
                "redirect_uris": [
                    "https://gateway.example.com/api/servers/jira/downstream/callback",
                ],
                "token_endpoint_auth_method": "client_secret_basic",
            }
        )

        await register_dcr_client(
            as_metadata=_oauth_metadata(registration_endpoint="https://auth.example.com/register"),
            gateway_base_url="https://gateway.example.com",
            server_path="/jira",
            scopes=["read", "write"],
        )

        payload = self._sent_payload(mock_httpx_client)
        assert payload["scope"] == "read write"
        assert payload["redirect_uris"] == [
            "https://gateway.example.com/api/servers/jira/downstream/callback",
        ]

    async def test_builds_correct_payload_without_scopes(self, mock_httpx_client: AsyncMock) -> None:
        mock_httpx_client.send.return_value = self._dcr_response(
            {
                "client_id": "client-123",
                "client_secret": "secret-123",
                "redirect_uris": [
                    "https://gateway.example.com/api/servers/jira/downstream/callback",
                ],
                "token_endpoint_auth_method": "client_secret_basic",
            }
        )

        await register_dcr_client(
            as_metadata=_oauth_metadata(registration_endpoint="https://auth.example.com/register"),
            gateway_base_url="https://gateway.example.com",
            server_path="/jira",
            scopes=[],
        )

        payload = self._sent_payload(mock_httpx_client)
        assert "scope" not in payload

    async def test_returns_validated_client_information(
        self,
        mock_httpx_client: AsyncMock,
    ) -> None:
        mock_httpx_client.send.return_value = self._dcr_response(
            {
                "client_id": "client-123",
                "client_secret": "secret-123",
                "redirect_uris": [
                    "https://gateway.example.com/api/servers/jira/downstream/callback",
                ],
                "token_endpoint_auth_method": "client_secret_post",
            }
        )

        result = await register_dcr_client(
            as_metadata=_oauth_metadata(registration_endpoint="https://auth.example.com/register"),
            gateway_base_url="https://gateway.example.com",
            server_path="/jira",
            scopes=["read"],
        )

        assert isinstance(result, OAuthClientInformationFull)
        assert result.token_endpoint_auth_method == "client_secret_post"

    async def test_raises_when_no_registration_endpoint(self) -> None:
        with pytest.raises(ValueError, match="registration_endpoint"):
            await register_dcr_client(
                as_metadata=_oauth_metadata(),
                gateway_base_url="https://gateway.example.com",
                server_path="/jira",
                scopes=["read"],
            )

    async def test_raises_on_dcr_http_error(self, mock_httpx_client: AsyncMock) -> None:
        request = httpx.Request("POST", "https://auth.example.com/register")
        mock_httpx_client.send.return_value = httpx.Response(
            status_code=400,
            json={"error": "invalid_client_metadata"},
            request=request,
        )

        with pytest.raises(httpx.HTTPStatusError):
            await register_dcr_client(
                as_metadata=_oauth_metadata(registration_endpoint="https://auth.example.com/register"),
                gateway_base_url="https://gateway.example.com",
                server_path="/jira",
                scopes=["read"],
            )


class TestResolveClientForServer:
    """Tests for client resolution and persistence."""

    async def test_returns_existing_cached_client(self) -> None:
        existing = ServerOAuthClient(
            server_path="/jira",
            client_id="client-123",
            token_endpoint_auth_method="none",
            client_secret_encrypted=None,
            token_endpoint="https://auth.example.com/token",
            authorization_endpoint="https://auth.example.com/authorize",
        )
        repo = AsyncMock()
        repo.get.return_value = existing

        result = await resolve_client_for_server(
            server_path="/jira",
            proxy_pass_url="https://resource.example.com/mcp",
            downstream_oauth_config={"downstream_auth_type": "oauth2"},
            gateway_base_url="https://gateway.example.com",
            repo=repo,
        )

        assert result is existing
        repo.upsert.assert_not_called()

    async def test_static_config_no_discovery(self) -> None:
        resolved = ServerOAuthClient(
            server_path="/jira",
            client_id="client-123",
            token_endpoint_auth_method="none",
            client_secret_encrypted=None,
            token_endpoint="https://auth.example.com/token",
            authorization_endpoint="https://auth.example.com/authorize",
            scopes_supported=["read"],
        )
        repo = AsyncMock()
        repo.get.side_effect = [None, resolved]

        with patch(
            "registry.services.downstream_oauth_service.discover_as_metadata",
            AsyncMock(),
        ) as mock_discover:
            result = await resolve_client_for_server(
                server_path="/jira",
                proxy_pass_url="https://resource.example.com/mcp",
                downstream_oauth_config={
                    "client_id": "client-123",
                    "auth_url": "https://auth.example.com/authorize",
                    "token_url": "https://auth.example.com/token",
                    "scopes": ["read"],
                },
                gateway_base_url="https://gateway.example.com",
                repo=repo,
            )

        assert result.client_id == "client-123"
        mock_discover.assert_not_awaited()
        assert repo.upsert.await_args.kwargs["token_endpoint_auth_method"] == "none"

    async def test_runs_dcr_when_enabled_and_endpoint_available(self) -> None:
        resolved = ServerOAuthClient(
            server_path="/jira",
            client_id="dynamic-client",
            token_endpoint_auth_method="client_secret_basic",
            client_secret_encrypted=None,
            token_endpoint="https://auth.example.com/token",
            authorization_endpoint="https://auth.example.com/authorize",
            scopes_supported=["read"],
            via_dcr=True,
        )
        repo = AsyncMock()
        repo.get.side_effect = [None, resolved]
        as_metadata = _oauth_metadata(
            registration_endpoint="https://auth.example.com/register",
            scopes_supported=["read"],
            token_endpoint_auth_methods_supported=["client_secret_basic", "none"],
        )

        with (
            patch(
                "registry.services.downstream_oauth_service.discover_as_metadata",
                AsyncMock(return_value=as_metadata),
            ),
            patch(
                "registry.services.downstream_oauth_service.register_dcr_client",
                AsyncMock(
                    return_value=_oauth_client_info(
                        client_id="dynamic-client",
                        client_secret="dynamic-secret",
                        token_endpoint_auth_method="client_secret_basic",
                    ),
                ),
            ) as mock_register,
        ):
            result = await resolve_client_for_server(
                server_path="/jira",
                proxy_pass_url="https://resource.example.com/mcp",
                downstream_oauth_config={
                    "dcr_enabled": True,
                    "scopes": ["read"],
                },
                gateway_base_url="https://gateway.example.com",
                repo=repo,
            )

        assert result.client_id == "dynamic-client"
        mock_register.assert_awaited_once()
        upsert_kwargs = repo.upsert.await_args.kwargs
        assert upsert_kwargs["via_dcr"] is True
        assert upsert_kwargs["client_secret"] == "dynamic-secret"
        assert upsert_kwargs["token_endpoint_auth_method"] == "client_secret_basic"

    async def test_public_client_stores_null_secret(self) -> None:
        resolved = ServerOAuthClient(
            server_path="/jira",
            client_id="public-client",
            token_endpoint_auth_method="none",
            client_secret_encrypted=None,
            token_endpoint="https://auth.example.com/token",
            authorization_endpoint="https://auth.example.com/authorize",
            via_dcr=True,
        )
        repo = AsyncMock()
        repo.get.side_effect = [None, resolved]
        as_metadata = _oauth_metadata(registration_endpoint="https://auth.example.com/register")

        with (
            patch(
                "registry.services.downstream_oauth_service.discover_as_metadata",
                AsyncMock(return_value=as_metadata),
            ),
            patch(
                "registry.services.downstream_oauth_service.register_dcr_client",
                AsyncMock(
                    return_value=_oauth_client_info(
                        client_id="public-client",
                        client_secret="ignored-secret",
                        token_endpoint_auth_method="none",
                    ),
                ),
            ),
        ):
            await resolve_client_for_server(
                server_path="/jira",
                proxy_pass_url="https://resource.example.com/mcp",
                downstream_oauth_config={"dcr_enabled": True, "scopes": []},
                gateway_base_url="https://gateway.example.com",
                repo=repo,
            )

        upsert_kwargs = repo.upsert.await_args.kwargs
        assert upsert_kwargs["client_secret"] is None
        assert upsert_kwargs["token_endpoint_auth_method"] == "none"

    async def test_confidential_client_stores_secret(self) -> None:
        resolved = ServerOAuthClient(
            server_path="/jira",
            client_id="confidential-client",
            token_endpoint_auth_method="client_secret_basic",
            client_secret_encrypted=None,
            token_endpoint="https://auth.example.com/token",
            authorization_endpoint="https://auth.example.com/authorize",
            via_dcr=True,
        )
        repo = AsyncMock()
        repo.get.side_effect = [None, resolved]
        as_metadata = _oauth_metadata(registration_endpoint="https://auth.example.com/register")

        with (
            patch(
                "registry.services.downstream_oauth_service.discover_as_metadata",
                AsyncMock(return_value=as_metadata),
            ),
            patch(
                "registry.services.downstream_oauth_service.register_dcr_client",
                AsyncMock(
                    return_value=_oauth_client_info(
                        client_id="confidential-client",
                        client_secret="kept-secret",
                        token_endpoint_auth_method="client_secret_basic",
                    ),
                ),
            ),
        ):
            await resolve_client_for_server(
                server_path="/jira",
                proxy_pass_url="https://resource.example.com/mcp",
                downstream_oauth_config={"dcr_enabled": True, "scopes": []},
                gateway_base_url="https://gateway.example.com",
                repo=repo,
            )

        assert repo.upsert.await_args.kwargs["client_secret"] == "kept-secret"

    async def test_raises_when_no_client_id_after_resolution(self) -> None:
        repo = AsyncMock()
        repo.get.return_value = None

        with pytest.raises(ValueError, match="No client_id available"):
            await resolve_client_for_server(
                server_path="/jira",
                proxy_pass_url="https://resource.example.com/mcp",
                downstream_oauth_config={
                    "auth_url": "https://auth.example.com/authorize",
                    "token_url": "https://auth.example.com/token",
                },
                gateway_base_url="https://gateway.example.com",
                repo=repo,
            )

    async def test_passes_token_auth_methods_to_dcr(self) -> None:
        resolved = ServerOAuthClient(
            server_path="/jira",
            client_id="dynamic-client",
            token_endpoint_auth_method="client_secret_basic",
            client_secret_encrypted=None,
            token_endpoint="https://auth.example.com/token",
            authorization_endpoint="https://auth.example.com/authorize",
            via_dcr=True,
        )
        repo = AsyncMock()
        repo.get.side_effect = [None, resolved]
        as_metadata = _oauth_metadata(
            registration_endpoint="https://auth.example.com/register",
            token_endpoint_auth_methods_supported=["client_secret_post"],
        )

        with (
            patch(
                "registry.services.downstream_oauth_service.discover_as_metadata",
                AsyncMock(return_value=as_metadata),
            ),
            patch(
                "registry.services.downstream_oauth_service.register_dcr_client",
                AsyncMock(return_value=_oauth_client_info()),
            ) as mock_register,
        ):
            await resolve_client_for_server(
                server_path="/jira",
                proxy_pass_url="https://resource.example.com/mcp",
                downstream_oauth_config={"dcr_enabled": True, "scopes": []},
                gateway_base_url="https://gateway.example.com",
                repo=repo,
            )

        passed_metadata = mock_register.await_args.kwargs["as_metadata"]
        assert passed_metadata.token_endpoint_auth_methods_supported == ["client_secret_post"]
