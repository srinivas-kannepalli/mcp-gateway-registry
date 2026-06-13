"""Unit tests for downstream OAuth service helpers."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from registry.schemas.server_oauth_client_models import ServerOAuthClient
from registry.services.downstream_oauth_service import (
    _reject_ssrf,
    discover_as_metadata,
    register_dcr_client,
    resolve_client_for_server,
)


def _response(
    status_code: int,
    payload: dict,
    method: str = "GET",
    url: str = "https://example.com",
) -> httpx.Response:
    request = httpx.Request(method, url)
    return httpx.Response(status_code=status_code, json=payload, request=request)


@pytest.fixture
def mock_httpx_client():
    with patch("registry.services.downstream_oauth_service.httpx.AsyncClient") as mock_client:
        instance = AsyncMock()
        mock_client.return_value.__aenter__ = AsyncMock(return_value=instance)
        mock_client.return_value.__aexit__ = AsyncMock(return_value=False)
        yield instance


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


class TestDiscoverAsMetadata:
    """Tests for protected-resource and AS metadata discovery."""

    async def test_discover_follows_prm_to_as_metadata(self, mock_httpx_client: AsyncMock) -> None:
        mock_httpx_client.get.side_effect = [
            _response(
                200,
                {"authorization_servers": ["https://auth.example.com"]},
                url="https://resource.example.com/.well-known/oauth-protected-resource",
            ),
            _response(
                200,
                {
                    "authorization_endpoint": "https://auth.example.com/authorize",
                    "token_endpoint": "https://auth.example.com/token",
                },
                url="https://auth.example.com/.well-known/oauth-authorization-server",
            ),
        ]

        result = await discover_as_metadata("https://resource.example.com")

        assert result["authorization_endpoint"] == "https://auth.example.com/authorize"
        assert result["token_endpoint"] == "https://auth.example.com/token"

    async def test_discover_raises_when_no_authorization_servers(
        self,
        mock_httpx_client: AsyncMock,
    ) -> None:
        mock_httpx_client.get.return_value = _response(
            200,
            {},
            url="https://resource.example.com/.well-known/oauth-protected-resource",
        )

        with pytest.raises(ValueError, match="No authorization_servers"):
            await discover_as_metadata("https://resource.example.com")

    async def test_discover_raises_when_prm_fails(self, mock_httpx_client: AsyncMock) -> None:
        request = httpx.Request("GET", "https://resource.example.com/.well-known/oauth-protected-resource")
        response = httpx.Response(500, request=request)
        mock_httpx_client.get.return_value = MagicMock(
            raise_for_status=MagicMock(side_effect=httpx.HTTPStatusError("boom", request=request, response=response))
        )

        with pytest.raises(httpx.HTTPStatusError):
            await discover_as_metadata("https://resource.example.com")


class TestRegisterDcrClient:
    """Tests for dynamic client registration."""

    async def test_dcr_sends_correct_payload(self, mock_httpx_client: AsyncMock) -> None:
        mock_httpx_client.post.return_value = _response(201, {"client_id": "client-123"}, method="POST")

        await register_dcr_client(
            "https://auth.example.com/register",
            "https://gateway.example.com",
            "/jira",
            ["read", "write"],
        )

        payload = mock_httpx_client.post.await_args.kwargs["json"]
        assert payload["client_name"] == "MCP Gateway — /jira"
        assert payload["redirect_uris"] == [
            "https://gateway.example.com/api/servers//jira/downstream/callback"
        ]
        assert payload["grant_types"] == ["authorization_code", "refresh_token"]
        assert payload["scope"] == "read write"

    async def test_dcr_returns_client_id(self, mock_httpx_client: AsyncMock) -> None:
        mock_httpx_client.post.return_value = _response(
            201,
            {"client_id": "client-123", "client_secret": "secret"},
            method="POST",
        )

        result = await register_dcr_client(
            "https://auth.example.com/register",
            "https://gateway.example.com",
            "/jira",
            ["read"],
        )

        assert result["client_id"] == "client-123"

    async def test_dcr_raises_on_http_error(self, mock_httpx_client: AsyncMock) -> None:
        request = httpx.Request("POST", "https://auth.example.com/register")
        response = httpx.Response(400, request=request)
        mock_httpx_client.post.return_value = MagicMock(
            raise_for_status=MagicMock(side_effect=httpx.HTTPStatusError("bad request", request=request, response=response))
        )

        with pytest.raises(httpx.HTTPStatusError):
            await register_dcr_client(
                "https://auth.example.com/register",
                "https://gateway.example.com",
                "/jira",
                ["read"],
            )


class TestResolveClientForServer:
    """Tests for client resolution and persistence."""

    async def test_returns_existing_client_without_discovery(self) -> None:
        existing = ServerOAuthClient(
            server_path="/jira",
            client_id="client-123",
            client_secret_encrypted=None,
            token_endpoint="https://auth.example.com/token",
            authorization_endpoint="https://auth.example.com/authorize",
        )
        repo = AsyncMock()
        repo.get.return_value = existing

        result = await resolve_client_for_server(
            server_path="/jira",
            proxy_pass_url="https://resource.example.com",
            downstream_oauth_config={"downstream_auth_type": "oauth2"},
            gateway_base_url="https://gateway.example.com",
            repo=repo,
        )

        assert result is existing
        repo.upsert.assert_not_called()

    async def test_creates_client_from_static_config(self) -> None:
        resolved = ServerOAuthClient(
            server_path="/jira",
            client_id="client-123",
            client_secret_encrypted=None,
            token_endpoint="https://auth.example.com/token",
            authorization_endpoint="https://auth.example.com/authorize",
            scopes_supported=["read"],
        )
        repo = AsyncMock()
        repo.get.side_effect = [None, resolved]

        result = await resolve_client_for_server(
            server_path="/jira",
            proxy_pass_url="https://resource.example.com",
            downstream_oauth_config={
                "dcr_enabled": False,
                "client_id": "client-123",
                "auth_url": "https://auth.example.com/authorize",
                "token_url": "https://auth.example.com/token",
                "scopes": ["read"],
            },
            gateway_base_url="https://gateway.example.com",
            repo=repo,
        )

        assert result.client_id == "client-123"
        repo.upsert.assert_awaited_once()

    async def test_runs_dcr_when_enabled(self) -> None:
        resolved = ServerOAuthClient(
            server_path="/jira",
            client_id="dynamic-client",
            client_secret_encrypted=None,
            token_endpoint="https://auth.example.com/token",
            authorization_endpoint="https://auth.example.com/authorize",
            scopes_supported=["read"],
            via_dcr=True,
        )
        repo = AsyncMock()
        repo.get.side_effect = [None, resolved]

        with (
            patch(
                "registry.services.downstream_oauth_service.discover_as_metadata",
                AsyncMock(
                    return_value={
                        "authorization_endpoint": "https://auth.example.com/authorize",
                        "token_endpoint": "https://auth.example.com/token",
                        "registration_endpoint": "https://auth.example.com/register",
                        "scopes_supported": ["read"],
                    }
                ),
            ),
            patch(
                "registry.services.downstream_oauth_service.register_dcr_client",
                AsyncMock(
                    return_value={
                        "client_id": "dynamic-client",
                        "client_secret": "dynamic-secret",
                        "registration_access_token": "reg-token",
                    }
                ),
            ) as mock_register,
        ):
            result = await resolve_client_for_server(
                server_path="/jira",
                proxy_pass_url="https://resource.example.com",
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
        assert upsert_kwargs["client_id"] == "dynamic-client"
        assert upsert_kwargs["client_secret"] == "dynamic-secret"
        assert upsert_kwargs["registration_access_token"] == "reg-token"
        assert upsert_kwargs["via_dcr"] is True

