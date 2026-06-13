"""Unit tests for downstream OAuth header injection in MCP client."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from registry.core.mcp_client import _build_headers_for_server_async


class TestBuildHeadersForServerAsync:
    """Tests for downstream token injection and refresh."""

    async def test_no_downstream_oauth_returns_base_headers(self) -> None:
        headers = await _build_headers_for_server_async(
            {"path": "/test-server", "downstream_oauth": {"downstream_auth_type": "none"}},
            username="alice",
        )

        assert headers == {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }

    async def test_injects_token_for_oauth2_server(self) -> None:
        mock_repo = AsyncMock()
        mock_repo.get.return_value = MagicMock(refresh_token_encrypted=None)
        mock_repo.is_expired.return_value = False
        mock_repo.get_access_token.return_value = "plain-token"

        with patch(
            "registry.repositories.documentdb.user_server_token_repository.UserServerTokenRepository",
            return_value=mock_repo,
        ):
            headers = await _build_headers_for_server_async(
                {"path": "/test-server", "downstream_oauth": {"downstream_auth_type": "oauth2"}},
                username="alice",
            )

        assert headers["Authorization"] == "Bearer plain-token"

    async def test_no_injection_when_no_token(self) -> None:
        mock_repo = AsyncMock()
        mock_repo.get.return_value = None

        with patch(
            "registry.repositories.documentdb.user_server_token_repository.UserServerTokenRepository",
            return_value=mock_repo,
        ):
            headers = await _build_headers_for_server_async(
                {"path": "/test-server", "downstream_oauth": {"downstream_auth_type": "oauth2"}},
                username="alice",
            )

        assert "Authorization" not in headers

    async def test_auto_refresh_when_expired(self) -> None:
        mock_repo = AsyncMock()
        mock_repo.get.return_value = MagicMock(refresh_token_encrypted="enc-refresh")
        mock_repo.is_expired.return_value = True
        mock_repo.get_access_token.return_value = None

        with (
            patch(
                "registry.repositories.documentdb.user_server_token_repository.UserServerTokenRepository",
                return_value=mock_repo,
            ),
            patch(
                "registry.core.mcp_client._refresh_downstream_access_token",
                AsyncMock(return_value="new-access-token"),
            ) as mock_refresh,
        ):
            headers = await _build_headers_for_server_async(
                {
                    "path": "/test-server",
                    "proxy_pass_url": "https://resource.example.com",
                    "downstream_oauth": {"downstream_auth_type": "oauth2"},
                },
                username="alice",
            )

        assert headers["Authorization"] == "Bearer new-access-token"
        mock_refresh.assert_awaited_once()

    async def test_no_refresh_when_no_refresh_token(self) -> None:
        mock_repo = AsyncMock()
        mock_repo.get.return_value = MagicMock(refresh_token_encrypted=None)
        mock_repo.is_expired.return_value = True
        mock_repo.get_access_token.return_value = "stale-token"

        with (
            patch(
                "registry.repositories.documentdb.user_server_token_repository.UserServerTokenRepository",
                return_value=mock_repo,
            ),
            patch(
                "registry.core.mcp_client._refresh_downstream_access_token",
                AsyncMock(return_value="new-access-token"),
            ) as mock_refresh,
        ):
            headers = await _build_headers_for_server_async(
                {"path": "/test-server", "downstream_oauth": {"downstream_auth_type": "oauth2"}},
                username="alice",
            )

        assert headers["Authorization"] == "Bearer stale-token"
        mock_refresh.assert_not_called()

    async def test_username_none_skips_downstream_lookup(self) -> None:
        with patch(
            "registry.repositories.documentdb.user_server_token_repository.UserServerTokenRepository"
        ) as mock_repo_cls:
            headers = await _build_headers_for_server_async(
                {"path": "/test-server", "downstream_oauth": {"downstream_auth_type": "oauth2"}},
                username=None,
            )

        assert "Authorization" not in headers
        mock_repo_cls.assert_not_called()

    async def test_refresh_helper_updates_stored_token(self) -> None:
        from registry.core import mcp_client
        from registry.schemas.server_oauth_client_models import ServerOAuthClient

        token_repo = AsyncMock()
        token_repo.get_refresh_token.return_value = "refresh-token"
        oauth_client = ServerOAuthClient(
            server_path="/test-server",
            client_id="client-123",
            client_secret_encrypted="enc-secret",
            token_endpoint="https://auth.example.com/token",
            authorization_endpoint="https://auth.example.com/authorize",
        )

        mock_http_client = AsyncMock()
        mock_http_client.post.return_value = MagicMock(
            raise_for_status=MagicMock(),
            json=MagicMock(
                return_value={
                    "access_token": "new-access-token",
                    "refresh_token": "new-refresh-token",
                    "token_type": "Bearer",
                    "scope": "read",
                    "expires_in": 1800,
                }
            ),
        )

        with (
            patch(
                "registry.repositories.documentdb.server_oauth_client_repository.ServerOAuthClientRepository.get",
                AsyncMock(return_value=oauth_client),
            ),
            patch(
                "registry.repositories.documentdb.server_oauth_client_repository._decrypt",
                return_value="plain-secret",
            ),
            patch("registry.core.mcp_client.httpx.AsyncClient") as mock_async_client,
        ):
            mock_async_client.return_value.__aenter__ = AsyncMock(return_value=mock_http_client)
            mock_async_client.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await mcp_client._refresh_downstream_access_token(
                "alice",
                {
                    "path": "/test-server",
                    "proxy_pass_url": "https://resource.example.com",
                    "downstream_oauth": {"resource_indicator": "https://api.example.com"},
                },
                token_repo,
            )

        assert result == "new-access-token"
        stored = token_repo.upsert.await_args.args[0]
        assert stored.username == "alice"
        assert stored.server_path == "/test-server"
        assert stored.access_token == "new-access-token"
        assert stored.refresh_token == "new-refresh-token"
        assert stored.expires_at >= datetime.now(UTC) + timedelta(minutes=20)
