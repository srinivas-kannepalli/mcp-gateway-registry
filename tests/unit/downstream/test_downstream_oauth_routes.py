"""Unit tests for downstream OAuth routes."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from registry.api import downstream_oauth_routes
from registry.schemas.server_oauth_client_models import ServerOAuthClient
from registry.schemas.user_server_token_models import UserServerToken


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(downstream_oauth_routes.router, prefix="/api")
    app.dependency_overrides[downstream_oauth_routes.enhanced_auth] = lambda: {
        "username": "testuser"
    }
    return app


@pytest.fixture
def route_client() -> TestClient:
    app = _make_app()
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client
    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def clear_state_store() -> None:
    downstream_oauth_routes._state_store.clear()


@pytest.fixture
def mock_server_service() -> AsyncMock:
    service = AsyncMock()
    service.get_server_info = AsyncMock()
    return service


@pytest.fixture
def mock_token_repo() -> AsyncMock:
    repo = AsyncMock()
    repo.get = AsyncMock(return_value=None)
    repo.is_expired = AsyncMock(return_value=True)
    repo.delete = AsyncMock(return_value=True)
    repo.upsert = AsyncMock()
    return repo


@pytest.fixture
def mock_client_repo() -> AsyncMock:
    repo = AsyncMock()
    repo.get = AsyncMock(return_value=None)
    return repo


@pytest.fixture
def mock_consent_repo() -> AsyncMock:
    repo = AsyncMock()
    repo.record_consent = AsyncMock()
    repo.revoke_consent = AsyncMock()
    return repo


@pytest.fixture
def oauth_server() -> dict[str, object]:
    return {
        "server_name": "Jira",
        "path": "/test-server",
        "proxy_pass_url": "https://resource.example.com",
        "downstream_oauth": {
            "downstream_auth_type": "oauth2",
            "scopes": ["read", "write"],
        },
    }


def _patch_routes(
    mock_server_service: AsyncMock,
    mock_token_repo: AsyncMock,
    mock_client_repo: AsyncMock,
    mock_consent_repo: AsyncMock,
):
    return patch.multiple(
        "registry.api.downstream_oauth_routes",
        server_service=mock_server_service,
        _token_repo=mock_token_repo,
        _client_repo=mock_client_repo,
        _consent_repo=mock_consent_repo,
    )


class TestDownstreamTokenStatus:
    """Tests for token status endpoint."""

    def test_status_no_token(
        self,
        route_client: TestClient,
        mock_server_service: AsyncMock,
        mock_token_repo: AsyncMock,
        mock_client_repo: AsyncMock,
        mock_consent_repo: AsyncMock,
        oauth_server: dict[str, object],
    ) -> None:
        mock_server_service.get_server_info.return_value = oauth_server

        with _patch_routes(
            mock_server_service,
            mock_token_repo,
            mock_client_repo,
            mock_consent_repo,
        ):
            response = route_client.get("/api/servers/test-server/downstream/token/status")

        assert response.status_code == 200
        assert response.json() == {
            "server_path": "/test-server",
            "has_token": False,
            "is_expired": True,
            "scope": None,
            "expires_at": None,
        }

    def test_status_valid_token(
        self,
        route_client: TestClient,
        mock_server_service: AsyncMock,
        mock_token_repo: AsyncMock,
        mock_client_repo: AsyncMock,
        mock_consent_repo: AsyncMock,
        oauth_server: dict[str, object],
    ) -> None:
        future = datetime.now(UTC) + timedelta(minutes=5)
        mock_server_service.get_server_info.return_value = oauth_server
        mock_token_repo.get.return_value = UserServerToken(
            username="testuser",
            server_path="/test-server",
            access_token_encrypted="enc",
            refresh_token_encrypted=None,
            expires_at=future,
            scope="read",
        )
        mock_token_repo.is_expired.return_value = False

        with _patch_routes(
            mock_server_service,
            mock_token_repo,
            mock_client_repo,
            mock_consent_repo,
        ):
            response = route_client.get("/api/servers/test-server/downstream/token/status")

        assert response.status_code == 200
        data = response.json()
        assert data["has_token"] is True
        assert data["is_expired"] is False
        assert data["scope"] == "read"

    def test_status_expired_token(
        self,
        route_client: TestClient,
        mock_server_service: AsyncMock,
        mock_token_repo: AsyncMock,
        mock_client_repo: AsyncMock,
        mock_consent_repo: AsyncMock,
        oauth_server: dict[str, object],
    ) -> None:
        past = datetime.now(UTC) - timedelta(minutes=5)
        mock_server_service.get_server_info.return_value = oauth_server
        mock_token_repo.get.return_value = UserServerToken(
            username="testuser",
            server_path="/test-server",
            access_token_encrypted="enc",
            refresh_token_encrypted=None,
            expires_at=past,
            scope="read",
        )
        mock_token_repo.is_expired.return_value = True

        with _patch_routes(
            mock_server_service,
            mock_token_repo,
            mock_client_repo,
            mock_consent_repo,
        ):
            response = route_client.get("/api/servers/test-server/downstream/token/status")

        assert response.status_code == 200
        data = response.json()
        assert data["has_token"] is True
        assert data["is_expired"] is True


class TestDownstreamTokenRevoke:
    """Tests for token revoke endpoint."""

    def test_revoke_calls_delete(
        self,
        route_client: TestClient,
        mock_server_service: AsyncMock,
        mock_token_repo: AsyncMock,
        mock_client_repo: AsyncMock,
        mock_consent_repo: AsyncMock,
        oauth_server: dict[str, object],
    ) -> None:
        mock_server_service.get_server_info.return_value = oauth_server

        with _patch_routes(
            mock_server_service,
            mock_token_repo,
            mock_client_repo,
            mock_consent_repo,
        ):
            response = route_client.delete("/api/servers/test-server/downstream/token")

        assert response.status_code == 204
        mock_token_repo.delete.assert_awaited_once_with("testuser", "/test-server")
        mock_consent_repo.revoke_consent.assert_awaited_once_with("testuser", "/test-server")


class TestDownstreamAuthorize:
    """Tests for authorize endpoint."""

    def test_authorize_redirects_to_idp(
        self,
        route_client: TestClient,
        mock_server_service: AsyncMock,
        mock_token_repo: AsyncMock,
        mock_client_repo: AsyncMock,
        mock_consent_repo: AsyncMock,
        oauth_server: dict[str, object],
    ) -> None:
        mock_server_service.get_server_info.return_value = oauth_server
        resolved_client = ServerOAuthClient(
            server_path="/test-server",
            client_id="client-123",
            client_secret_encrypted=None,
            token_endpoint="https://auth.example.com/token",
            authorization_endpoint="https://auth.example.com/authorize",
        )

        with (
            _patch_routes(
                mock_server_service,
                mock_token_repo,
                mock_client_repo,
                mock_consent_repo,
            ),
            patch(
                "registry.api.downstream_oauth_routes.resolve_client_for_server",
                AsyncMock(return_value=resolved_client),
            ),
        ):
            response = route_client.get(
                "/api/servers/test-server/downstream/authorize",
                follow_redirects=False,
            )

        assert response.status_code == 302
        assert response.headers["location"].startswith("https://auth.example.com/authorize?")
        assert "client_id=client-123" in response.headers["location"]

    def test_authorize_rejects_non_oauth_server(
        self,
        route_client: TestClient,
        mock_server_service: AsyncMock,
        mock_token_repo: AsyncMock,
        mock_client_repo: AsyncMock,
        mock_consent_repo: AsyncMock,
    ) -> None:
        mock_server_service.get_server_info.return_value = {
            "server_name": "Public",
            "path": "/public-server",
            "proxy_pass_url": "https://resource.example.com",
            "downstream_oauth": {"downstream_auth_type": "none"},
        }

        with _patch_routes(
            mock_server_service,
            mock_token_repo,
            mock_client_repo,
            mock_consent_repo,
        ):
            response = route_client.get("/api/servers/public-server/downstream/authorize")

        assert response.status_code == 400
        assert "does not require downstream OAuth" in response.text


class TestDownstreamCallback:
    """Tests for callback endpoint."""

    def test_callback_exchanges_code_for_token(
        self,
        route_client: TestClient,
        mock_server_service: AsyncMock,
        mock_token_repo: AsyncMock,
        mock_client_repo: AsyncMock,
        mock_consent_repo: AsyncMock,
        oauth_server: dict[str, object],
    ) -> None:
        downstream_oauth_routes._state_store["test-state"] = {
            "username": "testuser",
            "server_path": "/test-server",
            "code_verifier": "test_verifier",
            "created_at": datetime.now(UTC),
        }
        mock_server_service.get_server_info.return_value = oauth_server
        mock_client_repo.get.return_value = ServerOAuthClient(
            server_path="/test-server",
            client_id="client-123",
            client_secret_encrypted=None,
            token_endpoint="https://auth.example.com/token",
            authorization_endpoint="https://auth.example.com/authorize",
        )

        mock_http_client = AsyncMock()
        mock_http_client.post.return_value = MagicMock(
            raise_for_status=MagicMock(),
            json=MagicMock(
                return_value={
                    "access_token": "access-token",
                    "refresh_token": "refresh-token",
                    "token_type": "Bearer",
                    "scope": "read",
                    "expires_in": 3600,
                }
            ),
        )

        with (
            _patch_routes(
                mock_server_service,
                mock_token_repo,
                mock_client_repo,
                mock_consent_repo,
            ),
            patch("registry.api.downstream_oauth_routes.httpx.AsyncClient") as mock_async_client,
        ):
            mock_async_client.return_value.__aenter__ = AsyncMock(return_value=mock_http_client)
            mock_async_client.return_value.__aexit__ = AsyncMock(return_value=False)
            response = route_client.get(
                "/api/servers/test-server/downstream/callback?code=test-code&state=test-state"
            )

        assert response.status_code == 200
        assert "Connected!" in response.text
        stored = mock_token_repo.upsert.await_args.args[0]
        assert stored.username == "testuser"
        assert stored.server_path == "/test-server"
        assert stored.access_token == "access-token"
        assert stored.refresh_token == "refresh-token"

    def test_callback_missing_code(
        self,
        route_client: TestClient,
        mock_server_service: AsyncMock,
        mock_token_repo: AsyncMock,
        mock_client_repo: AsyncMock,
        mock_consent_repo: AsyncMock,
    ) -> None:
        with _patch_routes(
            mock_server_service,
            mock_token_repo,
            mock_client_repo,
            mock_consent_repo,
        ):
            response = route_client.get("/api/servers/test-server/downstream/callback?state=test-state")

        assert response.status_code == 400
        assert "Missing code or state" in response.text

    def test_callback_invalid_state(
        self,
        route_client: TestClient,
        mock_server_service: AsyncMock,
        mock_token_repo: AsyncMock,
        mock_client_repo: AsyncMock,
        mock_consent_repo: AsyncMock,
    ) -> None:
        with _patch_routes(
            mock_server_service,
            mock_token_repo,
            mock_client_repo,
            mock_consent_repo,
        ):
            response = route_client.get(
                "/api/servers/test-server/downstream/callback?code=test-code&state=missing"
            )

        assert response.status_code == 400
        assert "Invalid or expired state" in response.text

    def test_callback_error_param(
        self,
        route_client: TestClient,
        mock_server_service: AsyncMock,
        mock_token_repo: AsyncMock,
        mock_client_repo: AsyncMock,
        mock_consent_repo: AsyncMock,
    ) -> None:
        with _patch_routes(
            mock_server_service,
            mock_token_repo,
            mock_client_repo,
            mock_consent_repo,
        ):
            response = route_client.get(
                "/api/servers/test-server/downstream/callback?error=access_denied"
            )

        assert response.status_code == 400
        assert "access_denied" in response.text

