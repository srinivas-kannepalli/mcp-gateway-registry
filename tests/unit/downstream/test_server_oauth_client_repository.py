"""Unit tests for downstream server OAuth client repository."""

import base64
import hashlib
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography.fernet import Fernet

from registry.repositories.documentdb.server_oauth_client_repository import (
    ServerOAuthClientRepository,
)
from registry.schemas.server_oauth_client_models import ServerOAuthClient


def _test_fernet() -> Fernet:
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        b"test-secret-key",
        b"mcp-gateway-credential-encryption",
        100_000,
    )
    return Fernet(base64.urlsafe_b64encode(derived))


@pytest.fixture
def mock_collection() -> AsyncMock:
    collection = AsyncMock()
    collection.update_one = AsyncMock()
    collection.find_one = AsyncMock(return_value=None)
    collection.delete_one = AsyncMock()
    collection.create_index = AsyncMock()
    return collection


@pytest.fixture
def repo(mock_collection: AsyncMock) -> ServerOAuthClientRepository:
    repository = ServerOAuthClientRepository.__new__(ServerOAuthClientRepository)
    repository._collection = mock_collection
    repository._collection_name = "server_oauth_clients_test"
    return repository


class TestServerOAuthClientRepository:
    """Tests for encrypted server OAuth client persistence."""

    async def test_upsert_stores_encrypted_secret(
        self,
        repo: ServerOAuthClientRepository,
        mock_collection: AsyncMock,
    ) -> None:
        with patch(
            "registry.repositories.documentdb.server_oauth_client_repository._get_fernet",
            return_value=_test_fernet(),
        ):
            await repo.upsert(
                server_path="/jira",
                client_id="client-123",
                client_secret="plain-secret",
                token_endpoint="https://auth.example.com/token",
                authorization_endpoint="https://auth.example.com/authorize",
                scopes_supported=["read"],
            )

        update_doc = mock_collection.update_one.await_args.args[1]["$set"]
        assert update_doc["client_secret_encrypted"] != "plain-secret"
        assert _test_fernet().decrypt(update_doc["client_secret_encrypted"].encode()).decode() == "plain-secret"

    async def test_upsert_no_secret(
        self,
        repo: ServerOAuthClientRepository,
        mock_collection: AsyncMock,
    ) -> None:
        await repo.upsert(
            server_path="/jira",
            client_id="client-123",
            client_secret=None,
            token_endpoint="https://auth.example.com/token",
            authorization_endpoint="https://auth.example.com/authorize",
            scopes_supported=["read"],
        )

        update_doc = mock_collection.update_one.await_args.args[1]["$set"]
        assert update_doc["client_secret_encrypted"] is None

    async def test_get_returns_none_when_not_found(self, repo: ServerOAuthClientRepository) -> None:
        assert await repo.get("/jira") is None

    async def test_get_returns_client(
        self,
        repo: ServerOAuthClientRepository,
        mock_collection: AsyncMock,
    ) -> None:
        now = datetime.now(UTC)
        mock_collection.find_one.return_value = {
            "_id": "ignored",
            "server_path": "/jira",
            "client_id": "client-123",
            "client_secret_encrypted": "enc-secret",
            "registration_access_token_encrypted": None,
            "token_endpoint": "https://auth.example.com/token",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "scopes_supported": ["read"],
            "via_dcr": True,
            "created_at": now,
            "updated_at": now,
        }

        result = await repo.get("/jira")

        assert isinstance(result, ServerOAuthClient)
        assert result.client_id == "client-123"
        assert result.token_endpoint == "https://auth.example.com/token"
        assert result.authorization_endpoint == "https://auth.example.com/authorize"
        assert result.via_dcr is True

    async def test_get_client_secret_decrypts(
        self,
        repo: ServerOAuthClientRepository,
        mock_collection: AsyncMock,
    ) -> None:
        encrypted = _test_fernet().encrypt(b"plain-secret").decode()
        now = datetime.now(UTC)
        mock_collection.find_one.return_value = {
            "server_path": "/jira",
            "client_id": "client-123",
            "client_secret_encrypted": encrypted,
            "registration_access_token_encrypted": None,
            "token_endpoint": "https://auth.example.com/token",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "scopes_supported": ["read"],
            "via_dcr": False,
            "created_at": now,
            "updated_at": now,
        }

        with patch(
            "registry.repositories.documentdb.server_oauth_client_repository._get_fernet",
            return_value=_test_fernet(),
        ):
            result = await repo.get_client_secret("/jira")

        assert result == "plain-secret"

    async def test_delete_returns_true(
        self,
        repo: ServerOAuthClientRepository,
        mock_collection: AsyncMock,
    ) -> None:
        mock_collection.delete_one.return_value = MagicMock(deleted_count=1)

        assert await repo.delete("/jira") is True

    async def test_delete_returns_false(
        self,
        repo: ServerOAuthClientRepository,
        mock_collection: AsyncMock,
    ) -> None:
        mock_collection.delete_one.return_value = MagicMock(deleted_count=0)

        assert await repo.delete("/jira") is False

