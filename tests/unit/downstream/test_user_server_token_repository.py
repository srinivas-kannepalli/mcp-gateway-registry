"""Unit tests for user downstream token repository."""

import base64
import hashlib
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography.fernet import Fernet

from registry.repositories.documentdb.user_server_token_repository import UserServerTokenRepository
from registry.schemas.user_server_token_models import UserServerToken, UserServerTokenCreate


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
def repo(mock_collection: AsyncMock) -> UserServerTokenRepository:
    repository = UserServerTokenRepository.__new__(UserServerTokenRepository)
    repository._collection = mock_collection
    repository._collection_name = "user_server_tokens_test"
    return repository


class TestUserServerTokenRepository:
    """Tests for encrypted token persistence and retrieval."""

    async def test_upsert_encrypts_access_token(
        self,
        repo: UserServerTokenRepository,
        mock_collection: AsyncMock,
    ) -> None:
        token_in = UserServerTokenCreate(
            username="alice",
            server_path="/jira",
            access_token="plain-access",
        )

        with patch(
            "registry.repositories.documentdb.user_server_token_repository._get_fernet",
            return_value=_test_fernet(),
        ):
            await repo.upsert(token_in)

        update_doc = mock_collection.update_one.await_args.args[1]["$set"]
        assert update_doc["access_token_encrypted"] != "plain-access"
        assert _test_fernet().decrypt(update_doc["access_token_encrypted"].encode()).decode() == "plain-access"

    async def test_upsert_encrypts_refresh_token(
        self,
        repo: UserServerTokenRepository,
        mock_collection: AsyncMock,
    ) -> None:
        token_in = UserServerTokenCreate(
            username="alice",
            server_path="/jira",
            access_token="plain-access",
            refresh_token="plain-refresh",
        )

        with patch(
            "registry.repositories.documentdb.user_server_token_repository._get_fernet",
            return_value=_test_fernet(),
        ):
            await repo.upsert(token_in)

        update_doc = mock_collection.update_one.await_args.args[1]["$set"]
        assert update_doc["refresh_token_encrypted"] != "plain-refresh"
        assert (
            _test_fernet().decrypt(update_doc["refresh_token_encrypted"].encode()).decode()
            == "plain-refresh"
        )

    async def test_upsert_null_refresh_token(
        self,
        repo: UserServerTokenRepository,
        mock_collection: AsyncMock,
    ) -> None:
        token_in = UserServerTokenCreate(
            username="alice",
            server_path="/jira",
            access_token="plain-access",
            refresh_token=None,
        )

        with patch(
            "registry.repositories.documentdb.user_server_token_repository._get_fernet",
            return_value=_test_fernet(),
        ):
            await repo.upsert(token_in)

        update_doc = mock_collection.update_one.await_args.args[1]["$set"]
        assert update_doc["refresh_token_encrypted"] is None

    async def test_get_returns_none_when_not_found(self, repo: UserServerTokenRepository) -> None:
        assert await repo.get("alice", "/jira") is None

    async def test_get_returns_token_when_found(
        self,
        repo: UserServerTokenRepository,
        mock_collection: AsyncMock,
    ) -> None:
        now = datetime.now(UTC)
        mock_collection.find_one.return_value = {
            "_id": "ignored",
            "username": "alice",
            "server_path": "/jira",
            "access_token_encrypted": "enc-access",
            "refresh_token_encrypted": "enc-refresh",
            "expires_at": now,
            "token_type": "Bearer",
            "scope": "read",
            "created_at": now,
            "updated_at": now,
        }

        result = await repo.get("alice", "/jira")

        assert isinstance(result, UserServerToken)
        assert result.username == "alice"
        assert result.server_path == "/jira"
        assert result.scope == "read"

    async def test_get_access_token_decrypts(
        self,
        repo: UserServerTokenRepository,
        mock_collection: AsyncMock,
    ) -> None:
        encrypted = _test_fernet().encrypt(b"plain-access").decode()
        now = datetime.now(UTC)
        mock_collection.find_one.return_value = {
            "username": "alice",
            "server_path": "/jira",
            "access_token_encrypted": encrypted,
            "refresh_token_encrypted": None,
            "expires_at": now,
            "token_type": "Bearer",
            "scope": None,
            "created_at": now,
            "updated_at": now,
        }

        with patch(
            "registry.repositories.documentdb.user_server_token_repository._get_fernet",
            return_value=_test_fernet(),
        ):
            result = await repo.get_access_token("alice", "/jira")

        assert result == "plain-access"

    async def test_get_refresh_token_decrypts(
        self,
        repo: UserServerTokenRepository,
        mock_collection: AsyncMock,
    ) -> None:
        encrypted = _test_fernet().encrypt(b"plain-refresh").decode()
        now = datetime.now(UTC)
        mock_collection.find_one.return_value = {
            "username": "alice",
            "server_path": "/jira",
            "access_token_encrypted": "enc-access",
            "refresh_token_encrypted": encrypted,
            "expires_at": now,
            "token_type": "Bearer",
            "scope": None,
            "created_at": now,
            "updated_at": now,
        }

        with patch(
            "registry.repositories.documentdb.user_server_token_repository._get_fernet",
            return_value=_test_fernet(),
        ):
            result = await repo.get_refresh_token("alice", "/jira")

        assert result == "plain-refresh"

    async def test_delete_returns_true_when_deleted(
        self,
        repo: UserServerTokenRepository,
        mock_collection: AsyncMock,
    ) -> None:
        mock_collection.delete_one.return_value = MagicMock(deleted_count=1)

        assert await repo.delete("alice", "/jira") is True

    async def test_delete_returns_false_when_not_found(
        self,
        repo: UserServerTokenRepository,
        mock_collection: AsyncMock,
    ) -> None:
        mock_collection.delete_one.return_value = MagicMock(deleted_count=0)

        assert await repo.delete("alice", "/jira") is False

    async def test_is_expired_returns_true_when_no_token(
        self,
        repo: UserServerTokenRepository,
    ) -> None:
        assert await repo.is_expired("alice", "/jira") is True

    async def test_is_expired_returns_false_when_no_expiry(
        self,
        repo: UserServerTokenRepository,
    ) -> None:
        repo.get = AsyncMock(
            return_value=UserServerToken(
                username="alice",
                server_path="/jira",
                access_token_encrypted="enc",
                refresh_token_encrypted=None,
                expires_at=None,
            )
        )

        assert await repo.is_expired("alice", "/jira") is False

    async def test_is_expired_returns_true_when_past_expiry(
        self,
        repo: UserServerTokenRepository,
    ) -> None:
        repo.get = AsyncMock(
            return_value=UserServerToken(
                username="alice",
                server_path="/jira",
                access_token_encrypted="enc",
                refresh_token_encrypted=None,
                expires_at=datetime.now(UTC) - timedelta(minutes=1),
            )
        )

        assert await repo.is_expired("alice", "/jira") is True

    async def test_is_expired_returns_false_when_future_expiry(
        self,
        repo: UserServerTokenRepository,
    ) -> None:
        repo.get = AsyncMock(
            return_value=UserServerToken(
                username="alice",
                server_path="/jira",
                access_token_encrypted="enc",
                refresh_token_encrypted=None,
                expires_at=datetime.now(UTC) + timedelta(minutes=1),
            )
        )

        assert await repo.is_expired("alice", "/jira") is False

