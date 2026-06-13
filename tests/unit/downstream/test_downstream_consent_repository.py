"""Unit tests for downstream consent repository."""

from unittest.mock import AsyncMock

import pytest

from registry.repositories.documentdb.downstream_consent_repository import (
    DownstreamConsentRepository,
)


@pytest.fixture
def mock_collection() -> AsyncMock:
    collection = AsyncMock()
    collection.update_one = AsyncMock()
    collection.find_one = AsyncMock(return_value=None)
    collection.delete_one = AsyncMock()
    collection.create_index = AsyncMock()
    return collection


@pytest.fixture
def repo(mock_collection: AsyncMock) -> DownstreamConsentRepository:
    repository = DownstreamConsentRepository.__new__(DownstreamConsentRepository)
    repository._collection = mock_collection
    repository._collection_name = "downstream_oauth_consents_test"
    return repository


class TestDownstreamConsentRepository:
    """Tests for downstream consent persistence."""

    async def test_record_consent_calls_update_one(
        self,
        repo: DownstreamConsentRepository,
        mock_collection: AsyncMock,
    ) -> None:
        await repo.record_consent("alice", "/jira", ["read", "write"])

        filter_doc = mock_collection.update_one.await_args.args[0]
        update_doc = mock_collection.update_one.await_args.args[1]
        assert filter_doc == {"username": "alice", "server_path": "/jira"}
        assert update_doc["$set"]["scopes"] == ["read", "write"]

    async def test_has_consent_returns_true_when_found(
        self,
        repo: DownstreamConsentRepository,
        mock_collection: AsyncMock,
    ) -> None:
        mock_collection.find_one.return_value = {"username": "alice", "server_path": "/jira"}

        assert await repo.has_consent("alice", "/jira") is True

    async def test_has_consent_returns_false_when_not_found(
        self,
        repo: DownstreamConsentRepository,
    ) -> None:
        assert await repo.has_consent("alice", "/jira") is False

    async def test_revoke_consent_calls_delete_one(
        self,
        repo: DownstreamConsentRepository,
        mock_collection: AsyncMock,
    ) -> None:
        await repo.revoke_consent("alice", "/jira")

        mock_collection.delete_one.assert_awaited_once_with(
            {"username": "alice", "server_path": "/jira"}
        )

