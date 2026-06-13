"""Simple consent registry for downstream OAuth (confused deputy mitigation)."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from motor.motor_asyncio import AsyncIOMotorCollection

from registry.repositories.interfaces import DownstreamConsentRepositoryBase
from .client import get_collection_name, get_documentdb_client

logger = logging.getLogger(__name__)

_COLLECTION = "downstream_oauth_consents"


class DownstreamConsentRepository(DownstreamConsentRepositoryBase):
    """Tracks which users have consented to downstream OAuth for each server."""

    def __init__(self) -> None:
        self._collection: AsyncIOMotorCollection | None = None
        self._collection_name = get_collection_name(_COLLECTION)

    async def _get_collection(self) -> AsyncIOMotorCollection:
        if self._collection is None:
            db = await get_documentdb_client()
            self._collection = db[self._collection_name]
            await self._collection.create_index(
                [("username", 1), ("server_path", 1)],
                unique=True,
                background=True,
            )
        return self._collection

    async def record_consent(self, username: str, server_path: str, scopes: list[str]) -> None:
        col = await self._get_collection()
        await col.update_one(
            {"username": username, "server_path": server_path},
            {"$set": {"scopes": scopes, "consented_at": datetime.now(UTC)}},
            upsert=True,
        )

    async def has_consent(self, username: str, server_path: str) -> bool:
        col = await self._get_collection()
        doc = await col.find_one({"username": username, "server_path": server_path})
        return doc is not None

    async def revoke_consent(self, username: str, server_path: str) -> None:
        col = await self._get_collection()
        await col.delete_one({"username": username, "server_path": server_path})
