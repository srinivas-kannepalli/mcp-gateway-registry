"""DocumentDB repository for downstream OAuth PKCE/state entries.

Stores single-use, short-lived state tokens used during the downstream
OAuth authorization code flow. Each entry is consumed exactly once
(deleted on read) and expires after 10 minutes via a MongoDB TTL index.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from motor.motor_asyncio import AsyncIOMotorCollection

from registry.repositories.interfaces import DownstreamOAuthStateRepositoryBase
from .client import get_collection_name, get_documentdb_client

logger = logging.getLogger(__name__)

_COLLECTION = "downstream_oauth_states"
_STATE_TTL_SECONDS = 600  # 10 minutes


class DownstreamOAuthStateRepository(DownstreamOAuthStateRepositoryBase):
    """Single-use OAuth state store backed by DocumentDB.

    Safe for multi-instance deployments — no in-memory state.
    The TTL index on ``created_at`` ensures automatic cleanup of
    abandoned states even if the callback is never called.
    """

    def __init__(self) -> None:
        self._collection: AsyncIOMotorCollection | None = None
        self._collection_name = get_collection_name(_COLLECTION)

    async def _get_collection(self) -> AsyncIOMotorCollection:
        if self._collection is None:
            db = await get_documentdb_client()
            col = db[self._collection_name]
            # Unique index on the state token itself
            await col.create_index("state", unique=True, background=True)
            # TTL index — MongoDB automatically deletes documents after
            # _STATE_TTL_SECONDS from created_at
            await col.create_index(
                "created_at",
                expireAfterSeconds=_STATE_TTL_SECONDS,
                background=True,
            )
            self._collection = col
        return self._collection

    async def save(self, state: str, payload: dict) -> None:
        """Persist a state entry. Raises on duplicate state token."""
        col = await self._get_collection()
        doc = {
            "state": state,
            "created_at": datetime.now(UTC),
            **{k: v for k, v in payload.items() if k not in ("state", "created_at")},
        }
        await col.insert_one(doc)

    async def consume(self, state: str) -> dict | None:
        """Atomically find-and-delete the state entry.

        Returns the payload dict (without ``_id`` / ``state`` / ``created_at``)
        if valid, or None if missing or expired.
        """
        col = await self._get_collection()
        # find_one_and_delete is atomic — safe under concurrent requests
        doc = await col.find_one_and_delete({"state": state})
        if not doc:
            return None

        # Double-check TTL in application code in case the MongoDB TTL
        # reaper hasn't run yet (it runs ~once per minute).
        created_at = doc.get("created_at")
        if created_at:
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=UTC)
            if datetime.now(UTC) - created_at > timedelta(seconds=_STATE_TTL_SECONDS):
                logger.warning("Downstream OAuth state expired (TTL reaper lag): %s", state)
                return None

        doc.pop("_id", None)
        doc.pop("state", None)
        doc.pop("created_at", None)
        return doc
