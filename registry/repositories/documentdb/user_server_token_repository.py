"""DocumentDB repository for per-user downstream OAuth tokens."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from motor.motor_asyncio import AsyncIOMotorCollection

from registry.repositories.interfaces import UserServerTokenRepositoryBase
from registry.schemas.user_server_token_models import UserServerToken, UserServerTokenCreate
from registry.utils.credential_encryption import _get_fernet

from .client import get_collection_name, get_documentdb_client

logger = logging.getLogger(__name__)

_COLLECTION = "user_server_tokens"


def _encrypt(plaintext: str) -> str | None:
    fernet = _get_fernet()
    if not fernet or not plaintext:
        return None
    return fernet.encrypt(plaintext.encode()).decode()


def _decrypt(ciphertext: str | None) -> str | None:
    if not ciphertext:
        return None
    fernet = _get_fernet()
    if not fernet:
        return None
    try:
        return fernet.decrypt(ciphertext.encode()).decode()
    except Exception:
        logger.warning("Failed to decrypt downstream token")
        return None


class UserServerTokenRepository(UserServerTokenRepositoryBase):
    """Store and retrieve per-user OAuth tokens for downstream MCP servers."""

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

    async def upsert(self, token_in: UserServerTokenCreate) -> None:
        """Create or replace the token for (username, server_path)."""
        col = await self._get_collection()
        doc = {
            "username": token_in.username,
            "server_path": token_in.server_path,
            "access_token_encrypted": _encrypt(token_in.access_token),
            "refresh_token_encrypted": _encrypt(token_in.refresh_token)
            if token_in.refresh_token
            else None,
            "expires_at": token_in.expires_at,
            "token_type": token_in.token_type,
            "scope": token_in.scope,
            "updated_at": datetime.now(UTC),
        }
        await col.update_one(
            {"username": token_in.username, "server_path": token_in.server_path},
            {"$set": doc, "$setOnInsert": {"created_at": datetime.now(UTC)}},
            upsert=True,
        )

    async def get(self, username: str, server_path: str) -> UserServerToken | None:
        """Return the token model (with encrypted fields) or None."""
        col = await self._get_collection()
        doc = await col.find_one({"username": username, "server_path": server_path})
        if not doc:
            return None
        doc.pop("_id", None)
        return UserServerToken(**doc)

    async def get_access_token(self, username: str, server_path: str) -> str | None:
        """Return the decrypted access token or None."""
        token = await self.get(username, server_path)
        if not token:
            return None
        return _decrypt(token.access_token_encrypted)

    async def get_refresh_token(self, username: str, server_path: str) -> str | None:
        """Return the decrypted refresh token or None."""
        token = await self.get(username, server_path)
        if not token:
            return None
        return _decrypt(token.refresh_token_encrypted)

    async def delete(self, username: str, server_path: str) -> bool:
        """Delete the token. Returns True if a document was deleted."""
        col = await self._get_collection()
        result = await col.delete_one({"username": username, "server_path": server_path})
        return result.deleted_count > 0

    async def is_expired(self, username: str, server_path: str) -> bool:
        """Return True if the token is missing or past its expiry."""
        token = await self.get(username, server_path)
        if not token:
            return True
        if token.expires_at is None:
            return False
        return datetime.now(UTC) >= token.expires_at.replace(tzinfo=UTC)
