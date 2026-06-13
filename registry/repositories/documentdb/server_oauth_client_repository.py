"""DocumentDB repository for downstream server OAuth client credentials."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from motor.motor_asyncio import AsyncIOMotorCollection

from registry.schemas.server_oauth_client_models import ServerOAuthClient
from registry.utils.credential_encryption import _get_fernet

from .client import get_collection_name, get_documentdb_client

logger = logging.getLogger(__name__)

_COLLECTION = "server_oauth_clients"


def _encrypt(plaintext: str | None) -> str | None:
    if not plaintext:
        return None
    fernet = _get_fernet()
    return fernet.encrypt(plaintext.encode()).decode() if fernet else None


def _decrypt(ciphertext: str | None) -> str | None:
    if not ciphertext:
        return None
    fernet = _get_fernet()
    if not fernet:
        return None
    try:
        return fernet.decrypt(ciphertext.encode()).decode()
    except Exception:
        logger.warning("Failed to decrypt server OAuth client secret")
        return None


class ServerOAuthClientRepository:
    """Store and retrieve OAuth client credentials for downstream servers."""

    def __init__(self) -> None:
        self._collection: AsyncIOMotorCollection | None = None
        self._collection_name = get_collection_name(_COLLECTION)

    async def _get_collection(self) -> AsyncIOMotorCollection:
        if self._collection is None:
            db = await get_documentdb_client()
            self._collection = db[self._collection_name]
            await self._collection.create_index("server_path", unique=True, background=True)
        return self._collection

    async def upsert(
        self,
        server_path: str,
        client_id: str,
        client_secret: str | None,
        token_endpoint: str,
        authorization_endpoint: str,
        scopes_supported: list[str],
        via_dcr: bool = False,
        registration_access_token: str | None = None,
    ) -> None:
        col = await self._get_collection()
        doc = {
            "server_path": server_path,
            "client_id": client_id,
            "client_secret_encrypted": _encrypt(client_secret),
            "registration_access_token_encrypted": _encrypt(registration_access_token),
            "token_endpoint": token_endpoint,
            "authorization_endpoint": authorization_endpoint,
            "scopes_supported": scopes_supported,
            "via_dcr": via_dcr,
            "updated_at": datetime.now(UTC),
        }
        await col.update_one(
            {"server_path": server_path},
            {"$set": doc, "$setOnInsert": {"created_at": datetime.now(UTC)}},
            upsert=True,
        )

    async def get(self, server_path: str) -> ServerOAuthClient | None:
        col = await self._get_collection()
        doc = await col.find_one({"server_path": server_path})
        if not doc:
            return None
        doc.pop("_id", None)
        return ServerOAuthClient(**doc)

    async def get_client_secret(self, server_path: str) -> str | None:
        client = await self.get(server_path)
        if not client:
            return None
        return _decrypt(client.client_secret_encrypted)

    async def delete(self, server_path: str) -> bool:
        col = await self._get_collection()
        result = await col.delete_one({"server_path": server_path})
        return result.deleted_count > 0
