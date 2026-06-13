"""In-memory implementations of the downstream OAuth repository interfaces.

Used when ``STORAGE_BACKEND=file`` or in unit tests. All state is process-local
and lost on restart — suitable for development and single-instance deployments.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

from registry.repositories.interfaces import (
    DownstreamConsentRepositoryBase,
    DownstreamOAuthStateRepositoryBase,
    ServerOAuthClientRepositoryBase,
    UserServerTokenRepositoryBase,
)
from registry.schemas.server_oauth_client_models import ServerOAuthClient
from registry.schemas.user_server_token_models import UserServerToken, UserServerTokenCreate

_STATE_TTL_SECONDS = 600


class InMemoryUserServerTokenRepository(UserServerTokenRepositoryBase):
    """Thread-safe in-memory token store (asyncio.Lock protected)."""

    def __init__(self) -> None:
        self._store: dict[tuple[str, str], dict] = {}
        self._lock = asyncio.Lock()

    async def upsert(self, token_in: UserServerTokenCreate) -> None:
        async with self._lock:
            self._store[(token_in.username, token_in.server_path)] = {
                "username": token_in.username,
                "server_path": token_in.server_path,
                "access_token": token_in.access_token,
                "refresh_token": token_in.refresh_token,
                "expires_at": token_in.expires_at,
                "token_type": token_in.token_type,
                "scope": token_in.scope,
                "updated_at": datetime.now(UTC),
            }

    async def get(self, username: str, server_path: str) -> UserServerToken | None:
        async with self._lock:
            entry = self._store.get((username, server_path))
        if not entry:
            return None
        # In-memory: no encryption — store plaintext in the encrypted fields
        return UserServerToken(
            username=entry["username"],
            server_path=entry["server_path"],
            access_token_encrypted=entry["access_token"] or "",
            refresh_token_encrypted=entry.get("refresh_token"),
            expires_at=entry.get("expires_at"),
            token_type=entry.get("token_type", "Bearer"),
            scope=entry.get("scope"),
        )

    async def get_access_token(self, username: str, server_path: str) -> str | None:
        async with self._lock:
            entry = self._store.get((username, server_path))
        return entry["access_token"] if entry else None

    async def get_refresh_token(self, username: str, server_path: str) -> str | None:
        async with self._lock:
            entry = self._store.get((username, server_path))
        return entry.get("refresh_token") if entry else None

    async def delete(self, username: str, server_path: str) -> bool:
        async with self._lock:
            return self._store.pop((username, server_path), None) is not None

    async def is_expired(self, username: str, server_path: str) -> bool:
        async with self._lock:
            entry = self._store.get((username, server_path))
        if not entry:
            return True
        expires_at = entry.get("expires_at")
        if expires_at is None:
            return False
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        return datetime.now(UTC) >= expires_at


class InMemoryServerOAuthClientRepository(ServerOAuthClientRepositoryBase):
    """In-memory OAuth client credential store."""

    def __init__(self) -> None:
        self._store: dict[str, dict] = {}
        self._lock = asyncio.Lock()

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
        async with self._lock:
            self._store[server_path] = {
                "server_path": server_path,
                "client_id": client_id,
                "client_secret": client_secret,
                "registration_access_token": registration_access_token,
                "token_endpoint": token_endpoint,
                "authorization_endpoint": authorization_endpoint,
                "scopes_supported": scopes_supported,
                "via_dcr": via_dcr,
            }

    async def get(self, server_path: str) -> ServerOAuthClient | None:
        async with self._lock:
            entry = self._store.get(server_path)
        if not entry:
            return None
        return ServerOAuthClient(
            server_path=entry["server_path"],
            client_id=entry["client_id"],
            client_secret_encrypted=entry.get("client_secret"),
            registration_access_token_encrypted=entry.get("registration_access_token"),
            token_endpoint=entry["token_endpoint"],
            authorization_endpoint=entry["authorization_endpoint"],
            scopes_supported=entry.get("scopes_supported", []),
            via_dcr=entry.get("via_dcr", False),
        )

    async def get_client_secret(self, server_path: str) -> str | None:
        async with self._lock:
            entry = self._store.get(server_path)
        return entry.get("client_secret") if entry else None

    async def delete(self, server_path: str) -> bool:
        async with self._lock:
            return self._store.pop(server_path, None) is not None


class InMemoryDownstreamConsentRepository(DownstreamConsentRepositoryBase):
    """In-memory consent store."""

    def __init__(self) -> None:
        self._store: dict[tuple[str, str], dict] = {}
        self._lock = asyncio.Lock()

    async def record_consent(self, username: str, server_path: str, scopes: list[str]) -> None:
        async with self._lock:
            self._store[(username, server_path)] = {
                "scopes": scopes,
                "consented_at": datetime.now(UTC),
            }

    async def has_consent(self, username: str, server_path: str) -> bool:
        async with self._lock:
            return (username, server_path) in self._store

    async def revoke_consent(self, username: str, server_path: str) -> None:
        async with self._lock:
            self._store.pop((username, server_path), None)


class InMemoryDownstreamOAuthStateRepository(DownstreamOAuthStateRepositoryBase):
    """In-memory single-use OAuth state store with TTL enforcement."""

    def __init__(self) -> None:
        self._store: dict[str, dict] = {}
        self._lock = asyncio.Lock()

    async def save(self, state: str, payload: dict) -> None:
        async with self._lock:
            self._store[state] = {**payload, "created_at": datetime.now(UTC)}

    async def consume(self, state: str) -> dict | None:
        async with self._lock:
            entry = self._store.pop(state, None)
        if not entry:
            return None
        created_at = entry.get("created_at")
        if created_at:
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=UTC)
            if datetime.now(UTC) - created_at > timedelta(seconds=_STATE_TTL_SECONDS):
                return None
        entry.pop("created_at", None)
        return entry
