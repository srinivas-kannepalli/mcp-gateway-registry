"""Models for per-user downstream OAuth tokens."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class UserServerToken(BaseModel):
    """Per-user, per-server OAuth token stored encrypted in MongoDB."""

    username: str = Field(..., description="Gateway username (from session).")
    server_path: str = Field(..., description="Server path key (e.g. 'atlassian-jira').")
    access_token_encrypted: str = Field(..., description="Fernet-encrypted access token.")
    refresh_token_encrypted: str | None = Field(
        default=None,
        description="Fernet-encrypted refresh token (if issued).",
    )
    expires_at: datetime | None = Field(
        default=None,
        description="UTC expiry of the access token.",
    )
    token_type: str = Field(default="Bearer")
    scope: str | None = Field(default=None, description="Space-separated granted scopes.")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class UserServerTokenCreate(BaseModel):
    """Input for creating or replacing a user server token."""

    username: str
    server_path: str
    access_token: str
    refresh_token: str | None = None
    expires_at: datetime | None = None
    token_type: str = "Bearer"
    scope: str | None = None


class UserServerTokenStatus(BaseModel):
    """Public token status returned by the status endpoint."""

    server_path: str
    has_token: bool
    is_expired: bool
    scope: str | None = None
    expires_at: datetime | None = None
