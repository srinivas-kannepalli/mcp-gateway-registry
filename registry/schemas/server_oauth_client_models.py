"""Models for DCR-registered or statically-configured OAuth clients per server."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field


class ServerOAuthClient(BaseModel):
    """OAuth client credentials for a downstream MCP server."""

    server_path: str = Field(..., description="Server path key.")
    client_id: str = Field(..., description="OAuth client_id.")
    token_endpoint_auth_method: str = Field(
        default="none",
        description="Token endpoint client authentication method.",
    )
    client_secret_encrypted: str | None = Field(
        default=None,
        description="Fernet-encrypted client_secret.",
    )
    registration_access_token_encrypted: str | None = Field(
        default=None,
        description="Fernet-encrypted DCR management token.",
    )
    token_endpoint: str = Field(..., description="Resolved token endpoint URL.")
    authorization_endpoint: str = Field(..., description="Resolved authorization endpoint URL.")
    scopes_supported: list[str] = Field(default_factory=list)
    via_dcr: bool = Field(default=False, description="True if registered via DCR.")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
