"""Unit tests for downstream OAuth schema models."""

from registry.core.schemas import DownstreamOAuthConfig, ServerInfo


class TestDownstreamOAuthConfig:
    """Tests for downstream OAuth config defaults and validation."""

    def test_defaults(self) -> None:
        config = DownstreamOAuthConfig()

        assert config.downstream_auth_type == "none"
        assert config.dcr_enabled is False
        assert config.scopes == []
        assert config.client_secret_encrypted is None
        assert config.resource_indicator is None

    def test_accepts_valid_auth_types(self) -> None:
        assert DownstreamOAuthConfig(downstream_auth_type="none").downstream_auth_type == "none"
        assert DownstreamOAuthConfig(downstream_auth_type="oauth2").downstream_auth_type == "oauth2"

    def test_server_info_defaults_downstream_oauth(self) -> None:
        server = ServerInfo(server_name="Test Server", path="/test-server", proxy_pass_url="https://a")

        assert server.downstream_oauth.downstream_auth_type == "none"

    def test_server_info_accepts_full_config_dict(self) -> None:
        server = ServerInfo(
            server_name="Test Server",
            path="/test-server",
            proxy_pass_url="https://a",
            downstream_oauth={
                "downstream_auth_type": "oauth2",
                "dcr_enabled": True,
                "client_id": "client-123",
                "client_secret_encrypted": "enc-secret",
                "token_url": "https://auth.example.com/token",
                "auth_url": "https://auth.example.com/authorize",
                "scopes": ["read", "write"],
                "resource_indicator": "https://api.example.com",
            },
        )

        assert server.downstream_oauth.downstream_auth_type == "oauth2"
        assert server.downstream_oauth.dcr_enabled is True
        assert server.downstream_oauth.client_id == "client-123"
        assert server.downstream_oauth.client_secret_encrypted == "enc-secret"
        assert server.downstream_oauth.token_url == "https://auth.example.com/token"
        assert server.downstream_oauth.auth_url == "https://auth.example.com/authorize"
        assert server.downstream_oauth.scopes == ["read", "write"]
        assert server.downstream_oauth.resource_indicator == "https://api.example.com"

