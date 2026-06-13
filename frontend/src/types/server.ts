/**
 * Shared types for server data shapes.
 *
 * These mirror the backend Pydantic models in registry/core/schemas.py.
 * Keep field names and optionality in sync — the API contract is the source
 * of truth, this file just gives TypeScript a vocabulary for it.
 */


/**
 * Local stdio MCP server launch recipe. Stored on a Server when
 * deployment === 'local'.
 */
export interface LocalRuntime {
  type: 'npx' | 'docker' | 'uvx' | 'command';
  package: string;
  args?: string[];
  env?: Record<string, string>;
  required_env?: string[];
  image_digest?: string;
  platforms?: string[];
  version?: string;
}

export interface DownstreamOAuthConfig {
  downstream_auth_type?: 'none' | 'oauth2';
  dcr_enabled?: boolean;
  client_id?: string | null;
  token_url?: string | null;
  auth_url?: string | null;
  scopes?: string[];
  resource_indicator?: string | null;
}
