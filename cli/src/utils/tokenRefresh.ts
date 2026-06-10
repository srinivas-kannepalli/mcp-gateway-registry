import {exec} from "node:child_process";
import {promises as fs} from "node:fs";
import {promisify} from "node:util";
import path from "node:path";
import os from "node:os";

const execAsync = promisify(exec);

export interface TokenRefreshResult {
  success: boolean;
  message: string;
}

/**
 * Perform Auth0 device code flow to obtain a gateway token.
 * Saves the resulting token to .oauth-tokens/ingress.json.
 * @param onMessage - Optional callback to surface progress messages to the caller
 * @returns Result of the token acquisition
 */
async function auth0DeviceCodeFlow(onMessage?: (msg: string) => void): Promise<TokenRefreshResult> {
  const domain = process.env.AUTH0_DOMAIN;
  const clientId = process.env.AUTH0_CLI_CLIENT_ID;

  if (!domain || !clientId) {
    return {success: false, message: "AUTH0_DOMAIN and AUTH0_CLI_CLIENT_ID are required for Auth0 device code flow"};
  }

  // Step 1: initiate device code
  let deviceRes: Response;
  try {
    deviceRes = await fetch(`https://${domain}/oauth/device/code`, {
      method: "POST",
      headers: {"content-type": "application/x-www-form-urlencoded"},
      body: new URLSearchParams({client_id: clientId, scope: "openid profile email"}).toString()
    });
  } catch (err) {
    return {success: false, message: `Failed to contact Auth0: ${(err as Error).message}`};
  }

  if (!deviceRes.ok) {
    const body = await deviceRes.text();
    return {success: false, message: `Device code request failed (${deviceRes.status}): ${body}`};
  }

  const deviceData = (await deviceRes.json()) as {
    device_code: string;
    user_code: string;
    verification_uri: string;
    verification_uri_complete?: string;
    expires_in: number;
    interval: number;
  };

  const verifyUrl = deviceData.verification_uri_complete ?? deviceData.verification_uri;
  onMessage?.(`🔐 Open this URL to authenticate:\n\n  ${verifyUrl}\n\n  User code: **${deviceData.user_code}**`);

  // Step 2: poll for token
  const pollInterval = (deviceData.interval ?? 5) * 1000;
  const expiresAt = Date.now() + deviceData.expires_in * 1000;

  while (Date.now() < expiresAt) {
    await new Promise((resolve) => setTimeout(resolve, pollInterval));

    let tokenRes: Response;
    try {
      tokenRes = await fetch(`https://${domain}/oauth/token`, {
        method: "POST",
        headers: {"content-type": "application/x-www-form-urlencoded"},
        body: new URLSearchParams({
          grant_type: "urn:ietf:params:oauth:grant-type:device_code",
          device_code: deviceData.device_code,
          client_id: clientId
        }).toString()
      });
    } catch (err) {
      return {success: false, message: `Polling failed: ${(err as Error).message}`};
    }

    const tokenData = (await tokenRes.json()) as Record<string, unknown>;

    if (tokenData.error === "authorization_pending" || tokenData.error === "slow_down") {
      continue;
    }

    if (tokenData.error) {
      return {success: false, message: `Auth0 error: ${tokenData.error} — ${tokenData.error_description ?? ""}`};
    }

    if (typeof tokenData.access_token !== "string") {
      return {success: false, message: "No access_token in Auth0 response"};
    }

    // Step 3: save to ~/.mcp/ingress_token (plain text) — matches resolveGatewayToken home dir fallback
    const mcpDir = path.join(os.homedir(), ".mcp");
    await fs.mkdir(mcpDir, {recursive: true, mode: 0o700});
    await fs.writeFile(path.join(mcpDir, "ingress_token"), tokenData.access_token, {encoding: "utf-8", mode: 0o600});

    // Also set in-process env so the next resolveAuth call picks it up immediately via the env var path
    process.env.MCP_GATEWAY_TOKEN = tokenData.access_token;

    return {success: true, message: "Auth0 token obtained and saved successfully"};
  }

  return {success: false, message: "Device code flow timed out — user did not authenticate in time"};
}

/**
 * Automatically refresh OAuth tokens by calling generate_creds.sh.
 * If AUTH0_DOMAIN and AUTH0_CLI_CLIENT_ID are set, uses Auth0 device code flow instead.
 * @param projectRoot - Path to the project root directory
 * @param onMessage - Optional callback to surface progress messages (e.g. device code URL)
 * @returns Result of the token refresh operation
 */
export async function refreshTokens(projectRoot?: string, onMessage?: (msg: string) => void): Promise<TokenRefreshResult> {
  // Auth0 device code flow takes priority when env vars are present
  if (process.env.AUTH0_DOMAIN && process.env.AUTH0_CLI_CLIENT_ID) {
    return auth0DeviceCodeFlow(onMessage);
  }
  try {
    // Default to parent of cli directory
    const root = projectRoot || path.join(process.cwd(), "..");
    const scriptPath = path.join(root, "credentials-provider", "generate_creds.sh");

    // Check if script exists
    try {
      await execAsync(`test -f "${scriptPath}"`);
    } catch {
      return {
        success: false,
        message: `Token refresh script not found at ${scriptPath}`
      };
    }

    // Run the script with --ingress-only and --force flags
    const {stdout, stderr} = await execAsync(
      `cd "${root}" && ./credentials-provider/generate_creds.sh --ingress-only --force`,
      {
        timeout: 30000, // 30 second timeout
        maxBuffer: 1024 * 1024 // 1MB buffer
      }
    );

    // Check if successful by looking for success indicators in output
    const output = stdout + stderr;
    if (output.includes("Successfully") || output.includes("Token generated") || output.includes("Tokens saved")) {
      return {
        success: true,
        message: "OAuth tokens refreshed successfully"
      };
    }

    return {
      success: false,
      message: `Token refresh completed but status unclear: ${output.substring(0, 200)}`
    };
  } catch (error: any) {
    return {
      success: false,
      message: `Failed to refresh tokens: ${error.message}`
    };
  }
}

/**
 * Check if we should attempt automatic token refresh
 * @param secondsRemaining - Seconds until token expires
 * @returns true if we should refresh
 */
export function shouldRefreshToken(secondsRemaining: number | undefined): boolean {
  // Refresh if token expires in less than 10 seconds or already expired
  return secondsRemaining !== undefined && secondsRemaining <= 10;
}
