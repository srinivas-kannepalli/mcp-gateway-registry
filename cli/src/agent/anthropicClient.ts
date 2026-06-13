import Anthropic from "@anthropic-ai/sdk";

let cachedClient: Anthropic | null = null;

export function getAnthropicClient(): Anthropic {
  if (cachedClient) {
    return cachedClient;
  }

  const portkeyApiKey = process.env.PORTKEY_API_KEY;
  const anthropicApiKey = process.env.ANTHROPIC_API_KEY;

  if (!portkeyApiKey && !anthropicApiKey) {
    throw new Error(
      "Neither PORTKEY_API_KEY nor ANTHROPIC_API_KEY is set. Please export one before using the agent mode."
    );
  }

  if (portkeyApiKey) {
    // Portkey gateway: authenticate via x-portkey-api-key header.
    // The model string (e.g. @Anthropic/...) tells Portkey which provider virtual key to use.
    // The Anthropic SDK also sends x-api-key which Portkey ignores for routing.
    const baseURL = process.env.ANTHROPIC_BASE_URL ?? "https://gateway.ai.cimpress.io";
    cachedClient = new Anthropic({
      apiKey: portkeyApiKey,
      baseURL,
      defaultHeaders: {"x-portkey-api-key": portkeyApiKey}
    });
  } else {
    const options: ConstructorParameters<typeof Anthropic>[0] = {apiKey: anthropicApiKey!};
    if (process.env.ANTHROPIC_BASE_URL) {
      options.baseURL = process.env.ANTHROPIC_BASE_URL;
    }
    cachedClient = new Anthropic(options);
  }

  return cachedClient;
}
