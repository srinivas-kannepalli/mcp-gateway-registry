import React from 'react';
import { render, screen } from '@testing-library/react';
import ServerConfigModal from '../ServerConfigModal';
import type { Server } from '../ServerCard';

// Mock the useRegistryConfig hook
const mockUseRegistryConfig = jest.fn();
jest.mock('../../hooks/useRegistryConfig', () => ({
  useRegistryConfig: () => mockUseRegistryConfig(),
}));

// Mock clipboard API
Object.assign(navigator, {
  clipboard: { writeText: jest.fn().mockResolvedValue(undefined) },
});

const baseServer: Server = {
  name: 'Test Server',
  path: '/test-server',
  enabled: true,
  proxy_pass_url: 'http://internal-host:8080/mcp',
};

function renderModal(serverOverrides: Partial<Server> = {}, configOverride?: ReturnType<typeof mockUseRegistryConfig>) {
  const server = { ...baseServer, ...serverOverrides };
  return render(
    <ServerConfigModal
      server={server}
      isOpen={true}
      onClose={jest.fn()}
      onShowToast={jest.fn()}
    />
  );
}

function getDisplayedConfig(): any {
  // The config JSON is rendered inside a <pre> tag
  const preElement = screen.getByText(/{/, { selector: 'pre' });
  return JSON.parse(preElement.textContent || '');
}

describe('ServerConfigModal URL generation', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // Default: jsdom sets window.location.origin to http://localhost
  });

  test('should use gateway URL in with-gateway mode', () => {
    mockUseRegistryConfig.mockReturnValue({
      config: {
        deployment_mode: 'with-gateway',
        registry_mode: 'full',
        nginx_updates_enabled: true,
        features: { mcp_servers: true, agents: true, skills: true, federation: true, gateway_proxy: true },
      },
      loading: false,
      error: null,
    });

    renderModal({ proxy_pass_url: 'http://internal-host:8080/api' });
    const config = getDisplayedConfig();

    // Cursor is the default IDE — config uses "mcpServers" key
    const serverConfig = config.mcpServers['test-server'];
    expect(serverConfig.url).toBe('http://localhost/test-server/mcp');
    // Gateway mode includes auth headers (X-Authorization)
    expect(serverConfig.headers).toBeDefined();
    expect(serverConfig.headers['X-Authorization']).toContain('Bearer');
  });

  test('should use proxy_pass_url in registry-only mode', () => {
    mockUseRegistryConfig.mockReturnValue({
      config: {
        deployment_mode: 'registry-only',
        registry_mode: 'full',
        nginx_updates_enabled: false,
        features: { mcp_servers: true, agents: true, skills: true, federation: true, gateway_proxy: false },
      },
      loading: false,
      error: null,
    });

    renderModal({ proxy_pass_url: 'http://internal-host:8080/mcp' });
    const config = getDisplayedConfig();

    const serverConfig = config.mcpServers['test-server'];
    expect(serverConfig.url).toBe('http://internal-host:8080/mcp');
    // Registry-only mode should NOT include auth headers
    expect(serverConfig.headers).toBeUndefined();
  });

  test('should always use mcp_endpoint when provided', () => {
    // Test with with-gateway mode
    mockUseRegistryConfig.mockReturnValue({
      config: {
        deployment_mode: 'with-gateway',
        registry_mode: 'full',
        nginx_updates_enabled: true,
        features: { mcp_servers: true, agents: true, skills: true, federation: true, gateway_proxy: true },
      },
      loading: false,
      error: null,
    });

    const { unmount } = renderModal({
      mcp_endpoint: 'https://custom-endpoint.example.com/mcp',
      proxy_pass_url: 'http://internal-host:8080/mcp',
    });
    let config = getDisplayedConfig();
    let serverConfig = config.mcpServers['test-server'];
    expect(serverConfig.url).toBe('https://custom-endpoint.example.com/mcp');

    unmount();

    // Test with registry-only mode — mcp_endpoint still takes precedence
    mockUseRegistryConfig.mockReturnValue({
      config: {
        deployment_mode: 'registry-only',
        registry_mode: 'full',
        nginx_updates_enabled: false,
        features: { mcp_servers: true, agents: true, skills: true, federation: true, gateway_proxy: false },
      },
      loading: false,
      error: null,
    });

    renderModal({
      mcp_endpoint: 'https://custom-endpoint.example.com/mcp',
      proxy_pass_url: 'http://internal-host:8080/mcp',
    });
    config = getDisplayedConfig();
    serverConfig = config.mcpServers['test-server'];
    expect(serverConfig.url).toBe('https://custom-endpoint.example.com/mcp');
  });
});
