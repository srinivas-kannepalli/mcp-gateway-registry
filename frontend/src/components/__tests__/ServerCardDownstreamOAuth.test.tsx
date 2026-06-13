/**
 * Tests for downstream OAuth UI in ServerCard:
 * - Status badge renders correct state (connected / auth required / loading)
 * - fetchDownstreamStatus calls the correct endpoint on mount
 * - Connect button opens a popup to the authorize endpoint
 * - postMessage('oauth_complete') refreshes status and shows toast
 * - No badge rendered for servers without downstream_oauth
 */

import React from 'react';
import { render, screen, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import axios from 'axios';
import ServerCard from '../ServerCard';
import type { Server } from '../ServerCard';

// ---------------------------------------------------------------------------
// Module mocks
// ---------------------------------------------------------------------------

jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

jest.mock('../../contexts/AuthContext', () => ({
  useAuth: jest.fn().mockReturnValue({ user: { username: 'testuser', is_admin: true } }),
}));

jest.mock('../../hooks/useEscapeKey', () => jest.fn());

// ---------------------------------------------------------------------------
// Base server fixture
// ---------------------------------------------------------------------------

const baseServer: Server = {
  name: 'Test Server',
  path: '/test-server',
  enabled: true,
  proxy_pass_url: 'http://backend:8080/mcp',
};

const oauthServer: Server = {
  ...baseServer,
  downstream_oauth: { downstream_auth_type: 'oauth2' },
};

// ---------------------------------------------------------------------------
// Render helpers
// ---------------------------------------------------------------------------

function renderCard(server: Server = baseServer) {
  return render(
    <ServerCard
      server={server}
      onToggle={jest.fn()}
      onDelete={jest.fn()}
      onShowToast={jest.fn()}
    />
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ServerCard — downstream OAuth badge', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // Default: token endpoint returns no token
    mockedAxios.get.mockResolvedValue({ data: { has_token: false, is_expired: true } });
  });

  it('does not render a downstream badge for plain servers', async () => {
    renderCard(baseServer);
    expect(screen.queryByText(/DOWNSTREAM/i)).toBeNull();
  });

  it('renders AUTH REQUIRED badge when no token exists', async () => {
    mockedAxios.get.mockResolvedValue({ data: { has_token: false, is_expired: true } });
    renderCard(oauthServer);
    await waitFor(() =>
      expect(screen.getByText('DOWNSTREAM AUTH REQUIRED')).toBeInTheDocument()
    );
  });

  it('renders CONNECTED badge when valid token exists', async () => {
    mockedAxios.get.mockResolvedValue({ data: { has_token: true, is_expired: false } });
    renderCard(oauthServer);
    await waitFor(() =>
      expect(screen.getByText('DOWNSTREAM CONNECTED')).toBeInTheDocument()
    );
  });

  it('renders CONNECTING badge while request is in-flight', async () => {
    // Never resolves during this test
    mockedAxios.get.mockReturnValue(new Promise(() => {}));
    renderCard(oauthServer);
    expect(screen.getByText('DOWNSTREAM CONNECTING')).toBeInTheDocument();
  });

  it('calls the correct status endpoint on mount', async () => {
    mockedAxios.get.mockResolvedValue({ data: { has_token: false, is_expired: true } });
    renderCard(oauthServer);
    await waitFor(() =>
      expect(mockedAxios.get).toHaveBeenCalledWith(
        '/api/servers/test-server/downstream/token/status'
      )
    );
  });

  it('falls back to AUTH REQUIRED on network error', async () => {
    mockedAxios.get.mockRejectedValue(new Error('network error'));
    renderCard(oauthServer);
    await waitFor(() =>
      expect(screen.getByText('DOWNSTREAM AUTH REQUIRED')).toBeInTheDocument()
    );
  });
});

describe('ServerCard — downstream OAuth connect flow', () => {
  let mockOpen: jest.SpyInstance;
  let mockPopup: { closed: boolean };

  beforeEach(() => {
    jest.clearAllMocks();
    mockedAxios.get.mockResolvedValue({ data: { has_token: false, is_expired: true } });
    mockPopup = { closed: false };
    mockOpen = jest.spyOn(window, 'open').mockReturnValue(mockPopup as Window);
  });

  afterEach(() => {
    mockOpen.mockRestore();
  });

  it('opens a popup to the authorize endpoint when Authorize is clicked', async () => {
    const user = userEvent.setup();
    renderCard(oauthServer);

    const authorizeBtn = await screen.findByRole('button', {
      name: /Authorize downstream OAuth for/i,
    });
    await user.click(authorizeBtn);

    expect(mockOpen).toHaveBeenCalledWith(
      '/api/servers/test-server/downstream/authorize',
      expect.stringContaining('downstream-oauth'),
      expect.stringContaining('width=')
    );
  });

  it('refreshes status and shows toast after oauth_complete postMessage', async () => {
    const onShowToast = jest.fn();
    const user = userEvent.setup();

    // Two token-status calls: mount (no token) and post-oauth (has token).
    // Other axios.get calls (e.g. security scan) are rejected so they don't
    // consume the ordered mocks.
    let statusCallCount = 0;
    mockedAxios.get.mockImplementation((url: string) => {
      if (url.includes('downstream/token/status')) {
        statusCallCount += 1;
        return statusCallCount === 1
          ? Promise.resolve({ data: { has_token: false, is_expired: true } })
          : Promise.resolve({ data: { has_token: true, is_expired: false } });
      }
      return Promise.reject(new Error('not found'));
    });

    render(
      <ServerCard
        server={oauthServer}
        onToggle={jest.fn()}
        onDelete={jest.fn()}
        onShowToast={onShowToast}
      />
    );

    const authorizeBtn = await screen.findByRole('button', {
      name: /Authorize downstream OAuth for/i,
    });
    await user.click(authorizeBtn);

    // Simulate the popup posting oauth_complete
    await act(async () => {
      window.dispatchEvent(new MessageEvent('message', { data: 'oauth_complete' }));
    });

    await waitFor(() =>
      expect(screen.getByText('DOWNSTREAM CONNECTED')).toBeInTheDocument()
    );

    expect(onShowToast).toHaveBeenCalledWith(
      expect.stringContaining('connected'),
      'success'
    );
  });

  it('shows an error toast when popup is blocked', async () => {
    mockOpen.mockReturnValue(null); // popup blocked
    const onShowToast = jest.fn();
    const user = userEvent.setup();

    render(
      <ServerCard
        server={oauthServer}
        onToggle={jest.fn()}
        onDelete={jest.fn()}
        onShowToast={onShowToast}
      />
    );

    const authorizeBtn = await screen.findByRole('button', {
      name: /Authorize downstream OAuth for/i,
    });
    await user.click(authorizeBtn);

    expect(onShowToast).toHaveBeenCalledWith(
      expect.stringContaining('Popup'),
      'error'
    );
  });
});
