import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { AutoSignIn } from './AutoSignIn';

// Mock react-oidc-context so we can drive useAuth() return values per-test.
type AuthMock = {
  isAuthenticated: boolean;
  isLoading: boolean;
  activeNavigator: string | undefined;
  error: Error | undefined;
  signinRedirect: ReturnType<typeof vi.fn>;
};

const authState: AuthMock = {
  isAuthenticated: false,
  isLoading: false,
  activeNavigator: undefined,
  error: undefined,
  signinRedirect: vi.fn(),
};

vi.mock('react-oidc-context', () => ({
  useAuth: () => authState,
}));

describe('<AutoSignIn>', () => {
  let reloadSpy: ReturnType<typeof vi.fn>;
  let origLocation: Location;

  beforeEach(() => {
    authState.isAuthenticated = false;
    authState.isLoading = false;
    authState.activeNavigator = undefined;
    authState.error = undefined;
    authState.signinRedirect = vi.fn().mockResolvedValue(undefined);
    // jsdom's location.reload is non-configurable in some versions; replace
    // the whole location object so we can spy on reload().
    origLocation = window.location;
    reloadSpy = vi.fn();
    Object.defineProperty(window, 'location', {
      configurable: true,
      writable: true,
      value: { ...origLocation, reload: reloadSpy, search: '', pathname: '/' } as unknown as Location,
    });
    sessionStorage.clear();
  });

  afterEach(() => {
    cleanup();
    Object.defineProperty(window, 'location', {
      configurable: true,
      writable: true,
      value: origLocation,
    });
    sessionStorage.clear();
  });

  it('renders the spinner when not authenticated, not loading, no error', () => {
    render(<AutoSignIn />);
    expect(screen.getByText(/signing in/i)).toBeDefined();
  });

  it('calls signinRedirect when not authenticated and not loading', async () => {
    render(<AutoSignIn />);
    await waitFor(() => expect(authState.signinRedirect).toHaveBeenCalled());
  });

  it('renders the error block when auth.error is set (from callback failure)', () => {
    authState.error = new Error('invalid_grant: code has expired');
    render(<AutoSignIn />);
    expect(screen.getByText(/sign-in failed/i)).toBeDefined();
    expect(screen.getByText(/invalid_grant: code has expired/)).toBeDefined();
    expect(screen.getByRole('button', { name: /clear session and retry/i })).toBeDefined();
    // Importantly, no auto-redirect loop when error is present.
    expect(authState.signinRedirect).not.toHaveBeenCalled();
  });

  it('renders the error block when signinRedirect() itself throws', async () => {
    authState.signinRedirect = vi.fn().mockRejectedValue(new Error('network down'));
    render(<AutoSignIn />);
    await waitFor(() => expect(screen.getByText(/sign-in failed/i)).toBeDefined());
    expect(screen.getByText(/network down/)).toBeDefined();
  });

  it('"Clear session and retry" wipes oidc.* sessionStorage keys and reloads', async () => {
    sessionStorage.setItem('oidc.user:foo', '{}');
    sessionStorage.setItem('oidc.somethingelse', 'bar');
    sessionStorage.setItem('unrelated', 'keep-me');
    authState.error = new Error('boom');

    render(<AutoSignIn />);
    const btn = screen.getByRole('button', { name: /clear session and retry/i });
    fireEvent.click(btn);

    expect(sessionStorage.getItem('oidc.user:foo')).toBeNull();
    expect(sessionStorage.getItem('oidc.somethingelse')).toBeNull();
    expect(sessionStorage.getItem('unrelated')).toBe('keep-me');
    expect(reloadSpy).toHaveBeenCalled();
  });

  it('does not auto-redirect if the URL already carries a code/state', () => {
    Object.defineProperty(window, 'location', {
      configurable: true,
      writable: true,
      value: { ...origLocation, reload: reloadSpy, search: '?code=abc&state=xyz', pathname: '/' } as unknown as Location,
    });
    render(<AutoSignIn />);
    expect(authState.signinRedirect).not.toHaveBeenCalled();
  });

  it('manual mode renders a Sign in button instead of auto-redirecting', () => {
    render(<AutoSignIn manual />);
    expect(screen.getByRole('button', { name: /sign in/i })).toBeDefined();
    expect(authState.signinRedirect).not.toHaveBeenCalled();
  });
});
