import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { BffAuthProvider } from './BffAuthProvider';
import { BffAutoSignIn } from './BffAutoSignIn';

describe('<BffAutoSignIn>', () => {
  let fetchSpy: ReturnType<typeof vi.fn>;
  let assignSpy: ReturnType<typeof vi.fn>;
  let origLocation: Location;

  beforeEach(() => {
    fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);
    origLocation = window.location;
    assignSpy = vi.fn();
    Object.defineProperty(window, 'location', {
      configurable: true,
      writable: true,
      value: { ...origLocation, assign: assignSpy, pathname: '/', search: '' } as unknown as Location,
    });
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    Object.defineProperty(window, 'location', {
      configurable: true,
      writable: true,
      value: origLocation,
    });
  });

  it('redirects to /_bff/login when /me returns 401', async () => {
    fetchSpy.mockResolvedValueOnce(new Response(null, { status: 401 }));
    (window.location as unknown as { pathname: string; search: string }).pathname =
      '/dashboard';
    (window.location as unknown as { pathname: string; search: string }).search =
      '?tab=overview';
    render(
      <BffAuthProvider>
        <BffAutoSignIn heading="App 1" />
      </BffAuthProvider>,
    );
    await waitFor(() => expect(assignSpy).toHaveBeenCalled());
    expect(assignSpy).toHaveBeenCalledWith(
      '/_bff/login?redirect_back=' + encodeURIComponent('/dashboard?tab=overview'),
    );
  });

  it('does NOT redirect while loading', async () => {
    // Never-resolving fetch keeps provider in isLoading=true forever.
    fetchSpy.mockReturnValue(new Promise(() => {}));
    render(
      <BffAuthProvider>
        <BffAutoSignIn />
      </BffAuthProvider>,
    );
    // Give effects a tick to fire if they were going to.
    await new Promise((r) => setTimeout(r, 20));
    expect(assignSpy).not.toHaveBeenCalled();
  });

  it('does NOT redirect when already authenticated', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          user: { id: 'u', email: 'a@b', preferredUsername: 'a' },
          context: 'tenant',
          isPlatformAdmin: false,
          isTenantAdmin: false,
          permissions: [],
        }),
        { status: 200 },
      ),
    );
    render(
      <BffAuthProvider>
        <BffAutoSignIn />
      </BffAuthProvider>,
    );
    // wait for the resolution to flow through
    await new Promise((r) => setTimeout(r, 20));
    expect(assignSpy).not.toHaveBeenCalled();
  });

  it('renders heading and subtitle when provided', async () => {
    fetchSpy.mockResolvedValueOnce(new Response(null, { status: 401 }));
    render(
      <BffAuthProvider>
        <BffAutoSignIn heading="My App" subtitle="Sign in to continue." />
      </BffAuthProvider>,
    );
    expect(screen.getByText('My App')).toBeDefined();
    expect(screen.getByText('Sign in to continue.')).toBeDefined();
  });

  it('manual mode renders a button and does not auto-redirect', async () => {
    fetchSpy.mockResolvedValueOnce(new Response(null, { status: 401 }));
    render(
      <BffAuthProvider>
        <BffAutoSignIn manual />
      </BffAuthProvider>,
    );
    await waitFor(() => expect(screen.getByRole('button', { name: /sign in/i })).toBeDefined());
    expect(assignSpy).not.toHaveBeenCalled();
  });

  it('renders the error block when the /me probe fails (non-401)', async () => {
    // Edge returns 500 -> BffAuthProvider sets error -> BffAutoSignIn should
    // show the failure UI, NOT loop into /_bff/login.
    fetchSpy.mockResolvedValueOnce(new Response(null, { status: 500 }));
    render(
      <BffAuthProvider>
        <BffAutoSignIn />
      </BffAuthProvider>,
    );
    await waitFor(() => expect(screen.getByText(/sign-in failed/i)).toBeDefined());
    expect(screen.getByRole('button', { name: /retry/i })).toBeDefined();
    expect(assignSpy).not.toHaveBeenCalled();
  });

  it('renders the error block when the /me probe throws (network error)', async () => {
    fetchSpy.mockRejectedValueOnce(new TypeError('Failed to fetch'));
    render(
      <BffAuthProvider>
        <BffAutoSignIn />
      </BffAuthProvider>,
    );
    await waitFor(() => expect(screen.getByText(/sign-in failed/i)).toBeDefined());
    expect(screen.getByText(/Failed to fetch/)).toBeDefined();
    expect(assignSpy).not.toHaveBeenCalled();
  });

  it('"Retry" button on the error block reloads the page', async () => {
    fetchSpy.mockResolvedValueOnce(new Response(null, { status: 500 }));
    const reloadSpy = vi.fn();
    (window.location as unknown as { reload: () => void }).reload = reloadSpy;
    render(
      <BffAuthProvider>
        <BffAutoSignIn />
      </BffAuthProvider>,
    );
    await waitFor(() => expect(screen.getByRole('button', { name: /retry/i })).toBeDefined());
    fireEvent.click(screen.getByRole('button', { name: /retry/i }));
    expect(reloadSpy).toHaveBeenCalled();
  });
});
