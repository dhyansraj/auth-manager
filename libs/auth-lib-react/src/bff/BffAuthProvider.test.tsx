import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, render, screen, waitFor } from '@testing-library/react';
import { BffAuthProvider } from './BffAuthProvider';
import { useBffAuth } from './useBffAuth';
import type { MeResponse } from '../types';

const ME_OK: MeResponse = {
  user: {
    id: 'user-uuid-1',
    email: 'alice@example.com',
    preferredUsername: 'alice',
    name: 'Alice Doe',
  },
  context: 'tenant',
  tenant: {
    id: 'tenant-uuid-1',
    slug: 'app1',
    displayName: 'App 1',
    realmName: 't-app1',
  },
  isPlatformAdmin: false,
  isTenantAdmin: true,
  permissions: ['users.read', 'users.write'],
};

function Probe() {
  const a = useBffAuth();
  if (a.isLoading) return <div>loading</div>;
  if (a.error) return <div>error:{a.error.message}</div>;
  if (!a.isAuthenticated) return <div>anon</div>;
  return <div>auth:{a.user?.profile.preferred_username}</div>;
}

describe('<BffAuthProvider>', () => {
  let fetchSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('starts in loading state, then resolves to authenticated on 200', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify(ME_OK), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    );
    render(
      <BffAuthProvider>
        <Probe />
      </BffAuthProvider>,
    );
    expect(screen.getByText('loading')).toBeDefined();
    await waitFor(() => expect(screen.getByText('auth:alice')).toBeDefined());
    expect(fetchSpy).toHaveBeenCalledWith('/_bff/me', {
      credentials: 'include',
      headers: { Accept: 'application/json' },
    });
  });

  it('renders anon (not throwing) when /me returns 401', async () => {
    fetchSpy.mockResolvedValueOnce(new Response(null, { status: 401 }));
    render(
      <BffAuthProvider>
        <Probe />
      </BffAuthProvider>,
    );
    await waitFor(() => expect(screen.getByText('anon')).toBeDefined());
  });

  it('respects custom meEndpoint', async () => {
    fetchSpy.mockResolvedValueOnce(new Response(null, { status: 401 }));
    render(
      <BffAuthProvider meEndpoint="/api/v1/me">
        <Probe />
      </BffAuthProvider>,
    );
    await waitFor(() => expect(screen.getByText('anon')).toBeDefined());
    expect(fetchSpy.mock.calls[0][0]).toBe('/api/v1/me');
  });

  it('surfaces non-401 HTTP errors via error and renders anon', async () => {
    fetchSpy.mockResolvedValueOnce(new Response(null, { status: 500 }));
    render(
      <BffAuthProvider>
        <Probe />
      </BffAuthProvider>,
    );
    await waitFor(() => expect(screen.getByText(/error:/)).toBeDefined());
  });

  it('exposes user.me payload with the right shape', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify(ME_OK), { status: 200 }),
    );
    let captured: ReturnType<typeof useBffAuth> | null = null;
    function Capture() {
      captured = useBffAuth();
      return null;
    }
    render(
      <BffAuthProvider>
        <Capture />
      </BffAuthProvider>,
    );
    await waitFor(() => expect(captured?.isAuthenticated).toBe(true));
    expect(captured!.user!.me).toEqual(ME_OK);
    expect(captured!.user!.profile.sub).toBe('user-uuid-1');
    expect(captured!.user!.profile.email).toBe('alice@example.com');
  });

  it('refresh() re-fetches /me', async () => {
    fetchSpy
      .mockResolvedValueOnce(new Response(JSON.stringify(ME_OK), { status: 200 }))
      .mockResolvedValueOnce(new Response(null, { status: 401 }));
    let captured: ReturnType<typeof useBffAuth> | null = null;
    function Capture() {
      captured = useBffAuth();
      return null;
    }
    render(
      <BffAuthProvider>
        <Capture />
      </BffAuthProvider>,
    );
    await waitFor(() => expect(captured?.isAuthenticated).toBe(true));
    await act(async () => {
      await captured!.refresh();
    });
    expect(fetchSpy).toHaveBeenCalledTimes(2);
    expect(captured!.isAuthenticated).toBe(false);
  });
});

describe('useBffAuth without provider', () => {
  it('throws a helpful error', () => {
    // React 18 logs to console.error on uncaught render errors; suppress noise.
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    let thrown: unknown = null;
    try {
      render(<Probe />);
    } catch (e) {
      thrown = e;
    }
    spy.mockRestore();
    expect(thrown).toBeInstanceOf(Error);
    expect((thrown as Error).message).toMatch(
      /useBffAuth\(\) must be called inside <BffAuthProvider>/,
    );
  });
});
