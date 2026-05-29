import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, render, screen, waitFor } from '@testing-library/react';
import { PlatformAuthProvider } from './PlatformAuthProvider';
import {
  RequirePermission,
  usePermission,
  usePlatformAuth,
} from './usePlatformAuth';
import type { MeResponse } from '../types';

// /_bff/me payload: identity + the 6 platform usermanagement client roles only.
const BFF_ME: MeResponse = {
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
  isTenantAdmin: false,
  permissions: ['USER_READ'], // platform-usermanagement scope
};

// Tenant backend /api/me: authoritative app-level permissions.
const TENANT_ME: MeResponse = {
  ...BFF_ME,
  isTenantAdmin: true,
  permissions: ['ROUTES_EDIT', 'REPORT_VIEW_ANY'],
};

function makeJson(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function Probe() {
  const a = usePlatformAuth();
  if (a.isLoading) return <div>loading</div>;
  if (a.error && !a.isAuthenticated) return <div>error:{a.error.message}</div>;
  if (!a.isAuthenticated) return <div>anon</div>;
  return (
    <div>
      auth:{a.user?.profile.preferred_username}:
      {[...a.permissions].sort().join(',')}
    </div>
  );
}

describe('<PlatformAuthProvider>', () => {
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
      value: {
        ...origLocation,
        assign: assignSpy,
        pathname: '/',
        search: '',
      } as unknown as Location,
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

  it('both endpoints succeed: permissions come from /api/me, user.me is the /api/me payload', async () => {
    fetchSpy
      .mockResolvedValueOnce(makeJson(BFF_ME))
      .mockResolvedValueOnce(makeJson(TENANT_ME));
    let captured: ReturnType<typeof usePlatformAuth> | null = null;
    function Capture() {
      captured = usePlatformAuth();
      return null;
    }
    render(
      <PlatformAuthProvider meEndpoint="/api/me">
        <Capture />
      </PlatformAuthProvider>,
    );
    await waitFor(() => expect(captured?.isAuthenticated).toBe(true));
    expect(captured!.user!.me).toEqual(TENANT_ME);
    expect([...captured!.permissions].sort()).toEqual(
      ['REPORT_VIEW_ANY', 'ROUTES_EDIT'],
    );
    // First call /_bff/me, second call /api/me.
    expect(fetchSpy.mock.calls[0][0]).toBe('/_bff/me');
    expect(fetchSpy.mock.calls[1][0]).toBe('/api/me');
  });

  it('platformContextOnly=true: no /api/me fetch; permissions come from /_bff/me', async () => {
    fetchSpy.mockResolvedValueOnce(makeJson(BFF_ME));
    let captured: ReturnType<typeof usePlatformAuth> | null = null;
    function Capture() {
      captured = usePlatformAuth();
      return null;
    }
    render(
      <PlatformAuthProvider platformContextOnly>
        <Capture />
      </PlatformAuthProvider>,
    );
    await waitFor(() => expect(captured?.isAuthenticated).toBe(true));
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(fetchSpy.mock.calls[0][0]).toBe('/_bff/me');
    expect([...captured!.permissions]).toEqual(['USER_READ']);
    expect(captured!.user!.me).toEqual(BFF_ME);
  });

  it('/api/me returns 401: error state set, isAuthenticated false; signinRedirect navigates', async () => {
    fetchSpy
      .mockResolvedValueOnce(makeJson(BFF_ME))
      .mockResolvedValueOnce(new Response(null, { status: 401 }));
    let captured: ReturnType<typeof usePlatformAuth> | null = null;
    function Capture() {
      captured = usePlatformAuth();
      return null;
    }
    render(
      <PlatformAuthProvider meEndpoint="/api/me">
        <Capture />
      </PlatformAuthProvider>,
    );
    await waitFor(() => expect(captured?.isLoading).toBe(false));
    expect(captured!.isAuthenticated).toBe(false);
    expect(captured!.error).toBeInstanceOf(Error);
    expect(captured!.permissions.size).toBe(0);
    // The caller can invoke signinRedirect to bounce the user to /_bff/login.
    act(() => {
      captured!.signinRedirect();
    });
    expect(assignSpy).toHaveBeenCalledWith(
      expect.stringContaining('/_bff/login?redirect_back='),
    );
  });

  it('/api/me returns 403: permissions empty, user.me partial (from BFF), isAuthenticated true', async () => {
    fetchSpy
      .mockResolvedValueOnce(makeJson(BFF_ME))
      .mockResolvedValueOnce(new Response(null, { status: 403 }));
    let captured: ReturnType<typeof usePlatformAuth> | null = null;
    function Capture() {
      captured = usePlatformAuth();
      return null;
    }
    render(
      <PlatformAuthProvider meEndpoint="/api/me">
        <Capture />
      </PlatformAuthProvider>,
    );
    await waitFor(() => expect(captured?.isLoading).toBe(false));
    expect(captured!.isAuthenticated).toBe(true);
    expect(captured!.permissions.size).toBe(0);
    expect(captured!.user!.me).toEqual(BFF_ME);
  });

  it('while loading: usePermission(anything) === false', async () => {
    // Never-resolving fetch keeps provider in isLoading=true.
    fetchSpy.mockReturnValue(new Promise(() => {}));
    function PermProbe() {
      const has = usePermission('ROUTES_EDIT');
      return <div data-testid="perm">{String(has)}</div>;
    }
    const { getByTestId } = render(
      <PlatformAuthProvider meEndpoint="/api/me">
        <PermProbe />
      </PlatformAuthProvider>,
    );
    // Even with no resolution, the result must be false (default-DENY).
    expect(getByTestId('perm').textContent).toBe('false');
    await new Promise((r) => setTimeout(r, 20));
    expect(getByTestId('perm').textContent).toBe('false');
  });

  it('usePermission reflects tenant-backend perms after resolution', async () => {
    fetchSpy
      .mockResolvedValueOnce(makeJson(BFF_ME))
      .mockResolvedValueOnce(makeJson(TENANT_ME));
    function PermProbe() {
      const canEdit = usePermission('ROUTES_EDIT');
      const canDelete = usePermission('ROUTES_DELETE');
      return (
        <div>
          <span data-testid="edit">{String(canEdit)}</span>
          <span data-testid="delete">{String(canDelete)}</span>
        </div>
      );
    }
    const { getByTestId } = render(
      <PlatformAuthProvider meEndpoint="/api/me">
        <PermProbe />
      </PlatformAuthProvider>,
    );
    await waitFor(() => expect(getByTestId('edit').textContent).toBe('true'));
    expect(getByTestId('delete').textContent).toBe('false');
  });

  it('RequirePermission renders children when permission held, fallback otherwise', async () => {
    fetchSpy
      .mockResolvedValueOnce(makeJson(BFF_ME))
      .mockResolvedValueOnce(makeJson(TENANT_ME));
    render(
      <PlatformAuthProvider meEndpoint="/api/me">
        <RequirePermission permission="ROUTES_EDIT" fallback={<span>denied</span>}>
          <span>edit</span>
        </RequirePermission>
        <RequirePermission permission="NOPE" fallback={<span>nope-fallback</span>}>
          <span>nope-children</span>
        </RequirePermission>
      </PlatformAuthProvider>,
    );
    await waitFor(() => expect(screen.getByText('edit')).toBeDefined());
    expect(screen.getByText('nope-fallback')).toBeDefined();
  });

  it('renders anon (not throwing) when /_bff/me returns 401', async () => {
    fetchSpy.mockResolvedValueOnce(new Response(null, { status: 401 }));
    render(
      <PlatformAuthProvider meEndpoint="/api/me">
        <Probe />
      </PlatformAuthProvider>,
    );
    await waitFor(() => expect(screen.getByText('anon')).toBeDefined());
    // /api/me must NOT be probed when /_bff/me already said 401.
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it('refresh() re-runs both probes', async () => {
    fetchSpy
      .mockResolvedValueOnce(makeJson(BFF_ME))
      .mockResolvedValueOnce(makeJson(TENANT_ME))
      .mockResolvedValueOnce(makeJson(BFF_ME))
      .mockResolvedValueOnce(makeJson(TENANT_ME));
    let captured: ReturnType<typeof usePlatformAuth> | null = null;
    function Capture() {
      captured = usePlatformAuth();
      return null;
    }
    render(
      <PlatformAuthProvider meEndpoint="/api/me">
        <Capture />
      </PlatformAuthProvider>,
    );
    await waitFor(() => expect(captured?.isAuthenticated).toBe(true));
    await act(async () => {
      await captured!.refresh();
    });
    expect(fetchSpy).toHaveBeenCalledTimes(4);
  });
});

describe('usePlatformAuth without provider', () => {
  it('throws a helpful error', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    let thrown: unknown = null;
    function NakedProbe() {
      usePlatformAuth();
      return null;
    }
    try {
      render(<NakedProbe />);
    } catch (e) {
      thrown = e;
    }
    spy.mockRestore();
    expect(thrown).toBeInstanceOf(Error);
    expect((thrown as Error).message).toMatch(
      /usePlatformAuth\(\) must be called inside <PlatformAuthProvider>/,
    );
  });
});
