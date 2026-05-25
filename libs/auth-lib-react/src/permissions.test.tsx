import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import { MeProvider } from './MeProvider';
import {
  usePermission,
  useIsPlatformAdmin,
  useIsTenantAdmin,
} from './permissions';
import type { MeResponse } from './types';

const ME_WITH_PERMS: MeResponse = {
  user: { id: 'u1', email: 'a@b.c', preferredUsername: 'alice' },
  context: 'tenant',
  isPlatformAdmin: false,
  isTenantAdmin: true,
  permissions: ['ROUTES_EDIT', 'USER_LIST'],
};

function makeClient(): QueryClient {
  // No retries in tests so a failed fetch doesn't make assertions wait for
  // exponential backoff; gcTime 0 keeps tests isolated.
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0 },
    },
  });
}

function Wrap({ children }: { children: ReactNode }) {
  return (
    <QueryClientProvider client={makeClient()}>
      <MeProvider endpoint="/api/v1/me" authMode="cookie">
        {children}
      </MeProvider>
    </QueryClientProvider>
  );
}

function HarnessShowing({ perm }: { perm: string }) {
  const has = usePermission(perm);
  return <div data-testid="result">{String(has)}</div>;
}

function PlatformAdminHarness() {
  const v = useIsPlatformAdmin();
  return <div data-testid="result">{String(v)}</div>;
}

function TenantAdminHarness() {
  const v = useIsTenantAdmin();
  return <div data-testid="result">{String(v)}</div>;
}

describe('usePermission (default-DENY semantics)', () => {
  let fetchSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('returns false while /me is loading (no cache, in flight)', () => {
    fetchSpy.mockReturnValue(new Promise(() => {}));
    const { getByTestId } = render(
      <Wrap>
        <HarnessShowing perm="ROUTES_EDIT" />
      </Wrap>,
    );
    expect(getByTestId('result').textContent).toBe('false');
  });

  it('returns false when /me resolves but the perm is NOT held', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify(ME_WITH_PERMS), { status: 200 }),
    );
    const { getByTestId } = render(
      <Wrap>
        <HarnessShowing perm="IDP_EDIT" />
      </Wrap>,
    );
    // Initially loading -> 'false', then resolved without the perm -> still 'false'.
    await waitFor(() => expect(fetchSpy).toHaveBeenCalled());
    expect(getByTestId('result').textContent).toBe('false');
  });

  it('returns true when /me resolves and the perm IS held', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify(ME_WITH_PERMS), { status: 200 }),
    );
    const { getByTestId } = render(
      <Wrap>
        <HarnessShowing perm="ROUTES_EDIT" />
      </Wrap>,
    );
    await waitFor(() => expect(getByTestId('result').textContent).toBe('true'));
  });

  it('returns false when /me payload has no permissions array', async () => {
    const partial = { ...ME_WITH_PERMS };
    delete (partial as Partial<MeResponse>).permissions;
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify(partial), { status: 200 }),
    );
    const { getByTestId } = render(
      <Wrap>
        <HarnessShowing perm="ROUTES_EDIT" />
      </Wrap>,
    );
    await waitFor(() => expect(fetchSpy).toHaveBeenCalled());
    // After the fetch resolves there will still never be a moment where result === 'true'.
    await new Promise((r) => setTimeout(r, 20));
    expect(getByTestId('result').textContent).toBe('false');
  });
});

describe('useIsPlatformAdmin / useIsTenantAdmin (default-DENY)', () => {
  let fetchSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('useIsPlatformAdmin returns false while loading', () => {
    fetchSpy.mockReturnValue(new Promise(() => {}));
    const { getByTestId } = render(
      <Wrap>
        <PlatformAdminHarness />
      </Wrap>,
    );
    expect(getByTestId('result').textContent).toBe('false');
  });

  it('useIsTenantAdmin returns true when /me says isTenantAdmin', async () => {
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify(ME_WITH_PERMS), { status: 200 }),
    );
    const { getByTestId } = render(
      <Wrap>
        <TenantAdminHarness />
      </Wrap>,
    );
    await waitFor(() => expect(getByTestId('result').textContent).toBe('true'));
  });
});
