import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { bffFetch, readCsrfCookie, signinRedirect, signoutRedirect } from './bffClient';

describe('readCsrfCookie', () => {
  beforeEach(() => {
    // jsdom: reset cookies by expiring all of them
    document.cookie.split('; ').forEach((c) => {
      const name = c.split('=')[0];
      if (name) document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/`;
    });
  });

  it('returns null when no bff_csrf cookie is set', () => {
    expect(readCsrfCookie()).toBeNull();
  });

  it('reads bff_csrf cookie value', () => {
    document.cookie = 'bff_csrf=abc123';
    expect(readCsrfCookie()).toBe('abc123');
  });

  it('reads bff_csrf cookie among other cookies', () => {
    document.cookie = 'other=foo';
    document.cookie = 'bff_csrf=xyz789';
    document.cookie = 'another=bar';
    expect(readCsrfCookie()).toBe('xyz789');
  });

  it('does not match bff_csrf_something_else as bff_csrf', () => {
    document.cookie = 'bff_csrf_decoy=nope';
    expect(readCsrfCookie()).toBeNull();
  });
});

describe('bffFetch', () => {
  let fetchSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    document.cookie.split('; ').forEach((c) => {
      const name = c.split('=')[0];
      if (name) document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/`;
    });
    fetchSpy = vi.fn().mockResolvedValue(new Response(null, { status: 200 }));
    vi.stubGlobal('fetch', fetchSpy);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('always sets credentials: include', async () => {
    await bffFetch('/foo');
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const init = fetchSpy.mock.calls[0][1];
    expect(init.credentials).toBe('include');
  });

  it('does NOT attach CSRF header on GET', async () => {
    document.cookie = 'bff_csrf=tok';
    await bffFetch('/foo');
    const init = fetchSpy.mock.calls[0][1];
    expect((init.headers as Headers).has('X-CSRF-Token')).toBe(false);
  });

  it('does NOT attach CSRF header on HEAD/OPTIONS', async () => {
    document.cookie = 'bff_csrf=tok';
    await bffFetch('/foo', { method: 'HEAD' });
    await bffFetch('/foo', { method: 'OPTIONS' });
    expect((fetchSpy.mock.calls[0][1].headers as Headers).has('X-CSRF-Token')).toBe(false);
    expect((fetchSpy.mock.calls[1][1].headers as Headers).has('X-CSRF-Token')).toBe(false);
  });

  it('attaches CSRF header on POST/PUT/PATCH/DELETE when cookie present', async () => {
    document.cookie = 'bff_csrf=tok-42';
    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE'] as const) {
      fetchSpy.mockClear();
      await bffFetch('/foo', { method });
      const init = fetchSpy.mock.calls[0][1];
      expect((init.headers as Headers).get('X-CSRF-Token')).toBe('tok-42');
    }
  });

  it('does not overwrite a caller-supplied X-CSRF-Token header', async () => {
    document.cookie = 'bff_csrf=cookie-value';
    await bffFetch('/foo', { method: 'POST', headers: { 'X-CSRF-Token': 'caller-value' } });
    const init = fetchSpy.mock.calls[0][1];
    expect((init.headers as Headers).get('X-CSRF-Token')).toBe('caller-value');
  });

  it('omits CSRF header on POST when cookie missing (does not throw)', async () => {
    await bffFetch('/foo', { method: 'POST' });
    const init = fetchSpy.mock.calls[0][1];
    expect((init.headers as Headers).has('X-CSRF-Token')).toBe(false);
  });

  it('lowercase method still triggers CSRF attach', async () => {
    document.cookie = 'bff_csrf=tok';
    await bffFetch('/foo', { method: 'post' });
    const init = fetchSpy.mock.calls[0][1];
    expect((init.headers as Headers).get('X-CSRF-Token')).toBe('tok');
  });
});

describe('signinRedirect', () => {
  let assignSpy: ReturnType<typeof vi.fn>;
  let origLocation: Location;

  beforeEach(() => {
    origLocation = window.location;
    assignSpy = vi.fn();
    // jsdom marks window.location as configurable=false on the property of
    // window itself; but we can shadow it via Object.defineProperty(window, ...).
    Object.defineProperty(window, 'location', {
      configurable: true,
      writable: true,
      value: { ...origLocation, assign: assignSpy, pathname: '/', search: '' } as unknown as Location,
    });
  });

  afterEach(() => {
    Object.defineProperty(window, 'location', {
      configurable: true,
      writable: true,
      value: origLocation,
    });
  });

  it('uses current pathname+search when no target provided', () => {
    (window.location as unknown as { pathname: string; search: string }).pathname = '/some/path';
    (window.location as unknown as { pathname: string; search: string }).search = '?q=1';
    signinRedirect();
    expect(assignSpy).toHaveBeenCalledWith(
      '/_bff/login?redirect_back=' + encodeURIComponent('/some/path?q=1'),
    );
  });

  it('uses provided target path', () => {
    signinRedirect('/dashboard');
    expect(assignSpy).toHaveBeenCalledWith(
      '/_bff/login?redirect_back=' + encodeURIComponent('/dashboard'),
    );
  });

  it('URL-encodes special characters in the target', () => {
    signinRedirect('/path with spaces?x=&y=1');
    expect(assignSpy).toHaveBeenCalledWith(
      '/_bff/login?redirect_back=' + encodeURIComponent('/path with spaces?x=&y=1'),
    );
  });
});

describe('signoutRedirect', () => {
  let fetchSpy: ReturnType<typeof vi.fn>;
  let assignSpy: ReturnType<typeof vi.fn>;
  let origLocation: Location;

  beforeEach(() => {
    document.cookie.split('; ').forEach((c) => {
      const name = c.split('=')[0];
      if (name) document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/`;
    });
    fetchSpy = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
    vi.stubGlobal('fetch', fetchSpy);
    origLocation = window.location;
    assignSpy = vi.fn();
    Object.defineProperty(window, 'location', {
      configurable: true,
      writable: true,
      value: { ...origLocation, assign: assignSpy } as unknown as Location,
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    Object.defineProperty(window, 'location', {
      configurable: true,
      writable: true,
      value: origLocation,
    });
  });

  it('POSTs to /_bff/logout with credentials and CSRF', async () => {
    document.cookie = 'bff_csrf=secret';
    await signoutRedirect();
    expect(fetchSpy).toHaveBeenCalledWith('/_bff/logout', {
      method: 'POST',
      credentials: 'include',
      headers: { 'X-CSRF-Token': 'secret' },
    });
    expect(assignSpy).toHaveBeenCalledWith('/');
  });

  it('sends empty CSRF header when cookie absent', async () => {
    await signoutRedirect();
    expect(fetchSpy).toHaveBeenCalledWith('/_bff/logout', {
      method: 'POST',
      credentials: 'include',
      headers: { 'X-CSRF-Token': '' },
    });
  });

  it('still redirects to / even if logout fetch fails', async () => {
    fetchSpy.mockRejectedValueOnce(new Error('network down'));
    await signoutRedirect();
    expect(assignSpy).toHaveBeenCalledWith('/');
  });
});
