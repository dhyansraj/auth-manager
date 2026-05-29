import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render } from '@testing-library/react';
import {
  SessionExpiryHandler,
  handleSessionExpired,
} from './SessionExpiryHandler';

// Mock react-oidc-context's useAuth and capture the registered handlers
// so the test can fire them like real KC events would.
const registered = {
  signedOut: null as null | (() => void),
  expired: null as null | (() => void),
};
const unsubSignedOut = vi.fn();
const unsubExpired = vi.fn();

vi.mock('react-oidc-context', () => ({
  useAuth: () => ({
    events: {
      addUserSignedOut: (cb: () => void) => {
        registered.signedOut = cb;
        return unsubSignedOut;
      },
      addAccessTokenExpired: (cb: () => void) => {
        registered.expired = cb;
        return unsubExpired;
      },
    },
  }),
}));

describe('handleSessionExpired (module-level helper)', () => {
  let assignSpy: ReturnType<typeof vi.fn>;
  let origLocation: Location;

  beforeEach(() => {
    sessionStorage.clear();
    origLocation = window.location;
    assignSpy = vi.fn();
    Object.defineProperty(window, 'location', {
      configurable: true,
      writable: true,
      value: { ...origLocation, assign: assignSpy } as unknown as Location,
    });
  });

  afterEach(() => {
    sessionStorage.clear();
    Object.defineProperty(window, 'location', {
      configurable: true,
      writable: true,
      value: origLocation,
    });
  });

  it('clears all oidc.* keys and assigns to /', () => {
    sessionStorage.setItem('oidc.user:realm:client', JSON.stringify({ x: 1 }));
    sessionStorage.setItem('oidc.state:abc', 'pending');
    sessionStorage.setItem('keep-me', 'still here');
    handleSessionExpired();
    expect(sessionStorage.getItem('oidc.user:realm:client')).toBeNull();
    expect(sessionStorage.getItem('oidc.state:abc')).toBeNull();
    expect(sessionStorage.getItem('keep-me')).toBe('still here');
    expect(assignSpy).toHaveBeenCalledWith('/');
  });
});

describe('<SessionExpiryHandler>', () => {
  let assignSpy: ReturnType<typeof vi.fn>;
  let origLocation: Location;

  beforeEach(() => {
    sessionStorage.clear();
    registered.signedOut = null;
    registered.expired = null;
    unsubSignedOut.mockReset();
    unsubExpired.mockReset();
    origLocation = window.location;
    assignSpy = vi.fn();
    Object.defineProperty(window, 'location', {
      configurable: true,
      writable: true,
      value: { ...origLocation, assign: assignSpy } as unknown as Location,
    });
  });

  afterEach(() => {
    cleanup();
    sessionStorage.clear();
    Object.defineProperty(window, 'location', {
      configurable: true,
      writable: true,
      value: origLocation,
    });
  });

  it('renders children', () => {
    const { getByText } = render(
      <SessionExpiryHandler>
        <span>child</span>
      </SessionExpiryHandler>,
    );
    expect(getByText('child')).toBeDefined();
  });

  it('clears sessionStorage and redirects when user-signed-out fires', () => {
    sessionStorage.setItem('oidc.user:realm:client', JSON.stringify({ x: 1 }));
    render(
      <SessionExpiryHandler>
        <span>child</span>
      </SessionExpiryHandler>,
    );
    expect(registered.signedOut).not.toBeNull();
    registered.signedOut!();
    expect(sessionStorage.getItem('oidc.user:realm:client')).toBeNull();
    expect(assignSpy).toHaveBeenCalledWith('/');
  });

  it('clears sessionStorage and redirects when access-token-expired fires', () => {
    sessionStorage.setItem('oidc.user:realm:client', JSON.stringify({ x: 1 }));
    render(
      <SessionExpiryHandler>
        <span>child</span>
      </SessionExpiryHandler>,
    );
    expect(registered.expired).not.toBeNull();
    registered.expired!();
    expect(sessionStorage.getItem('oidc.user:realm:client')).toBeNull();
    expect(assignSpy).toHaveBeenCalledWith('/');
  });

  it('unsubscribes both handlers on unmount', () => {
    const { unmount } = render(
      <SessionExpiryHandler>
        <span>child</span>
      </SessionExpiryHandler>,
    );
    unmount();
    expect(unsubSignedOut).toHaveBeenCalled();
    expect(unsubExpired).toHaveBeenCalled();
  });
});
