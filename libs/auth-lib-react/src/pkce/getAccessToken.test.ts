import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { getAccessToken } from './getAccessToken';

describe('getAccessToken', () => {
  beforeEach(() => {
    sessionStorage.clear();
  });

  afterEach(() => {
    sessionStorage.clear();
  });

  it('returns null when sessionStorage has no oidc.user:* entry', () => {
    expect(getAccessToken()).toBeNull();
  });

  it('returns the access_token from an oidc.user:* entry', () => {
    sessionStorage.setItem(
      'oidc.user:https://auth.mcp-mesh.io/auth/realms/t-app1:app1-spa',
      JSON.stringify({
        access_token: 'eyJhbGciOiJSUzI1NiJ9.fake.token',
        token_type: 'Bearer',
        profile: { sub: 'u1' },
      }),
    );
    expect(getAccessToken()).toBe('eyJhbGciOiJSUzI1NiJ9.fake.token');
  });

  it('ignores non-oidc keys', () => {
    sessionStorage.setItem('something-else', 'x');
    sessionStorage.setItem('oidc.user:realm:client', JSON.stringify({ access_token: 'tok' }));
    expect(getAccessToken()).toBe('tok');
  });

  it('returns null when the oidc.user entry is malformed JSON', () => {
    sessionStorage.setItem('oidc.user:realm:client', '{not json');
    expect(getAccessToken()).toBeNull();
  });

  it('returns null when access_token is missing from the entry', () => {
    sessionStorage.setItem(
      'oidc.user:realm:client',
      JSON.stringify({ token_type: 'Bearer' }),
    );
    expect(getAccessToken()).toBeNull();
  });

  it('returns null when access_token is not a string', () => {
    sessionStorage.setItem(
      'oidc.user:realm:client',
      JSON.stringify({ access_token: 42 }),
    );
    expect(getAccessToken()).toBeNull();
  });

  it('falls through to a later valid entry if an earlier one is corrupt', () => {
    sessionStorage.setItem('oidc.user:realm-a:client-a', '{not json');
    sessionStorage.setItem(
      'oidc.user:realm-b:client-b',
      JSON.stringify({ access_token: 'recovered' }),
    );
    expect(getAccessToken()).toBe('recovered');
  });
});
