# BFF (cookie-based auth) — Quickstart for SPAs

The `@mcpmesh/auth-lib-react` library ships two complementary auth flows:

1. **PKCE** (legacy default) — uses `react-oidc-context` + `oidc-client-ts`.
   The SPA holds the access token in memory/sessionStorage and attaches it
   as `Authorization: Bearer` on every API call.
2. **BFF (cookie)** — the SPA never sees a token. The edge (OpenResty) owns
   a session cookie (`bff_sid`, HttpOnly) plus a CSRF token cookie
   (`bff_csrf`, JS-readable). The SPA makes plain `fetch()` calls with
   `credentials: 'include'`; the edge attaches `Authorization: Bearer` to
   the upstream request.

This doc covers migrating a SPA from flow 1 to flow 2. The PKCE exports are
unchanged and continue to work — migration is per-app and on your own
timeline.

## Why BFF?

- No tokens in browser-accessible storage → XSS-resilient.
- Refresh tokens stay server-side → silent rotation without iframe trickery.
- Logout actually invalidates the session in Redis, not just in the SPA.
- Simpler SPA code (no `react-oidc-context` ceremony, no callback page).

## Edge prerequisites

The deployment must run `platform-edge >= 0.1.7` with the BFF lua module
enabled. Endpoints provided by the edge (see
`dev/openresty/lua/bff_test_plan.md` for the contract):

| Path             | Method | Purpose                                    |
|------------------|--------|--------------------------------------------|
| `/_bff/login`    | GET    | Begin OIDC code+PKCE flow; 302 to KC.      |
| `/_bff/callback` | GET    | Exchange code for tokens; set cookies.     |
| `/_bff/logout`   | POST   | Revoke session, clear cookies.             |
| `/_bff/me`       | GET    | Cookie-auth probe; proxies to `/api/v1/me`.|
| `/_bff/csrf`     | GET    | Returns + refreshes the `bff_csrf` cookie. |

## Migration: replace each PKCE primitive with its BFF twin

| PKCE (react-oidc-context)        | BFF (this library)              |
|----------------------------------|---------------------------------|
| `<AuthProvider {...config}>`     | `<BffAuthProvider>`             |
| `<AutoSignIn />`                 | `<BffAutoSignIn />`             |
| `useAuth()`                      | `useBffAuth()`                  |
| `auth.signinRedirect()`          | `bffSigninRedirect()` or context method |
| `auth.signoutRedirect()`         | `bffSignoutRedirect()` or context method |
| `fetch(url, { headers: { Authorization: ... }})` | `bffFetch(url, opts)`         |
| `<MeProvider endpoint="...">`    | `<MeProvider endpoint="..." authMode="cookie">` |

The `useMe()`, `usePermission()`, `useIsPlatformAdmin()`, `RequirePermission`,
etc. helpers all keep working — they pull from `<MeProvider>`, which now
fetches with cookies instead of Bearer when `authMode="cookie"`.

## Minimal example

```tsx
import {
  BffAuthProvider,
  BffAutoSignIn,
  MeProvider,
  useBffAuth,
  useMeContext,
  bffFetch,
} from '@mcpmesh/auth-lib-react';

function Gate({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useBffAuth();
  if (isLoading) return <div>Loading…</div>;
  if (!isAuthenticated) return <BffAutoSignIn heading="My App" />;
  return <>{children}</>;
}

export function App() {
  return (
    <BffAuthProvider>
      <Gate>
        <MeProvider endpoint="/api/v1/me" authMode="cookie">
          <Dashboard />
        </MeProvider>
      </Gate>
    </BffAuthProvider>
  );
}

function Dashboard() {
  const { me } = useMeContext();
  return (
    <>
      <h1>Hello, {me?.user.name}</h1>
      <button onClick={createWidget}>New widget</button>
    </>
  );
}

async function createWidget() {
  // bffFetch attaches X-CSRF-Token automatically on POST/PUT/PATCH/DELETE.
  const res = await bffFetch('/api/v1/widgets', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'foo' }),
  });
  if (!res.ok) throw new Error(`failed: ${res.status}`);
}
```

## Same-origin cookie caveat

The BFF cookies are scoped to the exact origin the SPA loaded from
(e.g. `https://safesound-dev.mcp-mesh.io`). The SPA, the `/api/...` upstreams,
and the `/_bff/...` endpoints MUST all live behind that same hostname for
cookies to flow. Cross-origin (a SPA on `foo.com` calling APIs on `bar.com`)
will NOT work — the browser strips the cookies. If you need cross-origin,
either keep PKCE or front everything with the same edge hostname.

## CSRF: must use `bffFetch()` for writes

The edge rejects POST/PUT/PATCH/DELETE on cookie-authenticated requests
that lack a matching `X-CSRF-Token` header. `bffFetch()` reads the
`bff_csrf` cookie and attaches the header for you. If you use raw `fetch()`
you must do this manually:

```ts
function readCsrf(): string | null {
  return document.cookie
    .split('; ')
    .find((c) => c.startsWith('bff_csrf='))
    ?.split('=')[1] ?? null;
}

await fetch('/api/v1/widgets', {
  method: 'POST',
  credentials: 'include',
  headers: { 'X-CSRF-Token': readCsrf() ?? '' },
  body: ...,
});
```

GET/HEAD/OPTIONS do not need the CSRF header. Bearer-authenticated requests
(no cookie) also bypass CSRF — the check is gated to the cookie path only.

## API shape differences vs `useAuth()`

`useBffAuth()` returns a subset of `react-oidc-context`'s `AuthContextProps`:

```ts
interface BffAuthContextValue {
  isAuthenticated: boolean;
  isLoading: boolean;
  user: BffUser | null;       // { me, profile } — NO access_token
  error: Error | null;
  refresh: () => Promise<void>;
  signinRedirect: (targetPath?: string) => void;
  signoutRedirect: () => Promise<void>;
}
```

Key absences vs PKCE:

- `user.access_token` — does not exist. The token is server-side only.
  Code that previously reached for it (e.g. `fetch(url, { headers: {
  Authorization: \`Bearer ${auth.user!.access_token}\` }})`) should use
  `bffFetch(url, opts)` instead.
- `activeNavigator` — BFF is a single full-page redirect, no in-flight
  navigator state.
- `events`, `removeUser`, `revokeTokens`, etc. — the edge owns the
  session lifecycle. Use `signoutRedirect()` to end the session.

## Testing your migration

After wiring up `<BffAuthProvider>`:

1. Visit the SPA logged out → expect a 302 to `/_bff/login` then back to
   your original path after KC login.
2. Open devtools → Application → Cookies → confirm `bff_sid` (HttpOnly)
   and `bff_csrf` (not HttpOnly) on the SPA's origin.
3. Make a POST via `bffFetch` → confirm the network panel shows
   `X-CSRF-Token: ...` and the request succeeds.
4. Click logout → confirm both cookies cleared, page reloads to `/`,
   subsequent `/_bff/me` returns 401.

See `dev/openresty/lua/bff_test_plan.md` for the full edge-level test
sequence.
