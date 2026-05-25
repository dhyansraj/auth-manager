# admin-ui BFF Migration — Manual Test Plan

After deploying the BFF cookie-auth migration of admin-ui (replacing PKCE /
react-oidc-context), the operator should walk through the following to
confirm the SPA is fully off PKCE and exclusively on the BFF cookie flow.

## Pre-conditions

- Edge BFF endpoints are live and reachable at every admin-ui-serving host:
  - `/_bff/login`
  - `/_bff/callback`
  - `/_bff/logout`
  - `/_bff/me`
  - `/_bff/csrf`
- `@mcpmesh/auth-lib-react` v with `BffAuthProvider` / `useBffAuth` /
  `bffFetch` is deployed inside the admin-ui bundle.
- Keycloak realm(s) reachable at `https://auth.mcp-mesh.io/auth/`.

## Steps

1. **Clear browser session for both origins** (BFF cookies are per-origin):
   - `auth.mcp-mesh.io`
   - `safesound-dev.mcp-mesh.io`
   - Clear cookies, session storage, and local storage for both.

2. **Platform-admin view** — navigate to `https://auth.mcp-mesh.io/admin/`.
   - Expectation: browser should redirect to `/_bff/login` → Keycloak login
     page → after sign-in, land back on `/admin/` with NO `?code=...` and NO
     `&state=...` query parameters in the URL.

3. **Verify cookies are set correctly** — DevTools → Application → Cookies
   (for `auth.mcp-mesh.io`):
   - `bff_sid` is present, HttpOnly, Secure, SameSite=Lax.
   - `bff_csrf` is present, JS-readable (NOT HttpOnly), Secure, SameSite=Lax.

4. **Verify NO access tokens leaked to JS** — DevTools → Application →
   Session Storage / Local Storage:
   - No `oidc.user:*` entries (PKCE flow's marker).
   - No `access_token`, `id_token`, or `refresh_token` keys anywhere.

5. **Navigate Tenants tab** — click into a tenant, browse Overview / Users /
   Roles / etc. All data should load successfully.

6. **Confirm API calls use cookies, NOT bearer** — DevTools → Network → pick
   an API call (e.g., `GET /admin/api/v1/tenants`):
   - Request headers MUST include `Cookie: bff_sid=...`.
   - Request headers MUST NOT include `Authorization: Bearer ...`.
   - For state-changing requests (POST / PUT / DELETE), also confirm
     `X-CSRF-Token` header is present and matches the `bff_csrf` cookie
     value.

7. **Sign out** — click "Sign out" in the header.
   - POST to `/_bff/logout` fires (with `X-CSRF-Token`).
   - Browser navigates to `/`.
   - Cookies (`bff_sid` + `bff_csrf`) are cleared.
   - Returning to `/admin/` re-prompts sign-in (step 2 again).

8. **Repeat steps 2–7 on the tenant view** —
   `https://safesound-dev.mcp-mesh.io/admin/`, signing in as
   `dhyan.raj@gmail.com`.
   - Should see only Overview / Users / Audit tabs (the
     `tenant-user-manager` perm bundle is unchanged by the BFF migration).
   - All tabs that ARE visible should load without errors.

## Acceptance signals

- Zero `?code=` / `?state=` URL noise after the initial login round-trip.
- Zero PKCE-era artifacts in browser storage.
- Every admin-ui XHR carries `Cookie: bff_sid` and (on writes) `X-CSRF-Token`.
- Sign-out drops the session both client-side (cookies cleared) and
  server-side (Redis session deleted by the edge — verifiable by hitting
  `/_bff/me` and getting 401 after logout).

## Out of scope

- Tenant SPAs (app1, safesound, etc.) — they migrate to BFF on their own
  timeline.
- Audit / revoke endpoints — later.
- Removing PKCE exports from `@mcpmesh/auth-lib-react` — other SPAs still
  consume those during transition.
