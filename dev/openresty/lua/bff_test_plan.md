# BFF Phase A — Manual Test Plan

End-to-end curl sequence to validate the cookie-based BFF after deploying
`platform-edge:0.1.7`. Run from any host that can reach the cluster via
`https://app1.mcp-mesh.io/` (or any tenant subdomain you have provisioned;
the platform host `auth.mcp-mesh.io` also works — substitute below).

Conventions:
- `HOST=app1.mcp-mesh.io`
- `BASE=https://$HOST`
- `COOKIES=/tmp/bff.cookies` — curl cookie jar; delete between runs to reset.
- Redis CLI = `kubectl -n auth-platform exec -it platform-redis-master-0 -- redis-cli`
  (substitute your cluster's redis pod). All BFF keys live under
  `bff:session:*` and `bff:tx:*`.

---

## 0. Pre-flight: BFF endpoints respond at all

These should work with no session, no Redis state required beyond a
reachable Redis:

```
HOST=app1.mcp-mesh.io
BASE=https://$HOST

# Should 405 (POST-only)
curl -sk -i "$BASE/_bff/logout" | head -5

# Should 400 missing_code_or_state
curl -sk -i "$BASE/_bff/callback" | head -5

# Should 401 no_session
curl -sk -i "$BASE/_bff/csrf" | head -5
curl -sk -i "$BASE/_bff/me"   | head -5
```

Expected: each returns the documented status + JSON error. No 500s, no
"routing_error" — those would mean the new platform paths didn't register.

---

## 1. Login init — /_bff/login

```
rm -f /tmp/bff.cookies
curl -sk -i -c /tmp/bff.cookies \
  "$BASE/_bff/login?redirect=/admin/" | head -20
```

Expected:
- Status `302`.
- `Location:` header points at `https://$HOST/auth/realms/t-app1/protocol/openid-connect/auth?...`
  containing `response_type=code`, `client_id=usermanagement`,
  `redirect_uri=https://$HOST/_bff/callback`, `state=<43chars>`,
  `code_challenge=<43chars>`, `code_challenge_method=S256`, `nonce=...`.
- No cookies set yet (cookies are set on /_bff/callback, not /_bff/login).

Extract the `state` query param from the Location header — call it `$STATE`.

Then confirm Redis has the transaction key:

```
kubectl -n auth-platform exec platform-redis-master-0 -- \
  redis-cli HGETALL "bff:tx:$STATE"
```

Expected fields: `code_verifier`, `nonce`, `redirect_back=/admin/`,
`realm=t-app1`, `created_at=<unix-ts>`. TTL ~300s:

```
kubectl -n auth-platform exec platform-redis-master-0 -- \
  redis-cli TTL "bff:tx:$STATE"
```

---

## 2. Simulate the user logging in at KC

Easiest path: open the Location URL from step 1 in a real browser, log in
with a tenant-realm user, and let KC redirect to `/_bff/callback?code=...&state=...`.
Capture that callback URL.

Alternative for fully-automated testing: use KC's Resource Owner Password
Credentials grant to skip the browser — but that's a separate, non-PKCE
flow and won't validate the callback handler. The point of this plan is
to validate the callback path, so use the browser.

Once you have the callback URL (call it `$CB_URL`), invoke it via curl
with the same cookie jar:

```
curl -sk -i -c /tmp/bff.cookies -b /tmp/bff.cookies "$CB_URL" | head -30
```

Expected:
- Status `302` with `Location: /admin/` (whatever you passed as `?redirect=`).
- Two `Set-Cookie` headers:
  - `bff_sid=<43chars>; Path=/; Max-Age=1800; HttpOnly; Secure; SameSite=Strict`
  - `bff_csrf=<43chars>; Path=/; Max-Age=1800; Secure; SameSite=Strict`
    (NOT HttpOnly — SPA JavaScript must read it).
- `tmp/bff.cookies` now contains both cookies.

Confirm the session in Redis (use the bff_sid value):

```
SID=$(awk '/bff_sid/ {print $7}' /tmp/bff.cookies)
kubectl -n auth-platform exec platform-redis-master-0 -- \
  redis-cli HGETALL "bff:session:$SID"
```

Expected fields: `access_token`, `refresh_token`, `id_token`, `expires_at`,
`sub` (user UUID), `email`, `realm=t-app1`, `csrf`, `created_at`,
`last_seen_at`. TTL:

```
kubectl -n auth-platform exec platform-redis-master-0 -- \
  redis-cli TTL "bff:session:$SID"
```

Expected: ~1800 seconds.

The tx key from step 1 must now be gone (consumed):

```
kubectl -n auth-platform exec platform-redis-master-0 -- \
  redis-cli EXISTS "bff:tx:$STATE"
# → 0
```

---

## 3. Cookie-authenticated /_bff/me

```
curl -sk -i -b /tmp/bff.cookies "$BASE/_bff/me" | head -30
```

Expected:
- Status `200`.
- JSON body = whatever `GET /api/v1/me` returns for that user. This proves
  the cookie → bearer injection works end-to-end (the upstream sees only
  a Bearer header and replied normally).
- No new Set-Cookie headers (no refresh needed yet).

---

## 4. CSRF token endpoint

```
curl -sk -i -b /tmp/bff.cookies "$BASE/_bff/csrf"
```

Expected:
- Status `200`, body `{"csrfToken":"<43chars>"}`.
- One `Set-Cookie: bff_csrf=...` (refresh-the-cookie behavior).
- The csrfToken value MUST equal the `bff_csrf` cookie value (double-submit).

---

## 5. Cookie-authenticated state-changing request — CSRF enforcement

First a request WITHOUT the CSRF header (must fail):

```
curl -sk -i -X POST -b /tmp/bff.cookies \
  -H "Content-Type: application/json" \
  -d '{"name":"csrf-test"}' \
  "$BASE/api/v1/some-required-write-endpoint"
```

Expected:
- Status `403`, body `{"error":"csrf_mismatch"}`.

Now WITH the CSRF header. Read the value from /_bff/csrf:

```
CSRF=$(curl -sk -b /tmp/bff.cookies "$BASE/_bff/csrf" | jq -r .csrfToken)
curl -sk -i -X POST -b /tmp/bff.cookies \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $CSRF" \
  -d '{"name":"csrf-test"}' \
  "$BASE/api/v1/some-required-write-endpoint"
```

Expected:
- Status from the upstream (200/201/400/whatever) — but NOT 403 csrf_mismatch.
- Header `Authorization: Bearer <jwt>` was injected upstream (verifiable
  in the auth-manager pod logs).

Pick any real REQUIRED-mode POST/PUT/PATCH/DELETE endpoint your tenant
has. If unsure, `POST /api/v1/me` (if it allows) or any tenant route
configured with `authMode: REQUIRED`.

---

## 6. Bearer requests still bypass CSRF (regression)

The existing PKCE flow must continue to work. With a raw Bearer token
(no cookie, no X-CSRF-Token header), POST should succeed:

```
TOKEN=<a valid access token from KC>
curl -sk -i -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"bearer-test"}' \
  "$BASE/api/v1/some-required-write-endpoint"
```

Expected: status from the upstream (NOT 403 csrf_mismatch). This proves
the CSRF check is gated on cookie-auth path only.

---

## 7. Refresh window (optional — slow test)

Modify a session's `expires_at` to be inside the refresh window:

```
SID=$(awk '/bff_sid/ {print $7}' /tmp/bff.cookies)
NOW=$(date +%s)
NEAR=$((NOW + 10))   # < REFRESH_WINDOW (30s)
kubectl -n auth-platform exec platform-redis-master-0 -- \
  redis-cli HSET "bff:session:$SID" expires_at "$NEAR"
```

Capture the current access_token:

```
OLD_AT=$(kubectl -n auth-platform exec platform-redis-master-0 -- \
  redis-cli HGET "bff:session:$SID" access_token)
```

Hit /_bff/me, then re-read the access_token:

```
curl -sk -b /tmp/bff.cookies "$BASE/_bff/me" >/dev/null
NEW_AT=$(kubectl -n auth-platform exec platform-redis-master-0 -- \
  redis-cli HGET "bff:session:$SID" access_token)
[ "$OLD_AT" != "$NEW_AT" ] && echo "refreshed OK" || echo "NOT refreshed"
```

Expected: tokens differ → silent refresh worked. expires_at advanced ~5min.

To exercise the failure path: corrupt the refresh_token in Redis and hit
/_bff/me. Expected: 401, session deleted, cookies cleared.

---

## 8. Logout

```
curl -sk -i -X POST -b /tmp/bff.cookies "$BASE/_bff/logout"
```

Expected:
- Status `204`.
- Two `Set-Cookie` headers with `Max-Age=0` to delete bff_sid + bff_csrf.

Confirm session is gone:

```
kubectl -n auth-platform exec platform-redis-master-0 -- \
  redis-cli EXISTS "bff:session:$SID"
# → 0
```

Subsequent /_bff/me with the old cookies must 401:

```
curl -sk -i -b /tmp/bff.cookies "$BASE/_bff/me" | head -5
```

Expected: status 401 `{"error":"no_session"}` and cookies cleared in
response (defense in depth — the cookie jar may still hold the now-stale
bff_sid).

---

## 9. Negative cases

| Test | Expected |
|---|---|
| `GET /_bff/login` with `?redirect=https://evil.com/x` | 302 to KC; redirect_back stored in tx as `/` (open-redirect guard). After callback the browser ends up at `/`, not evil.com. |
| `GET /_bff/callback?code=x&state=nonexistent` | 400 `invalid_state`. |
| `POST /_bff/logout` with no cookie | 204 (idempotent). |
| `GET /admin/` with no Bearer + no cookie | unchanged behavior: served by admin-ui at OPTIONAL auth. |
| Existing `GET /api/v1/me` with Bearer (no cookie) | unchanged: REQUIRED enforced via header. |

---

## 10. Regression: existing PKCE flow

Run any test you already had pre-BFF — admin-ui login, app1 SPA login,
KC admin console at `/auth/admin/master/`. Nothing should have changed:
the new auth_mode `BFF_BEARER_INJECTED` is only set by /_bff/me itself;
all other paths use the original PUBLIC/REQUIRED/OPTIONAL modes (with
REQUIRED now also accepting cookies, but Bearer continues to win).

---

## 11. True SSO logout — KC end-session from /_bff/logout (v0.1.11)

The /_bff/logout endpoint now also POSTs to KC's
`/protocol/openid-connect/logout` with the session's refresh_token so KC
terminates the SSO session. After this, any access tokens minted from
that SSO session (incl. those held by PKCE SPAs at sibling origins) are
invalidated.

Pre-req: completed step 2 (you have a bff_sid cookie + Redis session
with realm=t-app1, refresh_token populated). Verify the session has the
new `sid` field (KC's session id, extracted from the access_token):

```
SID=$(awk '/bff_sid/ {print $7}' /tmp/bff.cookies)
kubectl -n auth-platform exec platform-redis-master-0 -- \
  redis-cli HGET "bff:session:$SID" sid
# → <UUID> (KC session id). If empty, the access_token had no sid claim
#   — confirm KC 26 client config has `sid` mapper enabled (default).
```

Tail KC pod logs:

```
kubectl -n auth-platform logs -f platform-kc-keycloak-0 | grep -i "LOGOUT\|end-session"
```

In another shell:

```
curl -sk -i -X POST -b /tmp/bff.cookies "$BASE/_bff/logout"
```

Expected on the curl side:
- Status `204`. Cookies cleared (Max-Age=0).

Expected in KC log:
- An event `type=LOGOUT, realmId=t-app1, clientId=usermanagement,
  userId=<UUID>` indicating KC processed the end-session call.

Expected in Redis:
- `bff:session:$SID` is gone.

Expected on edge log (`kubectl logs -n auth-platform <platform-edge-pod>`):
- A line like `[bff] logout: KC SSO session terminated sid=xxxxxxxx`.
  If you see `[bff] logout: KC end-session returned 4xx`, KC rejected
  the refresh_token (already expired or revoked) — local cleanup still
  ran, but cross-app SSO won't have ended. Check the response body in
  the warning to debug.

---

## 12. Back-channel logout receiver — /_bff/backchannel-logout (v0.1.11)

This endpoint is what KC POSTs to when another flow ends an SSO session
(e.g. user signs out of the sns PKCE SPA via react-oidc-context →
KC end-session → KC notifies every client). Effect: the BFF Redis
session for that KC sid is purged so the next /_bff/me returns 401.

### 12a. Manual smoke

Forge a minimal logout_token JWT (we don't validate signature):

```
SID=$(awk '/bff_sid/ {print $7}' /tmp/bff.cookies)
KC_SID=$(kubectl -n auth-platform exec platform-redis-master-0 -- \
  redis-cli HGET "bff:session:$SID" sid)

# Build base64url payload {iss, sid, aud, iat, jti, events}
PAYLOAD=$(printf '{"iss":"https://auth.mcp-mesh.io/auth/realms/t-app1","aud":"usermanagement","iat":%d,"jti":"test-%d","sid":"%s","events":{"http://schemas.openid.net/event/backchannel-logout":{}}}' \
  $(date +%s) $$ "$KC_SID")
B64_PAYLOAD=$(printf '%s' "$PAYLOAD" | base64 | tr '+/' '-_' | tr -d '=\n')
JWT="e30.$B64_PAYLOAD.x"

curl -sk -i -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "logout_token=$JWT" \
  "$BASE/_bff/backchannel-logout"
```

Expected:
- Status `200`, body `{"purged":1}` (or higher if multiple sessions
  shared the same KC sid).
- `bff:session:$SID` no longer exists in Redis.

Negative tests:

| Input | Expected |
|---|---|
| `GET /_bff/backchannel-logout` | 405 `method_not_allowed` |
| No `logout_token` body | 400 `missing_logout_token` |
| Body `logout_token=notajwt` | 400 `malformed_jwt` |
| JWT payload missing `sid` | 400 `missing_sid` |
| JWT `iss` not under `https://auth.mcp-mesh.io/auth/realms/` | 400 `invalid_iss` |
| Valid JWT, no matching session | 200 `{"purged":0}` (idempotent per OIDC spec) |

### 12b. End-to-end (KC actually calls us)

Requires the operator step below to have run for the tenant realm.

1. Sign into admin-ui via /_bff/login (creates BFF session).
2. In another browser/tab, sign into a sibling PKCE SPA at the same
   realm (e.g. app1 sns dashboard via react-oidc-context). Confirm both
   sessions are live (`/_bff/me` succeeds, SPA shows logged-in).
3. From the PKCE SPA, click "sign out" — react-oidc-context navigates
   to KC's end-session endpoint with id_token_hint.
4. KC processes the logout AND POSTs to every registered
   backchannel.logout.url. Tail edge logs:

```
kubectl -n auth-platform logs -f <platform-edge-pod> | grep backchannel
```

Expected: `[bff] backchannel_logout: purged 1 sessions for kc_sid=<UUID>`.

5. In the admin-ui tab, the next state-changing call (or refresh) hits
   /_bff/me which now 401s → admin-ui boots back to /_bff/login.

---

## Operator step (post-deploy, per tenant realm)

KC must be told to call /_bff/backchannel-logout when sessions end.
This is a per-client setting on the `usermanagement` client in every
tenant realm. Until `UsermanagementBootstrap` declaratively bootstraps
this (future), run kcadm by hand after deploy:

```
KC_POD=$(kubectl -n auth-platform get pod -l app.kubernetes.io/name=keycloak -o jsonpath='{.items[0].metadata.name}')
REALM=t-app1   # repeat per tenant; the 'dev' realm under auth.mcp-mesh.io also needs it

kubectl -n auth-platform exec "$KC_POD" -- /opt/bitnami/keycloak/bin/kcadm.sh \
  config credentials \
  --server http://localhost:8080 \
  --realm master --user admin --password "$KC_ADMIN_PASSWORD"

# Look up the client's internal id
CID=$(kubectl -n auth-platform exec "$KC_POD" -- /opt/bitnami/keycloak/bin/kcadm.sh \
  get clients -r "$REALM" -q clientId=usermanagement --fields id --format csv --noquotes | tail -1)

# Set the back-channel logout URL (and enable session-required back-channel)
kubectl -n auth-platform exec "$KC_POD" -- /opt/bitnami/keycloak/bin/kcadm.sh \
  update "clients/$CID" -r "$REALM" \
  -s 'attributes."backchannel.logout.url"=https://auth.mcp-mesh.io/_bff/backchannel-logout' \
  -s 'attributes."backchannel.logout.session.required"=true' \
  -s 'attributes."backchannel.logout.revoke.offline.tokens"=true'
```

Verify:

```
kubectl -n auth-platform exec "$KC_POD" -- /opt/bitnami/keycloak/bin/kcadm.sh \
  get "clients/$CID" -r "$REALM" --fields attributes
# should include backchannel.logout.url=...
```

Repeat for every tenant realm. Until the per-realm command is run, true
single sign-out won't fire for that realm (logout from the SPA will
still locally clear that SPA but not the BFF's Redis session).
