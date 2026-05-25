# Tenant Onboarding Runbook

**Audience:** platform admins onboarding a new tenant (creating a KC realm, wiring apps, setting up hostnames, handing off to the tenant team).

**Status:** living document — updated after each onboarding. Last revision based on the safesound prod launch (2026-05-25).

**Use this when:** standing up a new prod tenant. For dev tenants (`*-dev` slug), most steps are the same but several manual steps drop out (no CF DNS work needed if you use a `*.mcp-mesh.io` subdomain; no Google OAuth Console redirect-URI add).

---

## Prerequisites checklist

Before starting, confirm you have:

- [ ] `kubectl` context set to the beelink cluster (`kubectl config current-context` → `beelink`)
- [ ] Admin credentials for the master KC realm (admin / `$KC_ADMIN_PASSWORD`)
- [ ] Platform-admin role on the `dev` realm (auto-granted by `PlatformRoleBootstrap`)
- [ ] CF API token with Tunnel + DNS edit permissions for the account that owns both mcp-mesh.io and any customer zones
- [ ] Customer-provided info:
  - Tenant slug (DNS-safe; will become realm `t-<slug>`)
  - Display name
  - Admin contact email
  - Primary hostname (e.g., `customer.com` or `<slug>.mcp-mesh.io`)
  - Their k8s service URLs for backend + frontend (if they're co-located in the beelink cluster)
- [ ] If using a customer-owned domain: confirm they've updated their DNS so the zone is in our CF account (or they own a separate CF setup we'll re-point)

---

## The onboarding sequence

Steps are grouped by **who/what does them**: automated-by-platform, manual-by-platform-admin, manual-by-tenant-team. Run in order — later steps depend on earlier ones.

### 1. Create the tenant (automated)

```bash
TOKEN=$(curl -sS -X POST "https://auth.mcp-mesh.io/auth/realms/dev/protocol/openid-connect/token" \
  -d "grant_type=password" -d "client_id=admin-cli" \
  -d "username=admin" -d "password=$KC_ADMIN_PASSWORD" | jq -r .access_token)

curl -sS -X POST "https://auth.mcp-mesh.io/api/v1/tenants" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "slug": "<TENANT_SLUG>",
    "displayName": "<DISPLAY_NAME>",
    "adminEmail": "<ADMIN_EMAIL>",
    "hostnames": [{
      "host": "<PRIMARY_HOSTNAME>",
      "backend": "<frontend-cluster-DNS>:80"
    }]
  }'
```

Creates the KC realm `t-<slug>` + runs `UsermanagementBootstrap` (creates the `usermanagement` client + all atomic perms + tenant-admin/tenant-user-manager/user-viewer composite roles + canonical redirect URIs).

**Trap (session 7):** the tenant create occasionally appears to succeed but bootstrap silently fails (no `usermanagement` client created). Always verify with:

```bash
kubectl exec -n auth-platform platform-kc-keycloak-0 -- \
  curl -sS http://localhost/auth/admin/realms/t-<slug>/clients -H "Authorization: Bearer $TOKEN" | jq '.[].clientId'
```

If `usermanagement` is missing, run the retry endpoint:

```bash
TENANT_ID=$(curl -sS -H "Authorization: Bearer $TOKEN" \
  "https://auth.mcp-mesh.io/api/v1/tenants/by-slug/<TENANT_SLUG>" | jq -r .id)

curl -sS -X POST "https://auth.mcp-mesh.io/api/v1/tenants/$TENANT_ID/retry" \
  -H "Authorization: Bearer $TOKEN"
```

### 2. Create the tenant's apps (automated — Phase 2)

For each app the tenant needs, declare its `profile`. The new
`CreateAppRequest` accepts `profile` + `audience` fields so a single
POST produces a fully-configured KC client; no follow-up raw KC PATCHes.

**Backend (confidential, mints client_credentials tokens):**
```bash
curl -sS -X POST "https://auth.mcp-mesh.io/api/v1/tenants/$TENANT_ID/apps" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{
    "slug": "<TENANT>-backend",
    "displayName": "<TENANT> Backend",
    "profile": "CONFIDENTIAL_BACKEND"
  }'
```

Returns the clientSecret (operator-visible once — capture it).

**SPA (PKCE-S256, audience set to backend so backend can validate the SPA's tokens):**
```bash
curl -sS -X POST "https://auth.mcp-mesh.io/api/v1/tenants/$TENANT_ID/apps" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{
    "slug": "<TENANT>-ui",
    "displayName": "<TENANT> SPA",
    "profile": "SPA_PKCE",
    "audience": ["<TENANT>-backend"]
  }'
```

What `profile: SPA_PKCE` does automatically:
- `publicClient: true` + `pkce.code.challenge.method: S256`
- Disables `directAccessGrantsEnabled` + `serviceAccountsEnabled`
- Sets `lightweight.access.token.enabled: false`
- Populates `redirectUris` + `webOrigins` from the tenant's registered
  hostnames (plus the platform host + localhost dev variant)

What `audience: [...]` does automatically: creates one
`oidc-audience-mapper` per listed client on THIS app's KC client, so
tokens minted by THIS app carry the audience in `access_token.aud`.

**Profile reference:**
| Profile | Use for | KC state |
|---|---|---|
| `CONFIDENTIAL_BACKEND` (default) | Any backend that needs client_credentials OR auth-code with secret | Confidential, SA enabled, standard flow on |
| `SPA_PKCE` | Browser SPAs using PKCE | Public, PKCE-S256, redirects from tenant hostnames |
| `SERVICE_ACCOUNT_ONLY` | Backend daemons / cron jobs (m2m only) | Confidential, SA enabled, standardFlow off, directGrants off |

### 3. Apply the manifest (automated)

The tenant team provides a `<slug>-manifest.yaml` with their permission catalog + role bundles + IdPs + defaultRoles. Validate it first with the round-trip diff (irrelevant on a brand-new tenant since there's nothing in KC to diff against; useful after the apply lands).

Apply:

```bash
curl -sS -X POST "https://auth.mcp-mesh.io/api/v1/tenants/<slug>/manifest:apply?applyRoles=true" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/yaml" \
  --data-binary @./manifest.yaml
```

On first apply: expect `permissions.created: [...]`, `roles.created: [...]`, `identityProviders.unchanged: [google, github]` (assuming IdentityProvidersBootstrap already configured them), `defaultRoleMappers.created: ['google:<role>', 'github:<role>']` per defaultRole declared.

### 4. Grant service-account permissions to the backend (automated — Phase 2)

The backend needs the `USER_LIST` perm on the `usermanagement` client to
call auth-manager's `/api/v1/tenants/<slug>/users` endpoint (e.g., to
drive a Staff Console / Inspector list). Use the dedicated SA-perms
endpoint:

```bash
curl -sS -X PUT "https://auth.mcp-mesh.io/api/v1/tenants/$TENANT_ID/apps/$BACKEND_APP_ID/service-account/permissions" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"permissions": ["USER_LIST"]}'
```

**PUT semantics** (idempotent): the body is the COMPLETE desired set.
Anything in the current set not listed gets revoked; new ones added.
Returns the effective list after the change. Unknown perms (not present
as a client role on `usermanagement`) → 400 with the offending names
listed.

Common perm bundles to grant to a backend SA:
- `USER_LIST` — list users + filter by role (most common)
- `USER_LIST` + `AUDIT_VIEW` — also read audit logs
- `USER_LIST` + `USER_INVITE` — also create users (admin-grade backend
  that provisions accounts on signup)

`USER_SYSTEM_ROLE_ASSIGN` is privileged (grants the ability to mint
new tenant-admins). Don't grant to a backend SA unless absolutely
needed — same privilege-escalation guard applies to humans + SAs.

### 5. Update routes if the tenant team's services are in a different namespace (automated, easy to forget)

Tenant create accepts a single `backend` per hostname (the default). The Routes API holds the path-based split:

```bash
curl -sS -X PUT "https://auth.mcp-mesh.io/api/v1/tenants/<slug>/routes" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{
    "targets": {
      "backend":  "<backend-cluster-DNS>:8080",
      "frontend": "<frontend-cluster-DNS>:80"
    },
    "rules": [
      {"path": "/api/*", "authMode": "REQUIRED", "target": "backend"},
      {"path": "/*",     "authMode": "OPTIONAL", "target": "frontend"}
    ]
  }'
```

**Trap (session 7):** the initial tenant create on safesound prod auto-populated the routes with `<slug>-{backend,ui}.tenant-<slug>.svc.cluster.local` — but sns deploys into the `safe-sound` namespace with services named `gateway-mcp-mesh-agent` and `safe-sound-ui`. Always verify routes match the tenant's actual k8s services + namespace.

### 6. Upload theme (automated)

```bash
curl -sS -X POST "https://auth.mcp-mesh.io/api/v1/tenants/<slug>/theme" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@./theme.zip"
```

Auto-triggers a KC pod rolling restart (~30-60s downtime, drops active sessions). Init container materializes the ConfigMap into KC's themes/ dir. Status visible at `GET /api/v1/tenants/<slug>/theme/status`.

### 7. Configure Google + GitHub IdPs (mostly automated, one manual)

`IdentityProvidersBootstrap` enables Google + GitHub on every realm at startup if the `platform-oauth-providers` k8s Secret has creds. After tenant create, check:

```bash
curl -sS -H "Authorization: Bearer $TOKEN" \
  "https://auth.mcp-mesh.io/api/v1/tenants/<slug>/identity-providers"
```

If a provider needs **DIFFERENT creds** for this tenant (e.g., the customer wants their own Google OAuth App, not the shared one), update via the KC admin console: realm → Identity Providers → Google → Settings → Client ID + Secret.

**Manual platform-admin action:** add the realm's broker redirect URI to the Google Cloud Console OAuth client:

```
https://auth.mcp-mesh.io/auth/realms/t-<slug>/broker/google/endpoint
```

(Same URI scheme for GitHub OAuth Apps with `/github/` swapped in.)

Without this, sign-in fails with `redirect_uri_mismatch` on first attempt.

**Trap (session 7):** the safesound prod Google OAuth client was a DIFFERENT one (`0mgehudo6...`) from the dev OAuth client (`cfj060nkk...`). Verify which client KC has configured for the new realm AND make sure that's the one you're editing in Google Console.

### 8. CF DNS + tunnel ingress (still manual — Phase 2 sub-item 4 not yet shipped)

If using a `*.mcp-mesh.io` subdomain, edit `scripts/cf-setup-tunnel.sh` DNS_HOSTNAMES list, add the new subdomain, re-run with `CF_API_TOKEN` set. The wildcard tunnel ingress (`*.mcp-mesh.io → platform-edge`) already routes the traffic.

If using a customer-owned domain (e.g., `customer.com`):

a) Confirm the zone is in our CF account: `curl -H "Authorization: Bearer $CF_API_TOKEN" "https://api.cloudflare.com/client/v4/zones?name=customer.com"`.

b) Add the hostname to our tunnel's ingress config (BEFORE the `*.mcp-mesh.io` wildcard rule, AFTER the most-specific):

```bash
curl -sS -X PUT -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" \
  "https://api.cloudflare.com/client/v4/accounts/$CF_ACCOUNT_ID/cfd_tunnel/$CF_TUNNEL_ID/configurations" \
  -d '{"config": {"ingress": [<existing rules>, {"hostname": "customer.com", "service": "http://auth-platform-platform-edge.auth-platform.svc.cluster.local:80"}, <wildcard + catch-all>]}}'
```

c) Update the apex CNAME on the customer's zone to point at our tunnel UUID:
```
customer.com CNAME <CF_TUNNEL_ID>.cfargotunnel.com (proxied=true)
```

d) Kick cloudflared pod to force a fresh config fetch:
```bash
kubectl --context beelink rollout restart deployment -n auth-platform | grep cloudflared
```

**Trap (session 7):** initial probe after DNS flip returned CF error 1033 (tunnel doesn't have route). Cloudflared had loaded an old config snapshot; pod restart fixed it instantly.

(Phase 2 target: bake CF API client into auth-manager + auto-provision on tenant create when zone is in our account.)

**Status:** CF integration (sub-item 4 of Phase 2) is the only remaining
piece of the onboarding-automation backlog. Once shipped, tenant create
on a hostname in our CF zone will auto-add the DNS CNAME + tunnel ingress.
For tenants on customer-owned zones, this step stays partially manual
(we can't write to their CF account) but the tool will print the exact
commands they need to run on their side.

### 9. Bff Lua hostname → realm mapping (no action needed if Redis host:* hash is correct)

Step 1 wrote `host:<hostname>` to Redis with `tenant=<slug>`. The BFF Lua reads this to derive the realm (`t-<slug>`) regardless of how the hostname structure maps to the slug. Verify:

```bash
kubectl --context beelink exec -n auth-platform platform-redis-master-0 -- \
  redis-cli HGETALL "host:<hostname>"
```

Should show `tenant: <slug>` and a default backend. If missing, re-run the routes PUT from step 5 — that re-writes the Redis hash.

### 10. Handoff to tenant team (out-of-band)

Send the tenant team:

- **Client secret** (`safesound-backend` or equivalent — from step 2's create response). Share via Bitwarden / 1Password / encrypted channel; NOT email/Slack DM.
- **Env vars** for their helm-values:
  ```
  AUTH_LIB_ISSUER_URI       = https://auth.mcp-mesh.io/auth/realms/t-<slug>
  AUTH_LIB_CLIENT_ID        = <backend-slug>
  AUTH_LIB_CLIENT_SECRET    = <from above>
  AUTH_LIB_AUDIENCES        = <backend-slug>
  AUTH_LIB_PERMISSIONS_SOURCE = claims
  KC_BASE                   = https://auth.mcp-mesh.io/auth
  AUTH_MGR_BASE             = http://auth-platform-auth-manager.auth-platform.svc.cluster.local:8080
  <TENANT>_TENANT_SLUG      = <slug>
  ```
- **SPA `createOidcConfig`** snippet for their auth-lib-react setup:
  ```ts
  hostToRealm: {
    '<primary-hostname>': 't-<slug>',
    '<dev-hostname>':     't-<slug>-dev',  // if dev twin
  }
  clientId: '<spa-slug>'
  redirectUri: 'https://<primary-hostname>/_bff/callback'
  ```
- **Permission gating snippet** (UX hint for "manage users" deep link):
  ```tsx
  // Gate on a tenant-domain perm (e.g. their staff-ish perm).
  // DO NOT gate on USER_LIST — that lives in resource_access.usermanagement
  // and tenant apps shouldn't depend on the platform's internal role catalog.
  <RequirePermission permission="<TENANT_STAFF_PERM>">
    <a href={`${window.location.origin}/admin/`}>Manage Users</a>
  </RequirePermission>
  ```

Then wait for them to confirm helm upgrade is deployed.

### 11. Cutover (manual coordination)

Only if you're migrating an existing live domain (vs. greenfield):

- Confirm tenant team has deployed the new bundle (their SPA is auth-aware, env vars set, mesh agents at new version).
- Flip the CF DNS CNAME from old tunnel/origin → our tunnel (step 8c).
- Kick cloudflared pod (step 8d).
- Tail KC pod logs + first `/_bff/login` to confirm flow works end-to-end.

### 12. Smoke test (manual sign-off)

After all of the above:

- [ ] `curl -I https://<hostname>` returns 200 (SPA loaded)
- [ ] `curl -I https://<hostname>/_bff/me` returns 401 (no session, correct shape)
- [ ] `curl -sL https://<hostname>/_bff/login` 302s to `https://auth.mcp-mesh.io/auth/realms/t-<slug>/protocol/openid-connect/auth?...` (correct realm — verify the realm name in the URL matches the tenant slug)
- [ ] Visit `https://<hostname>` in incognito → click Sign In → KC login page loads with branded theme → click Continue with Google → completes broker flow → lands back on the SPA signed in
- [ ] Verify default role assignment: check the user's `realm_access.roles` in their JWT (or via admin-ui Users tab); they should have the manifest's `defaultRoles` (e.g., `customer`)
- [ ] Verify backend can list users: `curl -sS -H "Authorization: Bearer <SA-token>" https://auth.mcp-mesh.io/api/v1/tenants/<slug>/users?role=<some-role>` returns the expected list
- [ ] Verify Manage Users link surfaces for the right role (whoever has the gating perm sees it; others don't)

---

## Common traps from session 7

| Trap | Symptom | Fix |
|---|---|---|
| Tenant bootstrap silently partial | `usermanagement` client missing in KC after tenant create — also seen as `ForbiddenException: HTTP 403` from KC admin REST during the first tenant create immediately after an auth-manager pod restart (admin client cache miss; resolves on retry) | `POST /tenants/{id}/retry` |
| Routes auto-populated with wrong namespace | `502 Bad Gateway` on `/api/*` | PUT correct targets via routes API |
| Realm name mismatch in BFF redirect | KC returns "We are sorry... Page not found" | Verify Redis `host:*` hash; ensure platform-edge image has bff.lua with Redis-based realm lookup (not string-split fallback) |
| Sns app calling wrong base URL | sns app reports 502 from `listKcUsers` showing safeandsoundhouses.com's CF error page | Tenant team's `AUTH_MGR_BASE` env var is set to their own hostname; should be `http://auth-platform-auth-manager...svc.cluster.local:8080` or `https://auth.mcp-mesh.io` |
| Google `redirect_uri_mismatch` | Sign-in fails at Google with "Access blocked" | Verify the OAuth Client ID in KC's IdP config matches the one you're editing in Google Console; add `https://auth.mcp-mesh.io/auth/realms/t-<slug>/broker/google/endpoint` |
| CF tunnel cache | Tunnel ingress updated but requests still 1033/502 | `kubectl rollout restart deployment cloudflared` |
| Theme upload doesn't show new CSS | Browser still shows old theme | Hard-refresh (Cmd+Shift+R); also confirm `theme.status` reports rollout complete |
| Stale JWT after role change | User has role per kcadm but UI shows old perms | Sign out + back in to refresh token |
| Default role looks unassigned in popover | `customer` row unchecked despite being a default | Expected if `customer` is in `default-roles-<realm>` composite OR via IdP mapper; popover should mark it `isDefault` (after admin-ui:0.1.19) |

---

## Automation roadmap

**Phase 2 sub-items 1-3** (shipped 2026-05-25, auth-manager 0.1.27):
- ✓ App profiles (`profile: CONFIDENTIAL_BACKEND | SPA_PKCE | SERVICE_ACCOUNT_ONLY`)
- ✓ Audience mapper auto-create (`audience: [...]` field)
- ✓ Service-account permission grant API (`PUT /apps/{id}/service-account/permissions`)
- ✓ Validated end-to-end by creating a test tenant (`phase2test`) +
  both apps via the new automation; cleanup confirmed.

**Phase 2 sub-item 4** (open):
- CF API integration in auth-manager (auto-provision DNS CNAME +
  tunnel ingress + cloudflared reload on tenant create) — ~1 day.

**Phase 3** (open, optional):
- Wizard UI in admin-ui orchestrating the above + surfacing manual
  steps as a checklist with copy buttons — ~3-4 days.

See backlog item "Tenant onboarding automation — Phase 2" for the
detailed design.

---

## After onboarding

- Add the tenant to your runbook tracker (slug, realm, hostname, app slugs, who owns it)
- Document any tenant-specific quirks (e.g., they need a custom IdP, special role naming) in their entry
- Re-export the manifest periodically to detect drift: `scripts/manifest-diff.py <slug> <path-to-manifest.yaml>`
