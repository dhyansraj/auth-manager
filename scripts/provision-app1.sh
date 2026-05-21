#!/usr/bin/env bash
# Provision the app1 tenant on the live beelink platform.
#
# Idempotent-ish: re-running is OK as long as the tenant/app/user/client
# don't already exist (the script doesn't fight existing state — it just
# fails loudly if it sees conflict responses).
#
# Sequence:
#   1. Create tenant 'app1' with hostname app1.mcp-mesh.io
#   2. Create app 'orders' under the tenant (captures one-time client secret)
#   3. Apply access manifest (roles + resources + scopes + permissions)
#   4. Create user alice@app1.test in t-app1 realm + assign ADMIN on 'orders'
#   5. Create a dedicated public PKCE client 'app1-ui' in t-app1 realm
#
# Outputs the captured client secret to a file (default /tmp/app1-orders-secret)
# so the deploy script can mount it into the app1-backend deployment.
#
# Requires (on the box running this script):
#   - kubectl with context pointed at the beelink cluster
#   - jq, curl, python3
#
# Env overrides:
#   AUTH_MANAGER_URL     default https://auth.mcp-mesh.io
#   PUBLIC_HOST          default app1.mcp-mesh.io
#   TENANT_SLUG          default app1
#   APP_SLUG             default orders
#   USER_EMAIL           default alice@app1.test
#   USER_PASSWORD        default alice
#   KC_NAMESPACE         default auth-platform
#   KC_POD               default platform-kc-keycloak-0
#   KC_ADMIN_USER        default admin
#   KC_ADMIN_PASSWORD    default admin
#   SECRET_FILE          default /tmp/app1-orders-secret

set -euo pipefail

AUTH_MANAGER_URL="${AUTH_MANAGER_URL:-https://auth.mcp-mesh.io}"
PUBLIC_HOST="${PUBLIC_HOST:-app1.mcp-mesh.io}"
TENANT_SLUG="${TENANT_SLUG:-app1}"
TENANT_DISPLAY="${TENANT_DISPLAY:-App One}"
TENANT_ADMIN_EMAIL="${TENANT_ADMIN_EMAIL:-admin@app1.test}"
APP_SLUG="${APP_SLUG:-orders}"
APP_DISPLAY="${APP_DISPLAY:-Orders Service}"
USER_EMAIL="${USER_EMAIL:-alice@app1.test}"
USER_PASSWORD="${USER_PASSWORD:-alice}"
USER_FIRST="${USER_FIRST:-Alice}"
USER_LAST="${USER_LAST:-Example}"
USER_ROLE="${USER_ROLE:-ADMIN}"

KC_NAMESPACE="${KC_NAMESPACE:-auth-platform}"
KC_POD="${KC_POD:-platform-kc-keycloak-0}"
KC_ADMIN_USER="${KC_ADMIN_USER:-admin}"
KC_ADMIN_PASSWORD="${KC_ADMIN_PASSWORD:-admin}"
# Bitnami's KC image installs to /opt/bitnami/keycloak (not /opt/keycloak).
KCADM_PATH="${KCADM_PATH:-/opt/bitnami/keycloak/bin/kcadm.sh}"

SECRET_FILE="${SECRET_FILE:-/tmp/app1-orders-secret}"

REALM_NAME="t-${TENANT_SLUG}"
TENANT_UI_CLIENT="app1-ui"

bold() { printf "\033[1m%s\033[0m\n" "$*"; }
ok()   { printf "  \033[32m✓\033[0m %s\n" "$*"; }
step() { echo; bold "── $* ──"; }
warn() { printf "  \033[33m!\033[0m %s\n" "$*"; }

KCADM_CONFIG="/tmp/kcadm.config"

kcadm() {
    # Bitnami's KC image runs as non-root with no writable HOME; kcadm wants
    # to drop its config at ~/.keycloak/kcadm.config. Force it to a writable
    # path via --config. Append it last so it works for both single-word and
    # two-word subcommands (e.g. `kcadm config credentials --server ...`).
    kubectl exec -n "$KC_NAMESPACE" "$KC_POD" -- \
        "$KCADM_PATH" "$@" --config "$KCADM_CONFIG"
}

step "1. Create tenant '${TENANT_SLUG}'"

TENANT_BACKEND="${TENANT_SLUG}-ui.tenant-${TENANT_SLUG}.svc.cluster.local:80"
TENANT_REQ=$(python3 -c "
import json
print(json.dumps({
  'slug': '${TENANT_SLUG}',
  'displayName': '${TENANT_DISPLAY}',
  'adminEmail': '${TENANT_ADMIN_EMAIL}',
  'hostnames': [
    {'host': '${PUBLIC_HOST}', 'backend': '${TENANT_BACKEND}'}
  ]
}))
")

TENANT_RESP=$(curl -sS -X POST \
    -H 'Content-Type: application/json' \
    -d "$TENANT_REQ" \
    "${AUTH_MANAGER_URL}/api/v1/tenants")

# If it already exists, the API returns a 409/400; recover the tenant id.
if echo "$TENANT_RESP" | grep -q '"slug already in use"\|already exists\|"status":4'; then
    warn "tenant create returned conflict; looking up existing tenant"
    TENANT_LIST=$(curl -sS "${AUTH_MANAGER_URL}/api/v1/tenants")
    TENANT_ID=$(echo "$TENANT_LIST" | jq -r ".[] | select(.slug==\"${TENANT_SLUG}\") | .id")
else
    TENANT_ID=$(echo "$TENANT_RESP" | jq -r '.id // empty')
fi

if [ -z "$TENANT_ID" ] || [ "$TENANT_ID" = "null" ]; then
    echo "ERROR: could not resolve tenant id; response was:"
    echo "$TENANT_RESP"
    exit 1
fi
ok "tenant id : $TENANT_ID"
ok "realm     : $REALM_NAME"
ok "hostname  : ${PUBLIC_HOST}"

# The deployed auth-manager image predates the V3 migration that adds
# tenants.routing_config + auto-publishes route:<slug> on tenant create.
# Until the platform is redeployed, write the route directly to Redis so the
# edge (route.lua) can resolve app1.mcp-mesh.io → tenant 'app1' → rules.
step "1b. Backfill route:${TENANT_SLUG} in Redis (workaround for missing V3)"
ROUTE_JSON=$(python3 -c "
import json
print(json.dumps({
  'rules': [
    {'path': '/api/*', 'authMode': 'REQUIRED', 'target': 'backend'},
    {'path': '/*',     'authMode': 'OPTIONAL', 'target': 'frontend'}
  ],
  'targets': {
    'backend':  '${TENANT_SLUG}-backend.tenant-${TENANT_SLUG}.svc.cluster.local:8080',
    'frontend': '${TENANT_SLUG}-ui.tenant-${TENANT_SLUG}.svc.cluster.local:80'
  }
}))
")
kubectl exec -n "$KC_NAMESPACE" platform-redis-master-0 -c redis -- \
    redis-cli SET "route:${TENANT_SLUG}" "$ROUTE_JSON" >/dev/null
ok "route:${TENANT_SLUG} published (2 rules; backend → :8080; frontend → :80)"

step "2. Create app '${APP_SLUG}'"

APP_REQ=$(python3 -c "
import json
print(json.dumps({'slug': '${APP_SLUG}', 'displayName': '${APP_DISPLAY}'}))
")
APP_RESP=$(curl -sS -X POST \
    -H 'Content-Type: application/json' \
    -d "$APP_REQ" \
    "${AUTH_MANAGER_URL}/api/v1/tenants/${TENANT_ID}/apps")

APP_ID=$(echo "$APP_RESP" | jq -r '.id // empty')
CLIENT_SECRET=$(echo "$APP_RESP" | jq -r '.clientSecret // empty')

if [ -z "$APP_ID" ] || [ "$APP_ID" = "null" ]; then
    warn "app create returned non-success; looking up existing app"
    APPS=$(curl -sS "${AUTH_MANAGER_URL}/api/v1/tenants/${TENANT_ID}/apps")
    APP_ID=$(echo "$APPS" | jq -r ".[] | select(.slug==\"${APP_SLUG}\") | .id")
    if [ -z "$APP_ID" ] || [ "$APP_ID" = "null" ]; then
        echo "ERROR: app create failed and lookup yielded nothing; response was:"
        echo "$APP_RESP"
        exit 1
    fi
    warn "client_secret was already issued; reuse $SECRET_FILE if present or rotate via KC"
    if [ -f "$SECRET_FILE" ]; then
        CLIENT_SECRET=$(cat "$SECRET_FILE")
        ok "loaded cached secret from $SECRET_FILE"
    else
        # Last resort: get it from KC via kcadm
        CLIENT_UUID=$(kcadm get clients -r "$REALM_NAME" -q "clientId=${APP_SLUG}" --fields id 2>/dev/null \
            | python3 -c "import json,sys; d=json.load(sys.stdin); print(d[0]['id'] if d else '')")
        if [ -n "$CLIENT_UUID" ]; then
            CLIENT_SECRET=$(kcadm get "clients/${CLIENT_UUID}/client-secret" -r "$REALM_NAME" 2>/dev/null \
                | python3 -c "import json,sys; print(json.load(sys.stdin).get('value',''))")
            ok "recovered client secret via kcadm"
        else
            echo "ERROR: could not recover client secret for ${APP_SLUG}"
            exit 1
        fi
    fi
fi

# Cache the secret to disk so we can re-use on re-runs.
printf '%s' "$CLIENT_SECRET" > "$SECRET_FILE"
chmod 600 "$SECRET_FILE"
ok "app id        : $APP_ID"
ok "client_id     : $APP_SLUG"
ok "client_secret : ${CLIENT_SECRET:0:8}…  (cached at $SECRET_FILE)"

step "3. Apply access manifest"

MANIFEST_JSON=$(cat <<'JSON'
{
  "roles": ["ADMIN", "VIEWER"],
  "resources": [
    {"name": "ORDER",   "scopes": ["CREATE", "VIEW", "UPDATE", "CANCEL", "APPROVE"]},
    {"name": "INVOICE", "scopes": ["VIEW", "CREATE"]}
  ],
  "rolePermissions": {
    "ADMIN": [
      {"resource": "ORDER",   "scopes": ["VIEW", "CANCEL", "APPROVE"]},
      {"resource": "INVOICE", "scopes": ["VIEW"]}
    ],
    "VIEWER": [
      {"resource": "ORDER", "scopes": ["VIEW"]}
    ]
  }
}
JSON
)

MANIFEST_RESP=$(curl -sS -X POST \
    -H 'Content-Type: application/json' \
    -d "$MANIFEST_JSON" \
    "${AUTH_MANAGER_URL}/api/v1/tenants/${TENANT_ID}/apps/${APP_ID}/manifests/apply")

M_VERSION=$(echo "$MANIFEST_RESP" | jq -r '.version // empty')
if [ -z "$M_VERSION" ]; then
    echo "ERROR: manifest apply did not return a version. Response:"
    echo "$MANIFEST_RESP"
    exit 1
fi
ok "manifest version: $M_VERSION"

step "4. kcadm: create user ${USER_EMAIL}"

kcadm config credentials \
    --server http://localhost:8080 --realm master \
    --user "$KC_ADMIN_USER" --password "$KC_ADMIN_PASSWORD" >/dev/null
ok "kcadm authenticated"

USER_REP=$(python3 -c "
import json
print(json.dumps({
  'username': '${USER_EMAIL}',
  'email': '${USER_EMAIL}',
  'firstName': '${USER_FIRST}',
  'lastName':  '${USER_LAST}',
  'enabled': True,
  'emailVerified': True
}))
")

CREATE_OUT=$(kcadm create users -r "$REALM_NAME" -b "$USER_REP" 2>&1 || true)
USER_ID=$(echo "$CREATE_OUT" \
    | sed -n "s/.*Created new user with id '\\([^']*\\)'.*/\\1/p" | head -n1)
if [ -z "$USER_ID" ]; then
    USER_ID=$(kcadm get users -r "$REALM_NAME" -q "username=${USER_EMAIL}" --fields id 2>/dev/null \
        | python3 -c "import json,sys; d=json.load(sys.stdin); print(d[0]['id'] if d else '')")
fi
if [ -z "$USER_ID" ]; then
    echo "ERROR: could not get/create user id. kcadm output:"
    echo "$CREATE_OUT"
    exit 1
fi
ok "user id   : $USER_ID"

kcadm set-password -r "$REALM_NAME" \
    --username "$USER_EMAIL" --new-password "$USER_PASSWORD" >/dev/null
ok "password set (literal '${USER_PASSWORD}')"

kcadm add-roles -r "$REALM_NAME" \
    --uusername "$USER_EMAIL" \
    --cclientid "$APP_SLUG" \
    --rolename "$USER_ROLE" >/dev/null 2>&1 || warn "role assign may have been a no-op (already assigned)"
ok "role ${USER_ROLE} granted on ${APP_SLUG}"

step "5. kcadm: create public PKCE client '${TENANT_UI_CLIENT}'"

# Idempotent: skip if already exists.
EXISTING_UI=$(kcadm get clients -r "$REALM_NAME" -q "clientId=${TENANT_UI_CLIENT}" --fields id 2>/dev/null \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print(d[0]['id'] if d else '')")

if [ -n "$EXISTING_UI" ]; then
    ok "${TENANT_UI_CLIENT} client already exists (uuid: $EXISTING_UI) — updating redirectUris/webOrigins"
    UI_REP=$(python3 -c "
import json
print(json.dumps({
  'redirectUris': ['https://${PUBLIC_HOST}/*'],
  'webOrigins':   ['https://${PUBLIC_HOST}'],
  'publicClient': True,
  'standardFlowEnabled': True,
  'directAccessGrantsEnabled': False,
  'serviceAccountsEnabled': False
}))
")
    kcadm update "clients/${EXISTING_UI}" -r "$REALM_NAME" -b "$UI_REP" >/dev/null
else
    UI_REP=$(python3 -c "
import json
print(json.dumps({
  'clientId': '${TENANT_UI_CLIENT}',
  'name': 'App One UI',
  'protocol': 'openid-connect',
  'publicClient': True,
  'standardFlowEnabled': True,
  'directAccessGrantsEnabled': False,
  'serviceAccountsEnabled': False,
  'redirectUris': ['https://${PUBLIC_HOST}/*'],
  'webOrigins':   ['https://${PUBLIC_HOST}']
}))
")
    kcadm create clients -r "$REALM_NAME" -b "$UI_REP" >/dev/null
    ok "${TENANT_UI_CLIENT} client created"
fi

step "Done"
echo "  Tenant:      ${TENANT_SLUG} (id: ${TENANT_ID})"
echo "  Realm:       ${REALM_NAME}"
echo "  Hostname:    https://${PUBLIC_HOST}/"
echo "  User:        ${USER_EMAIL} / ${USER_PASSWORD}"
echo "  SPA client:  ${TENANT_UI_CLIENT}  (public + PKCE)"
echo "  API client:  ${APP_SLUG}          (confidential; secret cached at ${SECRET_FILE})"
echo
echo "  Next: deploy app1 backend+ui:"
echo "    scripts/deploy-app1.sh"
