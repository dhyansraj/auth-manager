#!/usr/bin/env bash
#
# demo-e2e.sh — end-to-end demo of the auth-platform.
#
# Walks through:
#   0. Preflight checks (Layer 1 services, auth-manager API, sample app)
#   1. Reset platform state (DB tables, t-* realms, host:* Redis keys)
#   2. Create a tenant via the API
#   3. Create an app under that tenant (captures one-time client secret)
#   4. Apply an access manifest (roles, resources, scopes, permissions)
#   5. Create a local Keycloak user + assign ADMIN role
#   6. Restart the sample app pointed at the new tenant realm
#   7. Mint a JWT via password grant and decode the claims
#   8. Hit the sample app's protected endpoints with the token
#   9. Repeat the flow through OpenResty (hostname-based routing)
#  10. Print the audit_events rows produced during the demo
#  11. Final summary banner
#
# Usage:
#   ./scripts/demo-e2e.sh
#
# Env overrides:
#   TENANT_SLUG=foo APP_SLUG=bar USER_EMAIL=x@y.z USER_PASSWORD=hunter2 ./scripts/demo-e2e.sh
#
# Requires (already on the box): bash, curl, python3, docker compose.

set -euo pipefail

# ─── Config (env-overridable) ────────────────────────────────────────────────
TENANT_SLUG="${TENANT_SLUG:-acme}"
TENANT_DISPLAY="${TENANT_DISPLAY:-Acme Corp}"
APP_SLUG="${APP_SLUG:-orders}"
APP_DISPLAY="${APP_DISPLAY:-Orders Service}"
USER_EMAIL="${USER_EMAIL:-alice@acme.test}"
USER_PASSWORD="${USER_PASSWORD:-alice}"
USER_FIRST="${USER_FIRST:-Alice}"
USER_LAST="${USER_LAST:-Example}"
USER_ROLE="${USER_ROLE:-ADMIN}"

AUTH_MANAGER_URL="${AUTH_MANAGER_URL:-http://localhost:8080}"
SAMPLE_URL="${SAMPLE_URL:-http://localhost:8081}"
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8180}"
OPENRESTY_URL="${OPENRESTY_URL:-http://localhost:8090}"

# Hostnames routed to the sample app via OpenResty/Redis.
PRIMARY_HOST="${PRIMARY_HOST:-${TENANT_SLUG}.local}"
WWW_HOST="${WWW_HOST:-www.${TENANT_SLUG}.local}"
SAMPLE_BACKEND="${SAMPLE_BACKEND:-host.docker.internal:8081}"

# Sample app jar + Java
SAMPLE_JAR="${SAMPLE_JAR:-apps/auth-client-sample/target/auth-client-sample-0.1.0-SNAPSHOT.jar}"
JAVA_HOME_PATH="${JAVA_HOME_PATH:-/opt/homebrew/opt/openjdk}"
SAMPLE_LOG="${SAMPLE_LOG:-/tmp/sample-demo.log}"
SAMPLE_PIDFILE="${SAMPLE_PIDFILE:-/tmp/sample-demo.pid}"

# Compose file for kcadm/psql/redis-cli execs.
COMPOSE_FILE="${COMPOSE_FILE:-dev/compose.yaml}"

# ─── Colors ──────────────────────────────────────────────────────────────────
if [ -t 1 ]; then
    BOLD=$'\033[1m'; DIM=$'\033[2m'; RESET=$'\033[0m'
    RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'
    BLUE=$'\033[34m'; CYAN=$'\033[36m'
else
    BOLD=""; DIM=""; RESET=""; RED=""; GREEN=""; YELLOW=""; BLUE=""; CYAN=""
fi

CHECK="${GREEN}\xE2\x9C\x93${RESET}"
CROSS="${RED}\xE2\x9C\x97${RESET}"
WARN="${YELLOW}\xE2\x9A\xA0${RESET}"

# ─── Helpers ─────────────────────────────────────────────────────────────────
step() {
    local title="$1"
    echo
    printf '%b\n' "${BOLD}${BLUE}════════════════════════════════════════════════════════════════════${RESET}"
    printf '%b\n' "${BOLD}${BLUE}  ${title}${RESET}"
    printf '%b\n' "${BOLD}${BLUE}════════════════════════════════════════════════════════════════════${RESET}"
}

indent() {
    sed 's/^/    /'
}

ok()   { printf '    %b %s\n' "${CHECK}" "$1"; }
fail() { printf '    %b %s\n' "${CROSS}" "$1"; }
warn() { printf '    %b %s\n' "${WARN}"  "$1"; }
note() { printf '    %s\n' "$1"; }

# Truncate any text to N chars with an ellipsis if longer.
truncate_str() {
    local s="$1"; local n="${2:-50}"
    if [ "${#s}" -le "$n" ]; then
        printf '%s' "$s"
    else
        printf '%s…' "${s:0:$n}"
    fi
}

# Truncate stdin to first N lines (default 6).
truncate_lines() {
    local n="${1:-6}"
    awk -v n="$n" 'NR<=n {print} NR==n+1 {print "    … (truncated) …"}'
}

# Pretty-print JSON if possible; passthrough on parse failure.
pretty_json() {
    python3 -c 'import json,sys
try:
    print(json.dumps(json.loads(sys.stdin.read()), indent=2))
except Exception:
    sys.stdout.write(sys.stdin.read() if False else "")' 2>/dev/null || cat
}

# Extract a field from JSON on stdin: jget '.path.to.field'
jget() {
    local path="$1"
    python3 -c "
import json, sys
data = json.load(sys.stdin)
keys = '$path'.strip('.').split('.')
cur = data
for k in keys:
    if k == '': continue
    if isinstance(cur, list):
        cur = cur[int(k)]
    else:
        cur = cur.get(k) if isinstance(cur, dict) else None
    if cur is None:
        break
if cur is None:
    print('')
elif isinstance(cur, (dict, list)):
    print(json.dumps(cur))
else:
    print(cur)
"
}

# kcadm wrapper — runs against the local Keycloak container.
kcadm() {
    docker compose -f "$COMPOSE_FILE" exec -T keycloak \
        /opt/keycloak/bin/kcadm.sh "$@"
}

# psql wrapper — runs against the local Postgres container.
pg() {
    docker compose -f "$COMPOSE_FILE" exec -T postgres \
        psql -U postgres -d authmanager -v ON_ERROR_STOP=1 "$@"
}

# redis-cli wrapper.
rcli() {
    docker compose -f "$COMPOSE_FILE" exec -T redis redis-cli "$@"
}

pause() {
    sleep "${1:-1}"
}

# EXIT trap — purely informational, no destructive cleanup.
on_exit() {
    local rc=$?
    if [ "$rc" -ne 0 ]; then
        echo
        printf '%b\n' "${YELLOW}${BOLD}── demo aborted (exit $rc) ─────────────────────────────────${RESET}"
        printf '%b\n' "${YELLOW}    Partial state may remain in DB/Keycloak/Redis.${RESET}"
        printf '%b\n' "${YELLOW}    Re-run the script to reset and start fresh, or inspect logs:${RESET}"
        printf '%b\n' "${YELLOW}      sample app : ${SAMPLE_LOG}${RESET}"
        printf '%b\n' "${YELLOW}      auth-mgr   : tail -n 100 \$AUTH_MANAGER_LOG (if you ran it externally)${RESET}"
    fi
}
trap on_exit EXIT

# ─────────────────────────────────────────────────────────────────────────────
# Step 0: Preflight
# ─────────────────────────────────────────────────────────────────────────────
step "Step 0: Preflight — verify Layer 1 + auth-manager + sample app"

PREFLIGHT_OK=1

check_url() {
    local label="$1"; local url="$2"; local hint="$3"
    if curl -sS -o /dev/null -m 3 --connect-timeout 2 "$url"; then
        ok "$label reachable at $url"
    else
        fail "$label NOT reachable at $url"
        note "  → $hint"
        PREFLIGHT_OK=0
    fi
}

check_url "Keycloak"      "${KEYCLOAK_URL}/realms/master/.well-known/openid-configuration" \
                          "start Layer 1:  make dev"
check_url "OpenResty"     "${OPENRESTY_URL}/" \
                          "start Layer 1:  make dev"
check_url "auth-manager"  "${AUTH_MANAGER_URL}/actuator/health" \
                          "start it:  cd apps/auth-manager && mvn spring-boot:run -Dspring-boot.run.profiles=local"
check_url "sample app"    "${SAMPLE_URL}/actuator/health" \
                          "start it:  cd apps/auth-client-sample && mvn spring-boot:run -Dspring-boot.run.profiles=local"

# Postgres + Redis via compose exec.
if docker compose -f "$COMPOSE_FILE" exec -T postgres pg_isready -U postgres >/dev/null 2>&1; then
    ok "Postgres reachable via compose"
else
    fail "Postgres NOT reachable via compose"
    note "  → start Layer 1:  make dev"
    PREFLIGHT_OK=0
fi
if rcli ping >/dev/null 2>&1; then
    ok "Redis reachable via compose"
else
    fail "Redis NOT reachable via compose"
    note "  → start Layer 1:  make dev"
    PREFLIGHT_OK=0
fi

if [ "$PREFLIGHT_OK" -ne 1 ]; then
    echo
    printf '%b\n' "${RED}${BOLD}Preflight failed. Start the missing services and re-run.${RESET}"
    exit 1
fi
pause 1

# ─────────────────────────────────────────────────────────────────────────────
# Step 1: Reset state
# ─────────────────────────────────────────────────────────────────────────────
step "Step 1: Reset platform state"

printf '%b\n' "${YELLOW}${BOLD}    ⚠  THIS DEMO RESETS ALL PLATFORM STATE.${RESET}"
printf '%b\n' "${YELLOW}       Ctrl-C now if you have data you care about. (5s pause)${RESET}"
sleep 5

note "Truncating auth_manager.* tables…"
pg -c "TRUNCATE auth_manager.audit_events,
                auth_manager.app_manifests,
                auth_manager.onboarding_jobs,
                auth_manager.tenant_hostnames,
                auth_manager.apps,
                auth_manager.tenants,
                auth_manager.user_cache
       RESTART IDENTITY CASCADE;" >/dev/null
ok "DB tables truncated"

note "Authenticating kcadm against master realm…"
kcadm config credentials \
    --server "http://localhost:8180" --realm master \
    --user admin --password admin >/dev/null
ok "kcadm authenticated"

note "Deleting any existing t-* realms in Keycloak…"
EXISTING_REALMS=$(kcadm get realms --fields realm 2>/dev/null \
    | python3 -c "import json,sys; print(' '.join(r['realm'] for r in json.load(sys.stdin) if r.get('realm','').startswith('t-')))" \
    || true)
if [ -n "${EXISTING_REALMS}" ]; then
    for r in $EXISTING_REALMS; do
        kcadm delete "realms/$r" >/dev/null 2>&1 || true
        ok "Deleted realm: $r"
    done
else
    ok "No t-* realms present"
fi

note "Clearing host:* keys in Redis…"
HOST_KEYS=$(rcli --scan --pattern 'host:*' 2>/dev/null || true)
if [ -n "$HOST_KEYS" ]; then
    count=0
    while IFS= read -r key; do
        [ -n "$key" ] || continue
        rcli DEL "$key" >/dev/null
        count=$((count + 1))
    done <<< "$HOST_KEYS"
    ok "Cleared $count host:* keys"
else
    ok "No host:* keys present"
fi
pause 1

# ─────────────────────────────────────────────────────────────────────────────
# Step 2: Create tenant
# ─────────────────────────────────────────────────────────────────────────────
step "Step 2: Create tenant '${TENANT_SLUG}'"

TENANT_REQ=$(python3 -c "
import json
print(json.dumps({
  'slug': '${TENANT_SLUG}',
  'displayName': '${TENANT_DISPLAY}',
  'settings': {},
  'hostnames': [
    {'host': '${PRIMARY_HOST}', 'backend': '${SAMPLE_BACKEND}'},
    {'host': '${WWW_HOST}',     'backend': '${SAMPLE_BACKEND}'}
  ]
}))
")

note "POST ${AUTH_MANAGER_URL}/api/v1/tenants"
TENANT_RESP=$(curl -sS -X POST \
    -H 'Content-Type: application/json' \
    -d "$TENANT_REQ" \
    "${AUTH_MANAGER_URL}/api/v1/tenants")

if ! echo "$TENANT_RESP" | python3 -c 'import json,sys; json.load(sys.stdin)' >/dev/null 2>&1; then
    fail "tenant create returned non-JSON:"
    echo "$TENANT_RESP" | indent
    exit 1
fi

TENANT_ID=$(echo   "$TENANT_RESP" | jget '.id')
REALM_NAME=$(echo  "$TENANT_RESP" | jget '.realmName')
TENANT_STATUS=$(echo "$TENANT_RESP" | jget '.status')

if [ -z "$TENANT_ID" ] || [ -z "$REALM_NAME" ]; then
    fail "tenant response missing id/realmName:"
    echo "$TENANT_RESP" | pretty_json | indent
    exit 1
fi

ok "tenant id     : $TENANT_ID"
ok "realm         : $REALM_NAME"
ok "status        : $TENANT_STATUS"
ok "hostnames     : ${PRIMARY_HOST}, ${WWW_HOST}  →  ${SAMPLE_BACKEND}"
pause 1

# ─────────────────────────────────────────────────────────────────────────────
# Step 3: Create app
# ─────────────────────────────────────────────────────────────────────────────
step "Step 3: Create app '${APP_SLUG}' under tenant"

APP_REQ=$(python3 -c "
import json
print(json.dumps({'slug': '${APP_SLUG}', 'displayName': '${APP_DISPLAY}'}))
")

note "POST ${AUTH_MANAGER_URL}/api/v1/tenants/${TENANT_ID}/apps"
APP_RESP=$(curl -sS -X POST \
    -H 'Content-Type: application/json' \
    -d "$APP_REQ" \
    "${AUTH_MANAGER_URL}/api/v1/tenants/${TENANT_ID}/apps")

if ! echo "$APP_RESP" | python3 -c 'import json,sys; json.load(sys.stdin)' >/dev/null 2>&1; then
    fail "app create returned non-JSON:"
    echo "$APP_RESP" | indent
    exit 1
fi

APP_ID=$(echo        "$APP_RESP" | jget '.id')
CLIENT_ID=$(echo     "$APP_RESP" | jget '.clientId')
CLIENT_SECRET=$(echo "$APP_RESP" | jget '.clientSecret')

if [ -z "$APP_ID" ] || [ -z "$CLIENT_SECRET" ]; then
    fail "app response missing id/clientSecret:"
    echo "$APP_RESP" | pretty_json | indent
    exit 1
fi

SECRET_PREVIEW="${CLIENT_SECRET:0:8}…"
ok "app id        : $APP_ID"
ok "client_id     : $CLIENT_ID"
ok "client_secret : $SECRET_PREVIEW   (full secret captured for later steps)"
pause 1

# ─────────────────────────────────────────────────────────────────────────────
# Step 4: Apply manifest
# ─────────────────────────────────────────────────────────────────────────────
step "Step 4: Apply access manifest (roles + resources + scopes + permissions)"

# Heredoc keeps the JSON literal — no shell interpolation inside.
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

note "POST ${AUTH_MANAGER_URL}/api/v1/tenants/${TENANT_ID}/apps/${APP_ID}/manifests/apply"
MANIFEST_RESP=$(curl -sS -X POST \
    -H 'Content-Type: application/json' \
    -d "$MANIFEST_JSON" \
    "${AUTH_MANAGER_URL}/api/v1/tenants/${TENANT_ID}/apps/${APP_ID}/manifests/apply")

if ! echo "$MANIFEST_RESP" | python3 -c 'import json,sys; json.load(sys.stdin)' >/dev/null 2>&1; then
    fail "manifest apply returned non-JSON:"
    echo "$MANIFEST_RESP" | indent
    exit 1
fi

M_VERSION=$(echo "$MANIFEST_RESP" | jget '.version')
M_HASH=$(echo    "$MANIFEST_RESP" | jget '.hash')
M_NOOP=$(echo    "$MANIFEST_RESP" | jget '.noOp')

ok "version       : $M_VERSION"
ok "hash          : $(truncate_str "$M_HASH" 16)"
ok "noOp          : $M_NOOP"
pause 1

# ─────────────────────────────────────────────────────────────────────────────
# Step 5: Create local user in t-<slug> realm
# ─────────────────────────────────────────────────────────────────────────────
step "Step 5: Create local user ${USER_EMAIL} in ${REALM_NAME}"

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

note "Creating user via kcadm…"
# kcadm create returns the new user id on the 'Created new user with id ...' stderr line.
CREATE_OUT=$(kcadm create users -r "$REALM_NAME" -b "$USER_REP" 2>&1 || true)
USER_ID=$(echo "$CREATE_OUT" \
    | sed -n "s/.*Created new user with id '\\([^']*\\)'.*/\\1/p" | head -n1)

if [ -z "$USER_ID" ]; then
    # User may already exist (re-runs without full reset); look it up.
    USER_ID=$(kcadm get users -r "$REALM_NAME" -q "username=${USER_EMAIL}" --fields id 2>/dev/null \
        | python3 -c "import json,sys
d = json.load(sys.stdin)
print(d[0]['id'] if d else '')")
fi

if [ -z "$USER_ID" ]; then
    fail "could not determine user id (kcadm output below):"
    echo "$CREATE_OUT" | indent
    exit 1
fi
ok "user id       : $USER_ID"

note "Setting password…"
kcadm set-password -r "$REALM_NAME" \
    --username "$USER_EMAIL" --new-password "$USER_PASSWORD" >/dev/null
ok "password set  : (literal '${USER_PASSWORD}')"

note "Looking up client uuid for '${APP_SLUG}'…"
CLIENT_UUID=$(kcadm get clients -r "$REALM_NAME" -q "clientId=${APP_SLUG}" --fields id 2>/dev/null \
    | python3 -c "import json,sys
d = json.load(sys.stdin)
print(d[0]['id'] if d else '')")
if [ -z "$CLIENT_UUID" ]; then
    fail "client '${APP_SLUG}' not found in realm ${REALM_NAME}"
    exit 1
fi
ok "client uuid   : $CLIENT_UUID"

note "Assigning client role '${USER_ROLE}' on '${APP_SLUG}' to ${USER_EMAIL}…"
kcadm add-roles -r "$REALM_NAME" \
    --uusername "$USER_EMAIL" \
    --cclientid "$APP_SLUG" \
    --rolename "$USER_ROLE" >/dev/null
ok "role granted  : ${USER_ROLE} on ${APP_SLUG}"
pause 1

# ─────────────────────────────────────────────────────────────────────────────
# Step 6: Restart sample app pointed at the new realm
# ─────────────────────────────────────────────────────────────────────────────
step "Step 6: Restart sample app pointed at realm ${REALM_NAME}"

if [ ! -f "$SAMPLE_JAR" ]; then
    fail "sample jar not found at ${SAMPLE_JAR}"
    note "  → build it:  (cd apps/auth-client-sample && mvn -DskipTests package)"
    exit 1
fi

note "Stopping any running sample app…"
pkill -f "auth-client-sample-0.1.0" 2>/dev/null || true
sleep 1
ok "previous sample (if any) stopped"

note "Starting sample app → ${SAMPLE_LOG}"
# Build the command, then nohup it. Using JAVA_HOME_PATH/bin/java explicitly so
# the user doesn't need java on PATH.
JAVA_BIN="${JAVA_HOME_PATH}/bin/java"
if [ ! -x "$JAVA_BIN" ]; then
    fail "java not found at ${JAVA_BIN}"
    note "  → adjust JAVA_HOME_PATH or install: brew install openjdk"
    exit 1
fi

: > "$SAMPLE_LOG"
nohup "$JAVA_BIN" -jar "$SAMPLE_JAR" \
    --spring.profiles.active=local \
    --auth-lib.issuer-uri="${KEYCLOAK_URL}/realms/${REALM_NAME}" \
    --auth-lib.client-id="${APP_SLUG}" \
    --auth-lib.client-secret="${CLIENT_SECRET}" \
    >> "$SAMPLE_LOG" 2>&1 &
SAMPLE_PID=$!
echo "$SAMPLE_PID" > "$SAMPLE_PIDFILE"
ok "sample app pid: $SAMPLE_PID"

note "Waiting up to 30s for /actuator/health to return 200…"
HEALTH_OK=0
for i in $(seq 1 30); do
    if curl -sS -o /dev/null -w '%{http_code}' -m 2 "${SAMPLE_URL}/actuator/health" 2>/dev/null \
        | grep -q '^200$'; then
        HEALTH_OK=1
        break
    fi
    sleep 1
done

if [ "$HEALTH_OK" -ne 1 ]; then
    fail "sample app did not become healthy within 30s — last 30 log lines:"
    tail -n 30 "$SAMPLE_LOG" | indent
    exit 1
fi
ok "sample app healthy at ${SAMPLE_URL}"
ok "now pointed at issuer: ${KEYCLOAK_URL}/realms/${REALM_NAME}"
pause 1

# ─────────────────────────────────────────────────────────────────────────────
# Step 7: Mint JWT via password grant
# ─────────────────────────────────────────────────────────────────────────────
step "Step 7: Get a JWT for ${USER_EMAIL} (password grant)"

TOKEN_URL="${KEYCLOAK_URL}/realms/${REALM_NAME}/protocol/openid-connect/token"
note "POST $TOKEN_URL"

TOKEN_RESP=$(curl -sS -X POST "$TOKEN_URL" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "grant_type=password" \
    --data-urlencode "client_id=${APP_SLUG}" \
    --data-urlencode "client_secret=${CLIENT_SECRET}" \
    --data-urlencode "username=${USER_EMAIL}" \
    --data-urlencode "password=${USER_PASSWORD}")

if ! echo "$TOKEN_RESP" | python3 -c 'import json,sys; json.load(sys.stdin)' >/dev/null 2>&1; then
    fail "token endpoint returned non-JSON:"
    echo "$TOKEN_RESP" | indent
    exit 1
fi

ACCESS_TOKEN=$(echo "$TOKEN_RESP" | jget '.access_token')
if [ -z "$ACCESS_TOKEN" ]; then
    fail "no access_token in response:"
    echo "$TOKEN_RESP" | pretty_json | indent
    exit 1
fi

ok "access_token  : $(truncate_str "$ACCESS_TOKEN" 50)"

note "Decoding JWT payload…"
# JWT payloads are url-safe base64 without padding — fix that in python.
CLAIMS_JSON=$(python3 -c "
import base64, json, sys
tok = '''${ACCESS_TOKEN}'''
payload = tok.split('.')[1]
payload += '=' * (-len(payload) % 4)
data = json.loads(base64.urlsafe_b64decode(payload))
print(json.dumps(data))
")

echo "$CLAIMS_JSON" | python3 -c "
import json, sys
c = json.load(sys.stdin)
def show(label, v):
    if isinstance(v, (dict, list)):
        v = json.dumps(v)
    print('    {:<32} {}'.format(label, v))
show('iss',                       c.get('iss'))
show('sub',                       c.get('sub'))
show('preferred_username',        c.get('preferred_username'))
show('realm_access.roles',        (c.get('realm_access') or {}).get('roles'))
show('resource_access.${APP_SLUG}.roles',
     ((c.get('resource_access') or {}).get('${APP_SLUG}') or {}).get('roles'))
"
pause 1

# ─────────────────────────────────────────────────────────────────────────────
# Step 8: Test endpoints against the sample app directly
# ─────────────────────────────────────────────────────────────────────────────
step "Step 8: Hit protected endpoints on sample app directly"

# Args: label, expected-code, curl-args...
hit() {
    local label="$1"; shift
    local expected="$1"; shift
    local body code

    # Capture body + status code in one call.
    local tmp; tmp=$(mktemp)
    code=$(curl -sS -o "$tmp" -w '%{http_code}' "$@" || echo "000")
    body=$(cat "$tmp"); rm -f "$tmp"

    local marker
    if [ "$code" = "$expected" ]; then
        marker="${CHECK}"
    else
        marker="${CROSS}"
    fi
    printf '    %b %-50s expected=%s got=%s\n' "$marker" "$label" "$expected" "$code"
    if [ -n "$body" ]; then
        printf '%s\n' "$body" | truncate_lines 6 | sed 's/^/        /'
    fi
}

BOGUS_TOKEN="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJib2d1cyJ9.invalidsig"

hit "no token         → GET /orders"          "401" \
    -X GET "${SAMPLE_URL}/orders"
hit "bogus token      → GET /orders"          "401" \
    -X GET -H "Authorization: Bearer ${BOGUS_TOKEN}" "${SAMPLE_URL}/orders"
hit "real token       → GET /orders/whoami"   "200" \
    -X GET -H "Authorization: Bearer ${ACCESS_TOKEN}" "${SAMPLE_URL}/orders/whoami"
hit "real token       → GET /orders"          "200" \
    -X GET -H "Authorization: Bearer ${ACCESS_TOKEN}" "${SAMPLE_URL}/orders"
hit "real token       → GET /orders/approve"  "200" \
    -X GET -H "Authorization: Bearer ${ACCESS_TOKEN}" "${SAMPLE_URL}/orders/approve"
pause 1

# ─────────────────────────────────────────────────────────────────────────────
# Step 9: Same flow through OpenResty (hostname routing)
# ─────────────────────────────────────────────────────────────────────────────
step "Step 9: Same flow through OpenResty edge (Host: ${PRIMARY_HOST})"

note "This proves: hostname → Redis route lookup → proxy to backend → JWT verify → @PreAuthorize."
hit "no token  via edge → GET /orders"          "401" \
    -X GET -H "Host: ${PRIMARY_HOST}" "${OPENRESTY_URL}/orders"
hit "real tok  via edge → GET /orders/whoami"   "200" \
    -X GET -H "Host: ${PRIMARY_HOST}" \
            -H "Authorization: Bearer ${ACCESS_TOKEN}" \
            "${OPENRESTY_URL}/orders/whoami"
pause 1

# ─────────────────────────────────────────────────────────────────────────────
# Step 10: Audit summary
# ─────────────────────────────────────────────────────────────────────────────
step "Step 10: Audit events recorded during the demo"

pg -P pager=off -c "
SELECT action,
       result,
       COALESCE(target_kind, '-') AS target,
       details->>'slug' AS slug,
       occurred_at::timestamp(0)
FROM auth_manager.audit_events
ORDER BY id;
" | indent

note "Expecting at minimum: tenant.create SUCCESS, app.create SUCCESS, app.apply SUCCESS."
pause 1

# ─────────────────────────────────────────────────────────────────────────────
# Step 11: Summary banner
# ─────────────────────────────────────────────────────────────────────────────
echo
printf '%b\n' "${BOLD}${GREEN}═════════════════════════════════════════════════════════════════════${RESET}"
printf '%b\n' "${BOLD}${GREEN}  END-TO-END DEMO COMPLETE${RESET}"
echo
printf '%s\n' "  Showed:"
printf '%s\n' "   - UI/API created tenant + app + manifest"
printf '%s\n' "   - Keycloak got a realm (${REALM_NAME}), a client (${APP_SLUG}), roles, resources,"
printf '%s\n' "     scopes, role policies, scope permissions — all from one POST"
printf '%s\n' "   - A real user was issued a JWT signed by the tenant realm"
printf '%s\n' "   - auth-lib v2 verified the signature via JWKS (rejects forged tokens)"
printf '%s\n' "   - @PreAuthorize fetched permissions via UMA, allowed ADMIN actions"
printf '%s\n' "   - OpenResty routed by hostname → same flow end-to-end through the edge"
printf '%s\n' "   - Every state change captured in audit_events"
echo
printf '%s\n' "  Sample app is now running pointed at ${REALM_NAME} realm (was pointed at dev)."
printf '%s\n' "  To restore default: pkill -f auth-client-sample && start with no"
printf '%s\n' "  override flags (or just kill it; it's optional for normal dev)."
printf '%b\n' "${BOLD}${GREEN}═════════════════════════════════════════════════════════════════════${RESET}"
echo

exit 0
