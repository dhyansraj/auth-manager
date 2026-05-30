#!/usr/bin/env bash
# Deploy the DEV auth-platform stack to the beelink k3s cluster.
#
# Peer of scripts/deploy-beelink.sh — same overall shape (CNPG + Bitnami
# Redis + Bitnami KC + our chart) but smaller footprint, in its own
# auth-platform-dev namespace. See deploy/helm/auth-platform/values-beelink-
# dev.yaml for the full sizing diff.
#
# Idempotent: re-running is safe (each command is upgrade-or-install).
#
# What this script does NOT do (intentionally, to keep dev cheap):
#   - Build / push images (uses whatever tags prod uses — same registry)
#   - Stand up a separate smtp-relay (dev pods reach prod's via
#     smtp-relay.auth-platform.svc.cluster.local cross-namespace DNS)
#   - Stand up a separate cloudflared connector (prod's tunnel will route
#     auth-dev.mcp-mesh.io to this namespace — see cf-setup-tunnel.sh)
#
# Prereqs:
#   - prod auth-platform already deployed (we copy creds Secrets from there)
#   - helm + kubectl with context pointed at beelink
#   - DB_PASSWORD + KC_ADMIN_PASSWORD env vars set (dev creds, NOT prod's)
#
# Use --debug to render+show without applying anything (helm runs in dry-run
# diagnostic mode for the chart step; PG/Redis/KC use --dry-run).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

DEBUG_MODE=false
if [ "${1:-}" = "--debug" ]; then
  DEBUG_MODE=true
  echo "DEBUG MODE: helm commands will run with --dry-run + --debug, nothing will be applied."
fi

NAMESPACE="${NAMESPACE:-auth-platform-dev}"
PROD_NAMESPACE="${PROD_NAMESPACE:-auth-platform}"

# Same registry + chart versions as prod (shared infra catalog).
PG_CHART_VERSION="${PG_CHART_VERSION:-18.6.7}"
REDIS_CHART_VERSION="${REDIS_CHART_VERSION:-25.5.3}"
KC_CHART_VERSION="${KC_CHART_VERSION:-25.2.0}"

KC_IMAGE_REPO="${KC_IMAGE_REPO:-bitnamilegacy/keycloak}"
KC_IMAGE_TAG="${KC_IMAGE_TAG:-26.3.3-debian-12-r0}"

DB_USER="${DB_USER:-authmanager}"
DB_PASSWORD="${DB_PASSWORD:-}"
DB_NAME="${DB_NAME:-authmanager}"

KC_ADMIN_USER="${KC_ADMIN_USER:-admin}"
KC_ADMIN_PASSWORD="${KC_ADMIN_PASSWORD:-}"

# Refuse to run with empty / well-known-default credentials (same guards as
# the prod script). Dev creds can — and should — differ from prod's.
if [ -z "$KC_ADMIN_PASSWORD" ] || [ "$KC_ADMIN_PASSWORD" = "admin" ]; then
  echo "ERROR: KC_ADMIN_PASSWORD env var must be set to a non-default value." >&2
  echo "  Example: export KC_ADMIN_PASSWORD='<dev-value-from-password-manager>'" >&2
  exit 2
fi
if [ -z "$DB_PASSWORD" ] || [ "$DB_PASSWORD" = "authmanager-dev-pass" ]; then
  echo "ERROR: DB_PASSWORD env var must be set to a non-default value." >&2
  echo "  Example: export DB_PASSWORD='<dev-value-from-password-manager>'" >&2
  exit 2
fi

# Public OIDC issuer for dev — KC builds the issuer as KC_HOSTNAME +
# "/realms/<realm>", so the /auth path component must be here.
KC_PUBLIC_HOSTNAME="${KC_PUBLIC_HOSTNAME:-https://auth-dev.mcp-mesh.io/auth}"

bold()  { printf "\033[1m%s\033[0m\n" "$*"; }
ok()    { printf "  \033[32m✓\033[0m %s\n" "$*"; }
step()  { echo; bold "── $* ──"; }

# Helper: pick --dry-run / --debug flags based on DEBUG_MODE.
helm_flags() {
  if $DEBUG_MODE; then
    echo "--dry-run --debug"
  fi
}
kubectl_flags() {
  if $DEBUG_MODE; then
    echo "--dry-run=server"
  fi
}

step "1. Namespace"
if $DEBUG_MODE; then
  echo "  (would ensure namespace $NAMESPACE)"
else
  kubectl get ns "$NAMESPACE" >/dev/null 2>&1 \
    || kubectl create ns "$NAMESPACE"
fi
ok "$NAMESPACE"

step "2. Bitnami repo"
helm repo list 2>/dev/null | grep -q '^bitnami' \
  || helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update bitnami >/dev/null
ok "bitnami repo present"

step "3. Copy shared Secrets from prod namespace"
# Dev pods need: sendgrid-api (for SENDGRID_API_KEY + smtp-relay shared
# from prod), cloudflare-api (for CF auto-provisioning), platform-oauth-
# providers (for Google/GitHub IdP brokering).
#
# K8s Secrets are namespace-scoped, so we literally copy them. This
# means dev uses the SAME OAuth client IDs as prod — dev-tenant redirect
# URIs still need to be added to the Google/GitHub OAuth apps separately
# (one-time, side-effect of sharing the platform OAuth clients).
copy_secret() {
  local name="$1"
  if $DEBUG_MODE; then
    echo "  (would copy Secret $name from $PROD_NAMESPACE → $NAMESPACE)"
    return 0
  fi
  if ! kubectl get secret "$name" -n "$PROD_NAMESPACE" >/dev/null 2>&1; then
    echo "  ⚠ Secret $name not found in $PROD_NAMESPACE — skipping (some features will degrade)"
    return 0
  fi
  kubectl get secret "$name" -n "$PROD_NAMESPACE" -o yaml \
    | sed -e "s/namespace: $PROD_NAMESPACE\$/namespace: $NAMESPACE/" \
          -e '/resourceVersion:/d' \
          -e '/uid:/d' \
          -e '/creationTimestamp:/d' \
    | kubectl apply -f -
  ok "Secret $name → $NAMESPACE"
}
copy_secret sendgrid-api
copy_secret cloudflare-api
copy_secret platform-oauth-providers

step "4. CNPG Postgres cluster (platform-pg-dev, 1 instance)"
# Inline manifest — small footprint variant of deploy/cnpg/pg-cluster.yaml.
# Single instance (no HA replication, no anti-affinity needed). Same
# storageClass as prod (longhorn). The CNPG operator creates the
# rw/ro/r services + the platform-pg-dev-superuser-secret automatically.
#
# `bootstrap.initdb.secret` references platform-pg-dev-app-secret which we
# create just before applying the Cluster manifest.
if $DEBUG_MODE; then
  echo "  (would create platform-pg-dev-app-secret + apply CNPG Cluster manifest)"
else
  kubectl create secret generic platform-pg-dev-app-secret \
    -n "$NAMESPACE" \
    --from-literal=username="$DB_USER" \
    --from-literal=password="$DB_PASSWORD" \
    --dry-run=client -o yaml | kubectl apply -f -

  cat <<EOF | kubectl apply -f -
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: platform-pg-dev
  namespace: $NAMESPACE
spec:
  instances: 1
  imageName: ghcr.io/cloudnative-pg/postgresql:18.4
  postgresql:
    parameters:
      max_connections: "100"
      shared_buffers: "128MB"
  bootstrap:
    initdb:
      database: $DB_NAME
      owner: $DB_USER
      secret:
        name: platform-pg-dev-app-secret
  superuserSecret:
    name: platform-pg-dev-superuser-secret
  storage:
    size: 5Gi
    storageClass: longhorn
  monitoring:
    enablePodMonitor: false
  resources:
    requests:
      memory: "256Mi"
      cpu: "100m"
    limits:
      memory: "512Mi"
      cpu: "500m"
EOF
  # Wait for CNPG to bring the cluster up before continuing (KC depends on PG).
  echo "  waiting for platform-pg-dev to be ready..."
  kubectl wait --for=condition=Ready cluster/platform-pg-dev \
    -n "$NAMESPACE" --timeout=300s || true

  # Create the keycloak DB on the cluster post-bootstrap (CNPG initdb only
  # supports a single database; prod uses a separate Job for this).
  kubectl exec -n "$NAMESPACE" platform-pg-dev-1 -- \
    psql -U postgres -tAc \
    "SELECT 1 FROM pg_database WHERE datname='keycloak'" 2>/dev/null \
    | grep -q 1 \
    || kubectl exec -n "$NAMESPACE" platform-pg-dev-1 -- \
       psql -U postgres -c "CREATE DATABASE keycloak;"
fi
ok "platform-pg-dev"

step "5. Redis (platform-redis-dev, standalone)"
helm upgrade --install platform-redis-dev bitnami/redis \
  --namespace "$NAMESPACE" \
  --version "$REDIS_CHART_VERSION" \
  --set "architecture=standalone" \
  --set "auth.enabled=false" \
  --set "master.persistence.enabled=false" \
  --set "replica.replicaCount=0" \
  --wait --timeout=300s $(helm_flags)
ok "platform-redis-dev"

step "6. Keycloak (platform-kc-dev, 1 pod, start-dev)"
# start-dev: skips production-mode validations + theme/template caching by
# default (faster iteration when fiddling with themes). We still pass the
# theme-cache disables explicitly so behaviour is independent of dev/prod
# mode default differences across KC versions.
#
# extraStartupArgs overrides Bitnami's default of `start --optimized`. We
# pass `start-dev` as a single argument; Bitnami threads it into the entry-
# point so KC boots in dev mode.
helm upgrade --install platform-kc-dev bitnami/keycloak \
  --namespace "$NAMESPACE" \
  --version "$KC_CHART_VERSION" \
  -f deploy/helm/keycloak-overrides/values-platform-kc.yaml \
  --set "image.registry=docker.io" \
  --set "image.repository=$KC_IMAGE_REPO" \
  --set "image.tag=$KC_IMAGE_TAG" \
  --set "auth.adminUser=$KC_ADMIN_USER" \
  --set "auth.adminPassword=$KC_ADMIN_PASSWORD" \
  --set "postgresql.enabled=false" \
  --set "externalDatabase.host=platform-pg-dev-rw" \
  --set "externalDatabase.user=$DB_USER" \
  --set "externalDatabase.password=$DB_PASSWORD" \
  --set "externalDatabase.database=keycloak" \
  --set "proxy=edge" \
  --set "production=false" \
  --set "extraStartupArgs=start-dev" \
  --set "extraEnvVars[0].name=KC_HOSTNAME" \
  --set "extraEnvVars[0].value=$KC_PUBLIC_HOSTNAME" \
  --set "extraEnvVars[1].name=KC_HOSTNAME_STRICT" \
  --set-string "extraEnvVars[1].value=true" \
  --set "extraEnvVars[2].name=KC_PROXY_HEADERS" \
  --set "extraEnvVars[2].value=xforwarded" \
  --set "extraEnvVars[3].name=KC_SPI_THEME_CACHE_THEMES" \
  --set-string "extraEnvVars[3].value=false" \
  --set "extraEnvVars[4].name=KC_SPI_THEME_CACHE_TEMPLATES" \
  --set-string "extraEnvVars[4].value=false" \
  --set "extraEnvVars[5].name=KC_SPI_THEME_STATIC_MAX_AGE" \
  --set-string "extraEnvVars[5].value=-1" \
  --set "replicaCount=1" \
  --wait --timeout=300s $(helm_flags)
ok "platform-kc-dev"

step "7. auth-manager + admin-ui + platform-edge (dev release)"
helm upgrade --install auth-platform-dev deploy/helm/auth-platform \
  --namespace "$NAMESPACE" \
  -f deploy/helm/auth-platform/values-beelink-dev.yaml \
  --wait --timeout=180s $(helm_flags)
ok "auth-platform-dev"

step "Status"
if $DEBUG_MODE; then
  echo "  (debug mode — no resources applied; re-run without --debug to deploy)"
else
  kubectl get pods -n "$NAMESPACE"
  echo
  echo "Public URLs (require scripts/cf-setup-tunnel-dev.sh to be run once):"
  echo "  https://auth-dev.mcp-mesh.io/"
  echo "  https://admin-dev.mcp-mesh.io/"
  echo
  echo "Local port-forward shortcuts:"
  echo "  kubectl port-forward -n $NAMESPACE svc/auth-platform-dev-auth-manager  18080:8080"
  echo "  kubectl port-forward -n $NAMESPACE svc/auth-platform-dev-admin-ui      15173:80"
  echo "  kubectl port-forward -n $NAMESPACE svc/auth-platform-dev-platform-edge 18090:80"
  echo "  kubectl port-forward -n $NAMESPACE svc/platform-kc-dev-keycloak        18180:80"
fi
