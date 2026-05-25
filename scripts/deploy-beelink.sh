#!/usr/bin/env bash
# Deploy the auth-platform stack to the beelink k3s cluster.
#
# Idempotent: re-running is safe (each command is upgrade-or-install).
# Run from the repo root, OR from anywhere — the script cd's to its own dir.
#
# Layout:
#   - Postgres, Redis, Keycloak installed as SEPARATE helm releases from
#     Bitnami's charts. Reason: helm 3.20.1 has a bug with OCI subchart
#     resolution AND Bitnami's free-tier image policy changed in 2024
#     (specific versioned tags moved to docker.io/bitnamilegacy/* for
#     unsubscribed users). Keeping them as separate releases lets us
#     override per-chart image flags without fighting subchart inheritance.
#   - Our own chart (auth-platform) holds just auth-manager + admin-ui;
#     it points at the service names of the three above.
#
# Prereqs:
#   - helm + kubectl with context set to beelink cluster
#   - mutagen sync running (so this repo's files are present on beelink)
#   - cloudflared-token Secret in the auth-platform namespace, holding the
#     tunnel token under key "token". Create with:
#       kubectl create secret generic cloudflared-token -n auth-platform \
#         --from-literal=token='<tunnel-token-from-CF-dashboard>'
#     Then configure routes + DNS with scripts/cf-setup-tunnel.sh.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

NAMESPACE="${NAMESPACE:-auth-platform}"

# Beelink build host + local registry. Images are built on beelink1 (which has
# the Docker daemon + access to the mutagen-synced repo) and pushed to the
# private registry on the same host (insecure HTTP, accessible only on the LAN).
BUILD_HOST="${BUILD_HOST:-beelink1}"
REPO_REMOTE_PATH="${REPO_REMOTE_PATH:-/home/dhyanraj/workspace/github/auth-manager}"
REGISTRY="${REGISTRY:-192.168.10.1:5000}"

PG_CHART_VERSION="${PG_CHART_VERSION:-18.6.7}"
REDIS_CHART_VERSION="${REDIS_CHART_VERSION:-25.5.3}"
KC_CHART_VERSION="${KC_CHART_VERSION:-25.2.0}"

# Bitnami's free-tier image registry for older tags (post-2024 catalog split).
KC_IMAGE_REPO="${KC_IMAGE_REPO:-bitnamilegacy/keycloak}"
KC_IMAGE_TAG="${KC_IMAGE_TAG:-26.3.3-debian-12-r0}"

DB_USER="${DB_USER:-authmanager}"
DB_PASSWORD="${DB_PASSWORD:-authmanager-dev-pass}"
DB_NAME="${DB_NAME:-authmanager}"

KC_ADMIN_USER="${KC_ADMIN_USER:-admin}"
KC_ADMIN_PASSWORD="${KC_ADMIN_PASSWORD:-admin}"
# Public OIDC issuer hostname (path-included). KC 26 hostname-v2 builds the
# issuer as KC_HOSTNAME + "/realms/<realm>", so a path component here means
# tokens get iss="https://auth.mcp-mesh.io/auth/realms/<realm>".
KC_PUBLIC_HOSTNAME="${KC_PUBLIC_HOSTNAME:-https://auth.mcp-mesh.io/auth}"

bold()  { printf "\033[1m%s\033[0m\n" "$*"; }
ok()    { printf "  \033[32m✓\033[0m %s\n" "$*"; }
step()  { echo; bold "── $* ──"; }

step "1. Namespace"
kubectl get ns "$NAMESPACE" >/dev/null 2>&1 \
  || kubectl create ns "$NAMESPACE"
ok "$NAMESPACE"

step "2. Bitnami repo"
helm repo list 2>/dev/null | grep -q '^bitnami' \
  || helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update bitnami >/dev/null
ok "bitnami repo present"

step "3. Postgres (platform-pg)"
helm upgrade --install platform-pg bitnami/postgresql \
  --namespace "$NAMESPACE" \
  --version "$PG_CHART_VERSION" \
  --set "global.storageClass=longhorn" \
  --set "auth.username=$DB_USER" \
  --set "auth.password=$DB_PASSWORD" \
  --set "auth.database=$DB_NAME" \
  --set "primary.persistence.size=8Gi" \
  --set-string "primary.initdb.scripts.00-keycloak-db\.sql=CREATE DATABASE keycloak;" \
  --wait --timeout=300s
ok "platform-pg"

step "4. Redis (platform-redis)"
helm upgrade --install platform-redis bitnami/redis \
  --namespace "$NAMESPACE" \
  --version "$REDIS_CHART_VERSION" \
  --set "architecture=standalone" \
  --set "auth.enabled=false" \
  --set "master.persistence.enabled=false" \
  --wait --timeout=300s
ok "platform-redis"

step "5. Keycloak (platform-kc)"
# Theme materializer init container + RBAC + shared volume are layered via
# the values-platform-kc.yaml overrides file. Re-running this step triggers
# a KC restart, which is exactly what we want when the materializer logic
# changes — but be aware logged-in user sessions are dropped.
helm upgrade --install platform-kc bitnami/keycloak \
  --namespace "$NAMESPACE" \
  --version "$KC_CHART_VERSION" \
  -f deploy/helm/keycloak-overrides/values-platform-kc.yaml \
  --set "image.registry=docker.io" \
  --set "image.repository=$KC_IMAGE_REPO" \
  --set "image.tag=$KC_IMAGE_TAG" \
  --set "auth.adminUser=$KC_ADMIN_USER" \
  --set "auth.adminPassword=$KC_ADMIN_PASSWORD" \
  --set "postgresql.enabled=false" \
  --set "externalDatabase.host=platform-pg-postgresql" \
  --set "externalDatabase.user=$DB_USER" \
  --set "externalDatabase.password=$DB_PASSWORD" \
  --set "externalDatabase.database=keycloak" \
  --set "proxy=edge" \
  --set "production=false" \
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
  --wait --timeout=300s
ok "platform-kc"

step "6. Build + push platform-edge image"
# Build context is the repo root; Dockerfile lives at dev/openresty/Dockerfile.
# Runs on beelink1 so it pushes to the local registry over plain HTTP (the
# registry is configured insecure for 192.168.10.1:5000).
ssh "$BUILD_HOST" "cd '$REPO_REMOTE_PATH' && \
  docker build -f dev/openresty/Dockerfile -t '$REGISTRY/platform-edge:0.1.6' . && \
  docker push '$REGISTRY/platform-edge:0.1.6'"
ok "platform-edge:0.1.6 pushed to $REGISTRY"

step "7. auth-manager + admin-ui + platform-edge"
helm upgrade --install auth-platform deploy/helm/auth-platform \
  --namespace "$NAMESPACE" \
  -f deploy/helm/auth-platform/values-beelink.yaml \
  --wait --timeout=180s
ok "auth-platform"

step "Status"
kubectl get pods -n "$NAMESPACE"
echo
echo "To reach the services from your Mac:"
echo "  kubectl port-forward -n $NAMESPACE svc/auth-platform-auth-manager  8080:8080"
echo "  kubectl port-forward -n $NAMESPACE svc/auth-platform-admin-ui      5173:80"
echo "  kubectl port-forward -n $NAMESPACE svc/auth-platform-platform-edge 8090:80"
echo "  kubectl port-forward -n $NAMESPACE svc/platform-kc-keycloak        8180:80"
echo
echo "Then open http://localhost:5173 for the admin UI."
