#!/usr/bin/env bash
# Build + push app1 images, then helm upgrade --install the app1 chart.
#
# Sequence:
#   1. Build + push app1-backend:0.1.0 (Maven multi-stage Dockerfile)
#   2. Build + push app1-ui:0.1.0      (Vite + nginx multi-stage Dockerfile)
#   3. Read the 'orders' client secret from $SECRET_FILE (written by
#      scripts/provision-app1.sh on tenant create)
#   4. helm upgrade --install app1 deploy/helm/app1 -f values-beelink.yaml
#      into namespace tenant-app1 (--create-namespace).
#
# Prereqs:
#   - scripts/provision-app1.sh has been run (tenant + app + client created,
#     client secret cached at $SECRET_FILE).
#   - kubectl context is the beelink cluster.
#   - The mutagen sync has the repo at $REPO_REMOTE_PATH on $BUILD_HOST.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

NAMESPACE="${NAMESPACE:-tenant-app1}"
BUILD_HOST="${BUILD_HOST:-beelink1}"
REPO_REMOTE_PATH="${REPO_REMOTE_PATH:-/home/dhyanraj/workspace/github/auth-manager}"
REGISTRY="${REGISTRY:-192.168.10.1:5000}"
BACKEND_TAG="${BACKEND_TAG:-0.1.0}"
UI_TAG="${UI_TAG:-0.1.0}"
SECRET_FILE="${SECRET_FILE:-/tmp/app1-orders-secret}"

bold() { printf "\033[1m%s\033[0m\n" "$*"; }
ok()   { printf "  \033[32m✓\033[0m %s\n" "$*"; }
step() { echo; bold "── $* ──"; }

step "1. Build + push app1-backend:${BACKEND_TAG}"
ssh "$BUILD_HOST" "cd '$REPO_REMOTE_PATH' && \
  docker build -f apps/app1-backend/Dockerfile -t '$REGISTRY/app1-backend:$BACKEND_TAG' . && \
  docker push '$REGISTRY/app1-backend:$BACKEND_TAG'"
ok "app1-backend:${BACKEND_TAG} pushed to $REGISTRY"

step "2. Build + push app1-ui:${UI_TAG}"
ssh "$BUILD_HOST" "cd '$REPO_REMOTE_PATH' && \
  docker build -f apps/app1-ui/Dockerfile -t '$REGISTRY/app1-ui:$UI_TAG' . && \
  docker push '$REGISTRY/app1-ui:$UI_TAG'"
ok "app1-ui:${UI_TAG} pushed to $REGISTRY"

step "3. Read the orders client secret"
if [ ! -f "$SECRET_FILE" ]; then
    echo "ERROR: client secret not found at $SECRET_FILE."
    echo "  → run scripts/provision-app1.sh first."
    exit 1
fi
CLIENT_SECRET=$(cat "$SECRET_FILE")
ok "loaded secret from $SECRET_FILE (${#CLIENT_SECRET} chars)"

step "4. helm upgrade --install app1"
helm upgrade --install app1 deploy/helm/app1 \
    --namespace "$NAMESPACE" \
    --create-namespace \
    -f deploy/helm/app1/values-beelink.yaml \
    --set "backend.config.authLibClientSecret=${CLIENT_SECRET}" \
    --wait --timeout=300s
ok "app1 release deployed"

step "Status"
kubectl get pods -n "$NAMESPACE"
echo
echo "Smoke test:"
echo "  curl -sS -m 10 -o /dev/null -w '  GET / → %{http_code}\\n' 'https://app1.mcp-mesh.io/'"
echo "  curl -sS -m 10 -o /dev/null -w '  GET /api/orders (no auth) → %{http_code}\\n' 'https://app1.mcp-mesh.io/api/orders'"
echo "  # Expected: 200 for /  ; 401 for /api/orders (REQUIRED at edge)"
