#!/usr/bin/env bash
# Fast theme iteration loop against the DEV Keycloak pod (#114).
#
# fswatch the local mcpmesh-flexible theme source and `kubectl cp` changed
# files straight into the running dev KC pod's themes directory. Safe ONLY
# because the dev KC release runs with KC_SPI_THEME_CACHE_THEMES=false +
# KC_SPI_THEME_CACHE_TEMPLATES=false (see deploy-beelink-dev.sh step 6) —
# KC re-reads templates/resources from disk on every request.
#
# Changes are ephemeral: the theme-materializer init container rebuilds the
# themes dir from ConfigMaps on the next pod restart. Once happy, commit the
# files and helm-upgrade the auth-platform-dev release to persist.
#
# Usage: scripts/theme-dev-sync.sh   (Ctrl-C to stop)
# Overrides: NAMESPACE, CONTEXT, KC_SELECTOR, KC_CONTAINER, POD_THEME_DIR, FORCE=1

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

NAMESPACE="${NAMESPACE:-auth-platform-dev}"
CONTEXT="${CONTEXT:-}"
KC_SELECTOR="${KC_SELECTOR:-app.kubernetes.io/name=keycloak,app.kubernetes.io/instance=platform-kc-dev}"
KC_CONTAINER="${KC_CONTAINER:-keycloak}"
THEME_SRC="${THEME_SRC:-$REPO_ROOT/deploy/helm/auth-platform/themes/mcpmesh-flexible}"
# Bitnami KC image: themes live under /opt/bitnami/keycloak/themes (NOT /opt/keycloak).
POD_THEME_DIR="${POD_THEME_DIR:-/opt/bitnami/keycloak/themes/mcpmesh-flexible}"

KCTL=(kubectl ${CONTEXT:+--context "$CONTEXT"} -n "$NAMESPACE")

command -v fswatch >/dev/null 2>&1 \
  || { echo "ERROR: fswatch not found. Install it with: brew install fswatch" >&2; exit 2; }
[ -d "$THEME_SRC" ] \
  || { echo "ERROR: theme source dir not found: $THEME_SRC" >&2; exit 2; }
if [[ "$NAMESPACE" != *-dev ]] && [ "${FORCE:-0}" != "1" ]; then
  echo "ERROR: refusing namespace '$NAMESPACE' — live-patching themes is only safe where" >&2
  echo "  KC theme caching is disabled (dev). Set FORCE=1 if you really mean it." >&2
  exit 2
fi

POD="$("${KCTL[@]}" get pod -l "$KC_SELECTOR" \
  --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)" \
  || { echo "ERROR: no running KC pod matching '$KC_SELECTOR' in $NAMESPACE" >&2; exit 2; }

sync_file() {  # $1 = absolute local path
  local rel="${1#"$THEME_SRC"/}"
  "${KCTL[@]}" exec "$POD" -c "$KC_CONTAINER" -- mkdir -p "$POD_THEME_DIR/$(dirname "$rel")"
  "${KCTL[@]}" cp "$1" "$POD:$POD_THEME_DIR/$rel" -c "$KC_CONTAINER"
  printf '[%s] synced %s\n' "$(date +%H:%M:%S)" "$rel"
}

echo "Syncing $THEME_SRC -> $POD:$POD_THEME_DIR ($NAMESPACE)"
while IFS= read -r f; do sync_file "$f"; done < <(find "$THEME_SRC" -type f)

echo "Watching for changes (Ctrl-C to stop)..."
fswatch -r --event Created --event Updated --event Renamed "$THEME_SRC" \
  | while IFS= read -r f; do
      [ -f "$f" ] && sync_file "$f"
    done
