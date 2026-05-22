#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# Platform-level OAuth provider credentials (Google + GitHub).
#
# auth-manager brokers Google + GitHub social login per-tenant via Keycloak
# IdP instances that all reference ONE OAuth app per provider, registered
# at the platform level by the platform admin (Dhyan). This script writes the
# creds into a k8s Secret named `platform-oauth-providers` in the
# `auth-platform` namespace; the auth-manager Deployment mounts the Secret
# (optionally — missing Secret is OK, providers just show available=false).
#
# -----------------------------------------------------------------------------
# One-time OAuth app registration (do this BEFORE running this script)
# -----------------------------------------------------------------------------
#
# === Google ===
# 1. https://console.cloud.google.com/apis/credentials → "Create credentials"
#    → "OAuth client ID" → "Web application".
# 2. Authorized redirect URIs: ONE PER TENANT REALM. Format:
#       https://auth.mcp-mesh.io/auth/realms/<realm>/broker/google/endpoint
#    Realm name follows the convention `t-<slug>`. Example for tenant "app1":
#       https://auth.mcp-mesh.io/auth/realms/t-app1/broker/google/endpoint
#    When a new tenant is provisioned, go back to this Google OAuth app and
#    APPEND the new realm's redirect URI. (Automating this via Google's API
#    is out of scope for now — see PLAN.org task 28 followup.)
# 3. Copy the resulting "Client ID" and "Client secret".
#
# === GitHub ===
# 1. https://github.com/settings/applications/new
#    or https://github.com/organizations/<org>/settings/applications/new
# 2. Authorization callback URL: ONLY ONE allowed per GitHub OAuth App.
#    Workaround: register one GitHub OAuth App PER TENANT, OR use GitHub Apps
#    (supports multiple callbacks). v1 ships with the one-app model:
#       https://auth.mcp-mesh.io/auth/realms/t-<slug>/broker/github/endpoint
#    If you later need multiple tenants on GitHub, consider migrating to
#    GitHub Apps or creating per-tenant OAuth apps. For now: pick ONE primary
#    tenant for the callback (e.g. `t-app1`) and document the constraint.
# 3. Copy "Client ID" and generate a new "Client secret".
#
# -----------------------------------------------------------------------------
# Usage
# -----------------------------------------------------------------------------
#   export GOOGLE_CLIENT_ID="..."
#   export GOOGLE_CLIENT_SECRET="..."
#   export GITHUB_CLIENT_ID="..."
#   export GITHUB_CLIENT_SECRET="..."
#   ./scripts/setup-oauth-providers.sh
#
# Re-running with new values updates the Secret in place (idempotent).
# After updating, rollout the auth-manager Deployment so it picks up new env:
#   kubectl --context beelink rollout restart -n auth-platform deploy/auth-platform-auth-manager
# -----------------------------------------------------------------------------

set -euo pipefail

: "${GOOGLE_CLIENT_ID:?Set GOOGLE_CLIENT_ID}"
: "${GOOGLE_CLIENT_SECRET:?Set GOOGLE_CLIENT_SECRET}"
: "${GITHUB_CLIENT_ID:?Set GITHUB_CLIENT_ID}"
: "${GITHUB_CLIENT_SECRET:?Set GITHUB_CLIENT_SECRET}"

KUBE_CONTEXT="${KUBE_CONTEXT:-beelink}"
NAMESPACE="${NAMESPACE:-auth-platform}"

echo "Writing platform-oauth-providers Secret to namespace=${NAMESPACE} context=${KUBE_CONTEXT}…"

kubectl --context "${KUBE_CONTEXT}" create secret generic platform-oauth-providers \
    -n "${NAMESPACE}" \
    --from-literal=google.client-id="${GOOGLE_CLIENT_ID}" \
    --from-literal=google.client-secret="${GOOGLE_CLIENT_SECRET}" \
    --from-literal=github.client-id="${GITHUB_CLIENT_ID}" \
    --from-literal=github.client-secret="${GITHUB_CLIENT_SECRET}" \
    --dry-run=client -o yaml | kubectl --context "${KUBE_CONTEXT}" apply -f -

echo "Done. Restart auth-manager to pick up the new credentials:"
echo "  kubectl --context ${KUBE_CONTEXT} rollout restart -n ${NAMESPACE} deploy/auth-platform-auth-manager"
