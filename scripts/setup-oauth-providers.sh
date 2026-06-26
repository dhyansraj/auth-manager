#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# Platform-level OAuth provider credentials (Google + GitHub + Apple).
#
# auth-manager brokers Google + GitHub + Apple social login per-tenant via
# Keycloak IdP instances that all reference ONE OAuth app per provider,
# registered at the platform level by the platform admin (Dhyan). This script
# writes the creds into a k8s Secret named `platform-oauth-providers` in the
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
# === Apple ("Sign in with Apple") ===
# Apple does NOT use a static client secret — auth-manager mints a short-lived
# ES256 JWT from your .p8 private key (AppleClientSecretSigner). You provide
# four values, all from https://developer.apple.com/account → Certificates,
# Identifiers & Profiles:
#   APPLE_SERVICES_ID — the "Services ID" identifier (Identifiers → Services
#       IDs). This is the OIDC client_id, e.g. "io.mcpmesh.auth.signin".
#       Configure its "Sign In with Apple" Return URLs to one per tenant realm:
#         https://auth.mcp-mesh.io/auth/realms/t-<slug>/broker/apple/endpoint
#   APPLE_TEAM_ID    — your 10-char Apple Developer Team ID (top-right of the
#       Membership page), e.g. "ABCDE12345".
#   APPLE_KEY_ID     — the 10-char Key ID of the private key you create under
#       Keys → "+" → enable "Sign In with Apple".
#   APPLE_PRIVATE_KEY / APPLE_PRIVATE_KEY_FILE — the downloaded .p8 file
#       contents (PKCS8 PEM). Pass the literal in APPLE_PRIVATE_KEY, OR set
#       APPLE_PRIVATE_KEY_FILE to the path of the .p8 and the script reads it.
# Apple is OPTIONAL: leave all four unset to skip it (available=false).
#
# -----------------------------------------------------------------------------
# Usage
# -----------------------------------------------------------------------------
#   export GOOGLE_CLIENT_ID="..."
#   export GOOGLE_CLIENT_SECRET="..."
#   export GITHUB_CLIENT_ID="..."
#   export GITHUB_CLIENT_SECRET="..."
#   # Optional Apple:
#   export APPLE_SERVICES_ID="io.mcpmesh.auth.signin"
#   export APPLE_TEAM_ID="ABCDE12345"
#   export APPLE_KEY_ID="KEY1234567"
#   export APPLE_PRIVATE_KEY_FILE="./AuthKey_KEY1234567.p8"
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

# Apple creds are optional. Default to empty so unset vars don't trip set -u.
APPLE_SERVICES_ID="${APPLE_SERVICES_ID:-}"
APPLE_TEAM_ID="${APPLE_TEAM_ID:-}"
APPLE_KEY_ID="${APPLE_KEY_ID:-}"
APPLE_PRIVATE_KEY="${APPLE_PRIVATE_KEY:-}"
# Convenience: read the .p8 file into the literal if a path was given.
if [[ -z "${APPLE_PRIVATE_KEY}" && -n "${APPLE_PRIVATE_KEY_FILE:-}" ]]; then
    APPLE_PRIVATE_KEY="$(cat "${APPLE_PRIVATE_KEY_FILE}")"
fi

KUBE_CONTEXT="${KUBE_CONTEXT:-beelink}"
NAMESPACE="${NAMESPACE:-auth-platform}"

echo "Writing platform-oauth-providers Secret to namespace=${NAMESPACE} context=${KUBE_CONTEXT}…"
if [[ -n "${APPLE_SERVICES_ID}" ]]; then
    echo "  Apple: configured (services-id=${APPLE_SERVICES_ID})"
else
    echo "  Apple: not configured (skipping — available=false)"
fi

kubectl --context "${KUBE_CONTEXT}" create secret generic platform-oauth-providers \
    -n "${NAMESPACE}" \
    --from-literal=google.client-id="${GOOGLE_CLIENT_ID}" \
    --from-literal=google.client-secret="${GOOGLE_CLIENT_SECRET}" \
    --from-literal=github.client-id="${GITHUB_CLIENT_ID}" \
    --from-literal=github.client-secret="${GITHUB_CLIENT_SECRET}" \
    --from-literal=apple.services-id="${APPLE_SERVICES_ID}" \
    --from-literal=apple.team-id="${APPLE_TEAM_ID}" \
    --from-literal=apple.key-id="${APPLE_KEY_ID}" \
    --from-literal=apple.private-key="${APPLE_PRIVATE_KEY}" \
    --dry-run=client -o yaml | kubectl --context "${KUBE_CONTEXT}" apply -f -

echo "Done. Restart auth-manager to pick up the new credentials:"
echo "  kubectl --context ${KUBE_CONTEXT} rollout restart -n ${NAMESPACE} deploy/auth-platform-auth-manager"
