#!/usr/bin/env bash
# Idempotent Cloudflare API setup for the auth-platform tunnel.
#
# Configures the tunnel's ingress rules and ensures DNS CNAMEs exist
# for each public hostname (pointing at <tunnel-uuid>.cfargotunnel.com).
#
# Requires:
#   CF_API_TOKEN     — Cloudflare API token with:
#                        Account · Cloudflare Tunnel · Edit
#                        Zone    · DNS              · Edit  (for the zone)
#   CF_ACCOUNT_ID    — Cloudflare account ID
#   CF_TUNNEL_ID     — UUID of the tunnel (the 't' claim in the tunnel token)
#   CF_ZONE          — Zone name (e.g. mcp-mesh.io)
#
# Hostnames + services are defined inline in INGRESS_RULES below — edit there
# to add/remove routes, then re-run.

set -euo pipefail

: "${CF_API_TOKEN:?env var CF_API_TOKEN is required}"
: "${CF_ACCOUNT_ID:?env var CF_ACCOUNT_ID is required}"
: "${CF_TUNNEL_ID:?env var CF_TUNNEL_ID is required}"
: "${CF_ZONE:?env var CF_ZONE is required}"

API="https://api.cloudflare.com/client/v4"
H_AUTH="Authorization: Bearer $CF_API_TOKEN"
H_JSON="Content-Type: application/json"

bold()  { printf "\033[1m%s\033[0m\n" "$*"; }
ok()    { printf "  \033[32m✓\033[0m %s\n" "$*"; }
step()  { echo; bold "── $* ──"; }

# ─── Ingress rules (HOSTNAME → in-cluster service URL) ───────────────────
# Service URLs use Kubernetes DNS: <svc>.<namespace>.svc.cluster.local
#
# This script OWNS only the platform hostnames below. Step 3 does a
# read-merge-write against the live tunnel config: it refreshes these
# platform rules and PRESERVES every other ingress rule (tenant custom apex
# domains, etc.) that auth-manager's CloudflareTunnelService adds at runtime.
#
# Hostname routing notes:
#   - auth.mcp-mesh.io      → prod platform-edge (admin UI + auth-manager + KC
#                             under /auth, including the KC admin console at
#                             /auth/admin/*). IP-restriction for the admin paths
#                             is enforced at the Cloudflare WAF layer on path
#                             /auth/admin/* — see scripts/cf-firewall-setup.sh.
#   - auth-dev.mcp-mesh.io  → DEV platform-edge in auth-platform-dev namespace.
#                             Side-by-side with prod; same cluster, separate
#                             namespace + edge release. Single hostname serves
#                             both KC (/auth/*) and admin UI (/admin/*) — edge
#                             router.lua routes by path regardless of host.
#   - *.mcp-mesh.io         → prod platform-edge (catch-all for tenant
#                             subdomains: app1.mcp-mesh.io, customer.mcp-mesh.io,
#                             etc.). Order matters in CF tunnel ingress; this
#                             MUST come after the more specific entries above.
#                             Dev tenant hostnames (e.g. <tenant>-dev.mcp-mesh.io
#                             created in dev) currently still hit prod edge via
#                             this catch-all; until per-tenant routing learns
#                             about dev, operators pick dev tenant hostnames
#                             that they explicitly route by adding a specific
#                             rule above the wildcard (Phase 2).
#
# Tenant custom apex domains (niralishappyfeetindia.com, maya-ai.ink, etc.) are
# NOT listed here — they are managed at runtime by auth-manager's
# CloudflareTunnelService via its own read-merge-write. Step 3 preserves them
# verbatim, so re-running this script no longer wipes tenant routes.
#
# Service URLs (single source of truth for the platform edges):
PROD_EDGE_SVC="http://auth-platform-platform-edge.auth-platform.svc.cluster.local:80"
DEV_EDGE_SVC="http://auth-platform-dev-platform-edge.auth-platform-dev.svc.cluster.local:80"

# Hostnames to ensure as DNS CNAMEs.
# The *.mcp-mesh.io wildcard ingress is matched by the tunnel based on the
# Host header; we still need per-subdomain CNAMEs at the DNS layer for each
# hostname that should resolve. "auth" is the platform admin/issuer host;
# tenant subdomains (app1, etc.) are added as we onboard tenants.
# "auth-dev" routes to the side-by-side dev namespace (single-host dev,
# mirrors prod's single-host architecture).
# Tenant apex domains (niralishappyfeetindia.com, etc.) are managed by their
# own DNS providers — only in-zone hostnames are listed here.
DNS_HOSTNAMES=(auth auth-dev app1 safesound-dev)

# Stale CNAMEs to remove (orphaned by ingress rules dropped above).
# - kc: superseded by auth.mcp-mesh.io
# - admin-dev: dropped in favour of single-host dev (auth-dev only)
DNS_HOSTNAMES_TO_REMOVE=(kc admin-dev)

step "1. Verify API token"
curl -sS -H "$H_AUTH" "$API/user/tokens/verify" | python3 -c '
import sys, json
d = json.load(sys.stdin)
if not d.get("success"):
    print("  token invalid:", d.get("errors"))
    sys.exit(1)
print("  token active, id:", d.get("result", {}).get("id", "?"))
'

step "2. Look up zone_id for $CF_ZONE"
ZONE_JSON=$(curl -sS -H "$H_AUTH" "$API/zones?name=$CF_ZONE")
ZONE_ID=$(echo "$ZONE_JSON" | python3 -c 'import sys, json; print(json.load(sys.stdin)["result"][0]["id"])')
ok "zone_id: $ZONE_ID"

step "3. Merge tunnel ingress config (preserve tenant rules)"
# Read the current live config, then merge: refresh the script-owned platform
# hostnames and PRESERVE all other (tenant) rules. This is critical — the
# auth-manager backend (CloudflareTunnelService) adds per-tenant apex-domain
# ingress rules at runtime; a blind overwrite here would wipe them.
CUR_CFG=$(curl -sS -H "$H_AUTH" \
  "$API/accounts/$CF_ACCOUNT_ID/cfd_tunnel/$CF_TUNNEL_ID/configurations")

INGRESS_RULES=$(echo "$CUR_CFG" | PROD_EDGE_SVC="$PROD_EDGE_SVC" DEV_EDGE_SVC="$DEV_EDGE_SVC" python3 -c '
import sys, json, os

prod = os.environ["PROD_EDGE_SVC"]
dev  = os.environ["DEV_EDGE_SVC"]

d = json.load(sys.stdin)
if not d.get("success"):
    print("  failed to read current config:", d.get("errors"), file=sys.stderr)
    sys.exit(1)

current = d.get("result", {}).get("config", {}).get("ingress", [])

# Hostnames this script owns (refreshed/overwritten by us).
owned = {"auth.mcp-mesh.io", "auth-dev.mcp-mesh.io", "*.mcp-mesh.io"}

# Preserve every rule whose hostname is not script-owned and that is not the
# hostname-less catch-all. Keep service + any other fields (originRequest, ...)
# verbatim.
preserved = [
    r for r in current
    if r.get("hostname") and r.get("hostname") not in owned
]

merged = (
    [
        {"hostname": "auth.mcp-mesh.io", "service": prod},
        {"hostname": "auth-dev.mcp-mesh.io", "service": dev},
    ]
    + preserved
    + [
        {"hostname": "*.mcp-mesh.io", "service": prod},
        {"service": "http_status:404"},
    ]
)

print(json.dumps({"config": {"ingress": merged}}))
')

RESP=$(curl -sS -X PUT -H "$H_AUTH" -H "$H_JSON" \
  "$API/accounts/$CF_ACCOUNT_ID/cfd_tunnel/$CF_TUNNEL_ID/configurations" \
  -d "$INGRESS_RULES")
echo "$RESP" | python3 -c '
import sys, json
d = json.load(sys.stdin)
if not d.get("success"):
    print("  failed:", d.get("errors"))
    sys.exit(1)
print("  ingress rules applied")
for r in d.get("result", {}).get("config", {}).get("ingress", []):
    h = r.get("hostname") or "(catch-all)"
    print("    ", h, "->", r.get("service"))
'

step "4. Ensure DNS CNAMEs exist"
CNAME_TARGET="$CF_TUNNEL_ID.cfargotunnel.com"
for name in "${DNS_HOSTNAMES[@]}"; do
  # Check if record already exists
  EXISTING=$(curl -sS -H "$H_AUTH" "$API/zones/$ZONE_ID/dns_records?type=CNAME&name=$name.$CF_ZONE" \
    | python3 -c 'import sys, json; r = json.load(sys.stdin).get("result", []); print(r[0]["id"] if r else "")')

  if [ -n "$EXISTING" ]; then
    # Update existing
    curl -sS -X PUT -H "$H_AUTH" -H "$H_JSON" \
      "$API/zones/$ZONE_ID/dns_records/$EXISTING" \
      -d "{\"type\":\"CNAME\",\"name\":\"$name\",\"content\":\"$CNAME_TARGET\",\"proxied\":true,\"ttl\":1,\"comment\":\"auth-platform tunnel route\"}" \
      > /dev/null
    ok "$name.$CF_ZONE → $CNAME_TARGET (updated)"
  else
    # Create
    curl -sS -X POST -H "$H_AUTH" -H "$H_JSON" \
      "$API/zones/$ZONE_ID/dns_records" \
      -d "{\"type\":\"CNAME\",\"name\":\"$name\",\"content\":\"$CNAME_TARGET\",\"proxied\":true,\"ttl\":1,\"comment\":\"auth-platform tunnel route\"}" \
      > /dev/null
    ok "$name.$CF_ZONE → $CNAME_TARGET (created)"
  fi
done

step "5. Delete stale DNS CNAMEs"
for name in "${DNS_HOSTNAMES_TO_REMOVE[@]}"; do
  EXISTING=$(curl -sS -H "$H_AUTH" "$API/zones/$ZONE_ID/dns_records?type=CNAME&name=$name.$CF_ZONE" \
    | python3 -c 'import sys, json; r = json.load(sys.stdin).get("result", []); print(r[0]["id"] if r else "")')

  if [ -n "$EXISTING" ]; then
    curl -sS -X DELETE -H "$H_AUTH" \
      "$API/zones/$ZONE_ID/dns_records/$EXISTING" \
      > /dev/null
    ok "$name.$CF_ZONE (deleted)"
  else
    ok "$name.$CF_ZONE (already absent)"
  fi
done

step "Done"
echo "  Try:  curl -sS https://auth.$CF_ZONE/actuator/health"
echo "        curl -sS https://auth.$CF_ZONE/auth/realms/master/.well-known/openid-configuration"
echo "        curl -sS https://auth.$CF_ZONE/auth/admin/master/console/   # IP-restricted on /auth/admin/*"
