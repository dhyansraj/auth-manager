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
# Edit this block to add new public hostnames.
# Service URLs use Kubernetes DNS: <svc>.<namespace>.svc.cluster.local
#
# Hostname routing notes:
#   - auth.mcp-mesh.io  → platform-edge (admin UI + auth-manager + KC under /auth)
#   - kc.mcp-mesh.io    → platform-edge (KC admin host; edge router has a
#                         dedicated branch keyed on Host that strips /auth from
#                         /auth/* paths — KC mounts at root, so /admin/* and
#                         /resources/* pass through unchanged. IP-restricted
#                         via Cloudflare WAF custom rule (fires at CF edge
#                         regardless of where the tunnel lands).
#                         Listed BEFORE the wildcard so the specific match wins.
#   - *.mcp-mesh.io     → platform-edge (catch-all for tenant subdomains:
#                         app1.mcp-mesh.io, customer.mcp-mesh.io, etc.).
#                         Order matters in CF tunnel ingress; this MUST come
#                         after the more specific entries above.
INGRESS_RULES=$(cat <<'JSON'
{
  "config": {
    "ingress": [
      {
        "hostname": "auth.mcp-mesh.io",
        "service": "http://auth-platform-platform-edge.auth-platform.svc.cluster.local:80"
      },
      {
        "hostname": "kc.mcp-mesh.io",
        "service": "http://auth-platform-platform-edge.auth-platform.svc.cluster.local:80"
      },
      {
        "hostname": "*.mcp-mesh.io",
        "service": "http://auth-platform-platform-edge.auth-platform.svc.cluster.local:80"
      },
      {
        "service": "http_status:404"
      }
    ]
  }
}
JSON
)

# Hostnames to ensure as DNS CNAMEs.
# The *.mcp-mesh.io wildcard ingress is matched by the tunnel based on the
# Host header; we still need per-subdomain CNAMEs at the DNS layer for each
# hostname that should resolve. "auth" and "kc" are the platform-owned ones.
# Tenant subdomains (app1, etc.) will be added as we onboard tenants.
DNS_HOSTNAMES=(auth kc)

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

step "3. PUT tunnel ingress config"
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

step "Done"
echo "  Try:  curl -sS https://auth.$CF_ZONE/actuator/health"
echo "        curl -sS https://auth.$CF_ZONE/auth/realms/master/.well-known/openid-configuration"
echo "        curl -sS https://kc.$CF_ZONE/admin/master/console/   # IP-restricted"
