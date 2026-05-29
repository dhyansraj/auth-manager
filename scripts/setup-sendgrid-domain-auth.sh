#!/usr/bin/env bash
# One-shot SendGrid domain authentication for mcp-mesh.io.
#
# What it does:
#   1. Fetches the SendGrid API key from the auth-platform sendgrid-api Secret.
#   2. Fetches CF API token from the auth-platform cloudflare-api Secret.
#   3. Calls SendGrid POST /v3/whitelabel/domains to register mcp-mesh.io for
#      sender authentication. SendGrid returns 3 CNAMEs (mail_cname + 2 DKIM).
#   4. For each CNAME, calls CF POST /zones/{zone}/dns_records with
#      proxied=false (CF proxying breaks DKIM lookups — must be DNS-only).
#   5. Calls SendGrid POST /v3/whitelabel/domains/{id}/validate to verify
#      that SendGrid can resolve the records and confirm domain ownership.
#
# Idempotent: skips creation when SendGrid already has the domain registered;
# skips CF records that already exist. Re-running just re-validates.
#
# Run from anywhere (script ssh's to beelink1 + kubectl exec for secrets):
#   bash scripts/setup-sendgrid-domain-auth.sh
#
# Or directly on beelink1:
#   bash ~/workspace/github/auth-manager/scripts/setup-sendgrid-domain-auth.sh

set -euo pipefail

DOMAIN="${DOMAIN:-mcp-mesh.io}"
CF_ZONE_ID="${CF_ZONE_ID:-2d42b23a17e9d4e0b200742acb76864d}"
NS="${NS:-auth-platform}"

# --- helpers ---------------------------------------------------------------

bold()  { printf "\033[1m%s\033[0m\n" "$*"; }
ok()    { printf "  \033[32m✓\033[0m %s\n" "$*"; }
err()   { printf "  \033[31m✗\033[0m %s\n" "$*" >&2; }
step()  { echo; bold "── $* ──"; }

# Fetch a Secret key, base64-decoded. Works both on-cluster and via ssh.
secret_value() {
  local secret=$1 key=$2
  if command -v kubectl >/dev/null && kubectl auth can-i get secret/"$secret" -n "$NS" >/dev/null 2>&1; then
    kubectl get secret "$secret" -n "$NS" -o jsonpath="{.data.$key}" | base64 -d
  else
    ssh beelink1 "kubectl get secret $secret -n $NS -o jsonpath='{.data.$key}' | base64 -d"
  fi
}

require_tool() {
  command -v "$1" >/dev/null || { err "Missing required tool: $1"; exit 2; }
}

# --- pre-flight ------------------------------------------------------------

step "1. Pre-flight"

require_tool curl
require_tool jq
ok "tools present"

SENDGRID_KEY=$(secret_value sendgrid-api api-key)
if [[ -z "$SENDGRID_KEY" ]]; then
  err "sendgrid-api Secret not found or empty in namespace $NS"
  err "Create it first:"
  err "  ssh beelink1 'read -s -p \"Key: \" KEY && kubectl create secret generic sendgrid-api -n $NS --from-literal=api-key=\"\$KEY\" --dry-run=client -o yaml | kubectl apply -f -'"
  exit 1
fi
ok "sendgrid-api Secret loaded"

CF_TOKEN=$(secret_value cloudflare-api api-token)
if [[ -z "$CF_TOKEN" ]]; then
  err "cloudflare-api Secret missing api-token key"
  exit 1
fi
ok "cloudflare-api Secret loaded"

SG_BASE="https://api.sendgrid.com/v3"
CF_BASE="https://api.cloudflare.com/client/v4"
SG_AUTH=(-H "Authorization: Bearer $SENDGRID_KEY")
CF_AUTH=(-H "Authorization: Bearer $CF_TOKEN")

# --- step 2: ensure domain registered in SendGrid -------------------------

step "2. Register domain in SendGrid (or load existing)"

# Check if already registered
existing=$(curl -sf "${SG_AUTH[@]}" "$SG_BASE/whitelabel/domains?domain=$DOMAIN" | jq -e ".[] | select(.domain==\"$DOMAIN\")" 2>/dev/null || true)

if [[ -n "$existing" ]]; then
  domain_id=$(echo "$existing" | jq -r .id)
  ok "Already registered in SendGrid (id=$domain_id)"
  dns_json=$(echo "$existing" | jq .dns)
else
  body=$(jq -nc --arg d "$DOMAIN" '{domain: $d, automatic_security: true, default: false}')
  resp=$(curl -sf "${SG_AUTH[@]}" -H "Content-Type: application/json" -X POST "$SG_BASE/whitelabel/domains" -d "$body")
  domain_id=$(echo "$resp" | jq -r .id)
  dns_json=$(echo "$resp" | jq .dns)
  ok "Registered (id=$domain_id)"
fi

# --- step 3: push CNAMEs to Cloudflare ------------------------------------

step "3. Push DKIM CNAMEs to Cloudflare (proxied=false)"

# dns_json shape: { "mail_cname": {host, data, ...}, "dkim1": {...}, "dkim2": {...} }
# Iterate every key.
echo "$dns_json" | jq -r 'to_entries[] | "\(.key)|\(.value.host)|\(.value.data)"' | \
while IFS='|' read -r kind host data; do
  [[ -z "$host" || -z "$data" ]] && continue

  # Check if record already exists
  existing_id=$(curl -sf "${CF_AUTH[@]}" \
    "$CF_BASE/zones/$CF_ZONE_ID/dns_records?type=CNAME&name=$host" \
    | jq -r '.result[0].id // empty')

  payload=$(jq -nc --arg t "$host" --arg c "$data" \
    '{type: "CNAME", name: $t, content: $c, ttl: 1, proxied: false, comment: "SendGrid domain auth (DKIM/return-path)"}')

  if [[ -n "$existing_id" ]]; then
    # Update in place so re-runs are safe if SendGrid changes anything
    curl -sf "${CF_AUTH[@]}" -H "Content-Type: application/json" -X PUT \
      "$CF_BASE/zones/$CF_ZONE_ID/dns_records/$existing_id" -d "$payload" >/dev/null
    ok "$kind: $host → $data (updated)"
  else
    curl -sf "${CF_AUTH[@]}" -H "Content-Type: application/json" -X POST \
      "$CF_BASE/zones/$CF_ZONE_ID/dns_records" -d "$payload" >/dev/null
    ok "$kind: $host → $data (created)"
  fi
done

# --- step 4: trigger SendGrid validation ----------------------------------

step "4. Trigger SendGrid validation"

# CF DNS propagation through SendGrid's resolver can lag by ~30s after a
# fresh insert. One soft retry covers the common case.
for attempt in 1 2; do
  vresp=$(curl -sf "${SG_AUTH[@]}" -X POST "$SG_BASE/whitelabel/domains/$domain_id/validate")
  valid=$(echo "$vresp" | jq -r .valid)
  if [[ "$valid" == "true" ]]; then
    ok "Domain authenticated ✓"
    exit 0
  fi
  if [[ $attempt -lt 2 ]]; then
    echo "  validation pending; sleeping 30s for DNS propagation"
    sleep 30
  fi
done

err "Validation failed. Per-record state:"
echo "$vresp" | jq '.validation_results' >&2
err "Re-run this script in a few minutes (CF DNS sometimes takes longer to propagate)."
exit 3
