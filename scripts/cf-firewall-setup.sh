#!/usr/bin/env bash
# Idempotently install a Cloudflare WAF Custom Rule on the zone that BLOCKS
# any request to kc.mcp-mesh.io originating outside the whitelisted IP set.
#
# The Keycloak admin console (kc.mcp-mesh.io) bypasses platform-edge so we
# can't gate it at the edge with Lua. Instead we gate at Cloudflare's WAF
# using a custom expression — cheaper, faster, and runs before traffic enters
# the tunnel.
#
# Requires:
#   CF_API_TOKEN     — Cloudflare API token with:
#                        Zone · Firewall Services · Edit  (for the zone)
#   CF_ZONE          — zone name, e.g. mcp-mesh.io
#   CF_KC_ALLOW_IPS  — comma-separated CIDRs/IPs allowed to reach
#                      kc.mcp-mesh.io. Default: 67.197.78.211 (home).
#
# This script uses the Rulesets API (modern). For the per-zone custom-rules
# phase the entrypoint ruleset is at:
#   /zones/{zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint
#
# It does an upsert by rule description: if a rule with
# description="block-kc-from-non-whitelisted" already exists, its expression
# is replaced; otherwise the rule is appended. Other rules on the zone are
# preserved.

set -euo pipefail

: "${CF_API_TOKEN:?env var CF_API_TOKEN is required}"
: "${CF_ZONE:?env var CF_ZONE is required}"

CF_KC_ALLOW_IPS="${CF_KC_ALLOW_IPS:-67.197.78.211}"
RULE_DESC="block-kc-from-non-whitelisted"
RULE_HOST="${CF_KC_RULE_HOST:-kc.mcp-mesh.io}"

API="https://api.cloudflare.com/client/v4"
H_AUTH="Authorization: Bearer $CF_API_TOKEN"
H_JSON="Content-Type: application/json"

bold()  { printf "\033[1m%s\033[0m\n" "$*"; }
ok()    { printf "  \033[32m✓\033[0m %s\n" "$*"; }
step()  { echo; bold "── $* ──"; }

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

# Build the firewall expression. Format the whitelist as a CF IP-set literal:
# {ip1 ip2 ...}.  Comma-separated input → space-separated tokens.
IP_SET=$(echo "$CF_KC_ALLOW_IPS" | tr ',' ' ' | xargs)
EXPRESSION="(http.host eq \"$RULE_HOST\" and not ip.src in {$IP_SET})"
ok "expression: $EXPRESSION"

ENTRYPOINT_URL="$API/zones/$ZONE_ID/rulesets/phases/http_request_firewall_custom/entrypoint"

step "3. Read existing custom-rules ruleset (may be empty)"
EXISTING=$(curl -sS -H "$H_AUTH" "$ENTRYPOINT_URL")
EXISTING_SUCCESS=$(echo "$EXISTING" | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
    print("yes" if d.get("success") else "no")
except Exception:
    print("no")
')
if [ "$EXISTING_SUCCESS" != "yes" ]; then
    # No entrypoint ruleset yet on this zone — treat as empty.
    ok "no existing custom-rules ruleset on zone (will create one)"
    EXISTING_RULES="[]"
else
    EXISTING_RULES=$(echo "$EXISTING" | python3 -c '
import sys, json
d = json.load(sys.stdin)
rules = d.get("result", {}).get("rules") or []
# Strip server-managed fields so we can PUT them back cleanly.
clean = []
for r in rules:
    clean.append({
        "action":      r.get("action"),
        "expression":  r.get("expression"),
        "description": r.get("description"),
        "enabled":     r.get("enabled", True),
    })
print(json.dumps(clean))
')
    ok "found $(echo "$EXISTING_RULES" | python3 -c 'import sys,json; print(len(json.load(sys.stdin)))') existing rule(s)"
fi

step "4. Upsert rule '$RULE_DESC'"
NEW_RULES=$(python3 -c "
import json
existing = json.loads('''$EXISTING_RULES''')
target = {
    'action':      'block',
    'expression':  '''$EXPRESSION''',
    'description': '$RULE_DESC',
    'enabled':     True,
}
out = []
replaced = False
for r in existing:
    if r.get('description') == '$RULE_DESC':
        out.append(target)
        replaced = True
    else:
        out.append(r)
if not replaced:
    out.append(target)
print(json.dumps({'rules': out}))
")

RESP=$(curl -sS -X PUT -H "$H_AUTH" -H "$H_JSON" \
  "$ENTRYPOINT_URL" \
  -d "$NEW_RULES")

echo "$RESP" | python3 -c "
import sys, json
d = json.load(sys.stdin)
if not d.get('success'):
    print('  failed:', d.get('errors'))
    sys.exit(1)
rules = d.get('result', {}).get('rules', [])
print(f'  ruleset applied ({len(rules)} rule(s) total)')
for r in rules:
    desc = r.get('description', '(no desc)')
    act  = r.get('action', '?')
    expr = r.get('expression', '')
    print(f'    [{act}] {desc}')
    print(f'           {expr}')
"

step "Done"
echo "  Test from a non-whitelisted IP:"
echo "    curl -i https://$RULE_HOST/admin/master/console/"
echo "  Expected: HTTP 403 (Cloudflare block page)"
echo
echo "  Test from a whitelisted IP ($IP_SET):"
echo "    curl -i https://$RULE_HOST/admin/master/console/"
echo "  Expected: HTTP 200 (KC admin console)"
