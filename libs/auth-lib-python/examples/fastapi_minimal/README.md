# fastapi_minimal

Self-contained demo of `mcpmesh-auth-lib` against a live Keycloak realm.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ../..        # install the library from source
pip install -r requirements.txt
```

## Run

```bash
export AUTH_LIB_ISSUER_URI=https://auth.mcp-mesh.io/auth/realms/t-app1
export AUTH_LIB_CLIENT_ID=orders
export AUTH_LIB_CLIENT_SECRET=<grab-from-cluster>
# Optional: aggregate UMA permissions across multiple resource servers.
# export AUTH_LIB_AUDIENCES=orders,invoices

uvicorn main:app --port 9090
```

## Call

Fetch a user access token, then:

```bash
curl -sS http://localhost:9090/api/me      -H "Authorization: Bearer $TOKEN" | jq
curl -sS http://localhost:9090/api/orders  -H "Authorization: Bearer $TOKEN" | jq
curl -sS http://localhost:9090/api/whoami  -H "Authorization: Bearer $TOKEN" | jq
```

`/api/me` returns the same `MeResponse` shape app1-backend's `/api/me` returns —
`{user, context, tenant, isPlatformAdmin, isTenantAdmin, permissions}` — so
the React `auth-lib-react` client decodes both transparently.
