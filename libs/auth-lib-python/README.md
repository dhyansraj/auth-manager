# mcpmesh-auth-lib

FastAPI client library for the mcp-mesh auth platform. Python equivalent of
`libs/auth-lib/` (the Spring Boot / Java auth-lib v2). Validates Keycloak-issued
JWTs, aggregates UMA permissions across one-or-more resource-server audiences,
and ships a Pydantic `MeResponse` model that matches the Java DTO byte-for-byte.

## Install

```bash
# from a sibling repo / monorepo path
pip install -e /path/to/auth-manager/libs/auth-lib-python

# or via git URL (private use)
pip install "mcpmesh-auth-lib @ git+https://github.com/your-org/auth-manager@main#subdirectory=libs/auth-lib-python"
```

Requires Python 3.11+.

## Environment variables

| Var                                    | Required | Default | Notes                                                              |
| -------------------------------------- | -------- | ------- | ------------------------------------------------------------------ |
| `AUTH_LIB_ISSUER_URI`                  | yes      |         | e.g. `https://auth.mcp-mesh.io/auth/realms/t-app1`                |
| `AUTH_LIB_CLIENT_ID`                   | yes      |         | This app's OIDC client_id; used as default audience               |
| `AUTH_LIB_CLIENT_SECRET`               | no       | `None`  | Confidential client secret (only used by callers that need extra KC calls; not used for UMA itself) |
| `AUTH_LIB_AUDIENCES`                   | no       | `[client_id]` | Comma-separated list. Extra resource servers to aggregate UMA permissions across. |
| `AUTH_LIB_JWKS_CACHE_TTL_SECONDS`      | no       | `3600`  | How long PyJWKClient caches JWKS keys                              |
| `AUTH_LIB_PERMISSION_CACHE_TTL_SECONDS`| no       | `60`    | UMA permission cache TTL                                           |
| `AUTH_LIB_REDIS_URL`                   | no       | `None`  | e.g. `redis://redis:6379/0`. If set, permissions cache uses Redis. |
| `AUTH_LIB_HTTP_TIMEOUT_SECONDS`        | no       | `5.0`   | HTTP timeout for JWKS + UMA calls.                                 |
| `AUTH_LIB_PERMISSIONS_SOURCE`          | no       | `claims`| `claims` reads perms from JWT `resource_access.<client>.roles`; `uma` calls KC's UMA endpoint. See below. |

### `AUTH_LIB_PERMISSIONS_SOURCE`

Controls where atomic permissions come from when `Permissions.all_for(token, claims)`
is called.

- **`claims` (default)** — reads from the JWT's `resource_access.<client>.roles`
  claim for each configured audience (`AUTH_LIB_AUDIENCES`, falling back to
  `AUTH_LIB_CLIENT_ID`). This is the auth-manager pattern: atomic permissions
  are KC client roles on the backend client, composite realm roles bundle them,
  and KC's role expansion flattens them into the token at mint time. No
  round-trip to KC is needed — the perms are already in the token. Typical
  when you've onboarded the tenant with `manifest:apply` and have a permission
  catalog defined.
- **`uma`** — calls Keycloak's UMA ticket-grant endpoint (the original
  `Permissions` behavior). Only needed for legacy tenants that still have KC
  Authorization Services (resources/scopes/policies/permissions) configured
  on their backend client. UMA is being phased out across the platform; a
  matching Java auth-lib migration is on the backlog.

The selection is wired up by `auth_lib_init(app)`. Pass an explicit
`permissions=` instance to override (e.g., a custom subclass).


## Quickstart

```python
from fastapi import Depends, FastAPI
from mcpmesh_auth_lib import (
    Tenant, auth_lib_init, build_me_response,
    current_user, require_permission,
)

app = FastAPI()
auth_lib_init(app)  # reads AUTH_LIB_* env vars

TENANT = Tenant(id="t-1", slug="app1", display_name="App One", realm_name="t-app1")


@app.get("/api/me")
def me(claims: dict = Depends(current_user)):
    return build_me_response(
        claims,
        app.state.auth_lib_permissions,
        TENANT,
        raw_token=claims["_raw_token"],
    ).model_dump(by_alias=True)


@app.get("/api/orders", dependencies=[Depends(require_permission("ORDER_VIEW"))])
def orders():
    return [{"id": 1, "item": "Widget", "qty": 3}]
```

A working version of this is in `examples/fastapi_minimal/`.

## API surface

```python
from mcpmesh_auth_lib import (
    AuthLibSettings,        # pydantic-settings: reads AUTH_LIB_* env vars
    auth_lib_init,          # one-call setup: auth_lib_init(app)

    current_user,           # Depends(): claims dict (raises 401 on bad/missing token)
    optional_user,          # Depends(): claims | None
    require_permission,     # Depends-factory: require_permission("ORDER_VIEW")
    require_any_permission, # Depends-factory: require_any_permission("ORDER_VIEW", "ORDER_APPROVE")
    require_role,           # Depends-factory: require_role("tenant-admin", client="usermanagement")

    Permissions,            # service: UMA-based .all_for(token, claims) -> Set[str]
    ClaimRolesPermissions,  # service: claims-based (default); reads resource_access.<client>.roles
    JwtValidator,           # service: .decode_and_verify(token) -> dict
    JwtValidationError,

    MeResponse, User, Tenant,
    build_me_response,
)
```

## Permission strings

UMA responses (`response_mode=permissions`) come back as
`[{rsname, scopes: [...]}]`. The lib flattens these to
`<RSNAME>_<SCOPE>` uppercased with `_` separator. So an "order" resource with a
"view" scope is exposed as the permission string `ORDER_VIEW`. This matches the
React `auth-lib-react` `usePermission("ORDER_VIEW")` hook and the Java side's
`Permissions.all_for(jwt)` set semantics.

(The Java side ALSO publishes `PERMISSION_ORDER_VIEW`-prefixed Spring authorities
for `@PreAuthorize("hasAuthority('PERMISSION_ORDER_VIEW')")` style checks. The
Python `require_permission(...)` factory uses the same un-prefixed strings as
`Permissions.all_for` for ergonomics — no `PERMISSION_` prefix needed.)

## /me payload shape

```json
{
  "user": {
    "id": "uuid",
    "email": "alice@app1.test",
    "preferredUsername": "alice@app1.test",
    "name": "Alice Tester"
  },
  "context": "tenant",
  "tenant": {
    "id": "t-1",
    "slug": "app1",
    "displayName": "App One",
    "realmName": "t-app1"
  },
  "isPlatformAdmin": false,
  "isTenantAdmin": false,
  "permissions": ["ORDER_VIEW", "ORDER_APPROVE"]
}
```

This is the same JSON the Java `app1-backend` returns — `auth-lib-react` can
decode either source with one helper.

## Differences vs. Java auth-lib v2

- **Single-realm.** Just like the Java side: one `AuthLibSettings` per app.
- **Multi-audience UMA aggregation.** Set `AUTH_LIB_AUDIENCES=orders,invoices`
  to pull UMA permissions from multiple resource servers in one /me response.
- **Permission decorator names.** The Python `require_permission("ORDER_VIEW")`
  uses the un-prefixed permission string. The Java side has both
  `Permissions#has(jwt, "ORDER_VIEW")` (un-prefixed) AND
  `@PreAuthorize("hasAuthority('PERMISSION_ORDER_VIEW')")` (prefixed). Python
  only ships the un-prefixed flavor — there's no Spring `GrantedAuthority`
  equivalent to mirror in FastAPI.
- **Sync only.** v1 uses `httpx.Client` + `redis-py` (sync). Async callers can
  wrap `Permissions.all_for` in `run_in_executor` if needed; an async variant
  may land in a later release.
- **No Spring autoconfig.** Call `auth_lib_init(app)` explicitly in your
  FastAPI app's startup. (Spring Boot magic doesn't have a Python analogue.)

## Testing

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest -v
```

Tests use `respx` to mock both the JWKS and UMA endpoints — no Keycloak needed.

## License

Apache-2.0.
