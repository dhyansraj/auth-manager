"""Minimal FastAPI app demonstrating mcpmesh-auth-lib.

Reads ``AUTH_LIB_*`` env vars and exposes:

  * ``GET /api/me``       — JWT-protected; returns the standard MeResponse shape.
  * ``GET /api/orders``   — protected by ``ORDER_VIEW`` UMA permission.
  * ``GET /api/whoami``   — open; returns the optional decoded JWT (or null).

Run with::

    AUTH_LIB_ISSUER_URI=https://auth.mcp-mesh.io/auth/realms/t-app1 \
    AUTH_LIB_CLIENT_ID=orders \
    AUTH_LIB_CLIENT_SECRET=... \
    uvicorn main:app --port 9090
"""

from __future__ import annotations

from fastapi import Depends, FastAPI

from mcpmesh_auth_lib import (
    Tenant,
    auth_lib_init,
    build_me_response,
    current_user,
    optional_user,
    require_permission,
)

app = FastAPI(title="auth-lib-python example")
auth_lib_init(app)


# Tenant identity is configuration, not derived from the JWT (matches
# app1-backend's MeController pattern).
TENANT = Tenant(
    id="",
    slug="app1",
    display_name="App One",
    realm_name="t-app1",
)


@app.get("/api/me")
def me(claims: dict = Depends(current_user)):
    return build_me_response(
        claims,
        app.state.auth_lib_permissions,
        TENANT,
        raw_token=claims["_raw_token"],
    ).model_dump(by_alias=True)


@app.get("/api/orders", dependencies=[Depends(require_permission("ORDER_VIEW"))])
def list_orders():
    return [
        {"id": 1, "item": "Widget", "qty": 3},
        {"id": 2, "item": "Gizmo", "qty": 1},
        {"id": 3, "item": "Sprocket", "qty": 5},
    ]


@app.get("/api/whoami")
def whoami(claims: dict | None = Depends(optional_user)):
    if claims is None:
        return {"authenticated": False}
    return {
        "authenticated": True,
        "sub": claims.get("sub"),
        "preferred_username": claims.get("preferred_username"),
    }
