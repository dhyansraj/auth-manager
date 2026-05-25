import httpx
import pytest
import respx
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from mcpmesh_auth_lib import (
    AuthLibSettings,
    ClaimRolesPermissions,
    Permissions,
    Tenant,
    auth_lib_init,
    build_me_response,
    current_user,
    optional_user,
    require_permission,
    require_role,
)

from .conftest import CLIENT_ID, ISSUER, JWKS_URL, TOKEN_URL, make_token


@pytest.fixture
def app(settings, rsa_keypair, respx_mock):
    respx_mock.get(JWKS_URL).mock(
        return_value=httpx.Response(200, json=rsa_keypair["jwks"])
    )
    app = FastAPI()
    auth_lib_init(app, settings)

    @app.get("/api/me")
    def me(claims=Depends(current_user)):
        return build_me_response(
            claims,
            app.state.auth_lib_permissions,
            Tenant(id="t-1", slug="app1", display_name="App One", realm_name="t-app1"),
            raw_token=claims["_raw_token"],
        ).model_dump(by_alias=True)

    @app.get("/api/orders", dependencies=[Depends(require_permission("ORDER_VIEW"))])
    def orders():
        return [{"id": 1}]

    @app.get("/api/admin", dependencies=[Depends(require_role("tenant-admin", client="usermanagement"))])
    def admin_only():
        return {"ok": True}

    @app.get("/api/realm-admin", dependencies=[Depends(require_role("realm-only-role"))])
    def realm_role_endpoint():
        return {"ok": True}

    @app.get("/api/optional")
    def optional(claims=Depends(optional_user)):
        return {"user": claims["sub"] if claims else None}

    return app


def test_current_user_valid_token(app, rsa_keypair):
    token = make_token(rsa_keypair)
    with TestClient(app) as client:
        r = client.get("/api/me", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["user"]["id"] == "alice"
        assert body["user"]["email"] == "alice@app1.test"
        assert body["context"] == "tenant"
        assert body["tenant"]["slug"] == "app1"
        assert body["isTenantAdmin"] is False
        assert body["isPlatformAdmin"] is False


def test_current_user_missing_token(app):
    with TestClient(app) as client:
        r = client.get("/api/me")
        assert r.status_code == 401
        assert r.json()["detail"] == "missing_token"


def test_current_user_invalid_token(app):
    with TestClient(app) as client:
        r = client.get("/api/me", headers={"Authorization": "Bearer not-a-jwt"})
        assert r.status_code == 401


def test_optional_user_no_token_returns_none(app):
    with TestClient(app) as client:
        r = client.get("/api/optional")
        assert r.status_code == 200
        assert r.json() == {"user": None}


def test_optional_user_with_token(app, rsa_keypair):
    token = make_token(rsa_keypair)
    with TestClient(app) as client:
        r = client.get("/api/optional", headers={"Authorization": f"Bearer {token}"})
        assert r.json() == {"user": "alice"}


def test_require_permission_granted(app, rsa_keypair, respx_mock):
    respx_mock.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json=[{"rsname": "order", "scopes": ["view"]}])
    )
    token = make_token(rsa_keypair)
    with TestClient(app) as client:
        r = client.get("/api/orders", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert r.json() == [{"id": 1}]


def test_require_permission_denied(app, rsa_keypair, respx_mock):
    respx_mock.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json=[{"rsname": "shipment", "scopes": ["view"]}])
    )
    token = make_token(rsa_keypair)
    with TestClient(app) as client:
        r = client.get("/api/orders", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403
        assert "missing_permission" in r.json()["detail"]


def test_require_role_client_match(app, rsa_keypair):
    token = make_token(rsa_keypair, extra_claims={
        "resource_access": {"usermanagement": {"roles": ["tenant-admin"]}}
    })
    with TestClient(app) as client:
        r = client.get("/api/admin", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200


def test_require_role_client_missing(app, rsa_keypair):
    token = make_token(rsa_keypair, extra_claims={
        "resource_access": {"usermanagement": {"roles": ["plain-user"]}}
    })
    with TestClient(app) as client:
        r = client.get("/api/admin", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403


def test_require_role_realm_match(app, rsa_keypair):
    token = make_token(rsa_keypair, extra_claims={
        "realm_access": {"roles": ["realm-only-role"]}
    })
    with TestClient(app) as client:
        r = client.get("/api/realm-admin", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# auth_lib_init: permissions-source selection
# ---------------------------------------------------------------------------


def test_auth_lib_init_defaults_to_claims_based_permissions():
    s = AuthLibSettings(issuer_uri=ISSUER, client_id=CLIENT_ID)
    a = FastAPI()
    auth_lib_init(a, s)
    assert isinstance(a.state.auth_lib_permissions, ClaimRolesPermissions)


def test_auth_lib_init_uma_setting_yields_uma_permissions():
    s = AuthLibSettings(
        issuer_uri=ISSUER, client_id=CLIENT_ID, permissions_source="uma",
    )
    a = FastAPI()
    auth_lib_init(a, s)
    assert isinstance(a.state.auth_lib_permissions, Permissions)
    assert not isinstance(a.state.auth_lib_permissions, ClaimRolesPermissions)


def test_auth_lib_init_claims_setting_yields_claims_permissions():
    s = AuthLibSettings(
        issuer_uri=ISSUER, client_id=CLIENT_ID, permissions_source="claims",
    )
    a = FastAPI()
    auth_lib_init(a, s)
    assert isinstance(a.state.auth_lib_permissions, ClaimRolesPermissions)


def test_auth_lib_init_env_default_is_claims(monkeypatch):
    monkeypatch.setenv("AUTH_LIB_ISSUER_URI", ISSUER)
    monkeypatch.setenv("AUTH_LIB_CLIENT_ID", CLIENT_ID)
    monkeypatch.delenv("AUTH_LIB_PERMISSIONS_SOURCE", raising=False)
    a = FastAPI()
    auth_lib_init(a)
    assert isinstance(a.state.auth_lib_permissions, ClaimRolesPermissions)


def test_auth_lib_init_env_uma(monkeypatch):
    monkeypatch.setenv("AUTH_LIB_ISSUER_URI", ISSUER)
    monkeypatch.setenv("AUTH_LIB_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("AUTH_LIB_PERMISSIONS_SOURCE", "uma")
    a = FastAPI()
    auth_lib_init(a)
    assert isinstance(a.state.auth_lib_permissions, Permissions)
    assert not isinstance(a.state.auth_lib_permissions, ClaimRolesPermissions)


def test_auth_lib_init_explicit_permissions_overrides_env(monkeypatch):
    monkeypatch.setenv("AUTH_LIB_ISSUER_URI", ISSUER)
    monkeypatch.setenv("AUTH_LIB_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("AUTH_LIB_PERMISSIONS_SOURCE", "claims")
    s = AuthLibSettings()  # picks up env
    explicit = Permissions(s)  # caller forces UMA despite claims default
    a = FastAPI()
    auth_lib_init(a, s, permissions=explicit)
    assert a.state.auth_lib_permissions is explicit


def test_me_includes_permissions(app, rsa_keypair, respx_mock):
    # Both audiences resolve; admin role on usermanagement -> isTenantAdmin=true.
    def _uma(request):
        from urllib.parse import unquote_plus
        body = dict(p.split("=", 1) for p in request.content.decode().split("&") if "=" in p)
        aud = unquote_plus(body.get("audience", ""))
        if aud == "orders":
            return httpx.Response(200, json=[{"rsname": "order", "scopes": ["view", "approve"]}])
        if aud == "invoices":
            return httpx.Response(200, json=[{"rsname": "invoice", "scopes": ["pay"]}])
        return httpx.Response(403, json={})

    respx_mock.post(TOKEN_URL).mock(side_effect=_uma)
    token = make_token(rsa_keypair, extra_claims={
        "resource_access": {"usermanagement": {"roles": ["tenant-admin"]}}
    })
    with TestClient(app) as client:
        r = client.get("/api/me", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200, r.text
        body = r.json()
        assert set(body["permissions"]) == {"ORDER_VIEW", "ORDER_APPROVE", "INVOICE_PAY"}
        assert body["isTenantAdmin"] is True
        assert body["tenant"] == {
            "id": "t-1", "slug": "app1",
            "displayName": "App One", "realmName": "t-app1",
        }
