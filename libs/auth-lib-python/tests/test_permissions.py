import time

import httpx
import pytest
import respx

from mcpmesh_auth_lib import AuthLibSettings, Permissions
from mcpmesh_auth_lib.permissions import _audience_hash, _normalize

from .conftest import ISSUER, TOKEN_URL


@pytest.fixture
def settings_two_aud():
    return AuthLibSettings(
        issuer_uri=ISSUER,
        client_id="orders",
        audiences=["orders", "invoices"],
        permission_cache_ttl_seconds=60,
    )


def _uma_responder(by_aud):
    def _responder(request):
        # form-encoded body
        body = dict(p.split("=", 1) for p in request.content.decode().split("&") if "=" in p)
        # URL-decode the value (httpx encodes ':' etc.)
        from urllib.parse import unquote_plus
        aud = unquote_plus(body.get("audience", ""))
        if aud in by_aud:
            return httpx.Response(200, json=by_aud[aud])
        return httpx.Response(403, json={"error": "access_denied"})

    return _responder


def test_normalize_uppercases_and_underscores():
    assert _normalize("order_view") == "ORDER_VIEW"
    assert _normalize("user mgmt_admin all") == "USER_MGMT_ADMIN_ALL"
    assert _normalize("a-b-c") == "A_B_C"


def test_audience_hash_is_order_independent():
    assert _audience_hash(["a", "b"]) == _audience_hash(["b", "a"])
    assert _audience_hash(["a", "b"]) != _audience_hash(["a", "c"])


@respx.mock
def test_all_for_aggregates_and_normalizes(settings_two_aud):
    respx.post(TOKEN_URL).mock(side_effect=_uma_responder({
        "orders": [
            {"rsname": "order", "scopes": ["view", "approve"]},
            {"rsname": "shipment", "scopes": ["view"]},
        ],
        "invoices": [
            {"rsname": "invoice", "scopes": ["view", "pay"]},
        ],
    }))
    perms = Permissions(settings_two_aud)
    result = perms.all_for("fake-token", {"sub": "alice"})
    assert result == {"ORDER_VIEW", "ORDER_APPROVE", "SHIPMENT_VIEW", "INVOICE_VIEW", "INVOICE_PAY"}
    assert perms.has("fake-token", {"sub": "alice"}, "ORDER_VIEW") is True
    assert perms.has("fake-token", {"sub": "alice"}, "ORDER_DELETE") is False


@respx.mock
def test_all_for_skips_failing_audience(settings_two_aud):
    respx.post(TOKEN_URL).mock(side_effect=_uma_responder({
        "orders": [{"rsname": "order", "scopes": ["view"]}],
        # invoices -> 403 (default branch in responder)
    }))
    perms = Permissions(settings_two_aud)
    result = perms.all_for("fake-token", {"sub": "alice"})
    assert result == {"ORDER_VIEW"}


@respx.mock
def test_all_for_returns_empty_when_all_audiences_fail(settings_two_aud):
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(403, json={"error": "access_denied"}))
    perms = Permissions(settings_two_aud)
    assert perms.all_for("fake-token", {"sub": "alice"}) == set()


@respx.mock
def test_all_for_caches(settings_two_aud):
    route = respx.post(TOKEN_URL).mock(side_effect=_uma_responder({
        "orders": [{"rsname": "order", "scopes": ["view"]}],
        "invoices": [{"rsname": "invoice", "scopes": ["view"]}],
    }))
    perms = Permissions(settings_two_aud)
    first = perms.all_for("tok", {"sub": "alice"})
    second = perms.all_for("tok", {"sub": "alice"})
    assert first == second
    # one POST per audience, only on the first call -> 2 calls total
    assert route.call_count == 2


@respx.mock
def test_audience_order_does_not_affect_cache_key(settings_two_aud):
    route = respx.post(TOKEN_URL).mock(side_effect=_uma_responder({
        "orders": [{"rsname": "order", "scopes": ["view"]}],
        "invoices": [{"rsname": "invoice", "scopes": ["view"]}],
    }))
    perms_a = Permissions(settings_two_aud)
    perms_a.all_for("tok", {"sub": "alice"})

    s2 = AuthLibSettings(
        issuer_uri=ISSUER, client_id="orders",
        audiences=["invoices", "orders"],
        permission_cache_ttl_seconds=60,
    )
    perms_b = Permissions(s2, cache=perms_a._cache)  # share cache
    perms_b.all_for("tok", {"sub": "alice"})
    # second instance should not have re-fetched
    assert route.call_count == 2


@respx.mock
def test_empty_token_returns_empty_set(settings_two_aud):
    perms = Permissions(settings_two_aud)
    assert perms.all_for("", {"sub": "x"}) == set()


@respx.mock
def test_cache_expires_after_ttl():
    s = AuthLibSettings(
        issuer_uri=ISSUER,
        client_id="orders",
        audiences=["orders"],
        permission_cache_ttl_seconds=1,
    )
    route = respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(200, json=[{"rsname": "order", "scopes": ["view"]}])
    )
    perms = Permissions(s)
    perms.all_for("tok", {"sub": "alice"})
    assert route.call_count == 1
    # TTL is 1s, sleep just over.
    time.sleep(1.2)
    perms.all_for("tok", {"sub": "alice"})
    assert route.call_count == 2


@respx.mock
def test_uma_request_shape(settings_two_aud):
    captured = {}

    def _cap(request):
        captured["url"] = str(request.url)
        captured["auth"] = request.headers.get("Authorization")
        body = dict(p.split("=", 1) for p in request.content.decode().split("&") if "=" in p)
        captured.setdefault("bodies", []).append(body)
        return httpx.Response(200, json=[])

    respx.post(TOKEN_URL).mock(side_effect=_cap)
    perms = Permissions(settings_two_aud)
    perms.all_for("the-bearer", {"sub": "alice"})
    assert captured["url"] == TOKEN_URL
    assert captured["auth"] == "Bearer the-bearer"
    grant_types = {b["grant_type"] for b in captured["bodies"]}
    assert grant_types == {"urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Auma-ticket"}
    response_modes = {b["response_mode"] for b in captured["bodies"]}
    assert response_modes == {"permissions"}
