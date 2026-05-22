from mcpmesh_auth_lib import AuthLibSettings


def test_audiences_default_to_client_id():
    s = AuthLibSettings(issuer_uri="http://kc/realms/t", client_id="orders")
    assert s.effective_audiences == ["orders"]


def test_audiences_comma_separated_env(monkeypatch):
    monkeypatch.setenv("AUTH_LIB_ISSUER_URI", "http://kc/realms/t")
    monkeypatch.setenv("AUTH_LIB_CLIENT_ID", "orders")
    monkeypatch.setenv("AUTH_LIB_AUDIENCES", "orders, invoices, shipments")
    s = AuthLibSettings()
    assert s.effective_audiences == ["orders", "invoices", "shipments"]


def test_jwks_and_token_urls():
    s = AuthLibSettings(issuer_uri="http://kc/realms/t/", client_id="orders")
    assert s.jwks_uri == "http://kc/realms/t/protocol/openid-connect/certs"
    assert s.token_endpoint == "http://kc/realms/t/protocol/openid-connect/token"


def test_defaults():
    s = AuthLibSettings(issuer_uri="http://kc/realms/t", client_id="orders")
    assert s.jwks_cache_ttl_seconds == 3600
    assert s.permission_cache_ttl_seconds == 60
    assert s.redis_url is None
