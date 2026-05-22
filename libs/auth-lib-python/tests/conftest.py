"""Shared test fixtures.

We build an in-test RSA keypair and serve it as a JWKS so the JwtValidator's
PyJWKClient can fetch real keys. UMA endpoint is also mocked via respx.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, Iterable, Optional

import httpx
import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.utils import base64url_encode

from mcpmesh_auth_lib import AuthLibSettings, JwtValidator, Permissions

ISSUER = "http://kc.test/realms/t-app1"
JWKS_URL = f"{ISSUER}/protocol/openid-connect/certs"
TOKEN_URL = f"{ISSUER}/protocol/openid-connect/token"
CLIENT_ID = "orders"


def _int_to_b64url(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64url_encode(raw).decode("ascii")


@pytest.fixture(scope="session")
def rsa_keypair():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_numbers = priv.public_key().public_numbers()
    kid = "test-kid-1"
    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _int_to_b64url(pub_numbers.n),
        "e": _int_to_b64url(pub_numbers.e),
    }
    return {
        "private_pem": priv_pem,
        "jwk": jwk,
        "kid": kid,
        "jwks": {"keys": [jwk]},
    }


def make_token(
    keypair: Dict[str, Any],
    *,
    sub: str = "alice",
    aud: Any = CLIENT_ID,
    iss: str = ISSUER,
    exp_offset: int = 300,
    extra_claims: Optional[Dict[str, Any]] = None,
    kid: Optional[str] = None,
    sign_with: Optional[bytes] = None,
) -> str:
    now = int(time.time())
    claims = {
        "iss": iss,
        "sub": sub,
        "aud": aud,
        "iat": now,
        "exp": now + exp_offset,
        "preferred_username": "alice@app1.test",
        "email": "alice@app1.test",
        "name": "Alice Tester",
    }
    if extra_claims:
        claims.update(extra_claims)
    headers = {"kid": kid or keypair["kid"], "alg": "RS256", "typ": "JWT"}
    return pyjwt.encode(claims, sign_with or keypair["private_pem"], algorithm="RS256", headers=headers)


@pytest.fixture
def settings() -> AuthLibSettings:
    return AuthLibSettings(
        issuer_uri=ISSUER,
        client_id=CLIENT_ID,
        audiences=["orders", "invoices"],
        jwks_cache_ttl_seconds=3600,
        permission_cache_ttl_seconds=60,
    )


@pytest.fixture
def mock_jwks(respx_mock, rsa_keypair):
    respx_mock.get(JWKS_URL).mock(
        return_value=httpx.Response(200, json=rsa_keypair["jwks"])
    )
    return respx_mock


@pytest.fixture
def validator(settings, mock_jwks) -> JwtValidator:
    return JwtValidator(settings)


@pytest.fixture
def permissions(settings) -> Permissions:
    return Permissions(settings)


@pytest.fixture
def alice_token(rsa_keypair) -> str:
    return make_token(rsa_keypair)
