import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from mcpmesh_auth_lib import JwtValidationError

from .conftest import CLIENT_ID, ISSUER, make_token


def test_valid_token_returns_claims(validator, rsa_keypair):
    token = make_token(rsa_keypair, sub="alice")
    claims = validator.decode_and_verify(token)
    assert claims["sub"] == "alice"
    assert claims["iss"] == ISSUER
    assert claims["aud"] == CLIENT_ID


def test_missing_token_raises(validator):
    with pytest.raises(JwtValidationError):
        validator.decode_and_verify("")


def test_expired_token_raises(validator, rsa_keypair):
    token = make_token(rsa_keypair, exp_offset=-10)
    with pytest.raises(JwtValidationError) as exc:
        validator.decode_and_verify(token)
    assert "expired" in str(exc.value).lower()


def test_wrong_issuer_raises(validator, rsa_keypair):
    token = make_token(rsa_keypair, iss="http://evil/realms/x")
    with pytest.raises(JwtValidationError) as exc:
        validator.decode_and_verify(token)
    assert "issuer" in str(exc.value).lower()


def test_wrong_signature_raises(validator, rsa_keypair):
    # Sign with a different RSA private key but keep the trusted kid.
    rogue = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rogue_pem = rogue.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    token = make_token(rsa_keypair, sign_with=rogue_pem)
    with pytest.raises(JwtValidationError) as exc:
        validator.decode_and_verify(token)
    assert "signature" in str(exc.value).lower()


def test_unknown_kid_raises(validator, rsa_keypair):
    token = make_token(rsa_keypair, kid="not-a-real-kid")
    with pytest.raises(JwtValidationError):
        validator.decode_and_verify(token)


def test_audience_via_azp_accepted(validator, rsa_keypair):
    # aud is some other resource server, but azp is our client_id -> accepted.
    token = make_token(
        rsa_keypair,
        aud="some-other-rs",
        extra_claims={"azp": CLIENT_ID},
    )
    claims = validator.decode_and_verify(token)
    assert claims["azp"] == CLIENT_ID


def test_audience_list_with_match_accepted(validator, rsa_keypair):
    token = make_token(rsa_keypair, aud=["some-other-rs", CLIENT_ID])
    claims = validator.decode_and_verify(token)
    assert CLIENT_ID in claims["aud"]


def test_audience_no_match_rejected(validator, rsa_keypair):
    token = make_token(rsa_keypair, aud="totally-unknown")
    with pytest.raises(JwtValidationError) as exc:
        validator.decode_and_verify(token)
    assert "audience" in str(exc.value).lower()
