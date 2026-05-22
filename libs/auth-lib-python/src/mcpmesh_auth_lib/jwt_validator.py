"""JWT signature + claims validation backed by Keycloak's JWKS endpoint.

The validator fetches the JWKS via :mod:`httpx` (so tests can mock it with
``respx``) and caches it for ``settings.jwks_cache_ttl_seconds``. On signature
failure where the kid isn't in the current cache, the JWKS is force-refreshed
once before re-raising — this handles Keycloak key rotation gracefully.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Dict, Optional

import httpx
import jwt as pyjwt
from jwt import PyJWKSet

from .config import AuthLibSettings

logger = logging.getLogger(__name__)


class JwtValidationError(Exception):
    """Raised when a token cannot be decoded or fails verification."""


class JwtValidator:
    """Validates JWTs against the configured Keycloak realm.

    Uses ``httpx`` to fetch JWKS so respx-based tests can intercept it. Public
    :meth:`decode_and_verify` raises :class:`JwtValidationError` on any failure;
    FastAPI's dependency layer maps that to a 401.
    """

    def __init__(
        self,
        settings: AuthLibSettings,
        *,
        http_client: Optional[httpx.Client] = None,
    ) -> None:
        self._settings = settings
        self._lock = threading.Lock()
        self._http = http_client or httpx.Client(timeout=settings.http_timeout_seconds)
        self._owns_http = http_client is None
        self._jwks: Optional[PyJWKSet] = None
        self._jwks_expires_at: float = 0.0
        self._last_refresh: float = 0.0

    @property
    def settings(self) -> AuthLibSettings:
        return self._settings

    def close(self) -> None:
        if self._owns_http:
            self._http.close()

    def decode_and_verify(self, token: str) -> Dict[str, Any]:
        """Verify signature/exp/iss/aud and return the decoded claims dict.

        Audience validation: accepts the token if its ``aud`` claim (string or
        list) contains ``settings.client_id`` (or any configured audience) OR
        if the token's ``azp`` matches it. Matches Keycloak's typical behavior
        where confidential clients receive tokens with their own ``client_id``
        as the authorized party.
        """
        if not token or not isinstance(token, str):
            raise JwtValidationError("missing_token")

        try:
            kid = self._kid_from(token)
        except pyjwt.DecodeError as e:
            raise JwtValidationError(f"invalid_token: {e}") from e

        signing_key = self._signing_key(kid)
        if signing_key is None:
            # Possibly rotated; refresh once and retry.
            self._refresh_jwks(force=True)
            signing_key = self._signing_key(kid)
            if signing_key is None:
                raise JwtValidationError(f"unknown_kid: {kid}")

        try:
            claims = pyjwt.decode(
                token,
                signing_key,
                algorithms=["RS256", "RS384", "RS512", "ES256", "ES384"],
                issuer=self._settings.issuer_uri,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iss": True,
                    # We do audience validation manually below to support
                    # multi-aud tokens with the azp-fallback rule that KC uses.
                    "verify_aud": False,
                    "require": ["exp", "iss"],
                },
            )
        except pyjwt.ExpiredSignatureError as e:
            raise JwtValidationError("token_expired") from e
        except pyjwt.InvalidIssuerError as e:
            raise JwtValidationError("invalid_issuer") from e
        except pyjwt.InvalidSignatureError as e:
            raise JwtValidationError("invalid_signature") from e
        except pyjwt.InvalidTokenError as e:
            raise JwtValidationError(f"invalid_token: {e}") from e

        self._verify_audience(claims)
        return claims

    # ---- internals ---------------------------------------------------------

    @staticmethod
    def _kid_from(token: str) -> Optional[str]:
        header = pyjwt.get_unverified_header(token)
        return header.get("kid")

    def _signing_key(self, kid: Optional[str]):
        jwks = self._get_jwks()
        if jwks is None:
            return None
        if kid:
            for key in jwks.keys:
                if key.key_id == kid:
                    return key.key
            return None
        # No kid in token; if exactly one key, use it.
        if len(jwks.keys) == 1:
            return jwks.keys[0].key
        return None

    def _get_jwks(self) -> Optional[PyJWKSet]:
        now = time.monotonic()
        if self._jwks is not None and now < self._jwks_expires_at:
            return self._jwks
        return self._refresh_jwks()

    def _refresh_jwks(self, force: bool = False) -> Optional[PyJWKSet]:
        now = time.monotonic()
        with self._lock:
            if not force and self._jwks is not None and now < self._jwks_expires_at:
                return self._jwks
            if force and (now - self._last_refresh) < 5.0 and self._jwks is not None:
                # Rate-limit forced refreshes to one per 5s.
                return self._jwks
            try:
                resp = self._http.get(self._settings.jwks_uri)
                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                logger.warning("auth-lib: JWKS fetch failed: %s", e)
                if self._jwks is not None:
                    return self._jwks
                raise JwtValidationError(f"jwks_fetch_failed: {e}") from e
            try:
                self._jwks = PyJWKSet.from_dict(data)
            except Exception as e:
                raise JwtValidationError(f"jwks_parse_failed: {e}") from e
            self._jwks_expires_at = now + max(1, int(self._settings.jwks_cache_ttl_seconds))
            self._last_refresh = now
            return self._jwks

    def _verify_audience(self, claims: Dict[str, Any]) -> None:
        aud = claims.get("aud")
        azp = claims.get("azp")
        client_id = self._settings.client_id
        candidates = set()
        if isinstance(aud, str):
            candidates.add(aud)
        elif isinstance(aud, list):
            candidates.update(str(a) for a in aud)
        if isinstance(azp, str):
            candidates.add(azp)
        if client_id in candidates:
            return
        for extra in self._settings.effective_audiences:
            if extra in candidates:
                return
        raise JwtValidationError(
            f"invalid_audience: expected one of "
            f"{sorted(set(self._settings.effective_audiences + [client_id]))}, "
            f"got {sorted(candidates) or 'none'}"
        )


def build_httpx_client(settings: AuthLibSettings) -> httpx.Client:
    """Construct a shared, pooled httpx.Client for outbound calls."""
    return httpx.Client(timeout=settings.http_timeout_seconds)
