"""Configuration for auth-lib-python.

Mirrors :class:`io.mcpmesh.auth.lib.AuthLibProperties` from the Java auth-lib.
Settings are read from environment variables prefixed with ``AUTH_LIB_`` (or
from a ``.env`` file in the working directory).
"""

from __future__ import annotations

from typing import List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AuthLibSettings(BaseSettings):
    """Connection + caching settings for a single Keycloak realm.

    Required env vars:
      * ``AUTH_LIB_ISSUER_URI``  e.g. ``https://auth.mcp-mesh.io/auth/realms/t-app1``
      * ``AUTH_LIB_CLIENT_ID``   e.g. ``orders``

    Optional:
      * ``AUTH_LIB_CLIENT_SECRET``  CONFIDENTIAL client secret (only needed if the
        client is confidential; UMA calls bear the user's access token so the
        client_secret is not used in the UMA flow itself, but it's surfaced here
        for completeness in case callers want to do additional KC calls).
      * ``AUTH_LIB_AUDIENCES``  JSON list or comma-separated list of additional
        resource-server clientIds to aggregate UMA permissions across. Defaults
        to ``[client_id]``.
      * ``AUTH_LIB_JWKS_CACHE_TTL_SECONDS``  default 3600
      * ``AUTH_LIB_PERMISSION_CACHE_TTL_SECONDS``  default 60
      * ``AUTH_LIB_REDIS_URL``  e.g. ``redis://redis:6379/0``. If unset, an
        in-process TTL cache is used.
    """

    model_config = SettingsConfigDict(
        env_prefix="AUTH_LIB_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    issuer_uri: str
    client_id: str
    client_secret: Optional[str] = None
    audiences: Optional[List[str]] = None
    jwks_cache_ttl_seconds: int = 3600
    permission_cache_ttl_seconds: int = 60
    redis_url: Optional[str] = None
    # Connection timeout for outbound calls (JWKS, UMA) in seconds.
    http_timeout_seconds: float = Field(default=5.0)

    @field_validator("audiences", mode="before")
    @classmethod
    def _split_audiences(cls, v):  # type: ignore[override]
        # Support comma-separated env var: AUTH_LIB_AUDIENCES=orders,invoices
        if isinstance(v, str):
            s = v.strip()
            if not s:
                return None
            if s.startswith("["):
                # let pydantic handle JSON
                return v
            return [p.strip() for p in s.split(",") if p.strip()]
        return v

    @property
    def effective_audiences(self) -> List[str]:
        """Always returns at least one audience (falling back to ``client_id``)."""
        if self.audiences:
            return list(self.audiences)
        return [self.client_id]

    @property
    def jwks_uri(self) -> str:
        return f"{self.issuer_uri.rstrip('/')}/protocol/openid-connect/certs"

    @property
    def token_endpoint(self) -> str:
        return f"{self.issuer_uri.rstrip('/')}/protocol/openid-connect/token"
