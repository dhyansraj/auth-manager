"""Configuration for auth-lib-python.

Mirrors :class:`io.mcpmesh.auth.lib.AuthLibProperties` from the Java auth-lib.
Settings are read from environment variables prefixed with ``AUTH_LIB_`` (or
from a ``.env`` file in the working directory).
"""

from __future__ import annotations

from typing import List, Literal, Optional

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
      * ``AUTH_LIB_JWK_SET_URI``  optional; when set, JWKS is fetched from this
        URL (e.g. the in-cluster KC certs URL) instead of deriving it from
        issuer_uri — lets in-cluster backends avoid a public-DNS hairpin while
        iss is still validated against the public issuer_uri.
      * ``AUTH_LIB_JWKS_CACHE_TTL_SECONDS``  default 3600
      * ``AUTH_LIB_PERMISSION_CACHE_TTL_SECONDS``  default 60
      * ``AUTH_LIB_REDIS_URL``  e.g. ``redis://redis:6379/0``. If unset, an
        in-process TTL cache is used.
      * ``AUTH_LIB_PERMISSIONS_SOURCE``  ``"claims"`` (default) reads atomic
        permissions from the JWT's ``resource_access.<client>.roles`` claim
        (auth-manager manifest pattern: composite realm roles bundle client
        roles, KC role expansion flattens them at token mint). ``"uma"`` calls
        Keycloak's UMA ticket grant — only needed for legacy tenants that
        still have KC Authorization Services configured on their backend
        client.
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
    # Optional JWKS URL override. When set, JWKS is fetched from this URL (e.g.
    # the in-cluster KC certs URL) instead of deriving it from issuer_uri —
    # lets in-cluster backends avoid a public-DNS hairpin while iss is still
    # validated against the public issuer_uri.
    jwk_set_uri: Optional[str] = None
    jwks_cache_ttl_seconds: int = 3600
    permission_cache_ttl_seconds: int = 60
    redis_url: Optional[str] = None
    # Connection timeout for outbound calls (JWKS, UMA) in seconds.
    http_timeout_seconds: float = Field(default=5.0)
    # Where to source atomic permissions from. "claims" reads from the JWT's
    # resource_access.<client>.roles claim (no Keycloak round-trip); "uma"
    # calls KC's UMA ticket endpoint. Default is "claims" — the auth-manager
    # composite-role-of-client-roles pattern surfaces atomic perms in the
    # token already. Use "uma" only for legacy tenants with KC Authorization
    # Services configured.
    permissions_source: Literal["claims", "uma"] = "claims"

    # ---- dev-mode bypass ---------------------------------------------------
    # When enabled, the FastAPI dependencies (current_user / optional_user /
    # require_permission / require_role) SHORT-CIRCUIT: no Bearer token is
    # required, a synthetic user is injected, and permission/role checks are
    # granted (optionally scoped to ``dev_user_roles``). This lets a tenant run
    # locally without the edge or a real token. NEVER enable in production.
    # Mirrors the Java auth-lib's ``auth-lib.dev-mode``.
    dev_mode: bool = False
    dev_user_email: str = "dev@example.com"
    # Roles the synthetic user carries (under the configured client in
    # ``resource_access``). If non-empty, dev-mode permission/role checks are
    # restricted to this set; if empty, all checks are granted.
    dev_user_roles: List[str] = Field(default_factory=list)

    @field_validator("dev_user_roles", mode="before")
    @classmethod
    def _split_dev_user_roles(cls, v):  # type: ignore[override]
        # Support comma-separated env var: AUTH_LIB_DEV_USER_ROLES=ORDER_VIEW,ORDER_EDIT
        if isinstance(v, str):
            s = v.strip()
            if not s:
                return []
            if s.startswith("["):
                # let pydantic handle JSON
                return v
            return [p.strip() for p in s.split(",") if p.strip()]
        return v

    @field_validator("permissions_source", mode="before")
    @classmethod
    def _normalize_permissions_source(cls, v):  # type: ignore[override]
        if isinstance(v, str):
            return v.strip().lower()
        return v

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
