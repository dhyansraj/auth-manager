"""UMA permission aggregation with Redis (or in-process) caching.

Mirrors :class:`io.mcpmesh.auth.lib.Permissions` from the Java auth-lib:

  * Calls Keycloak's ``/protocol/openid-connect/token`` UMA endpoint once per
    configured audience.
  * Uses ``response_mode=permissions`` (list of ``{rsname, scopes}``), NOT the
    RPT JWT path.
  * Aggregates ``rsname + "_" + scope`` into uppercased underscore-separated
    permission strings (e.g. ``order`` + ``view`` -> ``ORDER_VIEW``).
  * Per-audience failure is logged at DEBUG and skipped. If ALL audiences
    fail, logs at WARN and returns an empty set.
  * Cache key = ``perms:{sub}:{sha256(sorted-audiences)}``; TTL = settings.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any, Dict, Iterable, List, Optional, Set

import httpx
from cachetools import TTLCache

from .config import AuthLibSettings

logger = logging.getLogger(__name__)

_UMA_GRANT = "urn:ietf:params:oauth:grant-type:uma-ticket"
_CACHE_KEY_PREFIX = "perms:"


def _normalize(raw: str) -> str:
    return raw.strip().upper().replace(" ", "_").replace("-", "_")


def _audience_hash(audiences: Iterable[str]) -> str:
    joined = ",".join(sorted(audiences))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]


class _PermissionCache:
    """Tiny abstraction over Redis vs in-process TTLCache."""

    def __init__(self, settings: AuthLibSettings, redis_client: Optional[Any] = None) -> None:
        self._ttl = max(1, int(settings.permission_cache_ttl_seconds))
        self._redis = redis_client
        if self._redis is None and settings.redis_url:
            try:
                import redis  # type: ignore

                self._redis = redis.Redis.from_url(settings.redis_url, decode_responses=True)
            except Exception:  # pragma: no cover
                logger.warning("auth-lib: failed to init redis at %s; falling back to in-process cache",
                               settings.redis_url, exc_info=True)
                self._redis = None
        # In-process fallback. maxsize is generous; entries auto-evict on TTL.
        self._local: TTLCache = TTLCache(maxsize=10_000, ttl=self._ttl)

    def get(self, key: str) -> Optional[Set[str]]:
        if self._redis is not None:
            try:
                raw = self._redis.get(key)
            except Exception:  # pragma: no cover
                logger.debug("auth-lib: redis get failed for %s", key, exc_info=True)
                raw = None
            if raw is None:
                return None
            try:
                return set(json.loads(raw))
            except Exception:  # pragma: no cover
                return None
        return self._local.get(key)

    def set(self, key: str, value: Set[str]) -> None:
        if self._redis is not None:
            try:
                self._redis.setex(key, self._ttl, json.dumps(sorted(value)))
                return
            except Exception:  # pragma: no cover
                logger.debug("auth-lib: redis setex failed for %s", key, exc_info=True)
        self._local[key] = value


class Permissions:
    """Aggregates a JWT's UMA permissions across one or more audiences."""

    def __init__(
        self,
        settings: AuthLibSettings,
        http_client: Optional[httpx.Client] = None,
        cache: Optional[_PermissionCache] = None,
    ) -> None:
        self._settings = settings
        self._http = http_client or httpx.Client(timeout=settings.http_timeout_seconds)
        self._cache = cache or _PermissionCache(settings)

    @property
    def settings(self) -> AuthLibSettings:
        return self._settings

    def all_for(self, token: str, claims: Optional[Dict[str, Any]] = None) -> Set[str]:
        """Return the union of normalized permissions across configured audiences."""
        if not token:
            return set()
        sub = (claims or {}).get("sub", "anon")
        audiences = self._settings.effective_audiences
        cache_key = f"{_CACHE_KEY_PREFIX}{sub}:{_audience_hash(audiences)}"

        cached = self._cache.get(cache_key)
        if cached is not None:
            logger.debug("Permissions: cache hit sub=%s audiences=%s", sub, audiences)
            return set(cached)

        aggregated: Set[str] = set()
        failures = 0
        for audience in audiences:
            try:
                aggregated.update(self._fetch_for_audience(token, audience))
            except httpx.HTTPStatusError as e:
                logger.debug("Permissions: UMA call for audience=%s returned %s -- skipping",
                             audience, e.response.status_code)
                failures += 1
            except Exception as e:  # noqa: BLE001
                logger.debug("Permissions: UMA call for audience=%s failed: %s -- skipping",
                             audience, e)
                failures += 1

        if failures > 0 and failures == len(audiences):
            logger.warning("Permissions: ALL %d UMA audience calls failed for sub=%s",
                           len(audiences), sub)

        self._cache.set(cache_key, aggregated)
        return aggregated

    def has(self, token: str, claims: Dict[str, Any], permission: str) -> bool:
        """Convenience: check if a normalized permission is present."""
        if not permission:
            return False
        return permission in self.all_for(token, claims)

    # ---- internals ---------------------------------------------------------

    def _fetch_for_audience(self, token: str, audience: str) -> Set[str]:
        endpoint = self._settings.token_endpoint
        response = self._http.post(
            endpoint,
            data={
                "grant_type": _UMA_GRANT,
                "audience": audience,
                "response_mode": "permissions",
            },
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
        )
        if response.status_code >= 400:
            response.raise_for_status()
        try:
            payload = response.json()
        except ValueError:
            logger.debug("Permissions: non-JSON UMA response for audience=%s", audience)
            return set()
        if not isinstance(payload, list):
            return set()
        out: Set[str] = set()
        for entry in payload:
            if not isinstance(entry, dict):
                continue
            rsname = entry.get("rsname")
            scopes = entry.get("scopes")
            if not rsname or not isinstance(scopes, list):
                continue
            for scope in scopes:
                if scope is None:
                    continue
                out.add(_normalize(f"{rsname}_{scope}"))
        return out


class ClaimRolesPermissions(Permissions):
    """Reads permissions directly from the JWT's ``resource_access.<client>.roles``
    claim instead of calling Keycloak's UMA endpoint.

    Use this when your KC realm uses composite-role-of-client-roles expansion
    (the auth-manager manifest pattern) — atomic permissions are already in
    the token, no round-trip needed.

    Config: ``AUTH_LIB_PERMISSIONS_SOURCE=claims`` (the default).

    The audience clients to read from are configurable via the same
    ``AUTH_LIB_AUDIENCES`` setting that UMA mode uses; if unset, falls back
    to ``AUTH_LIB_CLIENT_ID``.
    """

    def all_for(self, token: str, claims: Optional[Dict[str, Any]] = None) -> Set[str]:
        if not claims:
            return set()
        resource_access = claims.get("resource_access") or {}
        if not isinstance(resource_access, dict):
            return set()
        perms: Set[str] = set()
        for client_id in self._audience_clients():
            client_block = resource_access.get(client_id) or {}
            if not isinstance(client_block, dict):
                continue
            roles = client_block.get("roles") or []
            if not isinstance(roles, list):
                continue
            for role in roles:
                if isinstance(role, str) and role:
                    perms.add(role)
        return perms

    def _audience_clients(self) -> List[str]:
        # Same resolution as UMA mode's audience set: AUTH_LIB_AUDIENCES if
        # set, else AUTH_LIB_CLIENT_ID.
        return self._settings.effective_audiences
