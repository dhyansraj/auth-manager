"""FastAPI Depends() factories for auth-lib.

Two singletons (``JwtValidator`` and ``Permissions``) are stashed on
``app.state`` by :func:`auth_lib_init`. The ``current_user`` /
``optional_user`` / ``require_permission`` / ``require_role`` dependencies
pull them off the request.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import AuthLibSettings
from .jwt_validator import JwtValidationError, JwtValidator
from .permissions import ClaimRolesPermissions, Permissions

logger = logging.getLogger(__name__)

bearer_scheme = HTTPBearer(auto_error=False)

# Key under which the JWT raw token is threaded through the claims dict so
# downstream dependencies (like require_permission) can perform UMA calls
# without needing to re-parse the Authorization header.
RAW_TOKEN_CLAIM = "_raw_token"

# Marker threaded into synthetic claims so downstream code can tell that the
# request was served by the dev-mode bypass (no real token was verified).
DEV_MODE_CLAIM = "_dev_mode"

_DEV_MODE_WARNED = False


def _warn_dev_mode_once() -> None:
    global _DEV_MODE_WARNED
    if not _DEV_MODE_WARNED:
        _DEV_MODE_WARNED = True
        logger.warning(
            "auth-lib dev_mode ENABLED: auth bypassed, synthetic user injected "
            "-- never use in production"
        )


def _dev_claims(settings: AuthLibSettings) -> Dict[str, Any]:
    """Build synthetic JWT-like claims for dev-mode.

    Shapes ``resource_access`` so the configured client carries
    ``dev_user_roles``, mirroring the real claims path that
    ``build_me_response`` / ``ClaimRolesPermissions`` read from.
    """
    roles = list(settings.dev_user_roles)
    resource_access = {client: {"roles": list(roles)} for client in settings.effective_audiences}
    return {
        "sub": "dev-user",
        "email": settings.dev_user_email,
        "preferred_username": settings.dev_user_email,
        "name": settings.dev_user_email,
        "realm_access": {"roles": list(roles)},
        "resource_access": resource_access,
        RAW_TOKEN_CLAIM: "",
        DEV_MODE_CLAIM: True,
    }


def _state(request: Request) -> Any:
    state = getattr(request.app, "state", None)
    if state is None or not hasattr(state, "auth_lib_validator"):
        raise RuntimeError(
            "auth-lib not initialised: call auth_lib_init(app) at startup."
        )
    return state


def get_settings(request: Request) -> AuthLibSettings:
    return _state(request).auth_lib_settings  # type: ignore[no-any-return]


def get_validator(request: Request) -> JwtValidator:
    return _state(request).auth_lib_validator  # type: ignore[no-any-return]


def get_permissions(request: Request) -> Permissions:
    return _state(request).auth_lib_permissions  # type: ignore[no-any-return]


def current_user(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    validator: JwtValidator = Depends(get_validator),
    settings: AuthLibSettings = Depends(get_settings),
) -> Dict[str, Any]:
    """FastAPI dependency that returns the decoded JWT claims dict.

    Raises 401 if the token is missing, malformed, expired, or its signature /
    issuer / audience fails verification. The raw token is threaded into the
    returned dict under :data:`RAW_TOKEN_CLAIM` so downstream dependencies can
    perform UMA calls without re-parsing headers.

    When ``settings.dev_mode`` is enabled, this SHORT-CIRCUITS: no token is
    required and a synthetic user is returned (see :func:`_dev_claims`).
    """
    if settings.dev_mode:
        _warn_dev_mode_once()
        return _dev_claims(settings)
    if creds is None or not creds.credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing_token")
    try:
        claims = validator.decode_and_verify(creds.credentials)
    except JwtValidationError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e)) from e
    claims[RAW_TOKEN_CLAIM] = creds.credentials
    return claims


def optional_user(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    validator: JwtValidator = Depends(get_validator),
    settings: AuthLibSettings = Depends(get_settings),
) -> Optional[Dict[str, Any]]:
    """Like :func:`current_user` but returns ``None`` instead of raising 401.

    In ``dev_mode`` the synthetic user is returned (never ``None``).
    """
    if settings.dev_mode:
        _warn_dev_mode_once()
        return _dev_claims(settings)
    if creds is None or not creds.credentials:
        return None
    try:
        claims = validator.decode_and_verify(creds.credentials)
    except JwtValidationError:
        return None
    claims[RAW_TOKEN_CLAIM] = creds.credentials
    return claims


def require_permission(permission: str) -> Callable[..., None]:
    """Factory that returns a FastAPI dependency enforcing a permission.

    Usage::

        @app.get("/api/orders", dependencies=[Depends(require_permission("ORDER_VIEW"))])
        def list_orders(): ...
    """
    if not permission:
        raise ValueError("require_permission(permission) needs a non-empty string")

    def _checker(
        claims: Dict[str, Any] = Depends(current_user),
        perms: Permissions = Depends(get_permissions),
        settings: AuthLibSettings = Depends(get_settings),
    ) -> None:
        if settings.dev_mode:
            # Grant in dev-mode. If dev_user_roles is set, only those are
            # granted; if empty, grant everything.
            if not settings.dev_user_roles or permission in settings.dev_user_roles:
                return
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"missing_permission:{permission}",
            )
        token = claims.get(RAW_TOKEN_CLAIM, "")
        if permission not in perms.all_for(token, claims):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"missing_permission:{permission}",
            )

    return _checker


def require_any_permission(*permissions: str) -> Callable[..., None]:
    """Variant requiring ANY of the listed permissions."""
    if not permissions:
        raise ValueError("require_any_permission needs at least one permission")
    permset = set(permissions)

    def _checker(
        claims: Dict[str, Any] = Depends(current_user),
        perms: Permissions = Depends(get_permissions),
        settings: AuthLibSettings = Depends(get_settings),
    ) -> None:
        if settings.dev_mode:
            if not settings.dev_user_roles or (set(settings.dev_user_roles) & permset):
                return
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"missing_permission_any:{sorted(permset)}",
            )
        token = claims.get(RAW_TOKEN_CLAIM, "")
        granted = perms.all_for(token, claims)
        if not (granted & permset):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"missing_permission_any:{sorted(permset)}",
            )

    return _checker


def _roles_in(claims: Dict[str, Any]) -> List[str]:
    """Flatten realm_access + resource_access roles into a single list."""
    roles: List[str] = []
    realm = claims.get("realm_access")
    if isinstance(realm, dict):
        rr = realm.get("roles")
        if isinstance(rr, list):
            roles.extend(str(r) for r in rr if r)
    res = claims.get("resource_access")
    if isinstance(res, dict):
        for client, val in res.items():
            if isinstance(val, dict):
                rr = val.get("roles")
                if isinstance(rr, list):
                    roles.extend(f"{client}:{r}" for r in rr if r)
                    # Also expose the bare role names for convenience.
                    roles.extend(str(r) for r in rr if r)
    return roles


def require_role(role: str, *, client: Optional[str] = None) -> Callable[..., None]:
    """Factory that enforces a realm or client role.

    If ``client`` is provided, only roles under ``resource_access.{client}.roles``
    are considered. Otherwise both realm roles and any client's roles match.
    """
    if not role:
        raise ValueError("require_role(role) needs a non-empty string")

    def _checker(
        claims: Dict[str, Any] = Depends(current_user),
        settings: AuthLibSettings = Depends(get_settings),
    ) -> None:
        if settings.dev_mode:
            if not settings.dev_user_roles or role in settings.dev_user_roles:
                return
            detail = f"missing_role:{client}:{role}" if client is not None else f"missing_role:{role}"
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)
        if client is not None:
            res = claims.get("resource_access")
            if isinstance(res, dict):
                c = res.get(client)
                if isinstance(c, dict) and isinstance(c.get("roles"), list) and role in c["roles"]:
                    return
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"missing_role:{client}:{role}",
            )
        if role in _roles_in(claims):
            return
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"missing_role:{role}",
        )

    return _checker


def auth_lib_init(
    app: FastAPI,
    settings: Optional[AuthLibSettings] = None,
    *,
    validator: Optional[JwtValidator] = None,
    permissions: Optional[Permissions] = None,
) -> None:
    """One-call setup for a FastAPI app.

    Reads ``AUTH_LIB_*`` env vars (unless ``settings`` is passed in), constructs
    the singletons, and stashes them on ``app.state`` so the ``Depends`` factories
    in this module can find them.

    Idempotent: safe to call twice (e.g. in tests).
    """
    resolved = settings or AuthLibSettings()  # type: ignore[call-arg]
    app.state.auth_lib_settings = resolved
    app.state.auth_lib_validator = validator or JwtValidator(resolved)
    if permissions is None:
        if resolved.permissions_source == "uma":
            permissions = Permissions(resolved)
        else:
            permissions = ClaimRolesPermissions(resolved)
    app.state.auth_lib_permissions = permissions
    logger.info(
        "auth-lib initialised: issuer=%s client_id=%s audiences=%s permissions_source=%s",
        resolved.issuer_uri, resolved.client_id, resolved.effective_audiences,
        resolved.permissions_source,
    )
