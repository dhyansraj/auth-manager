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
) -> Dict[str, Any]:
    """FastAPI dependency that returns the decoded JWT claims dict.

    Raises 401 if the token is missing, malformed, expired, or its signature /
    issuer / audience fails verification. The raw token is threaded into the
    returned dict under :data:`RAW_TOKEN_CLAIM` so downstream dependencies can
    perform UMA calls without re-parsing headers.
    """
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
) -> Optional[Dict[str, Any]]:
    """Like :func:`current_user` but returns ``None`` instead of raising 401."""
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
    ) -> None:
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
    ) -> None:
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

    def _checker(claims: Dict[str, Any] = Depends(current_user)) -> None:
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
