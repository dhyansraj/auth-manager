"""Helpers to compose ``/api/me`` responses with the same shape as
``apps/app1-backend``'s ``MeController``.
"""

from __future__ import annotations

from typing import Any, Dict, Literal, Optional

from .models import MeResponse, Tenant, User
from .permissions import Permissions

# Defaults mirroring app1-backend's MeController.
USERMANAGEMENT_CLIENT = "usermanagement"
TENANT_ADMIN_ROLE = "tenant-admin"
PLATFORM_ADMIN_ROLE = "platform-admin"


def _has_client_role(claims: Dict[str, Any], client: str, role: str) -> bool:
    ra = claims.get("resource_access")
    if not isinstance(ra, dict):
        return False
    c = ra.get(client)
    if not isinstance(c, dict):
        return False
    roles = c.get("roles")
    return isinstance(roles, list) and role in roles


def build_me_response(
    claims: Dict[str, Any],
    perms: Permissions,
    tenant: Optional[Tenant],
    *,
    raw_token: str = "",
    context: Literal["platform", "tenant"] = "tenant",
    usermanagement_client: str = USERMANAGEMENT_CLIENT,
    tenant_admin_role: str = TENANT_ADMIN_ROLE,
    platform_admin_role: str = PLATFORM_ADMIN_ROLE,
    extra_permissions: Optional[Any] = None,
) -> MeResponse:
    """Assemble a :class:`MeResponse` from JWT claims + UMA permissions.

    Mirrors :class:`io.mcpmesh.app1.api.MeController.me`:

      * ``user`` is sourced from JWT subject/email/preferred_username/name.
      * ``permissions`` aggregates UMA permissions for all configured audiences
        (using ``perms.all_for``). ``extra_permissions`` (iterable of strings) is
        unioned in for static capability flags.
      * ``isTenantAdmin`` = caller has the ``tenant-admin`` role under the
        ``usermanagement`` client (Java side's convention).
      * ``isPlatformAdmin`` = caller has the ``platform-admin`` realm/client role.

    ``raw_token`` should be the raw bearer string. When called from a FastAPI
    handler that depends on ``current_user``, pass ``claims["_raw_token"]``.
    """
    user = User(
        id=str(claims.get("sub", "")),
        email=claims.get("email"),
        preferred_username=claims.get("preferred_username"),
        name=claims.get("name"),
    )

    perm_set = set(perms.all_for(raw_token, claims)) if raw_token else set()
    if extra_permissions:
        perm_set.update(str(p) for p in extra_permissions if p)

    is_tenant_admin = _has_client_role(claims, usermanagement_client, tenant_admin_role)
    is_platform_admin = (
        _has_client_role(claims, usermanagement_client, platform_admin_role)
        or platform_admin_role in (claims.get("realm_access") or {}).get("roles", [])
    )

    return MeResponse(
        user=user,
        context=context,
        tenant=tenant if context == "tenant" else None,
        is_platform_admin=is_platform_admin,
        is_tenant_admin=is_tenant_admin,
        permissions=sorted(perm_set),
    )
