"""Pydantic models mirroring the Java DTOs in ``io.mcpmesh.auth.lib.dto``.

The wire format MUST match :class:`io.mcpmesh.auth.lib.dto.MeResponse` exactly
so the React client library (``libs/auth-lib-react``) can decode both Java- and
Python-served ``/api/me`` payloads with a single helper.
"""

from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class User(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    email: Optional[str] = None
    preferred_username: Optional[str] = Field(default=None, alias="preferredUsername")
    name: Optional[str] = None


class Tenant(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: Optional[str] = None
    slug: str
    display_name: str = Field(alias="displayName")
    realm_name: str = Field(alias="realmName")


class MeResponse(BaseModel):
    """Shared who-am-I payload returned by every tenant /api/me endpoint.

    Matches :class:`io.mcpmesh.auth.lib.dto.MeResponse` exactly. Note the camelCase
    aliases for ``isPlatformAdmin`` / ``isTenantAdmin`` so JSON output uses the
    same field names as the Java side.
    """

    model_config = ConfigDict(populate_by_name=True)

    user: User
    context: Literal["platform", "tenant"]
    tenant: Optional[Tenant] = None
    is_platform_admin: bool = Field(default=False, alias="isPlatformAdmin")
    is_tenant_admin: bool = Field(default=False, alias="isTenantAdmin")
    permissions: List[str] = Field(default_factory=list)
