"""mcpmesh-auth-lib — FastAPI client library for the mcp-mesh auth platform.

Python equivalent of ``libs/auth-lib/`` (Spring Boot + Java). Exposes the same
ergonomics for FastAPI consumers:

  * :func:`current_user` / :func:`optional_user`  — JWT-validating Depends().
  * :func:`require_permission` / :func:`require_role`  — Spring's @PreAuthorize equivalents.
  * :class:`Permissions`  — UMA aggregation with Redis (or in-process) caching.
  * :class:`MeResponse` / :class:`User` / :class:`Tenant`  — Pydantic models matching the Java DTO.
  * :func:`build_me_response`  — one-line ``/api/me`` helper.
  * :func:`auth_lib_init`  — one-call setup that reads ``AUTH_LIB_*`` env vars.

See README.md and ``examples/fastapi_minimal/`` for a working app.
"""

from .config import AuthLibSettings
from .dependencies import (
    auth_lib_init,
    current_user,
    get_permissions,
    get_settings,
    get_validator,
    optional_user,
    require_any_permission,
    require_permission,
    require_role,
)
from .jwt_validator import JwtValidationError, JwtValidator
from .me import build_me_response
from .models import MeResponse, Tenant, User
from .permissions import Permissions

__all__ = [
    "AuthLibSettings",
    "JwtValidator",
    "JwtValidationError",
    "Permissions",
    "MeResponse",
    "User",
    "Tenant",
    "build_me_response",
    "auth_lib_init",
    "current_user",
    "optional_user",
    "require_permission",
    "require_any_permission",
    "require_role",
    "get_settings",
    "get_validator",
    "get_permissions",
]

__version__ = "0.1.0"
