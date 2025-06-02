"""``TenantContext`` and the tenant directory the library consults.

A validated token alone is not enough: the managed-login session cookie can
authenticate a user to *every* app client in the pool, and clients can be
revoked. So every request also checks that

* the token carries a well-formed ``tenant_id`` claim,
* the token's ``client_id`` still maps to that same tenant, and
* the tenant is still active.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from authlib_mt.scopes import (
    DEFAULT_RESOURCE_SERVER,
    is_valid_tenant_id,
    normalize_scopes,
    split_scope_claim,
)
from authlib_mt.validator import InvalidToken

TENANT_ID_CLAIM = "tenant_id"
TENANT_ROLE_CLAIM = "tenant_role"
M2M_ROLE = "service"


class MissingTenant(InvalidToken):
    """The token isn't bound to a tenant."""


class TenantMismatch(Exception):
    """The request targets a different tenant than the token (403)."""


@dataclass(frozen=True)
class TenantContext:
    tenant_id: str
    sub: str
    client_id: str
    role: str
    scopes: frozenset[str]
    groups: frozenset[str] = field(default_factory=frozenset)
    claims: dict[str, Any] = field(default_factory=dict, compare=False, repr=False)

    @property
    def is_m2m(self) -> bool:
        return self.role == M2M_ROLE

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    def has_scopes(self, *required: str) -> bool:
        return all(s in self.scopes for s in required)


class TenantDirectory(Protocol):
    def tenant_for_client(self, client_id: str) -> str | None:
        """Tenant ID the client belongs to, or ``None``."""
        ...

    def is_tenant_active(self, tenant_id: str) -> bool: ...


class CachedTenantDirectory:
    """Small TTL cache in front of another directory (registry reads are cheap
    but not free; a revoked client is honoured at most ``ttl`` seconds late)."""

    def __init__(
        self,
        inner: TenantDirectory,
        *,
        ttl: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._inner = inner
        self._ttl = ttl
        self._clock = clock
        self._clients: dict[str, tuple[float, str | None]] = {}
        self._active: dict[str, tuple[float, bool]] = {}

    def tenant_for_client(self, client_id: str) -> str | None:
        hit = self._clients.get(client_id)
        now = self._clock()
        if hit and now - hit[0] < self._ttl:
            return hit[1]
        value = self._inner.tenant_for_client(client_id)
        self._clients[client_id] = (now, value)
        return value

    def is_tenant_active(self, tenant_id: str) -> bool:
        hit = self._active.get(tenant_id)
        now = self._clock()
        if hit and now - hit[0] < self._ttl:
            return hit[1]
        value = self._inner.is_tenant_active(tenant_id)
        self._active[tenant_id] = (now, value)
        return value

    def invalidate(self) -> None:
        self._clients.clear()
        self._active.clear()


def build_context(
    claims: dict[str, Any],
    directory: TenantDirectory,
    *,
    resource_server: str = DEFAULT_RESOURCE_SERVER,
) -> TenantContext:
    tenant_id = claims.get(TENANT_ID_CLAIM)
    if not isinstance(tenant_id, str) or not is_valid_tenant_id(tenant_id):
        raise MissingTenant("token is not bound to a tenant")
    client_id = str(claims["client_id"])
    if directory.tenant_for_client(client_id) != tenant_id:
        raise InvalidToken("client is not registered for this tenant")
    if not directory.is_tenant_active(tenant_id):
        raise InvalidToken("tenant is not active")
    role = str(claims.get(TENANT_ROLE_CLAIM) or "member")
    groups = claims.get("cognito:groups") or []
    return TenantContext(
        tenant_id=tenant_id,
        sub=str(claims["sub"]),
        client_id=client_id,
        role=role,
        scopes=normalize_scopes(split_scope_claim(claims.get("scope")), tenant_id, resource_server),
        groups=frozenset(str(g) for g in groups),
        claims=claims,
    )


def ensure_same_tenant(ctx: TenantContext, requested: str | None) -> None:
    if requested is not None and requested != ctx.tenant_id:
        raise TenantMismatch(f"token is for {ctx.tenant_id}, request targets {requested}")
