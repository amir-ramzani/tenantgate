"""Scope naming conventions shared by triggers, control plane and resource servers.

* User (authorization code) clients get the generic resource-server scopes
  ``api/read`` and ``api/write``; the tenant comes from the ``tenant_id`` claim.
* M2M (client credentials) clients get *tenant-scoped* scopes,
  ``api/tenant.<tenant_id>.read`` / ``.write`` (plan §2, custom scope per tenant).

A resource server maps a tenant-scoped scope to its generic form only when the
tenant in the scope equals the token's ``tenant_id`` claim. Scopes naming any
other tenant are dropped — fail closed.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

DEFAULT_RESOURCE_SERVER = "api"
ACTIONS: tuple[str, ...] = ("read", "write")
TENANT_ID_RE = re.compile(r"^t-[a-z0-9]{12}$")


def is_valid_tenant_id(value: str) -> bool:
    return bool(TENANT_ID_RE.fullmatch(value))


def generic_scope(action: str, resource_server: str = DEFAULT_RESOURCE_SERVER) -> str:
    return f"{resource_server}/{action}"


def tenant_scope_name(tenant_id: str, action: str) -> str:
    """Scope name as registered on the resource server (without the prefix)."""
    return f"tenant.{tenant_id}.{action}"


def tenant_scope(
    tenant_id: str, action: str, resource_server: str = DEFAULT_RESOURCE_SERVER
) -> str:
    return f"{resource_server}/{tenant_scope_name(tenant_id, action)}"


def parse_tenant_scope(
    scope: str, resource_server: str = DEFAULT_RESOURCE_SERVER
) -> tuple[str, str] | None:
    """``api/tenant.t-abc.read`` -> ``("t-abc", "read")``; anything else -> ``None``."""
    prefix = f"{resource_server}/tenant."
    if not scope.startswith(prefix):
        return None
    tenant_id, sep, action = scope[len(prefix) :].rpartition(".")
    if not sep or not is_valid_tenant_id(tenant_id) or action not in ACTIONS:
        return None
    return tenant_id, action


def split_scope_claim(raw: str | Iterable[str] | None) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        return [s for s in raw.split() if s]
    return [str(s) for s in raw]


def normalize_scopes(
    raw_scopes: Iterable[str],
    tenant_id: str,
    resource_server: str = DEFAULT_RESOURCE_SERVER,
) -> frozenset[str]:
    """Map a token's scopes to the generic scopes it grants for ``tenant_id``."""
    out: set[str] = set()
    for scope in raw_scopes:
        parsed = parse_tenant_scope(scope, resource_server)
        if parsed is None:
            if not scope.startswith(f"{resource_server}/tenant."):
                out.add(scope)
        elif parsed[0] == tenant_id:
            out.add(generic_scope(parsed[1], resource_server))
    return frozenset(out)
