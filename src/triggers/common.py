"""Shared helpers for the Cognito triggers.

* Triggers read only the *local* DynamoDB replica — no cross-Region calls on
  the sign-in path (plan §8).
* They fail closed: raising from a trigger makes Cognito deny the request. The
  exception text reaches the end user, so it is deliberately generic; the real
  reason is logged with the tenant and client IDs.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

from aws_lambda_powertools import Logger

from tenantgate.aws import client, dynamodb_table
from tenantgate.models import ClientKind, Membership, Tenant
from tenantgate.registry import TenantRegistry
from tenantgate.settings import Settings, get_settings

logger = Logger(service="tenantgate-triggers")

GENERIC_DENIAL = "Access denied."
SYSTEM_IDS_TTL = 300.0


class AccessDenied(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(GENERIC_DENIAL)
        self.reason = reason


@dataclass(frozen=True)
class ResolvedClient:
    tenant: Tenant
    kind: ClientKind


class _State:
    registry: TenantRegistry | None = None
    system_ids: tuple[float, frozenset[str]] | None = None


_state = _State()


def registry() -> TenantRegistry:
    if _state.registry is None:
        s = get_settings()
        _state.registry = TenantRegistry(dynamodb_table(s.table_name, s.region, profile="trigger"))
    return _state.registry


def reset_state(reg: TenantRegistry | None = None) -> None:
    """Test hook: inject a registry and forget cached system client IDs."""
    _state.registry = reg
    _state.system_ids = None


def client_id_of(event: dict[str, Any]) -> str:
    cid = (event.get("callerContext") or {}).get("clientId")
    if not cid:
        raise AccessDenied("event has no clientId")
    return str(cid)


def system_client_ids(settings: Settings | None = None) -> frozenset[str]:
    """``SYSTEM_CLIENT_IDS`` plus the SSM parameter ``SYSTEM_CLIENT_IDS_PARAM``.

    The parameter exists because the pool references this function, so the
    function's environment cannot reference the pool's clients (CloudFormation
    cycle). It's cached for five minutes; if SSM is unreachable the last value
    is kept, and with no value at all unknown clients simply get tenant checks.
    """
    s = settings or get_settings()
    ids = set(s.system_client_ids)
    if not s.system_client_ids_param:
        return frozenset(ids)
    now = time.monotonic()
    cached = _state.system_ids
    if cached is None or now - cached[0] >= SYSTEM_IDS_TTL:
        try:
            resp = client("ssm", s.region, profile="trigger").get_parameter(
                Name=s.system_client_ids_param
            )
            value = str(resp["Parameter"]["Value"])
            _state.system_ids = (now, frozenset(p.strip() for p in value.split(",") if p.strip()))
        except Exception:
            logger.exception("could not load system client IDs")
    if _state.system_ids is not None:
        ids |= _state.system_ids[1]
    return frozenset(ids)


def is_system_client(client_id: str, settings: Settings | None = None) -> bool:
    return client_id in system_client_ids(settings)


def resolve_tenant(client_id: str) -> ResolvedClient:
    reg = registry()
    mapping = reg.get_client(client_id)
    if mapping is None:
        raise AccessDenied(f"client {client_id} is not mapped to a tenant")
    tenant = reg.get_tenant(mapping.tenant_id)
    if tenant is None:
        raise AccessDenied(f"tenant {mapping.tenant_id} not found for client {client_id}")
    if not tenant.is_active:
        raise AccessDenied(f"tenant {tenant.tenant_id} is {tenant.status.value}")
    return ResolvedClient(tenant=tenant, kind=mapping.kind)


def require_membership(tenant: Tenant, sub: str) -> Membership:
    membership = registry().get_membership(tenant.tenant_id, sub)
    if membership is None:
        raise AccessDenied(f"user {sub} is not a member of {tenant.tenant_id}")
    return membership


def federated_provider(user_attributes: dict[str, Any]) -> str | None:
    """IdP name for a federated user (from the ``identities`` attribute)."""
    raw = user_attributes.get("identities")
    if not raw:
        return None
    try:
        identities = json.loads(raw) if isinstance(raw, str) else raw
        return str(identities[0]["providerName"])
    except (ValueError, KeyError, IndexError, TypeError):
        return None
