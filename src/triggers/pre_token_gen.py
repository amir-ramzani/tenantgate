"""Pre-token-generation trigger, V3 event (plan, Phases 3, 6 and 7).

User flows (authorization code, refresh token, ...):

* re-check tenant status and membership — the authoritative gate, because
  pre-authentication is skipped on managed-login cookie sessions (a user signed
  in to tenant A can otherwise hit tenant B's authorize URL);
* add ``tenant_id`` / ``tenant_role`` to the ID and access tokens;
* narrow scopes by role (members lose ``api/write``) and strip tenant-scoped
  M2M scopes, which user clients must never carry.

Client credentials (``TokenGeneration_ClientCredentials``, V3 only):

* the client must be an M2M client of an active tenant;
* add ``tenant_id`` and ``tenant_role=service``;
* suppress every scope that doesn't belong to this tenant.

Federated users without a membership get one just in time when the tenant
allows their IdP — primary Region only, to keep a single registry writer.
"""

from __future__ import annotations

from typing import Any

from aws_lambda_powertools.utilities.typing import LambdaContext

from authlib_mt.context import M2M_ROLE, TENANT_ID_CLAIM, TENANT_ROLE_CLAIM
from authlib_mt.scopes import generic_scope, parse_tenant_scope
from tenantgate.models import ClientKind, Membership, Role, Tenant
from tenantgate.settings import get_settings
from triggers.common import (
    AccessDenied,
    client_id_of,
    federated_provider,
    is_system_client,
    logger,
    registry,
    resolve_tenant,
)

CLIENT_CREDENTIALS = "TokenGeneration_ClientCredentials"

# Generic actions each role may NOT hold.
DENIED_ACTIONS: dict[Role, frozenset[str]] = {
    Role.ADMIN: frozenset(),
    Role.MEMBER: frozenset({"write"}),
}


def _requested_scopes(event: dict[str, Any]) -> list[str]:
    return [str(s) for s in (event["request"].get("scopes") or [])]


def _user_flow(event: dict[str, Any], tenant: Tenant, kind: ClientKind) -> dict[str, Any]:
    if kind is not ClientKind.USER:
        raise AccessDenied("M2M client used in a user flow")
    attrs = event["request"]["userAttributes"]
    sub = str(attrs["sub"])
    membership = registry().get_membership(tenant.tenant_id, sub) or _jit_membership(
        event, tenant, attrs
    )
    if membership is None:
        raise AccessDenied(f"user {sub} is not a member of {tenant.tenant_id}")

    rs = get_settings().resource_server_id
    denied = {generic_scope(a, rs) for a in DENIED_ACTIONS[membership.role]}
    suppress = [s for s in _requested_scopes(event) if s in denied or s.startswith(f"{rs}/tenant.")]

    claims = {TENANT_ID_CLAIM: tenant.tenant_id, TENANT_ROLE_CLAIM: membership.role.value}
    access: dict[str, Any] = {"claimsToAddOrOverride": dict(claims)}
    if suppress:
        access["scopesToSuppress"] = suppress
    event["response"]["claimsAndScopeOverrideDetails"] = {
        "idTokenGeneration": {"claimsToAddOrOverride": dict(claims)},
        "accessTokenGeneration": access,
    }
    return event


def _jit_membership(
    event: dict[str, Any], tenant: Tenant, attrs: dict[str, Any]
) -> Membership | None:
    provider = federated_provider(attrs)
    if provider is None or provider == "COGNITO" or provider not in tenant.allowed_idps:
        return None
    if not get_settings().is_primary:
        logger.warning("JIT membership skipped outside the primary Region", provider=provider)
        return None
    membership = Membership(
        tenant_id=tenant.tenant_id,
        sub=str(attrs["sub"]),
        role=Role.MEMBER,
        username=str(event.get("userName") or attrs["sub"]),
        email=attrs.get("email"),
    )
    registry().put_membership(membership)
    logger.info("JIT membership created", provider=provider)
    return membership


def _client_credentials_flow(
    event: dict[str, Any], tenant: Tenant, kind: ClientKind
) -> dict[str, Any]:
    if kind is not ClientKind.M2M:
        raise AccessDenied("user client used for client_credentials")
    rs = get_settings().resource_server_id
    suppress = []
    for scope in _requested_scopes(event):
        parsed = parse_tenant_scope(scope, rs)
        if parsed is None or parsed[0] != tenant.tenant_id:
            suppress.append(scope)
    access: dict[str, Any] = {
        "claimsToAddOrOverride": {TENANT_ID_CLAIM: tenant.tenant_id, TENANT_ROLE_CLAIM: M2M_ROLE}
    }
    if suppress:
        access["scopesToSuppress"] = suppress
    event["response"]["claimsAndScopeOverrideDetails"] = {"accessTokenGeneration": access}
    return event


@logger.inject_lambda_context(clear_state=True)
def handler(event: dict[str, Any], context: LambdaContext) -> dict[str, Any]:
    source = str(event.get("triggerSource", ""))
    logger.append_keys(trigger_source=source)
    try:
        client_id = client_id_of(event)
        logger.append_keys(client_id=client_id)
        if is_system_client(client_id):
            return event
        resolved = resolve_tenant(client_id)
        logger.append_keys(tenant_id=resolved.tenant.tenant_id)
        if source == CLIENT_CREDENTIALS:
            return _client_credentials_flow(event, resolved.tenant, resolved.kind)
        return _user_flow(event, resolved.tenant, resolved.kind)
    except AccessDenied as exc:
        logger.warning("token generation denied", reason=exc.reason)
        raise
