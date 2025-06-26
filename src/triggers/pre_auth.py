"""Pre-authentication trigger (plan, Phase 3).

Resolves the tenant from the app client and rejects the sign-in when the
client is unknown, the tenant is disabled, or the user isn't a member.
System clients (control-plane UI, canary) skip tenant checks.

This trigger does NOT run when managed login reuses a session cookie, so the
pre-token-generation trigger repeats the membership check.
"""

from __future__ import annotations

from typing import Any

from aws_lambda_powertools.utilities.typing import LambdaContext

from triggers.common import (
    AccessDenied,
    client_id_of,
    is_system_client,
    logger,
    require_membership,
    resolve_tenant,
)


@logger.inject_lambda_context(clear_state=True)
def handler(event: dict[str, Any], context: LambdaContext) -> dict[str, Any]:
    logger.append_keys(trigger_source=event.get("triggerSource"))
    try:
        client_id = client_id_of(event)
        logger.append_keys(client_id=client_id)
        if is_system_client(client_id):
            return event
        resolved = resolve_tenant(client_id)
        logger.append_keys(tenant_id=resolved.tenant.tenant_id)
        if resolved.kind.value != "user":
            raise AccessDenied("M2M client used for user sign-in")
        require_membership(resolved.tenant, event["request"]["userAttributes"]["sub"])
    except AccessDenied as exc:
        logger.warning("sign-in denied", reason=exc.reason)
        raise
    return event
