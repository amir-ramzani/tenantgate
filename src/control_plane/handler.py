"""Lambda entry points for the control plane.

* ``handler`` — API Gateway HTTP API (payload v2) via Mangum.
* ``purge_handler`` — EventBridge schedule that removes rotated M2M clients
  after their grace period (primary Region only).
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from aws_lambda_powertools import Logger
from mangum import Mangum

from control_plane.app import Deps, create_app
from control_plane.cognito import CognitoAdmin
from control_plane.service import TenantService
from tenantgate.auth_mode import AuthModeProvider
from tenantgate.auth_wiring import build_validator
from tenantgate.aws import client, dynamodb_table
from tenantgate.idempotency import IdempotencyStore
from tenantgate.registry import TenantRegistry
from tenantgate.settings import get_settings
from triggers.common import system_client_ids

logger = Logger(service="tenantgate-control-plane")


@lru_cache(maxsize=1)
def build_deps() -> Deps:
    s = get_settings()
    registry = TenantRegistry(dynamodb_table(s.table_name, s.region), consistent_reads=s.is_primary)
    cognito = CognitoAdmin(
        client("cognito-idp", s.region), s.user_pool_id, resource_server_id=s.resource_server_id
    )
    idempotency = (
        IdempotencyStore(dynamodb_table(s.idempotency_table_name, s.region))
        if s.idempotency_table_name
        else None
    )
    return Deps(
        settings=s,
        validator=build_validator(s, allowed_client_ids=tuple(system_client_ids(s)) or None),
        service=TenantService(registry, cognito),
        mode=AuthModeProvider(s, client("ssm", s.region)),
        idempotency=idempotency,
    )


app = create_app(build_deps)
_mangum = Mangum(app, lifespan="off", api_gateway_base_path="/control")


@logger.inject_lambda_context(clear_state=True)
def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    return dict(_mangum(event, context))


@logger.inject_lambda_context(clear_state=True)
def purge_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    deps = build_deps()
    if not deps.mode.writes_allowed():
        logger.info("skipping purge: writes not allowed in this Region/mode")
        return {"purged": [], "skipped": True}
    purged = deps.service.purge_retired_clients()
    logger.info("purged retired M2M clients", count=len(purged))
    return {"purged": purged, "skipped": False}
