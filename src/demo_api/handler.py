"""Lambda entry point for the demo API (API Gateway HTTP API via Mangum)."""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from aws_lambda_powertools import Logger
from mangum import Mangum

from demo_api.app import DemoDeps, create_app
from demo_api.notes import NotesRepository
from tenantgate.auth_wiring import build_directory, build_validator
from tenantgate.aws import dynamodb_table
from tenantgate.registry import TenantRegistry
from tenantgate.settings import get_settings

logger = Logger(service="tenantgate-demo-api")


@lru_cache(maxsize=1)
def build_deps() -> DemoDeps:
    s = get_settings()
    if not s.notes_table_name:
        raise RuntimeError("NOTES_TABLE_NAME is not set")
    registry = TenantRegistry(dynamodb_table(s.table_name, s.region))
    return DemoDeps(
        validator=build_validator(s),
        directory=build_directory(registry),
        notes=NotesRepository(dynamodb_table(s.notes_table_name, s.region)),
        region=s.region,
    )


app = create_app(build_deps, resource_server=get_settings().resource_server_id)
_mangum = Mangum(app, lifespan="off", api_gateway_base_path="/demo")


@logger.inject_lambda_context(clear_state=True)
def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    return dict(_mangum(event, context))
