"""Smoke tests for the Lambda entry points (Mangum wiring and env-driven setup)."""

from __future__ import annotations

import importlib
import json
from dataclasses import dataclass
from typing import Any

import pytest

from tests.conftest import create_notes_table


@dataclass
class Ctx:
    function_name: str = "fn"
    memory_limit_in_mb: int = 256
    invoked_function_arn: str = "arn:aws:lambda:ap-southeast-1:123456789012:function:fn"
    aws_request_id: str = "req"


def http_event(path: str, method: str = "GET", stage_prefix: str = "") -> dict[str, Any]:
    return {
        "version": "2.0",
        "routeKey": "$default",
        "rawPath": f"{stage_prefix}{path}",
        "rawQueryString": "",
        "headers": {"host": "api.example.test"},
        "requestContext": {
            "http": {
                "method": method,
                "path": f"{stage_prefix}{path}",
                "sourceIp": "1.2.3.4",
                "protocol": "HTTP/1.1",
            },
            "requestId": "r",
            "stage": "$default",
        },
        "isBase64Encoded": False,
    }


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch, table: Any) -> None:
    monkeypatch.setenv("USER_POOL_ID", "ap-southeast-1_test")
    monkeypatch.setenv("NOTES_TABLE_NAME", "tenantgate-notes")
    monkeypatch.setenv("SYSTEM_CLIENT_IDS", "sys")
    create_notes_table()


def test_control_plane_status(env: None) -> None:
    import control_plane.handler as h

    importlib.reload(h)
    resp = h.handler(http_event("/status", stage_prefix="/control"), Ctx())
    assert resp["statusCode"] == 200
    body = json.loads(resp["body"])
    assert body["region_role"] == "primary" and body["writes_allowed"] is True


def test_control_plane_requires_token(env: None) -> None:
    import control_plane.handler as h

    importlib.reload(h)
    resp = h.handler(http_event("/tenants", stage_prefix="/control"), Ctx())
    assert resp["statusCode"] == 401


def test_purge_handler_skips_in_secondary(env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REGION_ROLE", "secondary")
    from tenantgate.settings import get_settings

    get_settings.cache_clear()
    import control_plane.handler as h

    importlib.reload(h)
    assert h.purge_handler({}, Ctx()) == {"purged": [], "skipped": True}


def test_demo_api_health(env: None) -> None:
    import demo_api.handler as h

    importlib.reload(h)
    resp = h.handler(http_event("/health", stage_prefix="/demo"), Ctx())
    assert resp["statusCode"] == 200
    assert json.loads(resp["body"])["status"] == "ok"
    assert resp["headers"]["x-served-region"] == "ap-southeast-1"
