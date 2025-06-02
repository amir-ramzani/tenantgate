from __future__ import annotations

from typing import Any

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from authlib_mt import (
    CachedTenantDirectory,
    InvalidToken,
    MissingTenant,
    TenantContext,
    TokenValidator,
    build_context,
)
from authlib_mt.fastapi import TenantAuth
from authlib_mt.scopes import normalize_scopes, parse_tenant_scope, tenant_scope
from tests.conftest import TENANT_A, TENANT_B, TokenFactory


class Directory:
    def __init__(self) -> None:
        self.clients = {"client-a": TENANT_A, "client-b": TENANT_B, "m2m-a": TENANT_A}
        self.inactive: set[str] = set()
        self.calls = 0

    def tenant_for_client(self, client_id: str) -> str | None:
        self.calls += 1
        return self.clients.get(client_id)

    def is_tenant_active(self, tenant_id: str) -> bool:
        return tenant_id not in self.inactive


def _claims(**kw: Any) -> dict[str, Any]:
    base = {"sub": "u1", "client_id": "client-a", "tenant_id": TENANT_A, "scope": "api/read"}
    return {**base, **kw}


# ---------------------------------------------------------------- scopes


def test_scope_helpers() -> None:
    s = tenant_scope(TENANT_A, "write")
    assert s == f"api/tenant.{TENANT_A}.write"
    assert parse_tenant_scope(s) == (TENANT_A, "write")
    assert parse_tenant_scope("api/tenant.bad.read") is None
    assert parse_tenant_scope(f"api/tenant.{TENANT_A}.admin") is None
    assert normalize_scopes(
        [tenant_scope(TENANT_A, "read"), tenant_scope(TENANT_B, "write"), "api/write"], TENANT_A
    ) == {"api/read", "api/write"}
    assert normalize_scopes(["api/tenant.garbage.read"], TENANT_A) == frozenset()


# ---------------------------------------------------------------- context


def test_build_context() -> None:
    ctx = build_context(_claims(tenant_role="admin", **{"cognito:groups": ["g"]}), Directory())
    assert ctx.tenant_id == TENANT_A and ctx.is_admin and not ctx.is_m2m
    assert ctx.groups == {"g"}
    assert ctx.has_scopes("api/read") and not ctx.has_scopes("api/write")


def test_missing_or_malformed_tenant() -> None:
    with pytest.raises(MissingTenant):
        build_context(_claims(tenant_id=None), Directory())
    with pytest.raises(MissingTenant):
        build_context(_claims(tenant_id="acme"), Directory())


def test_client_of_another_tenant() -> None:
    with pytest.raises(InvalidToken, match="not registered"):
        build_context(_claims(client_id="client-b"), Directory())
    with pytest.raises(InvalidToken, match="not registered"):
        build_context(_claims(client_id="revoked"), Directory())


def test_disabled_tenant() -> None:
    d = Directory()
    d.inactive.add(TENANT_A)
    with pytest.raises(InvalidToken, match="not active"):
        build_context(_claims(), d)


def test_cached_directory() -> None:
    now = [0.0]
    inner = Directory()
    d = CachedTenantDirectory(inner, ttl=10, clock=lambda: now[0])
    assert d.tenant_for_client("client-a") == TENANT_A
    assert d.tenant_for_client("client-a") == TENANT_A
    assert inner.calls == 1
    now[0] = 11
    d.tenant_for_client("client-a")
    assert inner.calls == 2
    d.invalidate()
    d.tenant_for_client("client-a")
    assert inner.calls == 3


# ---------------------------------------------------------------- FastAPI


@pytest.fixture
def client(validator: TokenValidator) -> TestClient:
    auth = TenantAuth(validator, Directory())
    app = FastAPI()

    @app.get("/tenants/{tenant_id}/things")
    def read(ctx: TenantContext = Depends(auth.require("api/read"))) -> dict[str, str]:
        return {"tenant": ctx.tenant_id, "role": ctx.role}

    @app.post("/tenants/{tenant_id}/things")
    def write(ctx: TenantContext = Depends(auth.require("api/write"))) -> dict[str, str]:
        return {"tenant": ctx.tenant_id}

    return TestClient(app)


def _h(token: str, **extra: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", **extra}


def test_fastapi_happy_path(client: TestClient, make_token: TokenFactory) -> None:
    r = client.get(f"/tenants/{TENANT_A}/things", headers=_h(make_token()))
    assert r.status_code == 200
    assert r.json() == {"tenant": TENANT_A, "role": "admin"}


def test_fastapi_missing_token(client: TestClient) -> None:
    r = client.get(f"/tenants/{TENANT_A}/things")
    assert r.status_code == 401
    assert "Bearer" in r.headers["www-authenticate"]
    assert (
        client.get(f"/tenants/{TENANT_A}/things", headers={"Authorization": "Basic x"}).status_code
        == 401
    )


def test_fastapi_cross_tenant_path(client: TestClient, make_token: TokenFactory) -> None:
    r = client.get(f"/tenants/{TENANT_B}/things", headers=_h(make_token()))
    assert r.status_code == 403


def test_fastapi_cross_tenant_header(client: TestClient, make_token: TokenFactory) -> None:
    r = client.get(
        f"/tenants/{TENANT_A}/things", headers=_h(make_token(), **{"X-Tenant-Id": TENANT_B})
    )
    assert r.status_code == 403


def test_fastapi_missing_scope(client: TestClient, make_token: TokenFactory) -> None:
    r = client.post(f"/tenants/{TENANT_A}/things", headers=_h(make_token(scope="api/read")))
    assert r.status_code == 403
    assert "insufficient_scope" in r.headers["www-authenticate"]


def test_fastapi_m2m_tenant_scope(client: TestClient, make_token: TokenFactory) -> None:
    token = make_token(client_id="m2m-a", role="service", scope=tenant_scope(TENANT_A, "write"))
    assert client.post(f"/tenants/{TENANT_A}/things", headers=_h(token)).status_code == 200
    # Scope for another tenant grants nothing.
    token = make_token(client_id="m2m-a", role="service", scope=tenant_scope(TENANT_B, "write"))
    assert client.post(f"/tenants/{TENANT_A}/things", headers=_h(token)).status_code == 403


def test_fastapi_expired(client: TestClient, make_token: TokenFactory) -> None:
    r = client.get(f"/tenants/{TENANT_A}/things", headers=_h(make_token(exp_in=-300)))
    assert r.status_code == 401
