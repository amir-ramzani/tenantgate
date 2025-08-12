from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta
from typing import Any

import boto3
import pytest
from fastapi.testclient import TestClient

from authlib_mt import JWKSCache, TokenValidator
from control_plane.app import Deps, create_app
from control_plane.cognito import CognitoAdmin
from control_plane.service import Caller, Conflict, TenantService
from tenantgate.idempotency import IdempotencyStore
from tenantgate.models import ClientKind, Role, TenantStatus, utcnow
from tenantgate.registry import NotFound, TenantRegistry
from tenantgate.settings import load_settings
from tests.conftest import ISSUER, REGION, TokenFactory, create_idempotency_table

ADMIN = Caller(sub="sub-admin", username="admin@example.test", email="admin@example.test")


class IdpWithScopes:
    """moto has no UpdateResourceServer: keep the resource server's scopes in memory
    and delegate every other call to the moto-backed client."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.scopes: list[dict[str, str]] = [
            {"ScopeName": "read", "ScopeDescription": "read"},
            {"ScopeName": "write", "ScopeDescription": "write"},
        ]

    def describe_resource_server(self, **_: Any) -> dict[str, Any]:
        return {"ResourceServer": {"Identifier": "api", "Name": "api", "Scopes": list(self.scopes)}}

    def update_resource_server(self, *, Scopes: list[dict[str, str]], **_: Any) -> None:
        self.scopes = list(Scopes)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


@pytest.fixture
def idp(user_pool: dict[str, str]) -> IdpWithScopes:
    return IdpWithScopes(boto3.client("cognito-idp", region_name=REGION))


@pytest.fixture
def cognito(idp: Any, user_pool: dict[str, str]) -> CognitoAdmin:
    return CognitoAdmin(idp, user_pool["pool_id"], managed_login_branding=False)


@pytest.fixture
def service(registry: TenantRegistry, cognito: CognitoAdmin) -> TenantService:
    return TenantService(registry, cognito)


def _scopes(idp: Any, pool_id: str) -> set[str]:
    rs = idp.describe_resource_server(UserPoolId=pool_id, Identifier="api")["ResourceServer"]
    return {s["ScopeName"] for s in rs["Scopes"]}


def _create(service: TenantService, name: str = "Acme") -> Any:
    return service.create_tenant(
        name=name, creator=ADMIN, callback_urls=["https://acme.test/cb"], logout_urls=[]
    )


# ================================================================ service


def test_create_tenant(service: TenantService, idp: Any, user_pool: dict[str, str]) -> None:
    t = _create(service)
    pool = user_pool["pool_id"]
    client = idp.describe_user_pool_client(UserPoolId=pool, ClientId=t.app_client_ids[0])
    cfg = client["UserPoolClient"]
    assert cfg["AllowedOAuthFlows"] == ["code"]
    assert cfg["CallbackURLs"] == ["https://acme.test/cb"]
    assert "ClientSecret" not in cfg
    assert {f"tenant.{t.tenant_id}.read", f"tenant.{t.tenant_id}.write"} <= _scopes(idp, pool)
    mapping = service.registry.get_client(t.app_client_ids[0])
    assert mapping is not None and mapping.kind is ClientKind.USER
    member = service.registry.get_membership(t.tenant_id, ADMIN.sub)
    assert member is not None and member.role is Role.ADMIN


def test_create_tenant_compensates_on_failure(
    service: TenantService, idp: Any, user_pool: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_: Any, **__: Any) -> None:
        raise RuntimeError("registry down")

    monkeypatch.setattr(service.registry, "put_membership", boom)
    with pytest.raises(RuntimeError):
        _create(service)
    pool = user_pool["pool_id"]
    assert idp.list_user_pool_clients(UserPoolId=pool, MaxResults=60)["UserPoolClients"] == []
    assert not any(s.startswith("tenant.") for s in _scopes(idp, pool))
    assert service.registry.list_tenants()[0] == []


def test_disable_and_enable(service: TenantService, idp: Any, user_pool: dict[str, str]) -> None:
    t = _create(service)
    service.update_tenant(t.tenant_id, status=TenantStatus.DISABLED)
    cfg = idp.describe_user_pool_client(
        UserPoolId=user_pool["pool_id"], ClientId=t.app_client_ids[0]
    )
    assert not cfg["UserPoolClient"].get("AllowedOAuthFlowsUserPoolClient")
    assert service.get_tenant(t.tenant_id).status is TenantStatus.DISABLED

    service.update_tenant(
        t.tenant_id, status=TenantStatus.ACTIVE, callback_urls=["https://n.test/cb"]
    )
    cfg = idp.describe_user_pool_client(
        UserPoolId=user_pool["pool_id"], ClientId=t.app_client_ids[0]
    )
    assert cfg["UserPoolClient"]["AllowedOAuthFlowsUserPoolClient"] is True
    assert cfg["UserPoolClient"]["CallbackURLs"] == ["https://n.test/cb"]

    with pytest.raises(Conflict):
        service.update_tenant(t.tenant_id, status=TenantStatus.DELETING)


def test_delete_tenant(service: TenantService, idp: Any, user_pool: dict[str, str]) -> None:
    t = _create(service)
    service.create_m2m_client(t.tenant_id, "etl", ["read"])
    service.delete_tenant(t.tenant_id)
    pool = user_pool["pool_id"]
    assert service.registry.get_tenant(t.tenant_id) is None
    assert idp.list_user_pool_clients(UserPoolId=pool, MaxResults=60)["UserPoolClients"] == []
    assert not any(s.startswith(f"tenant.{t.tenant_id}") for s in _scopes(idp, pool))
    with pytest.raises(NotFound):
        service.delete_tenant(t.tenant_id)


def test_members(service: TenantService) -> None:
    t = _create(service)
    m = service.add_member(t.tenant_id, "bob@example.test", Role.MEMBER)
    assert m.email == "bob@example.test"
    with pytest.raises(Conflict):
        service.add_member(t.tenant_id, "bob@example.test", Role.ADMIN)
    # Same Cognito user joins a second tenant.
    t2 = _create(service, "Other")
    m2 = service.add_member(t2.tenant_id, "bob@example.test", Role.ADMIN)
    assert m2.sub == m.sub

    assert service.set_member_role(t.tenant_id, m.sub, Role.ADMIN).role is Role.ADMIN
    service.remove_member(t.tenant_id, m.sub)
    assert service.registry.get_membership(t.tenant_id, m.sub) is None
    with pytest.raises(NotFound):
        service.remove_member(t.tenant_id, m.sub)


def test_last_admin_is_protected(service: TenantService) -> None:
    t = _create(service)
    with pytest.raises(Conflict):
        service.remove_member(t.tenant_id, ADMIN.sub)
    with pytest.raises(Conflict):
        service.set_member_role(t.tenant_id, ADMIN.sub, Role.MEMBER)


def test_add_member_to_disabled_tenant(service: TenantService) -> None:
    t = _create(service)
    service.update_tenant(t.tenant_id, status=TenantStatus.DISABLED)
    with pytest.raises(Conflict):
        service.add_member(t.tenant_id, "x@example.test", Role.MEMBER)


def test_m2m_lifecycle(service: TenantService, idp: Any, user_pool: dict[str, str]) -> None:
    t = _create(service)
    creds = service.create_m2m_client(t.tenant_id, "etl", ["read", "write"])
    assert creds.client_secret
    cfg = idp.describe_user_pool_client(UserPoolId=user_pool["pool_id"], ClientId=creds.client_id)
    assert cfg["UserPoolClient"]["AllowedOAuthFlows"] == ["client_credentials"]
    assert set(cfg["UserPoolClient"]["AllowedOAuthScopes"]) == {
        f"api/tenant.{t.tenant_id}.read",
        f"api/tenant.{t.tenant_id}.write",
    }

    now = utcnow()
    rotated = service.rotate_m2m_client(
        t.tenant_id, creds.client_id, grace=timedelta(hours=1), now=now
    )
    assert rotated.replaces == creds.client_id and rotated.client_id != creds.client_id
    with pytest.raises(Conflict):
        service.rotate_m2m_client(t.tenant_id, creds.client_id, grace=timedelta(hours=1))
    assert set(service.get_tenant(t.tenant_id).m2m_client_ids) == {
        creds.client_id,
        rotated.client_id,
    }

    assert service.purge_retired_clients(now) == []
    assert service.purge_retired_clients(now + timedelta(hours=2)) == [creds.client_id]
    assert service.get_tenant(t.tenant_id).m2m_client_ids == [rotated.client_id]
    assert service.registry.get_client(creds.client_id) is None

    with pytest.raises(NotFound):
        service.delete_m2m_client("t-otherotherot", rotated.client_id)
    service.delete_m2m_client(t.tenant_id, rotated.client_id)
    assert service.get_tenant(t.tenant_id).m2m_client_ids == []


# ================================================================ HTTP API


class Mode:
    def __init__(self) -> None:
        self.writes = True

    def writes_allowed(self) -> bool:
        return self.writes

    def status(self) -> Any:
        from tenantgate.auth_mode import AuthMode, ModeStatus

        return ModeStatus(
            REGION, "primary", AuthMode.NORMAL if self.writes else AuthMode.FAILOVER, self.writes
        )


@pytest.fixture
def api(
    service: TenantService, jwks_doc: dict[str, Any], aws: None
) -> Iterator[tuple[TestClient, Mode]]:
    mode = Mode()
    deps = Deps(
        settings=load_settings(),
        validator=TokenValidator(issuers=[ISSUER], jwks=JWKSCache(lambda: jwks_doc)),
        service=service,
        mode=mode,  # type: ignore[arg-type]
        idempotency=IdempotencyStore(create_idempotency_table()),
    )
    yield TestClient(create_app(lambda: deps)), mode


def _auth(
    make_token: TokenFactory, sub: str = ADMIN.sub, *, platform: bool = True
) -> dict[str, str]:
    token = make_token(
        sub=sub,
        client_id="system-ui",
        tenant_id=None,
        role=None,
        groups=["platform-admins"] if platform else [],
        extra={"username": sub},
    )
    return {"Authorization": f"Bearer {token}"}


BODY = {"name": "Acme", "callback_urls": ["https://acme.test/cb"]}


def test_api_create_and_read(api: tuple[TestClient, Mode], make_token: TokenFactory) -> None:
    client, _ = api
    r = client.post("/tenants", json=BODY, headers=_auth(make_token))
    assert r.status_code == 201, r.text
    tid = r.json()["tenant_id"]
    assert client.get(f"/tenants/{tid}", headers=_auth(make_token)).json()["name"] == "Acme"
    assert client.get("/tenants", headers=_auth(make_token)).json()["items"][0]["tenant_id"] == tid
    mine = client.get("/me/tenants", headers=_auth(make_token)).json()
    assert mine == [{"tenant_id": tid, "name": "Acme", "role": "admin", "status": "active"}]


def test_api_rejects_tenant_tokens(api: tuple[TestClient, Mode], make_token: TokenFactory) -> None:
    client, _ = api
    r = client.get("/tenants", headers={"Authorization": f"Bearer {make_token()}"})
    assert r.status_code == 403


def test_api_requires_platform_admin(
    api: tuple[TestClient, Mode], make_token: TokenFactory
) -> None:
    client, _ = api
    assert (
        client.post("/tenants", json=BODY, headers=_auth(make_token, platform=False)).status_code
        == 403
    )
    assert client.get("/tenants").status_code == 401


def test_api_validation(api: tuple[TestClient, Mode], make_token: TokenFactory) -> None:
    client, _ = api
    bad = {"name": "x", "callback_urls": ["http://evil.test/cb"]}
    assert client.post("/tenants", json=bad, headers=_auth(make_token)).status_code == 422
    ok_local = {"name": "x", "callback_urls": ["http://localhost:3000/cb"]}
    assert client.post("/tenants", json=ok_local, headers=_auth(make_token)).status_code == 201
    extra = {**BODY, "surprise": 1}
    assert client.post("/tenants", json=extra, headers=_auth(make_token)).status_code == 422


def test_api_idempotency(api: tuple[TestClient, Mode], make_token: TokenFactory) -> None:
    client, _ = api
    h = {**_auth(make_token), "Idempotency-Key": "k1"}
    first = client.post("/tenants", json=BODY, headers=h)
    again = client.post("/tenants", json=BODY, headers=h)
    assert first.status_code == again.status_code == 201
    assert again.headers.get("idempotent-replayed") == "true"
    assert first.json()["tenant_id"] == again.json()["tenant_id"]
    assert len(client.get("/tenants", headers=_auth(make_token)).json()["items"]) == 1
    changed = client.post("/tenants", json={**BODY, "name": "Other"}, headers=h)
    assert changed.status_code == 422


def test_api_degraded_mode(api: tuple[TestClient, Mode], make_token: TokenFactory) -> None:
    client, mode = api
    tid = client.post("/tenants", json=BODY, headers=_auth(make_token)).json()["tenant_id"]
    mode.writes = False
    r = client.post("/tenants", json=BODY, headers=_auth(make_token))
    assert r.status_code == 503 and r.headers["retry-after"]
    assert (
        client.patch(f"/tenants/{tid}", json={"name": "n"}, headers=_auth(make_token)).status_code
        == 503
    )
    # Reads keep working.
    assert client.get(f"/tenants/{tid}", headers=_auth(make_token)).status_code == 200
    assert client.get("/status").json()["auth_mode"] == "failover"


def test_api_tenant_roles(api: tuple[TestClient, Mode], make_token: TokenFactory) -> None:
    client, _ = api
    tid = client.post("/tenants", json=BODY, headers=_auth(make_token)).json()["tenant_id"]
    r = client.post(
        f"/tenants/{tid}/members",
        json={"email": "Bob@Example.test", "role": "member"},
        headers=_auth(make_token),
    )
    assert r.status_code == 201, r.text
    bob = r.json()["sub"]
    assert r.json()["email"] == "bob@example.test"

    bob_h = _auth(make_token, bob, platform=False)
    stranger = _auth(make_token, "stranger", platform=False)
    assert client.get(f"/tenants/{tid}", headers=bob_h).status_code == 200
    assert client.get(f"/tenants/{tid}", headers=stranger).status_code == 404
    assert client.get(f"/tenants/{tid}/members", headers=bob_h).status_code == 403
    assert client.patch(f"/tenants/{tid}", json={"name": "n"}, headers=bob_h).status_code == 403

    # Tenant admin (not platform admin) can rename but not change status.
    client.patch(f"/tenants/{tid}/members/{bob}", json={"role": "admin"}, headers=_auth(make_token))
    assert client.patch(f"/tenants/{tid}", json={"name": "n"}, headers=bob_h).status_code == 200
    assert (
        client.patch(f"/tenants/{tid}", json={"status": "disabled"}, headers=bob_h).status_code
        == 403
    )

    # Last-admin guard surfaces as 409.
    assert (
        client.delete(f"/tenants/{tid}/members/{bob}", headers=_auth(make_token)).status_code == 204
    )
    r = client.delete(f"/tenants/{tid}/members/{ADMIN.sub}", headers=_auth(make_token))
    assert r.status_code == 409


def test_api_m2m(api: tuple[TestClient, Mode], make_token: TokenFactory) -> None:
    client, _ = api
    tid = client.post("/tenants", json=BODY, headers=_auth(make_token)).json()["tenant_id"]
    r = client.post(
        f"/tenants/{tid}/m2m-clients",
        json={"name": "etl", "actions": ["write", "read", "read"]},
        headers=_auth(make_token),
    )
    assert r.status_code == 201, r.text
    assert r.headers["cache-control"] == "no-store"
    body = r.json()
    assert body["client_secret"]
    assert body["scopes"] == [f"api/tenant.{tid}.read", f"api/tenant.{tid}.write"]
    cid = body["client_id"]
    rot = client.post(f"/tenants/{tid}/m2m-clients/{cid}/rotate", headers=_auth(make_token))
    assert rot.status_code == 201 and rot.json()["replaces"] == cid
    assert rot.json()["old_client_retires_at"]
    assert (
        client.delete(f"/tenants/{tid}/m2m-clients/{cid}", headers=_auth(make_token)).status_code
        == 204
    )
    assert (
        client.delete(f"/tenants/{tid}/m2m-clients/{cid}", headers=_auth(make_token)).status_code
        == 404
    )


def test_api_delete(api: tuple[TestClient, Mode], make_token: TokenFactory) -> None:
    client, _ = api
    tid = client.post("/tenants", json=BODY, headers=_auth(make_token)).json()["tenant_id"]
    assert client.delete(f"/tenants/{tid}", headers=_auth(make_token)).status_code == 204
    assert client.get(f"/tenants/{tid}", headers=_auth(make_token)).status_code == 404
