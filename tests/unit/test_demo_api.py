from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from authlib_mt.scopes import tenant_scope
from demo_api.app import DemoDeps, create_app
from demo_api.notes import NotesRepository
from tenantgate.auth_wiring import RegistryDirectory
from tenantgate.models import ClientKind, ClientMapping, Tenant, TenantStatus
from tenantgate.registry import TenantRegistry
from tests.conftest import TENANT_A, TENANT_B, TokenFactory, create_notes_table


@pytest.fixture
def setup(registry: TenantRegistry, validator: Any) -> tuple[TestClient, TenantRegistry]:
    for tid in (TENANT_A, TENANT_B):
        registry.create_tenant(Tenant(tenant_id=tid, name=tid))
        registry.put_client(ClientMapping(f"app-{tid}", tid, ClientKind.USER))
        registry.put_client(ClientMapping(f"m2m-{tid}", tid, ClientKind.M2M))
    # Uncached directory so status changes are visible immediately in tests.
    deps = DemoDeps(
        validator=validator,
        directory=RegistryDirectory(registry),
        notes=NotesRepository(create_notes_table()),
        region="ap-southeast-1",
    )
    return TestClient(create_app(lambda: deps)), registry


def _h(make_token: TokenFactory, tenant: str = TENANT_A, **kw: Any) -> dict[str, str]:
    kw.setdefault("client_id", f"app-{tenant}")
    return {"Authorization": f"Bearer {make_token(tenant_id=tenant, **kw)}"}


def _notes(t: str) -> str:
    return f"/tenants/{t}/notes"


def test_crud(setup: tuple[TestClient, TenantRegistry], make_token: TokenFactory) -> None:
    client, _ = setup
    h = _h(make_token, sub="alice")
    r = client.post(_notes(TENANT_A), json={"title": "hello", "body": "world"}, headers=h)
    assert r.status_code == 201, r.text
    assert r.headers["x-served-region"] == "ap-southeast-1"
    note = r.json()
    assert note["tenant_id"] == TENANT_A and note["author"] == "alice"
    nid = note["note_id"]

    assert [n["note_id"] for n in client.get(_notes(TENANT_A), headers=h).json()] == [nid]
    r = client.put(f"{_notes(TENANT_A)}/{nid}", json={"title": "t2"}, headers=h)
    assert r.json()["title"] == "t2" and r.json()["updated_at"]
    assert client.delete(f"{_notes(TENANT_A)}/{nid}", headers=h).status_code == 204
    assert client.get(f"{_notes(TENANT_A)}/{nid}", headers=h).status_code == 404
    assert (
        client.put(f"{_notes(TENANT_A)}/{nid}", json={"title": "x"}, headers=h).status_code == 404
    )


def test_tenant_isolation(
    setup: tuple[TestClient, TenantRegistry], make_token: TokenFactory
) -> None:
    client, _ = setup
    a = _h(make_token, TENANT_A)
    b = _h(make_token, TENANT_B)
    nid = client.post(_notes(TENANT_A), json={"title": "secret"}, headers=a).json()["note_id"]

    # B's token on A's route: 403 before any data access.
    assert client.get(_notes(TENANT_A), headers=b).status_code == 403
    assert client.get(f"{_notes(TENANT_A)}/{nid}", headers=b).status_code == 403
    # B's own partition doesn't contain A's note.
    assert client.get(_notes(TENANT_B), headers=b).json() == []
    assert client.get(f"{_notes(TENANT_B)}/{nid}", headers=b).status_code == 404


def test_token_claim_and_client_must_agree(
    setup: tuple[TestClient, TenantRegistry], make_token: TokenFactory
) -> None:
    client, _ = setup
    # tenant_id claim says A but the client belongs to B (e.g. forged claim injection).
    h = _h(make_token, TENANT_A, client_id=f"app-{TENANT_B}")
    assert client.get(_notes(TENANT_A), headers=h).status_code == 401


def test_member_cannot_write(
    setup: tuple[TestClient, TenantRegistry], make_token: TokenFactory
) -> None:
    client, _ = setup
    h = _h(make_token, role="member", scope="openid api/read")
    assert client.get(_notes(TENANT_A), headers=h).status_code == 200
    assert client.post(_notes(TENANT_A), json={"title": "x"}, headers=h).status_code == 403


def test_disabled_tenant(
    setup: tuple[TestClient, TenantRegistry], make_token: TokenFactory
) -> None:
    client, registry = setup
    registry.set_status(TENANT_A, TenantStatus.DISABLED)
    assert client.get(_notes(TENANT_A), headers=_h(make_token)).status_code == 401


def test_m2m_with_tenant_scopes(
    setup: tuple[TestClient, TenantRegistry], make_token: TokenFactory
) -> None:
    client, _ = setup
    h = _h(
        make_token,
        client_id=f"m2m-{TENANT_A}",
        role="service",
        scope=f"{tenant_scope(TENANT_A, 'read')} {tenant_scope(TENANT_A, 'write')}",
    )
    assert client.post(_notes(TENANT_A), json={"title": "etl"}, headers=h).status_code == 201
    who = client.get(f"/tenants/{TENANT_A}/whoami", headers=h).json()
    assert who["is_m2m"] is True and who["scopes"] == ["api/read", "api/write"]


def test_m2m_scope_for_other_tenant(
    setup: tuple[TestClient, TenantRegistry], make_token: TokenFactory
) -> None:
    client, _ = setup
    h = _h(
        make_token,
        client_id=f"m2m-{TENANT_A}",
        role="service",
        scope=tenant_scope(TENANT_B, "read"),
    )
    assert client.get(_notes(TENANT_A), headers=h).status_code == 403


def test_negative_token_cases(
    setup: tuple[TestClient, TenantRegistry], make_token: TokenFactory, other_key: Any
) -> None:
    client, _ = setup
    for kw in ({"exp_in": -600}, {"key": other_key}, {"token_use": "id"}, {"tenant_id": None}):
        token = make_token(client_id=f"app-{TENANT_A}", **{"tenant_id": TENANT_A, **kw})
        r = client.get(_notes(TENANT_A), headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 401, kw


def test_health(setup: tuple[TestClient, TenantRegistry]) -> None:
    client, _ = setup
    assert client.get("/health").json() == {"status": "ok", "region": "ap-southeast-1"}


def test_validation(setup: tuple[TestClient, TenantRegistry], make_token: TokenFactory) -> None:
    client, _ = setup
    r = client.post(_notes(TENANT_A), json={"title": ""}, headers=_h(make_token))
    assert r.status_code == 422
