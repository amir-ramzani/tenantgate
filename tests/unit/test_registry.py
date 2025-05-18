from __future__ import annotations

import re

import pytest

from tenantgate.models import (
    ClientKind,
    ClientMapping,
    Membership,
    Role,
    Tenant,
    TenantStatus,
    new_tenant_id,
)
from tenantgate.registry import AlreadyExists, NotFound, TenantRegistry
from tests.conftest import TENANT_A, TENANT_B


def _tenant(tid: str = TENANT_A, **kw: object) -> Tenant:
    return Tenant(tenant_id=tid, name=f"name-{tid}", app_client_ids=[f"app-{tid}"], **kw)  # type: ignore[arg-type]


def test_new_tenant_id_format() -> None:
    ids = {new_tenant_id() for _ in range(50)}
    assert len(ids) == 50
    assert all(re.fullmatch(r"t-[a-z0-9]{12}", i) for i in ids)


def test_create_get_roundtrip(registry: TenantRegistry) -> None:
    registry.create_tenant(_tenant(callback_urls=["https://a.test/cb"]))
    got = registry.get_tenant(TENANT_A)
    assert got is not None
    assert got.name == f"name-{TENANT_A}"
    assert got.callback_urls == ["https://a.test/cb"]
    assert got.is_active


def test_create_is_conditional(registry: TenantRegistry) -> None:
    registry.create_tenant(_tenant())
    with pytest.raises(AlreadyExists):
        registry.create_tenant(_tenant())


def test_missing_tenant(registry: TenantRegistry) -> None:
    assert registry.get_tenant("t-nope00000000") is None
    with pytest.raises(NotFound):
        registry.require_tenant("t-nope00000000")
    with pytest.raises(NotFound):
        registry.set_status("t-nope00000000", TenantStatus.DISABLED)


def test_status_and_save(registry: TenantRegistry) -> None:
    registry.create_tenant(_tenant())
    registry.set_status(TENANT_A, TenantStatus.DISABLED)
    t = registry.require_tenant(TENANT_A)
    assert t.status is TenantStatus.DISABLED
    t.name = "renamed"
    registry.save_tenant(t)
    again = registry.require_tenant(TENANT_A)
    assert again.name == "renamed"
    assert again.updated_at


def test_list_tenants_paginates(registry: TenantRegistry) -> None:
    ids = sorted(f"t-{i:012d}" for i in range(5))
    for tid in ids:
        registry.create_tenant(_tenant(tid))
    page, nxt = registry.list_tenants(limit=3)
    assert len(page) == 3 and nxt is not None
    rest, _ = registry.list_tenants(limit=10, start=nxt)
    assert sorted(t.tenant_id for t in [*page, *rest]) == ids


def test_memberships(registry: TenantRegistry) -> None:
    registry.create_tenant(_tenant(TENANT_A))
    registry.create_tenant(_tenant(TENANT_B))
    registry.put_membership(Membership(TENANT_A, "u1", Role.ADMIN, "alice"))
    registry.put_membership(Membership(TENANT_A, "u2", Role.MEMBER, "bob"))
    registry.put_membership(Membership(TENANT_B, "u1", Role.MEMBER, "alice"))

    assert registry.get_membership(TENANT_A, "u1").role is Role.ADMIN  # type: ignore[union-attr]
    assert registry.get_membership(TENANT_B, "u2") is None
    assert {m.sub for m in registry.list_members(TENANT_A)} == {"u1", "u2"}
    assert registry.count_admins(TENANT_A) == 1
    assert {m.tenant_id for m in registry.list_user_tenants("u1")} == {TENANT_A, TENANT_B}

    with pytest.raises(AlreadyExists):
        registry.put_membership(Membership(TENANT_A, "u2", Role.ADMIN, "bob"), overwrite=False)

    assert registry.delete_membership(TENANT_A, "u2") is True
    assert registry.delete_membership(TENANT_A, "u2") is False


def test_client_mapping_and_cascade_delete(registry: TenantRegistry) -> None:
    registry.create_tenant(_tenant(m2m_client_ids=["m2m-1"]))
    registry.put_client(ClientMapping(f"app-{TENANT_A}", TENANT_A, ClientKind.USER))
    registry.put_client(
        ClientMapping("m2m-1", TENANT_A, ClientKind.M2M, name="etl", actions=("read",))
    )
    registry.put_membership(Membership(TENANT_A, "u1", Role.ADMIN, "alice"))

    m2m = registry.get_client("m2m-1")
    assert m2m is not None and m2m.kind is ClientKind.M2M and m2m.actions == ("read",)

    registry.delete_tenant(TENANT_A)
    assert registry.get_tenant(TENANT_A) is None
    assert registry.get_client("m2m-1") is None
    assert registry.get_client(f"app-{TENANT_A}") is None
    assert registry.list_user_tenants("u1") == []
