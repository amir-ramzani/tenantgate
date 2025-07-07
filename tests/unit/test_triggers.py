from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import boto3
import pytest

from authlib_mt.scopes import tenant_scope
from tenantgate.models import (
    ClientKind,
    ClientMapping,
    Membership,
    Role,
    Tenant,
    TenantStatus,
)
from tenantgate.registry import TenantRegistry
from tests.conftest import REGION, TENANT_A, TENANT_B
from triggers import common, pre_auth, pre_token_gen
from triggers.common import AccessDenied


@dataclass
class Ctx:
    function_name: str = "trigger"
    memory_limit_in_mb: int = 512
    invoked_function_arn: str = "arn:aws:lambda:ap-southeast-1:123456789012:function:trigger"
    aws_request_id: str = "req-1"


@pytest.fixture
def reg(registry: TenantRegistry, monkeypatch: pytest.MonkeyPatch) -> Iterator[TenantRegistry]:
    monkeypatch.setenv("SYSTEM_CLIENT_IDS", "system-ui")
    from tenantgate.settings import get_settings

    get_settings.cache_clear()
    for tid in (TENANT_A, TENANT_B):
        registry.create_tenant(
            Tenant(
                tenant_id=tid,
                name=tid,
                app_client_ids=[f"app-{tid}"],
                allowed_idps=["COGNITO", "Okta"],
            )
        )
        registry.put_client(ClientMapping(f"app-{tid}", tid, ClientKind.USER))
        registry.put_client(ClientMapping(f"m2m-{tid}", tid, ClientKind.M2M))
    registry.put_membership(Membership(TENANT_A, "admin-a", Role.ADMIN, "alice"))
    registry.put_membership(Membership(TENANT_A, "member-a", Role.MEMBER, "bob"))
    registry.put_membership(Membership(TENANT_B, "admin-b", Role.ADMIN, "carol"))
    common.reset_state(registry)
    yield registry
    common.reset_state()


def user_event(
    client_id: str,
    sub: str,
    *,
    source: str = "TokenGeneration_Authentication",
    scopes: list[str] | None = None,
    attrs: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "version": "3",
        "triggerSource": source,
        "region": REGION,
        "userPoolId": "pool",
        "userName": sub,
        "callerContext": {"clientId": client_id},
        "request": {
            "userAttributes": {"sub": sub, "email": f"{sub}@example.test", **(attrs or {})},
            "scopes": scopes or ["openid", "api/read", "api/write"],
        },
        "response": {},
    }


def m2m_event(client_id: str, scopes: list[str]) -> dict[str, Any]:
    return {
        "version": "3",
        "triggerSource": pre_token_gen.CLIENT_CREDENTIALS,
        "region": REGION,
        "userPoolId": "pool",
        "callerContext": {"clientId": client_id},
        "request": {"scopes": scopes},
        "response": {},
    }


def access_overrides(event: dict[str, Any]) -> dict[str, Any]:
    return dict(event["response"]["claimsAndScopeOverrideDetails"]["accessTokenGeneration"])


# ---------------------------------------------------------------- pre-auth


def test_pre_auth_allows_member(reg: TenantRegistry) -> None:
    ev = user_event(f"app-{TENANT_A}", "member-a", source="PreAuthentication_Authentication")
    assert pre_auth.handler(ev, Ctx()) is ev


@pytest.mark.parametrize(
    ("client_id", "sub"),
    [
        (f"app-{TENANT_B}", "admin-a"),  # member of A signing in to B
        ("unknown-client", "admin-a"),
        (f"m2m-{TENANT_A}", "admin-a"),  # M2M client used for sign-in
    ],
)
def test_pre_auth_denies(reg: TenantRegistry, client_id: str, sub: str) -> None:
    with pytest.raises(AccessDenied, match="Access denied"):
        pre_auth.handler(user_event(client_id, sub), Ctx())


def test_pre_auth_denies_disabled_tenant(reg: TenantRegistry) -> None:
    reg.set_status(TENANT_A, TenantStatus.DISABLED)
    with pytest.raises(AccessDenied):
        pre_auth.handler(user_event(f"app-{TENANT_A}", "admin-a"), Ctx())


def test_pre_auth_missing_client_id(reg: TenantRegistry) -> None:
    ev = user_event("x", "admin-a")
    ev["callerContext"] = {}
    with pytest.raises(AccessDenied):
        pre_auth.handler(ev, Ctx())


def test_system_client_bypasses(reg: TenantRegistry) -> None:
    ev = user_event("system-ui", "nobody")
    assert pre_auth.handler(ev, Ctx()) is ev
    assert pre_token_gen.handler(user_event("system-ui", "nobody"), Ctx())["response"] == {}


def test_system_clients_from_ssm(reg: TenantRegistry, monkeypatch: pytest.MonkeyPatch) -> None:
    boto3.client("ssm", region_name=REGION).put_parameter(
        Name="/tg/system", Value="canary-1, canary-2", Type="String"
    )
    monkeypatch.setenv("SYSTEM_CLIENT_IDS_PARAM", "/tg/system")
    from tenantgate.settings import get_settings

    get_settings.cache_clear()
    assert common.system_client_ids() == {"system-ui", "canary-1", "canary-2"}


def test_system_clients_ssm_failure_falls_back(
    reg: TenantRegistry, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SYSTEM_CLIENT_IDS_PARAM", "/missing")
    from tenantgate.settings import get_settings

    get_settings.cache_clear()
    assert common.system_client_ids() == {"system-ui"}


# ---------------------------------------------------------------- pre-token, user flows


def test_admin_gets_claims_and_all_scopes(reg: TenantRegistry) -> None:
    ev = pre_token_gen.handler(user_event(f"app-{TENANT_A}", "admin-a"), Ctx())
    details = ev["response"]["claimsAndScopeOverrideDetails"]
    expected = {"tenant_id": TENANT_A, "tenant_role": "admin"}
    assert details["idTokenGeneration"]["claimsToAddOrOverride"] == expected
    assert details["accessTokenGeneration"]["claimsToAddOrOverride"] == expected
    assert "scopesToSuppress" not in details["accessTokenGeneration"]


def test_member_loses_write(reg: TenantRegistry) -> None:
    ev = pre_token_gen.handler(user_event(f"app-{TENANT_A}", "member-a"), Ctx())
    access = access_overrides(ev)
    assert access["claimsToAddOrOverride"]["tenant_role"] == "member"
    assert access["scopesToSuppress"] == ["api/write"]


def test_user_flow_strips_tenant_scopes(reg: TenantRegistry) -> None:
    scopes = ["openid", "api/read", tenant_scope(TENANT_A, "write"), tenant_scope(TENANT_B, "read")]
    ev = pre_token_gen.handler(user_event(f"app-{TENANT_A}", "admin-a", scopes=scopes), Ctx())
    assert access_overrides(ev)["scopesToSuppress"] == scopes[2:]


def test_cross_tenant_cookie_session_fails_closed(reg: TenantRegistry) -> None:
    """Signed in to A; managed-login cookie reused at B's authorize URL.

    Pre-auth doesn't fire on cookie sessions, so pre-token-gen must deny."""
    ev = user_event(f"app-{TENANT_B}", "admin-a", source="TokenGeneration_HostedAuth")
    with pytest.raises(AccessDenied):
        pre_token_gen.handler(ev, Ctx())


def test_refresh_after_removal_is_denied(reg: TenantRegistry) -> None:
    reg.delete_membership(TENANT_A, "member-a")
    ev = user_event(f"app-{TENANT_A}", "member-a", source="TokenGeneration_RefreshTokens")
    with pytest.raises(AccessDenied):
        pre_token_gen.handler(ev, Ctx())


def test_refresh_after_tenant_disabled_is_denied(reg: TenantRegistry) -> None:
    reg.set_status(TENANT_A, TenantStatus.DISABLED)
    ev = user_event(f"app-{TENANT_A}", "admin-a", source="TokenGeneration_RefreshTokens")
    with pytest.raises(AccessDenied):
        pre_token_gen.handler(ev, Ctx())


def test_m2m_client_in_user_flow_denied(reg: TenantRegistry) -> None:
    with pytest.raises(AccessDenied):
        pre_token_gen.handler(user_event(f"m2m-{TENANT_A}", "admin-a"), Ctx())


# ---------------------------------------------------------------- JIT (federated)


def _federated(provider: str) -> dict[str, Any]:
    return {"identities": json.dumps([{"providerName": provider, "userId": "x"}])}


def test_jit_membership_for_allowed_idp(reg: TenantRegistry) -> None:
    ev = user_event(f"app-{TENANT_A}", "fed-1", attrs=_federated("Okta"))
    out = pre_token_gen.handler(ev, Ctx())
    assert access_overrides(out)["claimsToAddOrOverride"]["tenant_role"] == "member"
    m = reg.get_membership(TENANT_A, "fed-1")
    assert m is not None and m.role is Role.MEMBER


def test_jit_denied_for_other_idp(reg: TenantRegistry) -> None:
    with pytest.raises(AccessDenied):
        pre_token_gen.handler(
            user_event(f"app-{TENANT_A}", "fed-2", attrs=_federated("Evil")), Ctx()
        )


def test_jit_skipped_in_secondary(reg: TenantRegistry, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REGION_ROLE", "secondary")
    from tenantgate.settings import get_settings

    get_settings.cache_clear()
    with pytest.raises(AccessDenied):
        pre_token_gen.handler(
            user_event(f"app-{TENANT_A}", "fed-3", attrs=_federated("Okta")), Ctx()
        )
    assert reg.get_membership(TENANT_A, "fed-3") is None


def test_federated_provider_parsing() -> None:
    assert common.federated_provider({}) is None
    assert common.federated_provider({"identities": "not json"}) is None
    assert common.federated_provider({"identities": [{"providerName": "X"}]}) == "X"


# ---------------------------------------------------------------- client credentials


def test_m2m_gets_tenant_claim_and_keeps_own_scopes(reg: TenantRegistry) -> None:
    own = tenant_scope(TENANT_A, "read")
    foreign = tenant_scope(TENANT_B, "write")
    ev = pre_token_gen.handler(m2m_event(f"m2m-{TENANT_A}", [own, foreign, "api/write"]), Ctx())
    access = access_overrides(ev)
    assert access["claimsToAddOrOverride"] == {"tenant_id": TENANT_A, "tenant_role": "service"}
    assert access["scopesToSuppress"] == [foreign, "api/write"]
    assert "idTokenGeneration" not in ev["response"]["claimsAndScopeOverrideDetails"]


def test_user_client_cannot_do_client_credentials(reg: TenantRegistry) -> None:
    with pytest.raises(AccessDenied):
        pre_token_gen.handler(m2m_event(f"app-{TENANT_A}", []), Ctx())


def test_m2m_disabled_tenant(reg: TenantRegistry) -> None:
    reg.set_status(TENANT_A, TenantStatus.DISABLED)
    with pytest.raises(AccessDenied):
        pre_token_gen.handler(m2m_event(f"m2m-{TENANT_A}", []), Ctx())
