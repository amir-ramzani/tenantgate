"""Request/response models for the control-plane API."""

from __future__ import annotations

from typing import Annotated, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator

from control_plane.service import M2MCredentials
from tenantgate.models import Membership, Role, Tenant, TenantStatus

Action = Literal["read", "write"]
Name = Annotated[str, Field(min_length=1, max_length=100)]
Email = Annotated[str, Field(min_length=3, max_length=254, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")]
IdpName = Annotated[str, Field(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9_.-]+$")]


def _check_urls(urls: list[str]) -> list[str]:
    for url in urls:
        parsed = urlparse(url)
        local = parsed.hostname in {"localhost", "127.0.0.1"}
        if parsed.scheme != "https" and not (parsed.scheme == "http" and local):
            raise ValueError(
                f"{url!r}: callback/logout URLs must use https (http only for localhost)"
            )
        if parsed.fragment:
            raise ValueError(f"{url!r}: URLs must not contain a fragment")
    return urls


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CreateTenant(_Strict):
    name: Name
    callback_urls: list[str] = Field(min_length=1, max_length=20)
    logout_urls: list[str] = Field(default_factory=list, max_length=20)
    plan: Literal["standard", "premium"] = "standard"
    allowed_idps: list[IdpName] = Field(default_factory=lambda: ["COGNITO"], max_length=10)

    _urls = field_validator("callback_urls", "logout_urls")(_check_urls)


class UpdateTenant(_Strict):
    name: Name | None = None
    callback_urls: list[str] | None = Field(default=None, min_length=1, max_length=20)
    logout_urls: list[str] | None = Field(default=None, max_length=20)
    allowed_idps: list[IdpName] | None = Field(default=None, min_length=1, max_length=10)
    status: Literal[TenantStatus.ACTIVE, TenantStatus.DISABLED] | None = None

    @field_validator("callback_urls", "logout_urls")
    @classmethod
    def _urls(cls, v: list[str] | None) -> list[str] | None:
        return None if v is None else _check_urls(v)


class TenantOut(BaseModel):
    tenant_id: str
    name: str
    status: TenantStatus
    plan: str
    app_client_ids: list[str]
    m2m_client_ids: list[str]
    allowed_idps: list[str]
    callback_urls: list[str]
    logout_urls: list[str]
    created_at: str
    updated_at: str | None = None

    @classmethod
    def of(cls, t: Tenant) -> TenantOut:
        return cls(**t.__dict__)


class TenantPage(BaseModel):
    items: list[TenantOut]
    next: str | None = None


class AddMember(_Strict):
    email: Email
    role: Role = Role.MEMBER

    @field_validator("email")
    @classmethod
    def _lower(cls, v: str) -> str:
        return v.strip().lower()


class UpdateMember(_Strict):
    role: Role


class MemberOut(BaseModel):
    tenant_id: str
    sub: str
    role: Role
    username: str
    email: str | None
    created_at: str

    @classmethod
    def of(cls, m: Membership) -> MemberOut:
        return cls(**m.__dict__)


def _default_actions() -> list[Action]:
    return ["read"]


class CreateM2MClient(_Strict):
    name: Annotated[str, Field(min_length=1, max_length=48, pattern=r"^[a-z0-9][a-z0-9-]*$")]
    actions: list[Action] = Field(default_factory=_default_actions, min_length=1)

    @field_validator("actions")
    @classmethod
    def _dedupe(cls, v: list[Action]) -> list[Action]:
        return sorted(set(v))  # "read" < "write": canonical order, no duplicates


class M2MClientOut(BaseModel):
    client_id: str
    client_secret: str | None = Field(description="Returned once; store it securely")
    tenant_id: str
    name: str
    scopes: list[str]
    replaces: str | None = None
    old_client_retires_at: str | None = None

    @classmethod
    def of(cls, c: M2MCredentials, resource_server: str) -> M2MClientOut:
        from authlib_mt.scopes import tenant_scope

        return cls(
            client_id=c.client_id,
            client_secret=c.client_secret,
            tenant_id=c.tenant_id,
            name=c.name,
            scopes=[tenant_scope(c.tenant_id, a, resource_server) for a in c.actions],
            replaces=c.replaces,
            old_client_retires_at=c.old_client_retires_at,
        )


class MyTenant(BaseModel):
    tenant_id: str
    name: str | None
    role: Role
    status: TenantStatus | None


class StatusOut(BaseModel):
    region: str
    region_role: str
    auth_mode: str
    writes_allowed: bool
