"""Domain models stored in the tenant registry (plan §5)."""

from __future__ import annotations

import secrets
import string
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

_ID_ALPHABET = string.ascii_lowercase + string.digits


class TenantStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"
    DELETING = "deleting"


class Role(StrEnum):
    ADMIN = "admin"
    MEMBER = "member"


class ClientKind(StrEnum):
    USER = "user"  # public client: authorization code + PKCE via managed login
    M2M = "m2m"  # confidential client: client_credentials


def utcnow() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def utcnow_iso() -> str:
    return utcnow().isoformat()


def new_tenant_id() -> str:
    """``t-`` followed by 12 lowercase alphanumerics (matches ``authlib_mt.scopes``)."""
    return "t-" + "".join(secrets.choice(_ID_ALPHABET) for _ in range(12))


@dataclass
class Tenant:
    tenant_id: str
    name: str
    status: TenantStatus = TenantStatus.ACTIVE
    plan: str = "standard"
    app_client_ids: list[str] = field(default_factory=list)
    m2m_client_ids: list[str] = field(default_factory=list)
    allowed_idps: list[str] = field(default_factory=lambda: ["COGNITO"])
    callback_urls: list[str] = field(default_factory=list)
    logout_urls: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=utcnow_iso)
    updated_at: str | None = None

    @property
    def is_active(self) -> bool:
        return self.status is TenantStatus.ACTIVE


@dataclass(frozen=True)
class Membership:
    tenant_id: str
    sub: str
    role: Role
    username: str
    email: str | None = None
    created_at: str = field(default_factory=utcnow_iso)


@dataclass(frozen=True)
class ClientMapping:
    """Reverse lookup ``client_id -> tenant`` used by triggers and resource servers."""

    client_id: str
    tenant_id: str
    kind: ClientKind
    name: str | None = None
    actions: tuple[str, ...] = ()
    # Set while an M2M secret is being rotated: the old client may be purged after this.
    retire_after: str | None = None
