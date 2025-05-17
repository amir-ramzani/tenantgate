"""Environment-driven settings shared by every Lambda function in the service.

Everything is read once per execution environment (``get_settings`` is cached);
tests call ``get_settings.cache_clear()`` after changing the environment.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache


class RegionRole(StrEnum):
    PRIMARY = "primary"
    SECONDARY = "secondary"


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name, "").strip()
    return value or default


def _csv(name: str) -> tuple[str, ...]:
    return tuple(p.strip() for p in (os.environ.get(name) or "").split(",") if p.strip())


@dataclass(frozen=True)
class Settings:
    region: str
    region_role: RegionRole
    table_name: str
    user_pool_id: str
    issuers: tuple[str, ...]
    jwks_url: str | None
    resource_server_id: str
    system_client_ids: tuple[str, ...]
    system_client_ids_param: str | None
    platform_admin_group: str
    auth_mode_param: str | None
    idempotency_table_name: str | None
    notes_table_name: str | None
    m2m_rotation_grace_hours: int

    @property
    def is_primary(self) -> bool:
        return self.region_role is RegionRole.PRIMARY

    @property
    def jwks_endpoint(self) -> str:
        """Explicit JWKS URL, else the first issuer's well-known document."""
        if self.jwks_url:
            return self.jwks_url
        if not self.issuers:
            raise RuntimeError("neither JWKS_URL nor TOKEN_ISSUERS/USER_POOL_ID is configured")
        return f"{self.issuers[0]}/.well-known/jwks.json"


def load_settings() -> Settings:
    region = _env("AWS_REGION") or _env("AWS_DEFAULT_REGION") or "ap-southeast-1"
    user_pool_id = _env("USER_POOL_ID", "") or ""
    issuers = _csv("TOKEN_ISSUERS")
    if not issuers and user_pool_id:
        # Default: the pool's regional issuer. Set TOKEN_ISSUERS explicitly when the
        # pool advertises a different `iss` (check its OIDC discovery document).
        issuers = (f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}",)
    return Settings(
        region=region,
        region_role=RegionRole(_env("REGION_ROLE") or RegionRole.PRIMARY.value),
        table_name=_env("TABLE_NAME", "tenantgate-registry") or "tenantgate-registry",
        user_pool_id=user_pool_id,
        issuers=issuers,
        jwks_url=_env("JWKS_URL"),
        resource_server_id=_env("RESOURCE_SERVER_ID", "api") or "api",
        system_client_ids=_csv("SYSTEM_CLIENT_IDS"),
        system_client_ids_param=_env("SYSTEM_CLIENT_IDS_PARAM"),
        platform_admin_group=_env("PLATFORM_ADMIN_GROUP", "platform-admins") or "platform-admins",
        auth_mode_param=_env("AUTH_MODE_PARAM"),
        idempotency_table_name=_env("IDEMPOTENCY_TABLE_NAME"),
        notes_table_name=_env("NOTES_TABLE_NAME"),
        m2m_rotation_grace_hours=int(_env("M2M_ROTATION_GRACE_HOURS", "24") or "24"),
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return load_settings()
