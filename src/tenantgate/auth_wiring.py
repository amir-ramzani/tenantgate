"""Glue between ``authlib_mt`` (boto3-free) and this deployment's settings/registry."""

from __future__ import annotations

from authlib_mt import CachedTenantDirectory, JWKSCache, TokenValidator, http_fetcher
from tenantgate.registry import TenantRegistry
from tenantgate.settings import Settings


class RegistryDirectory:
    """``TenantDirectory`` backed by the local replica of the tenant registry."""

    def __init__(self, registry: TenantRegistry) -> None:
        self._registry = registry

    def tenant_for_client(self, client_id: str) -> str | None:
        mapping = self._registry.get_client(client_id)
        return mapping.tenant_id if mapping else None

    def is_tenant_active(self, tenant_id: str) -> bool:
        tenant = self._registry.get_tenant(tenant_id)
        return bool(tenant and tenant.is_active)


def build_directory(registry: TenantRegistry, *, ttl: float = 30.0) -> CachedTenantDirectory:
    return CachedTenantDirectory(RegistryDirectory(registry), ttl=ttl)


def build_validator(
    settings: Settings, *, allowed_client_ids: tuple[str, ...] | None = None
) -> TokenValidator:
    return TokenValidator(
        issuers=settings.issuers,
        jwks=JWKSCache(http_fetcher(settings.jwks_endpoint)),
        allowed_client_ids=allowed_client_ids,
    )
