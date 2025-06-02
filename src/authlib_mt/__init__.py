"""authlib_mt — validate Cognito access tokens and enforce tenant isolation.

The library is deliberately free of boto3 so any resource server can use it:
plug in a ``TenantDirectory`` that knows which client belongs to which tenant.
"""

from authlib_mt.context import (
    M2M_ROLE,
    TENANT_ID_CLAIM,
    TENANT_ROLE_CLAIM,
    CachedTenantDirectory,
    MissingTenant,
    TenantContext,
    TenantDirectory,
    TenantMismatch,
    build_context,
)
from authlib_mt.jwks import JWKSCache, JWKSUnavailable, UnknownKey, http_fetcher
from authlib_mt.validator import AuthUnavailable, InvalidToken, TokenValidator

__all__ = [
    "M2M_ROLE",
    "TENANT_ID_CLAIM",
    "TENANT_ROLE_CLAIM",
    "AuthUnavailable",
    "CachedTenantDirectory",
    "InvalidToken",
    "JWKSCache",
    "JWKSUnavailable",
    "MissingTenant",
    "TenantContext",
    "TenantDirectory",
    "TenantMismatch",
    "TokenValidator",
    "UnknownKey",
    "build_context",
    "http_fetcher",
]
