"""FastAPI integration.

Usage::

    auth = TenantAuth(validator, directory)

    @app.get("/tenants/{tenant_id}/notes")
    def list_notes(ctx: TenantContext = Depends(auth.require("api/read"))): ...

``require`` validates the bearer token, builds a ``TenantContext`` and checks
that the tenant named in the path (``tenant_id``) and, if sent, the
``X-Tenant-Id`` header both equal the token's tenant. Errors map to:

* 401 — missing/invalid token, token not bound to an active tenant
* 403 — wrong tenant, or missing scope
* 503 — signing keys unavailable (retryable)
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.openapi.utils import get_openapi

from authlib_mt.context import (
    TenantContext,
    TenantDirectory,
    TenantMismatch,
    build_context,
    ensure_same_tenant,
)
from authlib_mt.scopes import DEFAULT_RESOURCE_SERVER
from authlib_mt.validator import AuthUnavailable, InvalidToken, TokenValidator

TENANT_HEADER = "X-Tenant-Id"


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
    )


def bearer_token(authorization: str | None) -> str:
    if not authorization:
        raise _unauthorized("missing bearer token")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise _unauthorized("missing bearer token")
    return token.strip()


class TenantAuth:
    def __init__(
        self,
        validator: TokenValidator | Callable[[], TokenValidator],
        directory: TenantDirectory | Callable[[], TenantDirectory],
        *,
        resource_server: str = DEFAULT_RESOURCE_SERVER,
        path_param: str = "tenant_id",
    ) -> None:
        # Accept factories so apps can build validators lazily (cold start, tests).
        self._validator = validator
        self._directory = directory
        self._rs = resource_server
        self._path_param = path_param

    def _get_validator(self) -> TokenValidator:
        v = self._validator
        return v if isinstance(v, TokenValidator) else v()

    def _get_directory(self) -> TenantDirectory:
        d = self._directory
        if hasattr(d, "tenant_for_client"):
            return cast(TenantDirectory, d)
        return d()

    def validate(self, authorization: str | None) -> dict[str, Any]:
        token = bearer_token(authorization)
        try:
            return self._get_validator().validate(token)
        except AuthUnavailable as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="authentication temporarily unavailable",
                headers={"Retry-After": "5"},
            ) from exc
        except InvalidToken as exc:
            raise _unauthorized(str(exc)) from exc

    def claims(self) -> Callable[..., dict[str, Any]]:
        """Dependency returning validated claims without tenant binding."""

        def dependency(authorization: str | None = Header(default=None)) -> dict[str, Any]:
            return self.validate(authorization)

        return dependency

    def context(self, request: Request, authorization: str | None) -> TenantContext:
        claims = self.validate(authorization)
        try:
            ctx = build_context(claims, self._get_directory(), resource_server=self._rs)
        except InvalidToken as exc:
            raise _unauthorized(str(exc)) from exc
        try:
            ensure_same_tenant(ctx, request.path_params.get(self._path_param))
            ensure_same_tenant(ctx, request.headers.get(TENANT_HEADER))
        except TenantMismatch as exc:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "tenant mismatch") from exc
        return ctx

    def require(self, *scopes: str) -> Callable[..., TenantContext]:
        """Dependency yielding a ``TenantContext`` that holds all ``scopes``."""

        def dependency(
            request: Request, authorization: str | None = Header(default=None)
        ) -> TenantContext:
            ctx = self.context(request, authorization)
            missing = [s for s in scopes if s not in ctx.scopes]
            if missing:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"missing scope: {' '.join(missing)}",
                    headers={
                        "WWW-Authenticate": (
                            f'Bearer error="insufficient_scope", scope="{" ".join(scopes)}"'
                        )
                    },
                )
            return ctx

        return dependency


def add_bearer_security(app: FastAPI, *, public_paths: set[str] | None = None) -> None:
    """Document bearer auth in the app's OpenAPI schema.

    The dependencies read the ``Authorization`` header directly, so FastAPI would
    list it as a plain header parameter. This replaces it with a ``bearerAuth``
    security scheme and adds the shared 401/403 responses to every protected
    operation. Paths in ``public_paths`` are left unauthenticated.
    """
    public = public_paths or set()

    def openapi() -> dict[str, Any]:
        if app.openapi_schema:
            return app.openapi_schema
        schema = get_openapi(
            title=app.title,
            version=app.version,
            description=app.description,
            routes=app.routes,
            servers=app.servers,
            tags=app.openapi_tags,
        )
        schema.setdefault("components", {}).setdefault("securitySchemes", {})["bearerAuth"] = {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "Cognito access token",
        }
        for path, operations in schema.get("paths", {}).items():
            if path in public:
                continue
            for op in operations.values():
                params = [
                    p
                    for p in op.get("parameters", [])
                    if not (
                        p.get("in") == "header" and p.get("name", "").lower() == "authorization"
                    )
                ]
                if params:
                    op["parameters"] = params
                else:
                    op.pop("parameters", None)
                op["security"] = [{"bearerAuth": []}]
                responses = op.setdefault("responses", {})
                responses.setdefault("401", {"description": "Missing, invalid or expired token"})
                responses.setdefault("403", {"description": "Wrong tenant, role or scope"})
                responses.setdefault(
                    "503", {"description": "Signing keys temporarily unavailable; retry"}
                )
                if "parameters" not in op and "requestBody" not in op:
                    responses.pop("422", None)  # nothing left to validate
        app.openapi_schema = schema
        return schema

    app.openapi = openapi  # type: ignore[method-assign]
