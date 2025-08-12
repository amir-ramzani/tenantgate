"""Control-plane HTTP API (FastAPI).

Callers authenticate with access tokens from the *system* app client (the
control-plane UI); tenant-client tokens are rejected outright. Authorisation:

* platform admin — member of the ``platform-admins`` Cognito group: create,
  list, delete tenants and change their status;
* tenant admin — ``admin`` membership in the registry: manage the tenant's
  settings, members and M2M clients;
* tenant member — read the tenant.

All writes are refused with ``503`` + ``Retry-After`` outside the primary
Region or while ``auth_mode=failover`` (single writer).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse

from authlib_mt import AuthUnavailable, InvalidToken, TokenValidator
from authlib_mt.fastapi import add_bearer_security, bearer_token
from control_plane.cognito import CognitoThrottled
from control_plane.schemas import (
    AddMember,
    CreateM2MClient,
    CreateTenant,
    M2MClientOut,
    MemberOut,
    MyTenant,
    StatusOut,
    TenantOut,
    TenantPage,
    UpdateMember,
    UpdateTenant,
)
from control_plane.service import Caller, Conflict, TenantService
from tenantgate.auth_mode import RETRY_AFTER_SECONDS, AuthModeProvider
from tenantgate.idempotency import (
    IdempotencyInProgress,
    IdempotencyMismatch,
    IdempotencyStore,
)
from tenantgate.models import Role, TenantStatus
from tenantgate.registry import NotFound
from tenantgate.settings import Settings

API_DESCRIPTION = """\
Tenant lifecycle API for tenantgate.

* Authenticate with an access token from the **system** app client (control-plane UI).
  Tokens of tenant clients are rejected.
* **Platform admins** (`platform-admins` group) create, list, delete tenants and change
  their status. **Tenant admins** manage settings, members and M2M clients of their tenant.
* All writes return `503` with `Retry-After` outside the primary Region or while
  `auth_mode=failover`.
"""

WRITE_RESPONSES: dict[int | str, dict[str, Any]] = {
    404: {"description": "Tenant, member or client not found (or caller is not a member)"},
    409: {"description": "Conflicts with the current state (e.g. removing the last admin)"},
    503: {"description": "Read-only: secondary Region, failover mode or Cognito throttling"},
}


@dataclass(frozen=True)
class Principal:
    sub: str
    username: str
    email: str | None
    groups: frozenset[str]
    is_platform_admin: bool

    @property
    def caller(self) -> Caller:
        return Caller(self.sub, self.username, self.email)


@dataclass
class Deps:
    settings: Settings
    validator: TokenValidator
    service: TenantService
    mode: AuthModeProvider
    idempotency: IdempotencyStore | None = None


def _service_unavailable(detail: str) -> HTTPException:
    return HTTPException(
        status.HTTP_503_SERVICE_UNAVAILABLE,
        detail,
        headers={"Retry-After": str(RETRY_AFTER_SECONDS)},
    )


def create_app(get_deps: Callable[[], Deps]) -> FastAPI:
    app = FastAPI(
        title="tenantgate control plane",
        version="0.1.0",
        description=API_DESCRIPTION,
        servers=[{"url": "/control", "description": "behind https://api.<domain>"}],
        openapi_tags=[
            {"name": "status", "description": "Region role and degraded-mode flag (public)"},
            {"name": "me", "description": "The calling operator"},
            {"name": "tenants", "description": "Tenant lifecycle"},
            {"name": "members", "description": "Tenant membership and roles"},
            {"name": "m2m-clients", "description": "Client-credentials clients and rotation"},
        ],
    )
    add_bearer_security(app, public_paths={"/status"})

    # ------------------------------------------------------------ error mapping

    @app.exception_handler(NotFound)
    def _not_found(_: Request, exc: NotFound) -> JSONResponse:
        return JSONResponse({"detail": "not found"}, status_code=404)

    @app.exception_handler(Conflict)
    def _conflict(_: Request, exc: Conflict) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=409)

    @app.exception_handler(CognitoThrottled)
    def _throttled(_: Request, exc: CognitoThrottled) -> JSONResponse:
        return JSONResponse(
            {"detail": "identity provider is busy, retry later"},
            status_code=503,
            headers={"Retry-After": "5"},
        )

    # ------------------------------------------------------------ dependencies

    def deps() -> Deps:
        return get_deps()

    def principal(
        d: Deps = Depends(deps), authorization: str | None = Header(default=None)
    ) -> Principal:
        token = bearer_token(authorization)
        try:
            claims = d.validator.validate(token)
        except AuthUnavailable as exc:
            raise _service_unavailable("authentication temporarily unavailable") from exc
        except InvalidToken as exc:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                str(exc),
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            ) from exc
        if "tenant_id" in claims:
            # Defence in depth: the validator is configured with the system clients only.
            raise HTTPException(status.HTTP_403_FORBIDDEN, "tenant tokens are not accepted")
        groups = frozenset(str(g) for g in claims.get("cognito:groups") or [])
        return Principal(
            sub=str(claims["sub"]),
            username=str(claims.get("username") or claims["sub"]),
            email=claims.get("email"),
            groups=groups,
            is_platform_admin=d.settings.platform_admin_group in groups,
        )

    def writable(d: Deps = Depends(deps)) -> None:
        if not d.mode.writes_allowed():
            raise _service_unavailable("control plane is read-only during failover")

    def platform_admin(p: Principal = Depends(principal)) -> Principal:
        if not p.is_platform_admin:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "platform admin required")
        return p

    def tenant_role(d: Deps, p: Principal, tenant_id: str) -> Role | None:
        m = d.service.registry.get_membership(tenant_id, p.sub)
        return m.role if m else None

    def tenant_reader(
        tenant_id: str, d: Deps = Depends(deps), p: Principal = Depends(principal)
    ) -> Principal:
        if p.is_platform_admin or tenant_role(d, p, tenant_id) is not None:
            return p
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")  # don't leak existence

    def tenant_admin(
        tenant_id: str, d: Deps = Depends(deps), p: Principal = Depends(principal)
    ) -> Principal:
        role = tenant_role(d, p, tenant_id)
        if p.is_platform_admin or role is Role.ADMIN:
            return p
        if role is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        raise HTTPException(status.HTTP_403_FORBIDDEN, "tenant admin required")

    # ------------------------------------------------------------ public

    @app.get("/status", tags=["status"], response_model=StatusOut)
    def get_status(d: Deps = Depends(deps)) -> dict[str, Any]:
        """
        Region, Region role, degraded-mode flag and whether writes are accepted. No authentication.
        """
        return d.mode.status().as_dict()

    @app.get("/me/tenants", tags=["me"], response_model=list[MyTenant])
    def my_tenants(d: Deps = Depends(deps), p: Principal = Depends(principal)) -> list[MyTenant]:
        """Tenants the caller belongs to (for a "choose workspace" screen)."""
        out = []
        for m in d.service.registry.list_user_tenants(p.sub):
            t = d.service.registry.get_tenant(m.tenant_id)
            out.append(
                MyTenant(
                    tenant_id=m.tenant_id,
                    name=t.name if t else None,
                    role=m.role,
                    status=t.status if t else None,
                )
            )
        return out

    # ------------------------------------------------------------ tenants

    @app.post(
        "/tenants",
        tags=["tenants"],
        responses=WRITE_RESPONSES,
        status_code=status.HTTP_201_CREATED,
        response_model=TenantOut,
        dependencies=[Depends(writable)],
    )
    def create_tenant(
        body: CreateTenant,
        response: Response,
        d: Deps = Depends(deps),
        p: Principal = Depends(platform_admin),
        idempotency_key: str | None = Header(default=None, max_length=128),
    ) -> Any:
        """
        Create a tenant: app client (code + PKCE), tenant scopes, registry record, and the caller as
        its first admin. Send `Idempotency-Key` to make retries safe; a replay returns the stored
        response with `Idempotent-Replayed: true`.
        """
        store = d.idempotency if idempotency_key else None
        if store is not None and idempotency_key:
            try:
                replay = store.begin(p.sub, idempotency_key, body.model_dump())
            except IdempotencyMismatch as exc:
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
            except IdempotencyInProgress as exc:
                raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
            if replay is not None:
                response.status_code = replay.status_code
                response.headers["Idempotent-Replayed"] = "true"
                return replay.body
        try:
            tenant = d.service.create_tenant(
                name=body.name,
                creator=p.caller,
                callback_urls=body.callback_urls,
                logout_urls=body.logout_urls,
                plan=body.plan,
                allowed_idps=body.allowed_idps,
            )
        except Exception:
            if store is not None and idempotency_key:
                store.release(p.sub, idempotency_key)
            raise
        out = TenantOut.of(tenant).model_dump(mode="json")
        if store is not None and idempotency_key:
            store.complete(p.sub, idempotency_key, status.HTTP_201_CREATED, out)
        return out

    @app.get("/tenants", tags=["tenants"], response_model=TenantPage)
    def list_tenants(
        d: Deps = Depends(deps),
        _: Principal = Depends(platform_admin),
        limit: int = Query(default=50, ge=1, le=100),
        start: str | None = None,
    ) -> TenantPage:
        """List tenants, paginated with `start` (the `next` value of the previous page)."""
        tenants, nxt = d.service.list_tenants(limit=limit, start=start)
        return TenantPage(items=[TenantOut.of(t) for t in tenants], next=nxt)

    @app.get("/tenants/{tenant_id}", tags=["tenants"], response_model=TenantOut)
    def get_tenant(
        tenant_id: str, d: Deps = Depends(deps), _: Principal = Depends(tenant_reader)
    ) -> TenantOut:
        """Read a tenant. Non-members get `404`."""
        return TenantOut.of(d.service.get_tenant(tenant_id))

    @app.patch(
        "/tenants/{tenant_id}",
        tags=["tenants"],
        responses=WRITE_RESPONSES,
        response_model=TenantOut,
        dependencies=[Depends(writable)],
    )
    def update_tenant(
        tenant_id: str,
        body: UpdateTenant,
        d: Deps = Depends(deps),
        p: Principal = Depends(tenant_admin),
    ) -> TenantOut:
        """
        Update settings. Changing `callback_urls`, `logout_urls` or `allowed_idps` reconfigures the
        app client. Only platform admins may change `status`; disabling a tenant revokes OAuth on
        all of its clients.
        """
        if body.status is not None and not p.is_platform_admin:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "only platform admins change status")
        tenant = d.service.update_tenant(
            tenant_id,
            name=body.name,
            callback_urls=body.callback_urls,
            logout_urls=body.logout_urls,
            allowed_idps=body.allowed_idps,
            status=TenantStatus(body.status) if body.status else None,
        )
        return TenantOut.of(tenant)

    @app.delete(
        "/tenants/{tenant_id}",
        tags=["tenants"],
        responses=WRITE_RESPONSES,
        status_code=status.HTTP_204_NO_CONTENT,
        dependencies=[Depends(writable)],
    )
    def delete_tenant(
        tenant_id: str, d: Deps = Depends(deps), _: Principal = Depends(platform_admin)
    ) -> Response:
        """
        Delete a tenant, its clients, scopes and memberships. Members who belong to no other tenant
        are signed out.
        """
        d.service.delete_tenant(tenant_id)
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    # ------------------------------------------------------------ members

    @app.get("/tenants/{tenant_id}/members", tags=["members"], response_model=list[MemberOut])
    def list_members(
        tenant_id: str, d: Deps = Depends(deps), _: Principal = Depends(tenant_admin)
    ) -> list[MemberOut]:
        return [MemberOut.of(m) for m in d.service.list_members(tenant_id)]

    @app.post(
        "/tenants/{tenant_id}/members",
        tags=["members"],
        responses=WRITE_RESPONSES,
        status_code=status.HTTP_201_CREATED,
        response_model=MemberOut,
        dependencies=[Depends(writable)],
    )
    def add_member(
        tenant_id: str,
        body: AddMember,
        d: Deps = Depends(deps),
        _: Principal = Depends(tenant_admin),
    ) -> MemberOut:
        """Invite a user by email (created in Cognito if needed) or add an existing user."""
        return MemberOut.of(d.service.add_member(tenant_id, body.email, body.role))

    @app.patch(
        "/tenants/{tenant_id}/members/{sub}",
        tags=["members"],
        responses=WRITE_RESPONSES,
        response_model=MemberOut,
        dependencies=[Depends(writable)],
    )
    def update_member(
        tenant_id: str,
        sub: str,
        body: UpdateMember,
        d: Deps = Depends(deps),
        _: Principal = Depends(tenant_admin),
    ) -> MemberOut:
        """Change a member's role. The member is signed out so new tokens carry the new role."""
        return MemberOut.of(d.service.set_member_role(tenant_id, sub, body.role))

    @app.delete(
        "/tenants/{tenant_id}/members/{sub}",
        tags=["members"],
        responses=WRITE_RESPONSES,
        status_code=status.HTTP_204_NO_CONTENT,
        dependencies=[Depends(writable)],
    )
    def remove_member(
        tenant_id: str, sub: str, d: Deps = Depends(deps), _: Principal = Depends(tenant_admin)
    ) -> Response:
        """Remove a member and revoke their refresh tokens. The last admin cannot be removed."""
        d.service.remove_member(tenant_id, sub)
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    # ------------------------------------------------------------ M2M clients

    @app.post(
        "/tenants/{tenant_id}/m2m-clients",
        tags=["m2m-clients"],
        responses=WRITE_RESPONSES,
        status_code=status.HTTP_201_CREATED,
        response_model=M2MClientOut,
        dependencies=[Depends(writable)],
    )
    def create_m2m(
        tenant_id: str,
        body: CreateM2MClient,
        response: Response,
        d: Deps = Depends(deps),
        _: Principal = Depends(tenant_admin),
    ) -> M2MClientOut:
        """
        Create a client-credentials client with tenant-scoped scopes. The secret is returned
        **once**.
        """
        response.headers["Cache-Control"] = "no-store"
        creds = d.service.create_m2m_client(tenant_id, body.name, list(body.actions))
        return M2MClientOut.of(creds, d.settings.resource_server_id)

    @app.post(
        "/tenants/{tenant_id}/m2m-clients/{client_id}/rotate",
        tags=["m2m-clients"],
        responses=WRITE_RESPONSES,
        status_code=status.HTTP_201_CREATED,
        response_model=M2MClientOut,
        dependencies=[Depends(writable)],
    )
    def rotate_m2m(
        tenant_id: str,
        client_id: str,
        response: Response,
        d: Deps = Depends(deps),
        _: Principal = Depends(tenant_admin),
    ) -> M2MClientOut:
        """
        Create a replacement client. The old one keeps working until `old_client_retires_at`, then
        is deleted by an hourly job.
        """
        response.headers["Cache-Control"] = "no-store"
        creds = d.service.rotate_m2m_client(
            tenant_id, client_id, grace=timedelta(hours=d.settings.m2m_rotation_grace_hours)
        )
        return M2MClientOut.of(creds, d.settings.resource_server_id)

    @app.delete(
        "/tenants/{tenant_id}/m2m-clients/{client_id}",
        tags=["m2m-clients"],
        responses=WRITE_RESPONSES,
        status_code=status.HTTP_204_NO_CONTENT,
        dependencies=[Depends(writable)],
    )
    def delete_m2m(
        tenant_id: str,
        client_id: str,
        d: Deps = Depends(deps),
        _: Principal = Depends(tenant_admin),
    ) -> Response:
        """Delete an M2M client immediately."""
        d.service.delete_m2m_client(tenant_id, client_id)
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    return app
