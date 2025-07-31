"""Tenant lifecycle (plan, Phases 2 and 6).

Creating a tenant touches two systems that can't share a transaction —
Cognito and DynamoDB — so it runs as a small saga: each completed step
registers a compensation, and any failure unwinds them in reverse order so a
half-created tenant never leaves an orphaned app client or scope behind.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta

from aws_lambda_powertools import Logger

from control_plane.cognito import CognitoAdmin
from tenantgate.models import (
    ClientKind,
    ClientMapping,
    Membership,
    Role,
    Tenant,
    TenantStatus,
    new_tenant_id,
    utcnow,
)
from tenantgate.registry import NotFound, TenantRegistry

logger = Logger(service="tenantgate-control-plane", child=True)


class Conflict(Exception):
    """The request is valid but conflicts with current state (409)."""


@dataclass(frozen=True)
class Caller:
    sub: str
    username: str
    email: str | None = None


@dataclass(frozen=True)
class M2MCredentials:
    client_id: str
    client_secret: str | None
    tenant_id: str
    name: str
    actions: tuple[str, ...]
    replaces: str | None = None
    old_client_retires_at: str | None = None


@dataclass
class Saga:
    """Collects compensations; ``unwind`` runs them newest first, best effort."""

    name: str
    _steps: list[tuple[str, Callable[[], object]]] = field(default_factory=list)

    def on_failure(self, label: str, undo: Callable[[], object]) -> None:
        self._steps.append((label, undo))

    def unwind(self) -> None:
        for label, undo in reversed(self._steps):
            try:
                undo()
            except Exception:
                logger.exception("compensation failed", saga=self.name, step=label)


class TenantService:
    def __init__(self, registry: TenantRegistry, cognito: CognitoAdmin) -> None:
        self.registry = registry
        self.cognito = cognito

    # ------------------------------------------------------------ tenants

    def create_tenant(
        self,
        *,
        name: str,
        creator: Caller,
        callback_urls: list[str],
        logout_urls: list[str],
        plan: str = "standard",
        allowed_idps: list[str] | None = None,
    ) -> Tenant:
        tenant_id = new_tenant_id()
        idps = allowed_idps or ["COGNITO"]
        saga = Saga(f"create-tenant:{tenant_id}")
        try:
            created = self.cognito.create_user_client(
                tenant_id,
                callback_urls=callback_urls,
                logout_urls=logout_urls,
                identity_providers=idps,
            )
            saga.on_failure(
                "delete app client", lambda: self.cognito.delete_client(created.client_id)
            )

            self.cognito.ensure_tenant_scopes(tenant_id)
            saga.on_failure("remove scopes", lambda: self.cognito.remove_tenant_scopes(tenant_id))

            tenant = Tenant(
                tenant_id=tenant_id,
                name=name,
                plan=plan,
                app_client_ids=[created.client_id],
                allowed_idps=idps,
                callback_urls=callback_urls,
                logout_urls=logout_urls,
            )
            self.registry.create_tenant(tenant)
            saga.on_failure("delete registry rows", lambda: self.registry.delete_tenant(tenant_id))

            self.registry.put_client(ClientMapping(created.client_id, tenant_id, ClientKind.USER))
            self.registry.put_membership(
                Membership(tenant_id, creator.sub, Role.ADMIN, creator.username, creator.email)
            )
        except Exception:
            saga.unwind()
            raise
        logger.info("tenant created", tenant_id=tenant_id)
        return tenant

    def get_tenant(self, tenant_id: str) -> Tenant:
        return self.registry.require_tenant(tenant_id)

    def list_tenants(
        self, limit: int = 50, start: str | None = None
    ) -> tuple[list[Tenant], str | None]:
        return self.registry.list_tenants(limit=limit, start=start)

    def update_tenant(
        self,
        tenant_id: str,
        *,
        name: str | None = None,
        callback_urls: list[str] | None = None,
        logout_urls: list[str] | None = None,
        allowed_idps: list[str] | None = None,
        status: TenantStatus | None = None,
    ) -> Tenant:
        tenant = self.registry.require_tenant(tenant_id)
        if tenant.status is TenantStatus.DELETING:
            raise Conflict("tenant is being deleted")
        reconfigure = any(v is not None for v in (callback_urls, logout_urls, allowed_idps))
        status_changed = status is not None and status is not tenant.status
        if name is not None:
            tenant.name = name
        if callback_urls is not None:
            tenant.callback_urls = callback_urls
        if logout_urls is not None:
            tenant.logout_urls = logout_urls
        if allowed_idps is not None:
            tenant.allowed_idps = allowed_idps
        if status is not None:
            if status is TenantStatus.DELETING:
                raise Conflict("use DELETE to delete a tenant")
            tenant.status = status

        # Disable: flag first (triggers + resource servers stop honouring the tenant
        # immediately), then revoke clients. Enable: clients first, then the flag.
        if status_changed and status is TenantStatus.DISABLED:
            self.registry.save_tenant(tenant)
            self._configure_clients(tenant)
        else:
            if reconfigure or status_changed:
                self._configure_clients(tenant)
            self.registry.save_tenant(tenant)
        return tenant

    def _configure_clients(self, tenant: Tenant) -> None:
        enabled = tenant.is_active
        for cid in tenant.app_client_ids:
            self.cognito.update_user_client(
                cid,
                tenant.tenant_id,
                callback_urls=tenant.callback_urls,
                logout_urls=tenant.logout_urls,
                identity_providers=tenant.allowed_idps,
                enabled=enabled,
            )
        for cid in tenant.m2m_client_ids:
            mapping = self.registry.get_client(cid)
            if mapping is None:
                continue
            self.cognito.set_m2m_client_enabled(
                cid,
                tenant.tenant_id,
                mapping.name or "client",
                list(mapping.actions),
                enabled=enabled,
            )

    def delete_tenant(self, tenant_id: str) -> None:
        tenant = self.registry.require_tenant(tenant_id)
        # Mark first: if we crash halfway, the tenant is already unusable and a retry
        # of DELETE picks up where we left off.
        self.registry.set_status(tenant_id, TenantStatus.DELETING)
        for cid in [*tenant.app_client_ids, *tenant.m2m_client_ids]:
            self.cognito.delete_client(cid)
        self.cognito.remove_tenant_scopes(tenant_id)
        for member in self.registry.list_members(tenant_id):
            if len(self.registry.list_user_tenants(member.sub)) <= 1:
                self.cognito.global_sign_out(member.username)
        self.registry.delete_tenant(tenant_id)
        logger.info("tenant deleted", tenant_id=tenant_id)

    # ------------------------------------------------------------ members

    def list_members(self, tenant_id: str) -> list[Membership]:
        self.registry.require_tenant(tenant_id)
        return self.registry.list_members(tenant_id)

    def add_member(self, tenant_id: str, email: str, role: Role) -> Membership:
        tenant = self.registry.require_tenant(tenant_id)
        if not tenant.is_active:
            raise Conflict("tenant is not active")
        user = self.cognito.invite_user(email)
        if self.registry.get_membership(tenant_id, user.sub) is not None:
            raise Conflict("user is already a member")
        membership = Membership(tenant_id, user.sub, role, user.username, user.email or email)
        try:
            self.registry.put_membership(membership, overwrite=False)
        except Exception:
            if user.created:
                self.cognito.delete_user(user.username)
            raise
        return membership

    def set_member_role(self, tenant_id: str, sub: str, role: Role) -> Membership:
        current = self.registry.get_membership(tenant_id, sub)
        if current is None:
            raise NotFound(sub)
        if current.role is role:
            return current
        if current.role is Role.ADMIN:
            self._ensure_not_last_admin(tenant_id)
        updated = Membership(
            tenant_id, sub, role, current.username, current.email, current.created_at
        )
        self.registry.put_membership(updated)
        # Existing tokens still carry the old role; force re-issue.
        self.cognito.global_sign_out(current.username)
        return updated

    def remove_member(self, tenant_id: str, sub: str) -> None:
        current = self.registry.get_membership(tenant_id, sub)
        if current is None:
            raise NotFound(sub)
        if current.role is Role.ADMIN:
            self._ensure_not_last_admin(tenant_id)
        self.registry.delete_membership(tenant_id, sub)
        # Revoke refresh tokens; pre-token-gen would refuse refreshes anyway.
        self.cognito.global_sign_out(current.username)

    def _ensure_not_last_admin(self, tenant_id: str) -> None:
        if self.registry.count_admins(tenant_id) <= 1:
            raise Conflict("a tenant needs at least one admin")

    # ------------------------------------------------------------ M2M clients

    def create_m2m_client(self, tenant_id: str, name: str, actions: list[str]) -> M2MCredentials:
        tenant = self.registry.require_tenant(tenant_id)
        if not tenant.is_active:
            raise Conflict("tenant is not active")
        return self._new_m2m(tenant, name, actions)

    def _new_m2m(
        self, tenant: Tenant, name: str, actions: list[str], *, replaces: str | None = None
    ) -> M2MCredentials:
        self.cognito.ensure_tenant_scopes(tenant.tenant_id)
        created = self.cognito.create_m2m_client(tenant.tenant_id, name, actions)
        try:
            self.registry.put_client(
                ClientMapping(
                    created.client_id, tenant.tenant_id, ClientKind.M2M, name, tuple(actions)
                )
            )
            fresh = self.registry.require_tenant(tenant.tenant_id)
            fresh.m2m_client_ids = [*fresh.m2m_client_ids, created.client_id]
            self.registry.save_tenant(fresh)
        except Exception:
            self.registry.delete_client(created.client_id)
            self.cognito.delete_client(created.client_id)
            raise
        return M2MCredentials(
            client_id=created.client_id,
            client_secret=created.client_secret,
            tenant_id=tenant.tenant_id,
            name=name,
            actions=tuple(actions),
            replaces=replaces,
        )

    def _owned_m2m(self, tenant_id: str, client_id: str) -> ClientMapping:
        mapping = self.registry.get_client(client_id)
        if mapping is None or mapping.tenant_id != tenant_id or mapping.kind is not ClientKind.M2M:
            raise NotFound(client_id)
        return mapping

    def rotate_m2m_client(
        self, tenant_id: str, client_id: str, *, grace: timedelta, now: datetime | None = None
    ) -> M2MCredentials:
        """Create a replacement client; the old one keeps working until the grace
        period ends and is then removed by ``purge_retired_clients``."""
        old = self._owned_m2m(tenant_id, client_id)
        if old.retire_after:
            raise Conflict("client is already being rotated")
        tenant = self.registry.require_tenant(tenant_id)
        creds = self._new_m2m(tenant, old.name or "client", list(old.actions), replaces=client_id)
        retire_at = ((now or utcnow()) + grace).isoformat()
        self.registry.put_client(
            ClientMapping(
                old.client_id, tenant_id, ClientKind.M2M, old.name, old.actions, retire_at
            )
        )
        return replace(creds, old_client_retires_at=retire_at)

    def delete_m2m_client(self, tenant_id: str, client_id: str) -> None:
        self._owned_m2m(tenant_id, client_id)
        self._remove_m2m(tenant_id, client_id)

    def _remove_m2m(self, tenant_id: str, client_id: str) -> None:
        self.cognito.delete_client(client_id)
        self.registry.delete_client(client_id)
        tenant = self.registry.get_tenant(tenant_id)
        if tenant is not None and client_id in tenant.m2m_client_ids:
            tenant.m2m_client_ids = [c for c in tenant.m2m_client_ids if c != client_id]
            self.registry.save_tenant(tenant)

    def purge_retired_clients(self, now: datetime | None = None) -> list[str]:
        """Scheduled job: delete rotated M2M clients whose grace period is over."""
        cutoff = now or utcnow()
        purged: list[str] = []
        start: str | None = None
        while True:
            tenants, start = self.registry.list_tenants(limit=100, start=start)
            for tenant in tenants:
                for cid in list(tenant.m2m_client_ids):
                    mapping = self.registry.get_client(cid)
                    if (
                        mapping
                        and mapping.retire_after
                        and datetime.fromisoformat(mapping.retire_after) <= cutoff
                    ):
                        self._remove_m2m(tenant.tenant_id, cid)
                        purged.append(cid)
            if start is None:
                return purged
