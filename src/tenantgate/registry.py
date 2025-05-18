"""DynamoDB single-table tenant registry (plan §5).

Item layout::

    PK                  SK              GSI1PK          GSI1SK          purpose
    TENANT#<id>         META            TENANTS         TENANT#<id>     tenant record
    TENANT#<id>         USER#<sub>      USER#<sub>      TENANT#<id>     membership + role
    CLIENT#<client_id>  TENANT          -               -               client -> tenant

* ``GSI1`` answers "list all tenants" and "list a user's tenants".
* Only the primary-Region control plane writes (single writer); every Region
  reads its local global-table replica.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from tenantgate.models import (
    ClientKind,
    ClientMapping,
    Membership,
    Role,
    Tenant,
    TenantStatus,
    utcnow_iso,
)

GSI1 = "GSI1"
META = "META"
ALL_TENANTS = "TENANTS"


class RegistryError(Exception):
    pass


class AlreadyExists(RegistryError):
    pass


class NotFound(RegistryError):
    pass


def tenant_pk(tenant_id: str) -> str:
    return f"TENANT#{tenant_id}"


def user_sk(sub: str) -> str:
    return f"USER#{sub}"


def client_pk(client_id: str) -> str:
    return f"CLIENT#{client_id}"


def _is_conditional_failure(exc: ClientError) -> bool:
    return exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException"


# ------------------------------------------------------------------ (de)serialisation


def tenant_to_item(t: Tenant) -> dict[str, Any]:
    item: dict[str, Any] = {
        "PK": tenant_pk(t.tenant_id),
        "SK": META,
        "GSI1PK": ALL_TENANTS,
        "GSI1SK": tenant_pk(t.tenant_id),
        "type": "tenant",
        "tenant_id": t.tenant_id,
        "name": t.name,
        "status": t.status.value,
        "plan": t.plan,
        "app_client_ids": list(t.app_client_ids),
        "m2m_client_ids": list(t.m2m_client_ids),
        "allowed_idps": list(t.allowed_idps),
        "callback_urls": list(t.callback_urls),
        "logout_urls": list(t.logout_urls),
        "created_at": t.created_at,
    }
    if t.updated_at:
        item["updated_at"] = t.updated_at
    return item


def tenant_from_item(item: dict[str, Any]) -> Tenant:
    return Tenant(
        tenant_id=str(item["tenant_id"]),
        name=str(item["name"]),
        status=TenantStatus(item.get("status", TenantStatus.ACTIVE.value)),
        plan=str(item.get("plan", "standard")),
        app_client_ids=[str(x) for x in item.get("app_client_ids", [])],
        m2m_client_ids=[str(x) for x in item.get("m2m_client_ids", [])],
        allowed_idps=[str(x) for x in item.get("allowed_idps", ["COGNITO"])],
        callback_urls=[str(x) for x in item.get("callback_urls", [])],
        logout_urls=[str(x) for x in item.get("logout_urls", [])],
        created_at=str(item.get("created_at", "")),
        updated_at=str(item["updated_at"]) if item.get("updated_at") else None,
    )


def membership_to_item(m: Membership) -> dict[str, Any]:
    item: dict[str, Any] = {
        "PK": tenant_pk(m.tenant_id),
        "SK": user_sk(m.sub),
        "GSI1PK": user_sk(m.sub),
        "GSI1SK": tenant_pk(m.tenant_id),
        "type": "membership",
        "tenant_id": m.tenant_id,
        "sub": m.sub,
        "role": m.role.value,
        "username": m.username,
        "created_at": m.created_at,
    }
    if m.email:
        item["email"] = m.email
    return item


def membership_from_item(item: dict[str, Any]) -> Membership:
    return Membership(
        tenant_id=str(item["tenant_id"]),
        sub=str(item["sub"]),
        role=Role(item["role"]),
        username=str(item.get("username", item["sub"])),
        email=str(item["email"]) if item.get("email") else None,
        created_at=str(item.get("created_at", "")),
    )


def client_to_item(c: ClientMapping) -> dict[str, Any]:
    item: dict[str, Any] = {
        "PK": client_pk(c.client_id),
        "SK": "TENANT",
        "type": "client",
        "client_id": c.client_id,
        "tenant_id": c.tenant_id,
        "kind": c.kind.value,
        "actions": list(c.actions),
    }
    if c.name:
        item["name"] = c.name
    if c.retire_after:
        item["retire_after"] = c.retire_after
    return item


def client_from_item(item: dict[str, Any]) -> ClientMapping:
    return ClientMapping(
        client_id=str(item["client_id"]),
        tenant_id=str(item["tenant_id"]),
        kind=ClientKind(item["kind"]),
        name=str(item["name"]) if item.get("name") else None,
        actions=tuple(str(a) for a in item.get("actions", [])),
        retire_after=str(item["retire_after"]) if item.get("retire_after") else None,
    )


# ------------------------------------------------------------------ registry


class TenantRegistry:
    """Thin repository over a boto3 ``Table`` resource."""

    def __init__(self, table: Any, *, consistent_reads: bool = False) -> None:
        self._t = table
        self._consistent = consistent_reads

    @property
    def table(self) -> Any:
        return self._t

    # ---- tenants

    def create_tenant(self, tenant: Tenant) -> Tenant:
        try:
            self._t.put_item(
                Item=tenant_to_item(tenant),
                ConditionExpression="attribute_not_exists(PK)",
            )
        except ClientError as exc:
            if _is_conditional_failure(exc):
                raise AlreadyExists(tenant.tenant_id) from exc
            raise
        return tenant

    def get_tenant(self, tenant_id: str) -> Tenant | None:
        resp = self._t.get_item(
            Key={"PK": tenant_pk(tenant_id), "SK": META}, ConsistentRead=self._consistent
        )
        item = resp.get("Item")
        return tenant_from_item(item) if item else None

    def require_tenant(self, tenant_id: str) -> Tenant:
        tenant = self.get_tenant(tenant_id)
        if tenant is None:
            raise NotFound(tenant_id)
        return tenant

    def save_tenant(self, tenant: Tenant) -> Tenant:
        """Overwrite an existing tenant record (must exist)."""
        tenant.updated_at = utcnow_iso()
        try:
            self._t.put_item(
                Item=tenant_to_item(tenant), ConditionExpression="attribute_exists(PK)"
            )
        except ClientError as exc:
            if _is_conditional_failure(exc):
                raise NotFound(tenant.tenant_id) from exc
            raise
        return tenant

    def set_status(self, tenant_id: str, status: TenantStatus) -> None:
        try:
            self._t.update_item(
                Key={"PK": tenant_pk(tenant_id), "SK": META},
                UpdateExpression="SET #s = :s, updated_at = :u",
                ConditionExpression="attribute_exists(PK)",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={":s": status.value, ":u": utcnow_iso()},
            )
        except ClientError as exc:
            if _is_conditional_failure(exc):
                raise NotFound(tenant_id) from exc
            raise

    def list_tenants(
        self, limit: int = 100, start: str | None = None
    ) -> tuple[list[Tenant], str | None]:
        kwargs: dict[str, Any] = {
            "IndexName": GSI1,
            "KeyConditionExpression": Key("GSI1PK").eq(ALL_TENANTS),
            "Limit": limit,
        }
        if start:
            kwargs["ExclusiveStartKey"] = {
                "PK": tenant_pk(start),
                "SK": META,
                "GSI1PK": ALL_TENANTS,
                "GSI1SK": tenant_pk(start),
            }
        resp = self._t.query(**kwargs)
        tenants = [tenant_from_item(i) for i in resp.get("Items", [])]
        last = resp.get("LastEvaluatedKey")
        return tenants, (str(last["PK"]).removeprefix("TENANT#") if last else None)

    def delete_tenant(self, tenant_id: str) -> None:
        """Delete the tenant record, every membership and every client mapping."""
        tenant = self.get_tenant(tenant_id)
        with self._t.batch_writer() as batch:
            for item in self._query_partition(tenant_pk(tenant_id)):
                batch.delete_item(Key={"PK": item["PK"], "SK": item["SK"]})
            if tenant is not None:
                for cid in [*tenant.app_client_ids, *tenant.m2m_client_ids]:
                    batch.delete_item(Key={"PK": client_pk(cid), "SK": "TENANT"})

    # ---- memberships

    def put_membership(self, m: Membership, *, overwrite: bool = True) -> Membership:
        kwargs: dict[str, Any] = {"Item": membership_to_item(m)}
        if not overwrite:
            kwargs["ConditionExpression"] = "attribute_not_exists(PK)"
        try:
            self._t.put_item(**kwargs)
        except ClientError as exc:
            if _is_conditional_failure(exc):
                raise AlreadyExists(f"{m.tenant_id}/{m.sub}") from exc
            raise
        return m

    def get_membership(self, tenant_id: str, sub: str) -> Membership | None:
        resp = self._t.get_item(
            Key={"PK": tenant_pk(tenant_id), "SK": user_sk(sub)},
            ConsistentRead=self._consistent,
        )
        item = resp.get("Item")
        return membership_from_item(item) if item else None

    def delete_membership(self, tenant_id: str, sub: str) -> bool:
        resp = self._t.delete_item(
            Key={"PK": tenant_pk(tenant_id), "SK": user_sk(sub)}, ReturnValues="ALL_OLD"
        )
        return bool(resp.get("Attributes"))

    def list_members(self, tenant_id: str) -> list[Membership]:
        resp = self._t.query(
            KeyConditionExpression=Key("PK").eq(tenant_pk(tenant_id))
            & Key("SK").begins_with("USER#"),
            ConsistentRead=self._consistent,
        )
        items = list(resp.get("Items", []))
        while "LastEvaluatedKey" in resp:
            resp = self._t.query(
                KeyConditionExpression=Key("PK").eq(tenant_pk(tenant_id))
                & Key("SK").begins_with("USER#"),
                ExclusiveStartKey=resp["LastEvaluatedKey"],
                ConsistentRead=self._consistent,
            )
            items.extend(resp.get("Items", []))
        return [membership_from_item(i) for i in items]

    def count_admins(self, tenant_id: str) -> int:
        return sum(1 for m in self.list_members(tenant_id) if m.role is Role.ADMIN)

    def list_user_tenants(self, sub: str) -> list[Membership]:
        """All memberships of a user (the "choose workspace" screen)."""
        resp = self._t.query(
            IndexName=GSI1,
            KeyConditionExpression=Key("GSI1PK").eq(user_sk(sub)),
        )
        return [membership_from_item(i) for i in resp.get("Items", [])]

    # ---- client mappings

    def put_client(self, c: ClientMapping) -> ClientMapping:
        self._t.put_item(Item=client_to_item(c))
        return c

    def get_client(self, client_id: str) -> ClientMapping | None:
        resp = self._t.get_item(
            Key={"PK": client_pk(client_id), "SK": "TENANT"}, ConsistentRead=self._consistent
        )
        item = resp.get("Item")
        return client_from_item(item) if item else None

    def delete_client(self, client_id: str) -> None:
        self._t.delete_item(Key={"PK": client_pk(client_id), "SK": "TENANT"})

    # ---- helpers

    def _query_partition(self, pk: str) -> Iterator[dict[str, Any]]:
        kwargs: dict[str, Any] = {"KeyConditionExpression": Key("PK").eq(pk)}
        while True:
            resp = self._t.query(**kwargs)
            yield from resp.get("Items", [])
            if "LastEvaluatedKey" not in resp:
                return
            kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
