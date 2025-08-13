"""Tenant-partitioned notes store.

Every key starts with the tenant: ``PK = TENANT#<tenant_id>``, ``SK = NOTE#<id>``.
The repository takes the tenant ID from a ``TenantContext`` — never from the
request body — so one tenant can't address another tenant's partition even if
a route forgets a check. In production the Lambda role can additionally be
scoped with ``dynamodb:LeadingKeys``.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from authlib_mt import TenantContext
from tenantgate.models import utcnow_iso


@dataclass(frozen=True)
class Note:
    note_id: str
    tenant_id: str
    title: str
    body: str
    author: str
    created_at: str
    updated_at: str | None = None


def _pk(tenant_id: str) -> str:
    return f"TENANT#{tenant_id}"


def _sk(note_id: str) -> str:
    return f"NOTE#{note_id}"


def _from_item(item: dict[str, Any]) -> Note:
    return Note(
        note_id=str(item["note_id"]),
        tenant_id=str(item["tenant_id"]),
        title=str(item["title"]),
        body=str(item.get("body", "")),
        author=str(item["author"]),
        created_at=str(item["created_at"]),
        updated_at=str(item["updated_at"]) if item.get("updated_at") else None,
    )


class NotesRepository:
    def __init__(self, table: Any) -> None:
        self._t = table

    def list(self, ctx: TenantContext, limit: int = 50) -> list[Note]:
        resp = self._t.query(
            KeyConditionExpression=Key("PK").eq(_pk(ctx.tenant_id))
            & Key("SK").begins_with("NOTE#"),
            Limit=limit,
        )
        return [_from_item(i) for i in resp.get("Items", [])]

    def get(self, ctx: TenantContext, note_id: str) -> Note | None:
        item = self._t.get_item(Key={"PK": _pk(ctx.tenant_id), "SK": _sk(note_id)}).get("Item")
        return _from_item(item) if item else None

    def create(self, ctx: TenantContext, title: str, body: str) -> Note:
        note = Note(
            note_id=uuid.uuid4().hex,
            tenant_id=ctx.tenant_id,
            title=title,
            body=body,
            author=ctx.sub,
            created_at=utcnow_iso(),
        )
        self._t.put_item(
            Item={"PK": _pk(ctx.tenant_id), "SK": _sk(note.note_id), **note.__dict__},
            ConditionExpression="attribute_not_exists(PK)",
        )
        return note

    def update(self, ctx: TenantContext, note_id: str, title: str, body: str) -> Note | None:
        try:
            resp = self._t.update_item(
                Key={"PK": _pk(ctx.tenant_id), "SK": _sk(note_id)},
                UpdateExpression="SET title = :t, body = :b, updated_at = :u",
                ConditionExpression="attribute_exists(PK)",
                ExpressionAttributeValues={":t": title, ":b": body, ":u": utcnow_iso()},
                ReturnValues="ALL_NEW",
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                return None
            raise
        return _from_item(resp["Attributes"])

    def delete(self, ctx: TenantContext, note_id: str) -> bool:
        resp = self._t.delete_item(
            Key={"PK": _pk(ctx.tenant_id), "SK": _sk(note_id)}, ReturnValues="ALL_OLD"
        )
        return bool(resp.get("Attributes"))
