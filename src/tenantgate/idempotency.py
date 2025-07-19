"""Idempotency keys for control-plane writes (plan §8).

A client sends ``Idempotency-Key``; the first request records ``IN_PROGRESS``
with a conditional put, runs, and stores the response. Replays return the
stored response; a replay with a *different* body is rejected; a replay while
the first request is still running gets ``409``. Records expire via DynamoDB
TTL (``expires_at``).

Keys are namespaced by caller (``sub``) so two callers can't collide.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any

from botocore.exceptions import ClientError

IN_PROGRESS = "IN_PROGRESS"
COMPLETED = "COMPLETED"


class IdempotencyError(Exception):
    pass


class IdempotencyInProgress(IdempotencyError):
    pass


class IdempotencyMismatch(IdempotencyError):
    pass


@dataclass(frozen=True)
class StoredResponse:
    status_code: int
    body: Any


def fingerprint(payload: Any) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class IdempotencyStore:
    def __init__(
        self,
        table: Any,
        *,
        ttl_seconds: int = 24 * 3600,
        lock_seconds: int = 60,
    ) -> None:
        self._t = table
        self._ttl = ttl_seconds
        self._lock = lock_seconds

    @staticmethod
    def record_id(namespace: str, key: str) -> str:
        return f"{namespace}#{key}"

    def begin(self, namespace: str, key: str, payload: Any) -> StoredResponse | None:
        """Claim the key. Returns a stored response for a completed replay, else None."""
        rid = self.record_id(namespace, key)
        fp = fingerprint(payload)
        now = int(time.time())
        try:
            self._t.put_item(
                Item={
                    "id": rid,
                    "status": IN_PROGRESS,
                    "fingerprint": fp,
                    "locked_until": now + self._lock,
                    "expires_at": now + self._ttl,
                },
                # Take the key if it's new, or if a previous attempt died mid-flight.
                ConditionExpression=(
                    "attribute_not_exists(id) OR (#s = :ip AND locked_until < :now)"
                ),
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={":ip": IN_PROGRESS, ":now": now},
            )
            return None
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ConditionalCheckFailedException":
                raise
        existing = self._t.get_item(Key={"id": rid}, ConsistentRead=True).get("Item") or {}
        if existing.get("fingerprint") != fp:
            raise IdempotencyMismatch("Idempotency-Key reused with a different request")
        if existing.get("status") == COMPLETED:
            return StoredResponse(
                status_code=int(existing["status_code"]), body=json.loads(existing["body"])
            )
        raise IdempotencyInProgress("a request with this Idempotency-Key is in progress")

    def complete(self, namespace: str, key: str, status_code: int, body: Any) -> None:
        self._t.update_item(
            Key={"id": self.record_id(namespace, key)},
            UpdateExpression="SET #s = :c, status_code = :sc, body = :b",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":c": COMPLETED,
                ":sc": status_code,
                ":b": json.dumps(body, default=str),
            },
        )

    def release(self, namespace: str, key: str) -> None:
        """Forget a failed attempt so the client can retry with the same key."""
        self._t.delete_item(Key={"id": self.record_id(namespace, key)})
