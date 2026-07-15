"""DynamoDB global tables (§5).

* registry — single-table tenant registry; GSI1 lists tenants / a user's tenants.
* notes — demo API data, partitioned by tenant.
* idempotency — control-plane idempotency keys (TTL ``expires_at``); primary only
  in practice, but replicated so a promoted Region could take over.

Replicas are added with ``-c multi_region=true``; until then the tables are
single-Region (cheaper dev stacks). Only the primary-Region control plane writes
to the registry.
"""

from __future__ import annotations

from typing import Any

from aws_cdk import RemovalPolicy, Stack
from aws_cdk import aws_dynamodb as ddb
from constructs import Construct

from stacks.config import Config

PK = ddb.Attribute(name="PK", type=ddb.AttributeType.STRING)
SK = ddb.Attribute(name="SK", type=ddb.AttributeType.STRING)


class DataStack(Stack):
    def __init__(self, scope: Construct, cid: str, *, cfg: Config, **kw: Any) -> None:
        super().__init__(scope, cid, **kw)
        replicas = (
            [ddb.ReplicaTableProps(region=cfg.secondary_region)] if cfg.multi_region else None
        )
        common: dict[str, Any] = {
            "billing": ddb.Billing.on_demand(),
            "replicas": replicas,
            "deletion_protection": cfg.is_prod,
            "removal_policy": RemovalPolicy.RETAIN if cfg.is_prod else RemovalPolicy.DESTROY,
            "point_in_time_recovery_specification": ddb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True
            ),
        }
        self.registry = ddb.TableV2(
            self,
            "Registry",
            table_name=cfg.registry_table_name,
            partition_key=PK,
            sort_key=SK,
            global_secondary_indexes=[
                ddb.GlobalSecondaryIndexPropsV2(
                    index_name="GSI1",
                    partition_key=ddb.Attribute(name="GSI1PK", type=ddb.AttributeType.STRING),
                    sort_key=ddb.Attribute(name="GSI1SK", type=ddb.AttributeType.STRING),
                )
            ],
            **common,
        )
        self.notes = ddb.TableV2(
            self, "Notes", table_name=cfg.notes_table_name, partition_key=PK, sort_key=SK, **common
        )
        self.idempotency = ddb.TableV2(
            self,
            "Idempotency",
            table_name=cfg.idempotency_table_name,
            partition_key=ddb.Attribute(name="id", type=ddb.AttributeType.STRING),
            time_to_live_attribute="expires_at",
            **common,
        )
