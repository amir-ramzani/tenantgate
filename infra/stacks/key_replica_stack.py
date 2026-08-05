"""Replica of the multi-Region pool key in the secondary Region (MRR requirement)."""

from __future__ import annotations

from typing import Any

from aws_cdk import RemovalPolicy, Stack
from aws_cdk import aws_kms as kms
from constructs import Construct

from stacks.config import Config
from stacks.global_stack import pool_key_policy


class KeyReplicaStack(Stack):
    def __init__(
        self, scope: Construct, cid: str, *, cfg: Config, primary_key_arn: str, **kw: Any
    ) -> None:
        super().__init__(scope, cid, **kw)
        replica = kms.CfnReplicaKey(
            self,
            "PoolKeyReplica",
            primary_key_arn=primary_key_arn,
            key_policy=pool_key_policy(self),
            description=f"tenantgate {cfg.stage} user pool (replica)",
            pending_window_in_days=30 if cfg.is_prod else 7,
        )
        replica.apply_removal_policy(RemovalPolicy.RETAIN if cfg.is_prod else RemovalPolicy.DESTROY)
        self.replica_key_arn = replica.attr_arn
