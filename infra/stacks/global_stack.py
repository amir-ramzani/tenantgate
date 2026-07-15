"""Global, deploy-once resources in the primary Region.

* Multi-Region KMS customer-managed key (primary) used for the user pool —
  a day-one decision: MRR requires it and it can't be swapped in later (§7.3).
* The hosted zone is imported, not created (it usually predates this project).
"""

from __future__ import annotations

from typing import Any

from aws_cdk import CfnOutput, RemovalPolicy, Stack
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from constructs import Construct

from stacks.config import Config


def pool_key_policy(stack: Stack) -> iam.PolicyDocument:
    """Account admin + Cognito (scoped to this account) may use the key."""
    return iam.PolicyDocument(
        statements=[
            iam.PolicyStatement(
                sid="AccountAdmin",
                principals=[iam.AccountRootPrincipal()],
                actions=["kms:*"],
                resources=["*"],
            ),
            iam.PolicyStatement(
                sid="CognitoUserPool",
                principals=[iam.ServicePrincipal("cognito-idp.amazonaws.com")],
                actions=[
                    "kms:Decrypt",
                    "kms:DescribeKey",
                    "kms:GenerateDataKey*",
                    "kms:CreateGrant",
                    "kms:Encrypt",
                    "kms:ReEncrypt*",
                ],
                resources=["*"],
                conditions={"StringEquals": {"aws:SourceAccount": stack.account}},
            ),
        ]
    )


class GlobalStack(Stack):
    def __init__(self, scope: Construct, cid: str, *, cfg: Config, **kw: Any) -> None:
        super().__init__(scope, cid, **kw)
        key = kms.CfnKey(
            self,
            "PoolKey",
            description=f"tenantgate {cfg.stage} user pool (multi-Region)",
            multi_region=True,
            enable_key_rotation=True,
            key_policy=pool_key_policy(self),
            pending_window_in_days=30 if cfg.is_prod else 7,
        )
        key.apply_removal_policy(RemovalPolicy.RETAIN if cfg.is_prod else RemovalPolicy.DESTROY)
        kms.CfnAlias(
            self,
            "PoolKeyAlias",
            alias_name=f"alias/tenantgate-{cfg.stage}-pool",
            target_key_id=key.ref,
        )
        self.pool_key_arn = key.attr_arn
        CfnOutput(self, "PoolKeyArn", value=key.attr_arn)
