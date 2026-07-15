"""GitHub Actions deploy role via OIDC federation — no long-lived AWS keys.

The role can only be assumed from workflows of ``github_repo`` on ``main`` or
from the ``dev``/``prod`` GitHub environments, and only assumes the CDK
bootstrap roles (which do the actual deployment).
"""

from __future__ import annotations

from typing import Any

from aws_cdk import CfnOutput, Duration, Stack
from aws_cdk import aws_iam as iam
from constructs import Construct

from stacks.config import Config

GITHUB_OIDC = "token.actions.githubusercontent.com"


class CiStack(Stack):
    def __init__(self, scope: Construct, cid: str, *, cfg: Config, **kw: Any) -> None:
        super().__init__(scope, cid, **kw)
        assert cfg.github_repo, "github_repo context is required for the CI stack"
        provider = iam.OidcProviderNative(
            self,
            "GitHubOidc",
            url=f"https://{GITHUB_OIDC}",
            client_ids=["sts.amazonaws.com"],
        )
        repo = cfg.github_repo
        role = iam.Role(
            self,
            "DeployRole",
            role_name=f"tenantgate-{cfg.stage}-github-deploy",
            max_session_duration=Duration.hours(1),
            assumed_by=iam.WebIdentityPrincipal(
                provider.oidc_provider_arn,
                conditions={
                    "StringEquals": {f"{GITHUB_OIDC}:aud": "sts.amazonaws.com"},
                    "StringLike": {
                        f"{GITHUB_OIDC}:sub": [
                            f"repo:{repo}:ref:refs/heads/main",
                            f"repo:{repo}:environment:dev",
                            f"repo:{repo}:environment:prod",
                        ]
                    },
                },
            ),
        )
        role.add_to_policy(
            iam.PolicyStatement(
                actions=["sts:AssumeRole"],
                resources=[f"arn:aws:iam::{self.account}:role/cdk-*"],
            )
        )
        # Lets the DR drill job flip health checks and read stack outputs.
        role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "cloudformation:DescribeStacks",
                    "route53:GetHealthCheck",
                    "route53:GetHealthCheckStatus",
                    "route53:UpdateHealthCheck",
                    "ssm:GetParameter",
                    "ssm:PutParameter",
                ],
                resources=["*"],
            )
        )
        CfnOutput(self, "DeployRoleArn", value=role.role_arn)
