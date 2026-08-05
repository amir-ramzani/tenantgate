"""Route 53 records for ``api.<domain>`` (§9).

Single signal: the health check created in the identity stack (backed by the
canary alarm) drives both the Cognito custom domain's failover and the PRIMARY
failover record below. ``auth.<domain>`` needs no records here — it is one alias
to the pool domain and Cognito switches Regions behind it.
"""

from __future__ import annotations

from typing import Any

from aws_cdk import Stack
from aws_cdk import aws_route53 as route53
from constructs import Construct

from stacks.config import Config
from stacks.regional_stack import RegionalOutputs


class DnsStack(Stack):
    def __init__(
        self,
        scope: Construct,
        cid: str,
        *,
        cfg: Config,
        regionals: list[RegionalOutputs],
        health_check_id: str | None,
        **kw: Any,
    ) -> None:
        super().__init__(scope, cid, **kw)
        by_role = {r.region_role: r for r in regionals}
        primary = by_role["primary"]
        secondary = by_role.get("secondary")

        def alias(r: RegionalOutputs, evaluate: bool) -> route53.CfnRecordSet.AliasTargetProperty:
            return route53.CfnRecordSet.AliasTargetProperty(
                dns_name=r.api_target_domain,
                hosted_zone_id=r.api_target_zone_id,
                evaluate_target_health=evaluate,
            )

        if secondary is None or health_check_id is None:
            route53.CfnRecordSet(
                self,
                "Api",
                hosted_zone_id=cfg.hosted_zone_id,
                name=cfg.api_domain,
                type="A",
                alias_target=alias(primary, False),
            )
            return

        route53.CfnRecordSet(
            self,
            "ApiPrimary",
            hosted_zone_id=cfg.hosted_zone_id,
            name=cfg.api_domain,
            type="A",
            set_identifier="api-primary",
            failover="PRIMARY",
            health_check_id=health_check_id,
            alias_target=alias(primary, False),
        )
        route53.CfnRecordSet(
            self,
            "ApiSecondary",
            hosted_zone_id=cfg.hosted_zone_id,
            name=cfg.api_domain,
            type="A",
            set_identifier="api-secondary",
            failover="SECONDARY",
            alias_target=alias(secondary, True),
        )
