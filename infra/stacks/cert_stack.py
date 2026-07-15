"""ACM certificate for the Cognito custom domain.

Cognito custom domains are fronted by CloudFront, so the certificate must live
in ``us-east-1`` regardless of the pool's Region.
"""

from __future__ import annotations

from typing import Any

from aws_cdk import Stack
from aws_cdk import aws_certificatemanager as acm
from aws_cdk import aws_route53 as route53
from constructs import Construct

from stacks.config import Config


class CertStack(Stack):
    def __init__(self, scope: Construct, cid: str, *, cfg: Config, **kw: Any) -> None:
        super().__init__(scope, cid, **kw)
        zone = route53.HostedZone.from_hosted_zone_attributes(
            self, "Zone", hosted_zone_id=cfg.hosted_zone_id, zone_name=cfg.domain_name
        )
        self.auth_certificate = acm.Certificate(
            self,
            "AuthCert",
            domain_name=cfg.auth_domain,
            validation=acm.CertificateValidation.from_dns(zone),
        )
