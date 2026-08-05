#!/usr/bin/env python3
"""tenantgate CDK app.

Deploy order (§12), enforced through stack dependencies:

    ci (once) -> cert (us-east-1) -> global -> [key-replica] -> data
      -> identity (+ replica) -> regional (primary) -> [regional (secondary)] -> dns

After the secondary's regional configuration is in place, redeploy with
``-c activate_replica=true`` to set the replica ACTIVE.

Context (cdk.json or ``-c key=value``):

    stage               dev | prod
    domain_name         e.g. example.com (auth.<domain>, api.<domain>)
    hosted_zone_id      existing public hosted zone for domain_name
    primary_region      default ap-southeast-1
    secondary_region    default ap-southeast-2 (ap-southeast-5 once MRR is confirmed there)
    multi_region        "true" adds the replica Region
    activate_replica    "true" sets the MRR replica ACTIVE
    ses_from_email      optional; SES-backed email, required for email MFA
    admin_callback_urls comma-separated callback URLs for the control-plane UI
    github_repo         owner/name, for the CI OIDC deploy role
    token_issuer        pin the accepted `iss` (from the pool's OIDC discovery document)
    alarm_email         optional; subscribed to the auth-health alarm topic
"""

from __future__ import annotations

import os

import aws_cdk as cdk

from stacks.cert_stack import CertStack
from stacks.ci_stack import CiStack
from stacks.config import Config
from stacks.data_stack import DataStack
from stacks.dns_stack import DnsStack
from stacks.global_stack import GlobalStack
from stacks.identity_stack import IdentityStack
from stacks.key_replica_stack import KeyReplicaStack
from stacks.regional_stack import RegionalStack

app = cdk.App()
cfg = Config.from_app(app)
account = os.environ.get("CDK_DEFAULT_ACCOUNT")


def env(region: str) -> cdk.Environment:
    return cdk.Environment(account=account, region=region)


p = cfg.prefix

if cfg.github_repo:
    CiStack(app, f"{p}-ci", cfg=cfg, env=env(cfg.primary_region))

cert = CertStack(app, f"{p}-cert", cfg=cfg, env=env("us-east-1"), cross_region_references=True)
glob = GlobalStack(
    app, f"{p}-global", cfg=cfg, env=env(cfg.primary_region), cross_region_references=True
)
data = DataStack(app, f"{p}-data", cfg=cfg, env=env(cfg.primary_region))

key_replica: KeyReplicaStack | None = None
if cfg.multi_region:
    key_replica = KeyReplicaStack(
        app,
        f"{p}-key-replica",
        cfg=cfg,
        primary_key_arn=glob.pool_key_arn,
        env=env(cfg.secondary_region),
        cross_region_references=True,
    )

identity = IdentityStack(
    app,
    f"{p}-identity",
    cfg=cfg,
    auth_certificate=cert.auth_certificate,
    pool_key_arn=glob.pool_key_arn,
    env=env(cfg.primary_region),
    cross_region_references=True,
)
identity.add_dependency(data)
if key_replica is not None:
    identity.add_dependency(key_replica)

regionals = [
    RegionalStack(
        app,
        f"{p}-regional-{cfg.primary_region}",
        cfg=cfg,
        region_role="primary",
        identity=identity.outputs,
        env=env(cfg.primary_region),
    )
]
regionals[0].add_dependency(identity)
if cfg.multi_region:
    secondary = RegionalStack(
        app,
        f"{p}-regional-{cfg.secondary_region}",
        cfg=cfg,
        region_role="secondary",
        identity=identity.outputs,
        env=env(cfg.secondary_region),
        cross_region_references=True,
    )
    secondary.add_dependency(regionals[0])
    regionals.append(secondary)

dns = DnsStack(
    app,
    f"{p}-dns",
    cfg=cfg,
    regionals=[r.outputs for r in regionals],
    health_check_id=identity.outputs.health_check_id,
    env=env(cfg.primary_region),
    cross_region_references=True,
)
for r in regionals:
    dns.add_dependency(r)

cdk.Tags.of(app).add("project", "tenantgate")
cdk.Tags.of(app).add("stage", cfg.stage)
app.synth()
