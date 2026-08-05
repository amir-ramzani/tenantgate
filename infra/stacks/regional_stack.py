"""Per-Region resources, deployed once per Region (§6).

primary:   control plane (read-write), demo API, canary, M2M purge job, WAF on the pool
secondary: control plane (read-only), demo API, WAF on the replica, replica triggers,
           and the replica's regional configuration (triggers, email, ACTIVE/INACTIVE)

Everything a sign-in or token request touches is local to the Region: triggers
read the local DynamoDB replica and the local copy of the system-client list.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from aws_cdk import CfnOutput, Duration, Stack
from aws_cdk import aws_apigatewayv2 as apigw
from aws_cdk import aws_apigatewayv2_integrations as integrations
from aws_cdk import aws_certificatemanager as acm
from aws_cdk import aws_cloudwatch as cw
from aws_cdk import aws_cloudwatch_actions as cw_actions
from aws_cdk import aws_cognito as cognito
from aws_cdk import aws_dynamodb as ddb
from aws_cdk import aws_events as events
from aws_cdk import aws_events_targets as events_targets
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from aws_cdk import aws_route53 as route53
from aws_cdk import aws_secretsmanager as sm
from aws_cdk import aws_ses as ses
from aws_cdk import aws_sns as sns
from aws_cdk import aws_ssm as ssm
from aws_cdk import aws_wafv2 as waf
from constructs import Construct

from stacks.config import LAMBDA_ASSET, Config
from stacks.identity_stack import (
    CANARY_NAMESPACE,
    PLATFORM_ADMIN_GROUP,
    RESOURCE_SERVER_ID,
    IdentityOutputs,
    trigger_function,
)

COGNITO_ADMIN_ACTIONS = [
    "cognito-idp:AdminCreateUser",
    "cognito-idp:AdminDeleteUser",
    "cognito-idp:AdminGetUser",
    "cognito-idp:AdminUserGlobalSignOut",
    "cognito-idp:CreateManagedLoginBranding",
    "cognito-idp:CreateUserPoolClient",
    "cognito-idp:DeleteUserPoolClient",
    "cognito-idp:DescribeResourceServer",
    "cognito-idp:DescribeUserPoolClient",
    "cognito-idp:ListUsers",
    "cognito-idp:UpdateResourceServer",
    "cognito-idp:UpdateUserPoolClient",
]


@dataclass(frozen=True)
class RegionalOutputs:
    region: str
    region_role: str
    api_target_domain: str
    api_target_zone_id: str


class RegionalStack(Stack):
    def __init__(
        self,
        scope: Construct,
        cid: str,
        *,
        cfg: Config,
        region_role: str,
        identity: IdentityOutputs,
        **kw: Any,
    ) -> None:
        super().__init__(scope, cid, **kw)
        primary = region_role == "primary"
        code = lambda_.Code.from_asset(str(LAMBDA_ASSET))
        registry = ddb.TableV2.from_table_name(self, "Registry", cfg.registry_table_name)
        notes = ddb.TableV2.from_table_name(self, "Notes", cfg.notes_table_name)
        idempotency = ddb.TableV2.from_table_name(self, "Idem", cfg.idempotency_table_name)
        # Replicas keep the primary's pool ID; only the Region in the ARN differs.
        pool_arn = self.format_arn(
            service="cognito-idp", resource="userpool", resource_name=identity.user_pool_id
        )
        alarms = sns.Topic(self, "Alarms", display_name=f"tenantgate {cfg.stage} {region_role}")

        # ------------------------------------------------------------ degraded-mode flag
        # The secondary starts in "failover": if it is serving control-plane traffic,
        # the primary is down. Operators flip the primary to "failover" during drills.
        auth_mode = ssm.StringParameter(
            self,
            "AuthMode",
            parameter_name=cfg.param("auth-mode"),
            string_value="normal" if primary else "failover",
            description="tenantgate degraded-mode flag: normal | failover",
        )

        env = {
            "REGION_ROLE": region_role,
            "TABLE_NAME": cfg.registry_table_name,
            "NOTES_TABLE_NAME": cfg.notes_table_name,
            "IDEMPOTENCY_TABLE_NAME": cfg.idempotency_table_name,
            "USER_POOL_ID": identity.user_pool_id,
            "TOKEN_ISSUERS": identity.issuer,
            "RESOURCE_SERVER_ID": RESOURCE_SERVER_ID,
            "SYSTEM_CLIENT_IDS": identity.system_client_ids_csv,
            "PLATFORM_ADMIN_GROUP": PLATFORM_ADMIN_GROUP,
            "AUTH_MODE_PARAM": auth_mode.parameter_name,
            "POWERTOOLS_LOG_LEVEL": "INFO",
        }

        def fn(cid: str, handler: str, service: str, **extra: Any) -> lambda_.Function:
            f = lambda_.Function(
                self,
                cid,
                runtime=lambda_.Runtime.PYTHON_3_12,
                architecture=lambda_.Architecture.ARM_64,
                handler=handler,
                code=code,
                memory_size=extra.pop("memory_size", 512),
                timeout=extra.pop("timeout", Duration.seconds(15)),
                tracing=lambda_.Tracing.ACTIVE,
                log_retention=logs.RetentionDays.ONE_MONTH,
                environment={**env, "POWERTOOLS_SERVICE_NAME": service, **extra.pop("env", {})},
                **extra,
            )
            auth_mode.grant_read(f)
            return f

        # ------------------------------------------------------------ control plane
        control = fn("ControlPlane", "control_plane.handler.handler", "tenantgate-control-plane")
        registry.grant_read_data(control)
        if primary:
            registry.grant_read_write_data(control)
            idempotency.grant_read_write_data(control)
            control.add_to_role_policy(
                iam.PolicyStatement(actions=COGNITO_ADMIN_ACTIONS, resources=[pool_arn])
            )

        # ------------------------------------------------------------ demo API
        demo = fn("DemoApi", "demo_api.handler.handler", "tenantgate-demo-api")
        registry.grant_read_data(demo)
        notes.grant_read_write_data(demo)

        # ------------------------------------------------------------ HTTP API + domain
        api = apigw.HttpApi(
            self,
            "Api",
            api_name=f"tenantgate-{cfg.stage}",
            cors_preflight=apigw.CorsPreflightOptions(
                allow_origins=sorted({_origin(u) for u in cfg.admin_callback_urls})
                or ["http://localhost:3000"],
                allow_methods=[apigw.CorsHttpMethod.ANY],
                allow_headers=["authorization", "content-type", "idempotency-key", "x-tenant-id"],
                max_age=Duration.hours(1),
            ),
        )
        for prefix, target in (("control", control), ("demo", demo)):
            integration = integrations.HttpLambdaIntegration(f"{prefix.title()}Int", target)
            api.add_routes(
                path=f"/{prefix}/{{proxy+}}",
                methods=[apigw.HttpMethod.ANY],
                integration=integration,
            )
        stage = api.default_stage
        assert stage is not None
        cfn_stage = stage.node.default_child
        assert isinstance(cfn_stage, apigw.CfnStage)
        cfn_stage.default_route_settings = apigw.CfnStage.RouteSettingsProperty(
            throttling_burst_limit=200, throttling_rate_limit=100
        )

        zone = route53.HostedZone.from_hosted_zone_attributes(
            self, "Zone", hosted_zone_id=cfg.hosted_zone_id, zone_name=cfg.domain_name
        )
        api_cert = acm.Certificate(
            self,
            "ApiCert",
            domain_name=cfg.api_domain,
            validation=acm.CertificateValidation.from_dns(zone),
        )
        domain = apigw.DomainName(
            self, "ApiDomain", domain_name=cfg.api_domain, certificate=api_cert
        )
        apigw.ApiMapping(self, "ApiMapping", api=api, domain_name=domain)

        cw.Alarm(
            self,
            "Api5xx",
            metric=api.metric_server_error(period=Duration.minutes(5)),
            threshold=5,
            evaluation_periods=1,
            treat_missing_data=cw.TreatMissingData.NOT_BREACHING,
        ).add_alarm_action(cw_actions.SnsAction(alarms))

        # ------------------------------------------------------------ WAF on the pool
        acl = waf.CfnWebACL(
            self,
            "PoolAcl",
            scope="REGIONAL",
            default_action=waf.CfnWebACL.DefaultActionProperty(allow={}),
            visibility_config=_visibility("tenantgate-pool"),
            rules=[
                waf.CfnWebACL.RuleProperty(
                    name="rate-limit-per-ip",
                    priority=0,
                    action=waf.CfnWebACL.RuleActionProperty(block={}),
                    statement=waf.CfnWebACL.StatementProperty(
                        rate_based_statement=waf.CfnWebACL.RateBasedStatementProperty(
                            limit=1000, aggregate_key_type="IP"
                        )
                    ),
                    visibility_config=_visibility("rate-limit-per-ip"),
                ),
                _managed_rule("AWSManagedRulesCommonRuleSet", 1),
                _managed_rule("AWSManagedRulesKnownBadInputsRuleSet", 2),
                _managed_rule("AWSManagedRulesAmazonIpReputationList", 3),
            ],
        )
        waf.CfnWebACLAssociation(
            self, "PoolAclAssoc", resource_arn=pool_arn, web_acl_arn=acl.attr_arn
        )

        if primary:
            self._primary_only(cfg, identity, fn, registry, alarms)
        else:
            self._secondary_only(cfg, identity, pool_arn)

        self.outputs = RegionalOutputs(
            region=self.region,
            region_role=region_role,
            api_target_domain=domain.regional_domain_name,
            api_target_zone_id=domain.regional_hosted_zone_id,
        )
        CfnOutput(self, "ApiUrl", value=api.api_endpoint)
        CfnOutput(self, "AuthModeParam", value=auth_mode.parameter_name)

    # ---------------------------------------------------------------- primary only

    def _primary_only(
        self,
        cfg: Config,
        identity: IdentityOutputs,
        fn: Any,
        registry: ddb.ITableV2,
        alarms: sns.ITopic,
    ) -> None:
        # Rotated M2M clients are removed after their grace period.
        purge = fn(
            "PurgeRetiredClients",
            "control_plane.handler.purge_handler",
            "tenantgate-purge",
            timeout=Duration.minutes(5),
        )
        registry.grant_read_write_data(purge)
        purge.add_to_role_policy(
            iam.PolicyStatement(
                actions=["cognito-idp:DeleteUserPoolClient"],
                resources=[
                    self.format_arn(
                        service="cognito-idp",
                        resource="userpool",
                        resource_name=identity.user_pool_id,
                    )
                ],
            )
        )
        events.Rule(
            self,
            "PurgeSchedule",
            schedule=events.Schedule.rate(Duration.hours(1)),
            targets=[events_targets.LambdaFunction(purge)],
        )

        # Canary credentials are filled in by an operator after the first deploy
        # (see README): M2M secret + canary user.
        secret = sm.Secret(
            self,
            "CanarySecret",
            secret_name=f"tenantgate/{cfg.stage}/canary",
            description=(
                "Canary credentials: m2m_client_id/secret, user_client_id, username, password"
            ),
        )
        force_param = ssm.StringParameter(
            self,
            "CanaryForce",
            parameter_name=cfg.param("canary-force"),
            string_value="off",
            description="Set to 'unhealthy' to force failover during a DR drill",
        )
        canary = fn(
            "Canary",
            "canary.handler.handler",
            "tenantgate-canary",
            timeout=Duration.seconds(30),
            memory_size=256,
            env={
                "TOKEN_ENDPOINT": (
                    f"https://{identity.regional_domain_prefix}.auth.{self.region}"
                    ".amazoncognito.com/oauth2/token"
                ),
                "CANARY_SECRET_ID": secret.secret_arn,
                "CANARY_FORCE_PARAM": force_param.parameter_name,
                "CANARY_NAMESPACE": CANARY_NAMESPACE,
            },
        )
        secret.grant_read(canary)
        force_param.grant_read(canary)
        canary.add_to_role_policy(
            iam.PolicyStatement(
                actions=["cloudwatch:PutMetricData"],
                resources=["*"],
                conditions={"StringEquals": {"cloudwatch:namespace": CANARY_NAMESPACE}},
            )
        )
        events.Rule(
            self,
            "CanarySchedule",
            schedule=events.Schedule.rate(Duration.minutes(1)),
            targets=[events_targets.LambdaFunction(canary, retry_attempts=0)],
        )

    # ---------------------------------------------------------------- secondary only

    def _secondary_only(self, cfg: Config, identity: IdentityOutputs, pool_arn: str) -> None:
        triggers: dict[str, lambda_.Function] = {}
        for cid, handler in (
            ("ReplicaPreAuth", "triggers.pre_auth.handler"),
            ("ReplicaPreTokenGen", "triggers.pre_token_gen.handler"),
        ):
            t = trigger_function(
                self,
                cid,
                cfg=cfg,
                handler=handler,
                region_role="secondary",
                system_ids_param=identity.system_ids_param,
                can_write=False,
            )
            t.add_permission(
                f"{cid}Invoke",
                principal=iam.ServicePrincipal("cognito-idp.amazonaws.com"),
                source_arn=pool_arn,
            )
            triggers[cid] = t

        # Local copy of the system-client list, so replica triggers never cross Regions.
        ssm.StringParameter(
            self,
            "SystemClientIds",
            parameter_name=identity.system_ids_param,
            string_value=identity.system_client_ids_csv,
        )

        attachment = cognito.CfnUserPoolRegionalConfigurationAttachment
        email = None
        if cfg.ses_from_email:
            # SES identities are Regional: the replica sends from this Region's SES.
            zone = route53.HostedZone.from_hosted_zone_attributes(
                self, "SesZone", hosted_zone_id=cfg.hosted_zone_id, zone_name=cfg.domain_name
            )
            ses.EmailIdentity(self, "SesDomain", identity=ses.Identity.public_hosted_zone(zone))
            domain = cfg.ses_from_email.split("@", 1)[1]
            email = attachment.EmailConfigurationProperty(
                email_sending_account="DEVELOPER",
                from_=cfg.ses_from_email,
                source_arn=self.format_arn(
                    service="ses", resource="identity", resource_name=domain
                ),
            )
        attachment(
            self,
            "ReplicaConfig",
            user_pool_id=identity.user_pool_id,
            lambda_config=attachment.LambdaConfigProperty(
                pre_authentication=triggers["ReplicaPreAuth"].function_arn,
                pre_token_generation_config=attachment.PreTokenGenerationConfigProperty(
                    lambda_arn=triggers["ReplicaPreTokenGen"].function_arn,
                    lambda_version="V3_0",
                ),
            ),
            email_configuration=email,
            # Configure on one deploy, activate on the next (-c activate_replica=true).
            status="ACTIVE" if cfg.activate_replica else "INACTIVE",
        )


def _origin(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _visibility(name: str) -> waf.CfnWebACL.VisibilityConfigProperty:
    return waf.CfnWebACL.VisibilityConfigProperty(
        cloud_watch_metrics_enabled=True, metric_name=name, sampled_requests_enabled=True
    )


def _managed_rule(name: str, priority: int) -> waf.CfnWebACL.RuleProperty:
    return waf.CfnWebACL.RuleProperty(
        name=name,
        priority=priority,
        override_action=waf.CfnWebACL.OverrideActionProperty(none={}),
        statement=waf.CfnWebACL.StatementProperty(
            managed_rule_group_statement=waf.CfnWebACL.ManagedRuleGroupStatementProperty(
                vendor_name="AWS", name=name
            )
        ),
        visibility_config=_visibility(name),
    )
