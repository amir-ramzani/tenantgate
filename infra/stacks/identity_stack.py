"""User pool, triggers, system clients, custom domain, health check and MRR replica.

Day-one decisions (§7.3) live here because they are expensive to change later:

* Essentials feature plan (access-token customisation, multi-Region replication);
* multi-Region KMS customer-managed key (``KeyConfiguration``);
* multi-Region issuer (``IssuerConfiguration = UPDATED``) — changing ``iss``
  later would break every validator;
* custom domain with managed login v2 (the classic hosted UI isn't supported
  on replicas);
* email MFA instead of TOTP (TOTP doesn't work in the secondary); no passkeys.

With ``-c multi_region=true`` this stack also creates the canary-backed Route 53
health check, the ``AWS::Cognito::UserPoolReplica`` (starts INACTIVE) and the
custom domain's ``Routing.Failover`` so Cognito serves managed login and the
token endpoint from the replica when the health check fails.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from aws_cdk import CfnOutput, Duration, Fn, RemovalPolicy, Stack
from aws_cdk import aws_certificatemanager as acm
from aws_cdk import aws_cloudwatch as cw
from aws_cdk import aws_cloudwatch_actions as cw_actions
from aws_cdk import aws_cognito as cognito
from aws_cdk import aws_dynamodb as ddb
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_route53 as route53
from aws_cdk import aws_route53_targets as targets
from aws_cdk import aws_sns as sns
from aws_cdk import aws_sns_subscriptions as subs
from aws_cdk import aws_ssm as ssm
from aws_cdk import custom_resources as cr
from constructs import Construct

from stacks.config import LAMBDA_ASSET, Config

PLATFORM_ADMIN_GROUP = "platform-admins"
CANARY_NAMESPACE = "Tenantgate/Canary"
RESOURCE_SERVER_ID = "api"


@dataclass(frozen=True)
class IdentityOutputs:
    user_pool_id: str
    issuer: str
    system_client_id: str
    system_client_ids_csv: str
    system_ids_param: str
    canary_user_client_id: str
    canary_m2m_client_id: str
    regional_domain_prefix: str
    health_check_id: str | None


def trigger_function(
    scope: Construct,
    cid: str,
    *,
    cfg: Config,
    handler: str,
    region_role: str,
    system_ids_param: str,
    can_write: bool,
) -> lambda_.Function:
    """Same trigger code in every Region; reads only the local table replica."""
    fn = lambda_.Function(
        scope,
        cid,
        runtime=lambda_.Runtime.PYTHON_3_12,
        architecture=lambda_.Architecture.ARM_64,
        handler=handler,
        code=lambda_.Code.from_asset(str(LAMBDA_ASSET)),
        memory_size=512,
        # Cognito gives a trigger 5 s; boto3 is capped at 3 x (1 s + 1 s) and backs off.
        timeout=Duration.seconds(4),
        tracing=lambda_.Tracing.ACTIVE,
        environment={
            "TABLE_NAME": cfg.registry_table_name,
            "SYSTEM_CLIENT_IDS_PARAM": system_ids_param,
            "REGION_ROLE": region_role,
            "RESOURCE_SERVER_ID": RESOURCE_SERVER_ID,
            "POWERTOOLS_SERVICE_NAME": "tenantgate-triggers",
            "POWERTOOLS_LOG_LEVEL": "INFO",
        },
    )
    table = ddb.TableV2.from_table_name(scope, f"{cid}Registry", cfg.registry_table_name)
    if can_write:
        table.grant_read_write_data(fn)  # JIT membership; code enforces primary-only
    else:
        table.grant_read_data(fn)
    fn.add_to_role_policy(
        iam.PolicyStatement(
            actions=["ssm:GetParameter"],
            resources=[
                Stack.of(scope).format_arn(
                    service="ssm", resource="parameter", resource_name=system_ids_param.lstrip("/")
                )
            ],
        )
    )
    return fn


class IdentityStack(Stack):
    def __init__(
        self,
        scope: Construct,
        cid: str,
        *,
        cfg: Config,
        auth_certificate: acm.ICertificate,
        pool_key_arn: str,
        **kw: Any,
    ) -> None:
        super().__init__(scope, cid, **kw)
        system_ids_param = cfg.param("system-client-ids")
        zone = route53.HostedZone.from_hosted_zone_attributes(
            self, "Zone", hosted_zone_id=cfg.hosted_zone_id, zone_name=cfg.domain_name
        )

        # ------------------------------------------------------------ user pool
        email = (
            cognito.UserPoolEmail.with_ses(
                from_email=cfg.ses_from_email,
                ses_verified_domain=cfg.ses_from_email.split("@", 1)[1],
            )
            if cfg.ses_from_email
            else None
        )
        pool = cognito.UserPool(
            self,
            "Pool",
            user_pool_name=f"tenantgate-{cfg.stage}",
            feature_plan=cognito.FeaturePlan.ESSENTIALS,
            self_sign_up_enabled=False,
            sign_in_aliases=cognito.SignInAliases(email=True),
            auto_verify=cognito.AutoVerifiedAttrs(email=True),
            account_recovery=cognito.AccountRecovery.EMAIL_ONLY,
            # Email MFA needs SES-backed email; without SES (cheap dev) MFA stays off.
            mfa=cognito.Mfa.OPTIONAL if email else cognito.Mfa.OFF,
            mfa_second_factor=(
                cognito.MfaSecondFactor(sms=False, otp=False, email=True) if email else None
            ),
            email=email,
            password_policy=cognito.PasswordPolicy(
                min_length=12, require_digits=True, require_lowercase=True, require_uppercase=True
            ),
            deletion_protection=cfg.is_prod,
            removal_policy=RemovalPolicy.RETAIN if cfg.is_prod else RemovalPolicy.DESTROY,
        )
        cfn_pool = pool.node.default_child
        assert isinstance(cfn_pool, cognito.CfnUserPool)
        cfn_pool.key_configuration = cognito.CfnUserPool.KeyConfigurationProperty(
            key_type="CUSTOMER_MANAGED_KEY", kms_key_arn=pool_key_arn
        )
        cfn_pool.issuer_configuration = cognito.CfnUserPool.IssuerConfigurationProperty(
            type="UPDATED"
        )

        # ------------------------------------------------------------ triggers
        pre_auth = trigger_function(
            self,
            "PreAuth",
            cfg=cfg,
            handler="triggers.pre_auth.handler",
            region_role="primary",
            system_ids_param=system_ids_param,
            can_write=False,
        )
        pre_token = trigger_function(
            self,
            "PreTokenGen",
            cfg=cfg,
            handler="triggers.pre_token_gen.handler",
            region_role="primary",
            system_ids_param=system_ids_param,
            can_write=True,
        )
        pool.add_trigger(cognito.UserPoolOperation.PRE_AUTHENTICATION, pre_auth)
        # V3 covers both user flows and client-credentials token generation.
        pool.add_trigger(
            cognito.UserPoolOperation.PRE_TOKEN_GENERATION_CONFIG,
            pre_token,
            cognito.LambdaVersion.V3_0,
        )

        # ------------------------------------------------------------ resource server
        # Created once via SDK call, then *owned by the control plane*, which appends
        # per-tenant M2M scopes. A CDK-managed resource server would reset those
        # scopes on every deploy and silently break every tenant's M2M clients.
        rs = cr.AwsCustomResource(
            self,
            "ResourceServer",
            on_create=cr.AwsSdkCall(
                service="CognitoIdentityServiceProvider",
                action="createResourceServer",
                parameters={
                    "UserPoolId": pool.user_pool_id,
                    "Identifier": RESOURCE_SERVER_ID,
                    "Name": "tenantgate api",
                    "Scopes": [
                        {"ScopeName": "read", "ScopeDescription": "Read tenant data"},
                        {"ScopeName": "write", "ScopeDescription": "Write tenant data"},
                    ],
                },
                physical_resource_id=cr.PhysicalResourceId.of(RESOURCE_SERVER_ID),
            ),
            on_delete=cr.AwsSdkCall(
                service="CognitoIdentityServiceProvider",
                action="deleteResourceServer",
                parameters={"UserPoolId": pool.user_pool_id, "Identifier": RESOURCE_SERVER_ID},
            ),
            policy=cr.AwsCustomResourcePolicy.from_sdk_calls(resources=[pool.user_pool_arn]),
            install_latest_aws_sdk=False,
        )

        cognito.CfnUserPoolGroup(
            self,
            "PlatformAdmins",
            user_pool_id=pool.user_pool_id,
            group_name=PLATFORM_ADMIN_GROUP,
            description="Operators of the tenantgate control plane",
        )

        # ------------------------------------------------------------ system clients
        system_client = pool.add_client(
            "ControlPlaneUi",
            user_pool_client_name="system-control-plane",
            generate_secret=False,
            auth_flows=cognito.AuthFlow(user_srp=True),
            o_auth=cognito.OAuthSettings(
                flows=cognito.OAuthFlows(authorization_code_grant=True),
                scopes=[cognito.OAuthScope.OPENID, cognito.OAuthScope.EMAIL],
                callback_urls=list(cfg.admin_callback_urls),
            ),
            prevent_user_existence_errors=True,
            enable_token_revocation=True,
            access_token_validity=Duration.minutes(60),
        )
        canary_user = pool.add_client(
            "CanaryUser",
            user_pool_client_name="system-canary-user",
            generate_secret=False,
            auth_flows=cognito.AuthFlow(user_password=True),
            disable_o_auth=True,
            access_token_validity=Duration.minutes(5),
            id_token_validity=Duration.minutes(5),
        )
        canary_m2m = pool.add_client(
            "CanaryM2M",
            user_pool_client_name="system-canary-m2m",
            generate_secret=True,
            o_auth=cognito.OAuthSettings(
                flows=cognito.OAuthFlows(client_credentials=True),
                scopes=[cognito.OAuthScope.custom(f"{RESOURCE_SERVER_ID}/read")],
            ),
            access_token_validity=Duration.minutes(5),
        )
        canary_m2m.node.add_dependency(rs)

        system_ids_csv = Fn.join(
            ",",
            [
                system_client.user_pool_client_id,
                canary_user.user_pool_client_id,
                canary_m2m.user_pool_client_id,
            ],
        )
        # The triggers can't reference the clients directly (pool -> trigger -> client
        # would be a cycle), so they read the list from SSM.
        ssm.StringParameter(
            self, "SystemClientIds", parameter_name=system_ids_param, string_value=system_ids_csv
        )

        # ------------------------------------------------------------ domains
        custom_domain = pool.add_domain(
            "CustomDomain",
            custom_domain=cognito.CustomDomainOptions(
                domain_name=cfg.auth_domain, certificate=auth_certificate
            ),
            managed_login_version=cognito.ManagedLoginVersion.NEWER_MANAGED_LOGIN,
        )
        # Regional prefix domain: the canary probes *this* Region's token endpoint,
        # never the failover-routed custom domain.
        domain_prefix = f"tenantgate-{cfg.stage}-{self.account}"
        pool.add_domain(
            "PrefixDomain",
            cognito_domain=cognito.CognitoDomainOptions(domain_prefix=domain_prefix),
            managed_login_version=cognito.ManagedLoginVersion.NEWER_MANAGED_LOGIN,
        )
        route53.ARecord(
            self,
            "AuthAlias",
            zone=zone,
            record_name=cfg.auth_domain,
            target=route53.RecordTarget.from_alias(targets.UserPoolDomainTarget(custom_domain)),
        )
        cognito.CfnManagedLoginBranding(
            self,
            "SystemClientBranding",
            user_pool_id=pool.user_pool_id,
            client_id=system_client.user_pool_client_id,
            use_cognito_provided_values=True,
        )

        # ------------------------------------------------------------ health signal (§9)
        topic = sns.Topic(self, "AuthAlarms", display_name=f"tenantgate {cfg.stage} auth")
        if cfg.alarm_email:
            topic.add_subscription(subs.EmailSubscription(cfg.alarm_email))
        alarm = cw.Alarm(
            self,
            "AuthUnhealthy",
            alarm_name=cfg.canary_alarm_name,
            alarm_description="Synthetic canary cannot obtain tokens in the primary Region",
            metric=cw.Metric(
                namespace=CANARY_NAMESPACE,
                metric_name="AuthHealthy",
                dimensions_map={"Region": self.region},
                statistic="Minimum",
                period=Duration.minutes(1),
            ),
            comparison_operator=cw.ComparisonOperator.LESS_THAN_THRESHOLD,
            threshold=1,
            evaluation_periods=3,
            datapoints_to_alarm=3,
            # No data means the canary itself can't run: treat as unhealthy.
            treat_missing_data=cw.TreatMissingData.BREACHING,
        )
        alarm.add_alarm_action(cw_actions.SnsAction(topic))
        alarm.add_ok_action(cw_actions.SnsAction(topic))

        health_check_id: str | None = None
        if cfg.multi_region:
            health = route53.CfnHealthCheck(
                self,
                "AuthHealth",
                health_check_config=route53.CfnHealthCheck.HealthCheckConfigProperty(
                    type="CLOUDWATCH_METRIC",
                    alarm_identifier=route53.CfnHealthCheck.AlarmIdentifierProperty(
                        name=alarm.alarm_name, region=self.region
                    ),
                    insufficient_data_health_status="LastKnownStatus",
                    inverted=False,  # scripts/dr_drill.py flips this to force failover
                ),
                health_check_tags=[
                    route53.CfnHealthCheck.HealthCheckTagProperty(
                        key="Name", value=f"tenantgate-{cfg.stage}-auth"
                    )
                ],
            )
            health_check_id = health.attr_health_check_id
            replica = cognito.CfnUserPoolReplica(
                self,
                "PoolReplica",
                user_pool_id=pool.user_pool_id,
                region_name=cfg.secondary_region,
            )
            cfn_domain = custom_domain.node.default_child
            assert isinstance(cfn_domain, cognito.CfnUserPoolDomain)
            cfn_domain.routing = cognito.CfnUserPoolDomain.RoutingTypeProperty(
                failover=cognito.CfnUserPoolDomain.FailoverTypeProperty(
                    primary_route53_health_check_id=health.attr_health_check_id,
                    secondary_region=cfg.secondary_region,
                )
            )
            cfn_domain.add_dependency(replica)
            CfnOutput(self, "HealthCheckId", value=health.attr_health_check_id)

        # With IssuerConfiguration=UPDATED, read the real `iss` from the pool's
        # /.well-known/openid-configuration after the first deploy and pin it with
        # -c token_issuer=... ; every validator compares against this value.
        issuer = cfg.token_issuer or (
            f"https://cognito-idp.{self.region}.amazonaws.com/{pool.user_pool_id}"
        )

        self.pool = pool
        self.outputs = IdentityOutputs(
            user_pool_id=pool.user_pool_id,
            issuer=issuer,
            system_client_id=system_client.user_pool_client_id,
            system_client_ids_csv=system_ids_csv,
            system_ids_param=system_ids_param,
            canary_user_client_id=canary_user.user_pool_client_id,
            canary_m2m_client_id=canary_m2m.user_pool_client_id,
            regional_domain_prefix=domain_prefix,
            health_check_id=health_check_id,
        )
        CfnOutput(self, "UserPoolId", value=pool.user_pool_id)
        CfnOutput(self, "Issuer", value=issuer)
        CfnOutput(self, "SystemClientId", value=system_client.user_pool_client_id)
        CfnOutput(self, "CanaryUserClientId", value=canary_user.user_pool_client_id)
        CfnOutput(self, "CanaryM2MClientId", value=canary_m2m.user_pool_client_id)
