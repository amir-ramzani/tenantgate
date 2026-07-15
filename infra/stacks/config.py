"""Typed view of the CDK context (cdk.json + ``-c key=value``)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import aws_cdk as cdk

REPO_ROOT = Path(__file__).resolve().parents[2]
# Built by scripts/build_lambda.sh: src/ packages + runtime dependencies (arm64).
LAMBDA_ASSET = REPO_ROOT / "build" / "lambda"


def _bool(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes"}


@dataclass(frozen=True)
class Config:
    stage: str
    domain_name: str
    hosted_zone_id: str
    primary_region: str
    secondary_region: str
    multi_region: bool
    activate_replica: bool
    ses_from_email: str | None
    admin_callback_urls: tuple[str, ...]
    github_repo: str | None
    token_issuer: str | None
    alarm_email: str | None

    # ---- derived names (shared by every stack, so no cross-stack references needed)

    @property
    def prefix(self) -> str:
        return f"tg-{self.stage}"

    @property
    def is_prod(self) -> bool:
        return self.stage == "prod"

    @property
    def auth_domain(self) -> str:
        return f"auth.{self.domain_name}"

    @property
    def api_domain(self) -> str:
        return f"api.{self.domain_name}"

    @property
    def registry_table_name(self) -> str:
        return f"tenantgate-{self.stage}-registry"

    @property
    def notes_table_name(self) -> str:
        return f"tenantgate-{self.stage}-notes"

    @property
    def idempotency_table_name(self) -> str:
        return f"tenantgate-{self.stage}-idempotency"

    @property
    def canary_alarm_name(self) -> str:
        return f"tenantgate-{self.stage}-auth-unhealthy"

    @property
    def regions(self) -> tuple[str, ...]:
        if self.multi_region:
            return (self.primary_region, self.secondary_region)
        return (self.primary_region,)

    def param(self, name: str) -> str:
        return f"/tenantgate/{self.stage}/{name}"

    @classmethod
    def from_app(cls, app: cdk.App) -> Config:
        def ctx(key: str, default: str | None = None) -> str | None:
            value = app.node.try_get_context(key)
            return default if value in (None, "") else str(value)

        def required(key: str) -> str:
            value = ctx(key)
            if value is None:
                raise ValueError(f"missing CDK context value: -c {key}=...")
            return value

        callbacks = ctx("admin_callback_urls", "http://localhost:3000/callback") or ""
        cfg = cls(
            stage=ctx("stage", "dev") or "dev",
            domain_name=required("domain_name"),
            hosted_zone_id=required("hosted_zone_id"),
            primary_region=ctx("primary_region", "ap-southeast-1") or "ap-southeast-1",
            secondary_region=ctx("secondary_region", "ap-southeast-2") or "ap-southeast-2",
            multi_region=_bool(ctx("multi_region")),
            activate_replica=_bool(ctx("activate_replica")),
            ses_from_email=ctx("ses_from_email"),
            admin_callback_urls=tuple(u.strip() for u in callbacks.split(",") if u.strip()),
            github_repo=ctx("github_repo"),
            token_issuer=ctx("token_issuer"),
            alarm_email=ctx("alarm_email"),
        )
        if cfg.multi_region and cfg.primary_region == cfg.secondary_region:
            raise ValueError("secondary_region must differ from primary_region")
        return cfg
