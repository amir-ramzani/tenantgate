"""Synthetic auth canary (plan §9).

Runs every minute in the primary Region and probes the two things tenants
depend on:

1. **M2M** — ``client_credentials`` against the Region's own token endpoint
   (the prefix domain, so the probe never follows a failover);
2. **User sign-in** — ``InitiateAuth`` (``USER_PASSWORD_AUTH``) for a canary
   user on a dedicated system client.

It publishes ``AuthHealthy`` (1/0) plus per-probe latency to CloudWatch. An
alarm on ``AuthHealthy`` backs the Route 53 health check, which in turn drives
the Cognito custom-domain failover and the ``api.*`` failover record.

For DR drills, setting the SSM parameter ``CANARY_FORCE_PARAM`` to
``unhealthy`` makes the canary report 0 without touching Cognito.
"""

from __future__ import annotations

import base64
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from aws_lambda_powertools import Logger

from tenantgate.aws import client

logger = Logger(service="tenantgate-canary")

NAMESPACE = "Tenantgate/Canary"


@dataclass(frozen=True)
class CanaryConfig:
    region: str
    token_endpoint: str
    secret_id: str
    force_param: str | None = None
    namespace: str = NAMESPACE
    scope: str = "api/read"

    @classmethod
    def from_env(cls) -> CanaryConfig:
        return cls(
            region=os.environ.get("AWS_REGION", "ap-southeast-1"),
            token_endpoint=os.environ["TOKEN_ENDPOINT"],
            secret_id=os.environ["CANARY_SECRET_ID"],
            force_param=os.environ.get("CANARY_FORCE_PARAM") or None,
            namespace=os.environ.get("CANARY_NAMESPACE", NAMESPACE),
            scope=os.environ.get("CANARY_SCOPE", "api/read"),
        )


@dataclass
class ProbeResult:
    name: str
    ok: bool
    latency_ms: float
    error: str | None = None


@dataclass
class CanaryReport:
    probes: list[ProbeResult] = field(default_factory=list)
    forced: bool = False

    @property
    def healthy(self) -> bool:
        return not self.forced and bool(self.probes) and all(p.ok for p in self.probes)


HttpPost = Callable[[str, bytes, dict[str, str]], tuple[int, bytes]]


def http_post(url: str, data: bytes, headers: dict[str, str]) -> tuple[int, bytes]:
    if not url.startswith("https://"):
        raise ValueError("token endpoint must use https")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")  # noqa: S310
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310
            return int(resp.status), resp.read()
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read()


def _timed(name: str, fn: Callable[[], None]) -> ProbeResult:
    start = time.perf_counter()
    try:
        fn()
        return ProbeResult(name, True, (time.perf_counter() - start) * 1000)
    except Exception as exc:
        return ProbeResult(name, False, (time.perf_counter() - start) * 1000, type(exc).__name__)


class Canary:
    def __init__(
        self,
        cfg: CanaryConfig,
        *,
        secrets: Any,
        idp: Any,
        cloudwatch: Any,
        ssm: Any | None = None,
        post: HttpPost = http_post,
    ) -> None:
        self.cfg = cfg
        self._secrets = secrets
        self._idp = idp
        self._cw = cloudwatch
        self._ssm = ssm
        self._post = post

    def _secret(self) -> dict[str, str]:
        raw = self._secrets.get_secret_value(SecretId=self.cfg.secret_id)["SecretString"]
        data: dict[str, str] = json.loads(raw)
        return data

    def _forced_unhealthy(self) -> bool:
        if not self.cfg.force_param or self._ssm is None:
            return False
        try:
            value = self._ssm.get_parameter(Name=self.cfg.force_param)["Parameter"]["Value"]
        except Exception:
            return False
        return str(value).strip().lower() == "unhealthy"

    def probe_m2m(self, secret: dict[str, str]) -> None:
        basic = base64.b64encode(
            f"{secret['m2m_client_id']}:{secret['m2m_client_secret']}".encode()
        ).decode()
        body = urllib.parse.urlencode(
            {"grant_type": "client_credentials", "scope": self.cfg.scope}
        ).encode()
        status, payload = self._post(
            self.cfg.token_endpoint,
            body,
            {
                "Authorization": f"Basic {basic}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        if status != 200 or "access_token" not in json.loads(payload or b"{}"):
            raise RuntimeError(f"token endpoint returned {status}")

    def probe_user(self, secret: dict[str, str]) -> None:
        resp = self._idp.initiate_auth(
            ClientId=secret["user_client_id"],
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": secret["username"], "PASSWORD": secret["password"]},
        )
        if "AuthenticationResult" not in resp:
            raise RuntimeError(f"unexpected challenge {resp.get('ChallengeName')}")

    def run(self) -> CanaryReport:
        report = CanaryReport(forced=self._forced_unhealthy())
        if not report.forced:
            try:
                secret = self._secret()
            except Exception as exc:
                report.probes.append(ProbeResult("secret", False, 0.0, type(exc).__name__))
            else:
                report.probes.append(_timed("m2m", lambda: self.probe_m2m(secret)))
                report.probes.append(_timed("user", lambda: self.probe_user(secret)))
        self.publish(report)
        return report

    def publish(self, report: CanaryReport) -> None:
        dims = [{"Name": "Region", "Value": self.cfg.region}]
        data: list[dict[str, Any]] = [
            {
                "MetricName": "AuthHealthy",
                "Dimensions": dims,
                "Value": 1 if report.healthy else 0,
                "Unit": "Count",
            }
        ]
        for p in report.probes:
            data.append(
                {
                    "MetricName": f"{p.name.capitalize()}LatencyMs",
                    "Dimensions": dims,
                    "Value": round(p.latency_ms, 1),
                    "Unit": "Milliseconds",
                }
            )
        self._cw.put_metric_data(Namespace=self.cfg.namespace, MetricData=data)


def build_canary() -> Canary:
    cfg = CanaryConfig.from_env()
    return Canary(
        cfg,
        secrets=client("secretsmanager", cfg.region),
        idp=client("cognito-idp", cfg.region),
        cloudwatch=client("cloudwatch", cfg.region),
        ssm=client("ssm", cfg.region),
    )


_canary: Canary | None = None


@logger.inject_lambda_context(clear_state=True)
def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    global _canary
    if _canary is None:
        _canary = build_canary()
    report = _canary.run()
    result = {
        "healthy": report.healthy,
        "forced": report.forced,
        "probes": [p.__dict__ for p in report.probes],
    }
    if report.healthy:
        logger.info("canary result", extra=result)
    else:
        logger.warning("canary result", extra=result)
    return result
