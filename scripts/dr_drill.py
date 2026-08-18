#!/usr/bin/env python3
"""Forced failover / failback drill (plan §9, Phase 9).

Steps:

1. Pre-flight: the API answers from the primary; the health check is healthy.
2. Force failover, either
   * ``--method canary`` (default): set the canary-force parameter to
     ``unhealthy`` -> alarm -> health check -> DNS. Exercises the whole chain.
   * ``--method invert``: invert the Route 53 health check. Faster; skips the alarm.
3. Put the primary control plane in ``auth_mode=failover`` (read-only).
4. Poll ``https://api.<domain>/demo/health`` until the secondary answers and
   record the time to failover (the identity RTO proxy).
5. Run the integration suite against the failed-over stack.
6. Failback — only with ``--failback`` (it is a deliberate manual step in the
   runbook): revert the forcing, set ``auth_mode=normal``, wait for the primary.

The report is printed as JSON and can be appended to docs/dr-runbook.md.

Example::

    python scripts/dr_drill.py --domain example.com --stage dev \
        --primary ap-southeast-1 --secondary ap-southeast-2 --failback
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

import boto3


@dataclass
class Report:
    started_at: str
    method: str
    primary: str
    secondary: str
    steps: list[dict[str, Any]] = field(default_factory=list)
    failover_seconds: float | None = None
    failback_seconds: float | None = None
    integration_passed: bool | None = None

    def step(self, name: str, **details: Any) -> None:
        entry = {"at": datetime.now(UTC).isoformat(timespec="seconds"), "step": name, **details}
        self.steps.append(entry)
        print(f"[drill] {name} {details if details else ''}", flush=True)


def served_region(url: str) -> str | None:
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:  # noqa: S310
            return resp.headers.get("X-Served-Region")
    except Exception:
        return None


def wait_for_region(url: str, region: str, timeout: float, interval: float = 10.0) -> float:
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        if served_region(url) == region:
            return time.monotonic() - start
        time.sleep(interval)
    raise TimeoutError(f"{url} not served from {region} within {timeout:.0f}s")


def output(cfn: Any, stack: str, key: str) -> str:
    desc = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    for o in desc.get("Outputs", []):
        if o["OutputKey"] == key:
            return str(o["OutputValue"])
    raise KeyError(f"{stack} has no output {key}")


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--domain", required=True)
    ap.add_argument("--stage", default="dev")
    ap.add_argument("--primary", default="ap-southeast-1")
    ap.add_argument("--secondary", default="ap-southeast-2")
    ap.add_argument("--method", choices=["canary", "invert"], default="canary")
    ap.add_argument("--timeout", type=float, default=900, help="seconds to wait for each switch")
    ap.add_argument("--skip-tests", action="store_true")
    ap.add_argument("--failback", action="store_true", help="also fail back at the end")
    ap.add_argument("--report", help="write the JSON report to this file")
    args = ap.parse_args()

    health_url = f"https://api.{args.domain}/demo/health"
    prefix = f"tg-{args.stage}"
    cfn = boto3.client("cloudformation", region_name=args.primary)
    r53 = boto3.client("route53")
    ssm_primary = boto3.client("ssm", region_name=args.primary)
    force_param = f"/tenantgate/{args.stage}/canary-force"
    mode_param = f"/tenantgate/{args.stage}/auth-mode"

    report = Report(
        started_at=datetime.now(UTC).isoformat(timespec="seconds"),
        method=args.method,
        primary=args.primary,
        secondary=args.secondary,
    )

    # 1. pre-flight
    health_check_id = output(cfn, f"{prefix}-identity", "HealthCheckId")
    status = r53.get_health_check_status(HealthCheckId=health_check_id)
    healthy = all(
        "Success" in o["StatusReport"]["Status"] for o in status["HealthCheckObservations"]
    )
    region_now = served_region(health_url)
    report.step("preflight", health_check_id=health_check_id, healthy=healthy, served=region_now)
    if region_now != args.primary:
        print("API is not served from the primary; aborting", file=sys.stderr)
        return 2

    # 2-3. force failover + degraded mode
    if args.method == "canary":
        ssm_primary.put_parameter(
            Name=force_param, Value="unhealthy", Overwrite=True, Type="String"
        )
    else:
        r53.update_health_check(HealthCheckId=health_check_id, Inverted=True)
    ssm_primary.put_parameter(Name=mode_param, Value="failover", Overwrite=True, Type="String")
    report.step("forced-failover")

    # 4. measure
    try:
        report.failover_seconds = round(
            wait_for_region(health_url, args.secondary, args.timeout), 1
        )
        report.step("failed-over", seconds=report.failover_seconds)
    except TimeoutError as exc:
        report.step("failover-timeout", error=str(exc))

    # 5. integration suite against the secondary
    if not args.skip_tests and report.failover_seconds is not None:
        env = {**os.environ, "TG_EXPECT_REGION": args.secondary, "TG_EXPECT_DEGRADED": "1"}
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "-m", "integration", "-q", "tests/integration"],
            env=env,
            check=False,
        )
        report.integration_passed = result.returncode == 0
        report.step("integration", passed=report.integration_passed)

    # 6. failback (manual by default)
    if args.failback:
        if args.method == "canary":
            ssm_primary.put_parameter(Name=force_param, Value="off", Overwrite=True, Type="String")
        else:
            r53.update_health_check(HealthCheckId=health_check_id, Inverted=False)
        try:
            report.failback_seconds = round(
                wait_for_region(health_url, args.primary, args.timeout), 1
            )
            ssm_primary.put_parameter(
                Name=mode_param, Value="normal", Overwrite=True, Type="String"
            )
            report.step("failed-back", seconds=report.failback_seconds)
        except TimeoutError as exc:
            report.step("failback-timeout", error=str(exc))
    else:
        report.step("failback-pending", note="follow docs/dr-runbook.md to fail back")

    out = json.dumps(asdict(report), indent=2)
    print(out)
    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
    ok = report.failover_seconds is not None and report.integration_passed is not False
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
