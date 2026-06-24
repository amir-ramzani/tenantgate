"""Resilience building blocks: boto3 config, degraded-mode flag, idempotency, canary."""

from __future__ import annotations

import json
from typing import Any

import boto3
import pytest

from canary.handler import Canary, CanaryConfig
from tenantgate.auth_mode import AuthMode, AuthModeProvider
from tenantgate.aws import client, config_for
from tenantgate.idempotency import IdempotencyInProgress, IdempotencyMismatch, IdempotencyStore
from tenantgate.settings import load_settings
from tests.conftest import REGION, create_idempotency_table

# ---------------------------------------------------------------- boto3 config


def test_trigger_profile_fits_cognito_budget() -> None:
    cfg = config_for("trigger")
    assert cfg.retries == {"mode": "adaptive", "max_attempts": 3}
    worst = cfg.retries["max_attempts"] * (cfg.connect_timeout + cfg.read_timeout)
    assert worst <= 6  # plus backoff, still bounded by the Lambda's 4 s timeout
    assert config_for("api").retries["mode"] == "adaptive"


def test_clients_are_cached(aws: None) -> None:
    assert client("ssm", REGION) is client("ssm", REGION)
    assert client("ssm", REGION) is not client("ssm", REGION, profile="trigger")


# ---------------------------------------------------------------- auth mode


@pytest.fixture
def ssm(aws: None) -> Any:
    return boto3.client("ssm", region_name=REGION)


def _provider(
    monkeypatch: pytest.MonkeyPatch, ssm: Any, role: str = "primary", **kw: Any
) -> AuthModeProvider:
    monkeypatch.setenv("AUTH_MODE_PARAM", "/tg/auth_mode")
    monkeypatch.setenv("REGION_ROLE", role)
    return AuthModeProvider(load_settings(), ssm, **kw)


def test_mode_defaults_to_normal_without_param(monkeypatch: pytest.MonkeyPatch, ssm: Any) -> None:
    p = _provider(monkeypatch, ssm)
    assert p.current() is AuthMode.NORMAL and p.writes_allowed()


def test_failover_blocks_writes(monkeypatch: pytest.MonkeyPatch, ssm: Any) -> None:
    p = _provider(monkeypatch, ssm, ttl=0)
    p.set_mode(AuthMode.FAILOVER)
    assert p.current() is AuthMode.FAILOVER
    assert not p.writes_allowed()
    assert p.status().as_dict()["auth_mode"] == "failover"
    p.set_mode(AuthMode.NORMAL)
    assert p.writes_allowed()


def test_secondary_never_writes(monkeypatch: pytest.MonkeyPatch, ssm: Any) -> None:
    p = _provider(monkeypatch, ssm, role="secondary")
    assert p.current() is AuthMode.NORMAL
    assert not p.writes_allowed()


def test_mode_cache_and_last_known_value(monkeypatch: pytest.MonkeyPatch, ssm: Any) -> None:
    now = [0.0]
    p = _provider(monkeypatch, ssm, ttl=30, clock=lambda: now[0])
    ssm.put_parameter(Name="/tg/auth_mode", Value="failover", Type="String")
    assert p.current() is AuthMode.FAILOVER
    ssm.put_parameter(Name="/tg/auth_mode", Value="normal", Type="String", Overwrite=True)
    assert p.current() is AuthMode.FAILOVER  # cached
    ssm.put_parameter(Name="/tg/auth_mode", Value="garbage", Type="String", Overwrite=True)
    now[0] = 31
    assert p.current() is AuthMode.FAILOVER  # unreadable value: keep last known


def test_set_mode_requires_param(ssm: Any) -> None:
    with pytest.raises(RuntimeError):
        AuthModeProvider(load_settings(), ssm).set_mode(AuthMode.FAILOVER)


# ---------------------------------------------------------------- idempotency


@pytest.fixture
def store(aws: None) -> IdempotencyStore:
    return IdempotencyStore(create_idempotency_table(), lock_seconds=60)


def test_idempotent_replay(store: IdempotencyStore) -> None:
    assert store.begin("u1", "k", {"a": 1}) is None
    with pytest.raises(IdempotencyInProgress):
        store.begin("u1", "k", {"a": 1})
    store.complete("u1", "k", 201, {"id": "t-1"})
    replay = store.begin("u1", "k", {"a": 1})
    assert replay is not None and replay.status_code == 201 and replay.body == {"id": "t-1"}
    with pytest.raises(IdempotencyMismatch):
        store.begin("u1", "k", {"a": 2})
    # Keys are per caller.
    assert store.begin("u2", "k", {"a": 2}) is None


def test_release_allows_retry(store: IdempotencyStore) -> None:
    assert store.begin("u1", "k", {}) is None
    store.release("u1", "k")
    assert store.begin("u1", "k", {}) is None


def test_stale_lock_is_taken_over(aws: None) -> None:
    s = IdempotencyStore(create_idempotency_table(), lock_seconds=-1)
    assert s.begin("u1", "k", {}) is None
    assert s.begin("u1", "k", {}) is None  # first attempt died; lock expired


# ---------------------------------------------------------------- canary


class Recorder:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def put_metric_data(self, **kw: Any) -> None:
        self.calls.append(kw)

    def healthy_value(self) -> float:
        data = self.calls[-1]["MetricData"]
        return float(next(d["Value"] for d in data if d["MetricName"] == "AuthHealthy"))


class Secrets:
    def get_secret_value(self, SecretId: str) -> dict[str, str]:
        return {
            "SecretString": json.dumps(
                {
                    "m2m_client_id": "m2m",
                    "m2m_client_secret": "s3cret",
                    "user_client_id": "uc",
                    "username": "canary",
                    "password": "pw",
                }
            )
        }


class Idp:
    def __init__(self, ok: bool = True) -> None:
        self.ok = ok

    def initiate_auth(self, **kw: Any) -> dict[str, Any]:
        assert kw["AuthFlow"] == "USER_PASSWORD_AUTH"
        if not self.ok:
            raise RuntimeError("NotAuthorizedException")
        return {"AuthenticationResult": {"AccessToken": "x"}}


class Ssm:
    def __init__(self, value: str | None) -> None:
        self.value = value

    def get_parameter(self, Name: str) -> dict[str, Any]:
        if self.value is None:
            raise RuntimeError("ParameterNotFound")
        return {"Parameter": {"Value": self.value}}


CFG = CanaryConfig(
    region=REGION, token_endpoint="https://auth.test/oauth2/token", secret_id="s", force_param="/f"
)


def _post_ok(url: str, data: bytes, headers: dict[str, str]) -> tuple[int, bytes]:
    assert headers["Authorization"].startswith("Basic ")
    assert b"grant_type=client_credentials" in data
    return 200, b'{"access_token": "x", "expires_in": 300}'


def test_canary_healthy() -> None:
    cw = Recorder()
    report = Canary(
        CFG, secrets=Secrets(), idp=Idp(), cloudwatch=cw, ssm=Ssm(None), post=_post_ok
    ).run()
    assert report.healthy
    assert cw.healthy_value() == 1
    names = {d["MetricName"] for d in cw.calls[-1]["MetricData"]}
    assert names == {"AuthHealthy", "M2mLatencyMs", "UserLatencyMs"}


def test_canary_m2m_failure() -> None:
    cw = Recorder()
    canary = Canary(CFG, secrets=Secrets(), idp=Idp(), cloudwatch=cw, post=lambda *_: (500, b"{}"))
    report = canary.run()
    assert not report.healthy
    assert [p.ok for p in report.probes] == [False, True]
    assert cw.healthy_value() == 0


def test_canary_user_failure() -> None:
    cw = Recorder()
    report = Canary(CFG, secrets=Secrets(), idp=Idp(ok=False), cloudwatch=cw, post=_post_ok).run()
    assert not report.healthy and report.probes[1].error == "RuntimeError"


def test_canary_forced_unhealthy_for_drills() -> None:
    cw = Recorder()
    idp = Idp()
    report = Canary(
        CFG, secrets=Secrets(), idp=idp, cloudwatch=cw, ssm=Ssm("unhealthy"), post=_post_ok
    ).run()
    assert report.forced and not report.healthy and report.probes == []
    assert cw.healthy_value() == 0
