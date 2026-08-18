"""Integration suite against a deployed stack (``pytest -m integration``).

Configuration (environment):

    TG_API_URL            https://api.<domain>
    TG_TOKEN_ENDPOINT     https://auth.<domain>/oauth2/token
    TG_TENANT_A / _B      two tenant IDs created through the control plane
    TG_M2M_A_ID / _SECRET M2M client of tenant A with read+write
    TG_CONTROL_TOKEN      optional: access token of a platform admin (system client)
    TG_PRIMARY_TOKEN      optional: a tenant-A M2M token minted *before* failover
    TG_EXPECT_REGION      optional: Region that should be serving (set by dr_drill.py)
    TG_EXPECT_DEGRADED    "1" while the control plane should be read-only

The negative cases are the isolation spec (plan §11).
"""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

import jwt
import pytest

pytestmark = pytest.mark.integration


def env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        pytest.skip(f"{name} not set")
    return value


def request(
    method: str, url: str, *, token: str | None = None, body: Any = None
) -> tuple[int, dict[str, str], Any]:
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)  # noqa: S310
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
            raw = resp.read()
            return resp.status, dict(resp.headers), json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            parsed = json.loads(raw) if raw else None
        except ValueError:
            parsed = raw.decode(errors="replace")
        return exc.code, dict(exc.headers), parsed


def m2m_token(client_id: str, secret: str, scope: str) -> tuple[int, dict[str, Any]]:
    basic = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
    body = urllib.parse.urlencode({"grant_type": "client_credentials", "scope": scope}).encode()
    req = urllib.request.Request(  # noqa: S310
        env("TG_TOKEN_ENDPOINT"),
        data=body,
        headers={
            "Authorization": f"Basic {basic}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


@pytest.fixture(scope="module")
def tenant_a() -> str:
    return env("TG_TENANT_A")


@pytest.fixture(scope="module")
def tenant_b() -> str:
    return env("TG_TENANT_B")


@pytest.fixture(scope="module")
def token_a(tenant_a: str) -> str:
    status, payload = m2m_token(
        env("TG_M2M_A_ID"),
        env("TG_M2M_A_SECRET"),
        f"api/tenant.{tenant_a}.read api/tenant.{tenant_a}.write",
    )
    assert status == 200, payload
    return str(payload["access_token"])


def notes_url(tenant: str) -> str:
    return f"{env('TG_API_URL')}/demo/tenants/{tenant}/notes"


# ---------------------------------------------------------------- happy path


def test_served_region() -> None:
    status, headers, body = request("GET", f"{env('TG_API_URL')}/demo/health")
    assert status == 200 and body["status"] == "ok"
    expected = os.environ.get("TG_EXPECT_REGION")
    if expected:
        assert headers.get("X-Served-Region", headers.get("x-served-region")) == expected


def test_m2m_token_claims(token_a: str, tenant_a: str) -> None:
    claims = jwt.decode(token_a, options={"verify_signature": False})
    assert claims["tenant_id"] == tenant_a
    assert claims["tenant_role"] == "service"
    assert claims["token_use"] == "access"


def test_m2m_write_and_read(token_a: str, tenant_a: str) -> None:
    status, _, note = request("POST", notes_url(tenant_a), token=token_a, body={"title": "it"})
    assert status == 201, note
    status, _, notes = request("GET", notes_url(tenant_a), token=token_a)
    assert status == 200
    assert note["note_id"] in {n["note_id"] for n in notes}
    request("DELETE", f"{notes_url(tenant_a)}/{note['note_id']}", token=token_a)


# ---------------------------------------------------------------- isolation spec


def test_no_token(tenant_a: str) -> None:
    assert request("GET", notes_url(tenant_a))[0] == 401


def test_garbage_token(tenant_a: str) -> None:
    assert request("GET", notes_url(tenant_a), token="x.y.z")[0] == 401


def test_tenant_a_token_on_tenant_b_route(token_a: str, tenant_b: str) -> None:
    assert request("GET", notes_url(tenant_b), token=token_a)[0] == 403


def test_cannot_request_other_tenants_scope(tenant_b: str) -> None:
    status, payload = m2m_token(
        env("TG_M2M_A_ID"), env("TG_M2M_A_SECRET"), f"api/tenant.{tenant_b}.read"
    )
    if status == 200:
        # Pre-token-gen suppresses foreign scopes; the token must not carry them.
        claims = jwt.decode(payload["access_token"], options={"verify_signature": False})
        assert f"api/tenant.{tenant_b}.read" not in claims.get("scope", "")
    else:
        assert payload.get("error") in {"invalid_scope", "invalid_grant", "access_denied"}


# ---------------------------------------------------------------- multi-Region


def test_primary_issued_token_still_valid(tenant_a: str) -> None:
    token = os.environ.get("TG_PRIMARY_TOKEN")
    if not token:
        pytest.skip("TG_PRIMARY_TOKEN not set")
    status, _, _ = request("GET", notes_url(tenant_a), token=token)
    assert status == 200


def test_control_plane_mode() -> None:
    token = os.environ.get("TG_CONTROL_TOKEN")
    status, _, body = request("GET", f"{env('TG_API_URL')}/control/status")
    assert status == 200
    degraded = os.environ.get("TG_EXPECT_DEGRADED") == "1"
    assert body["writes_allowed"] is (not degraded)
    if token and degraded:
        status, headers, _ = request(
            "POST",
            f"{env('TG_API_URL')}/control/tenants",
            token=token,
            body={"name": "drill", "callback_urls": ["https://drill.example/cb"]},
        )
        assert status == 503
        assert "retry-after" in {k.lower() for k in headers}
