"""Shared fixtures: moto-backed AWS, registry tables, and locally signed JWTs."""

from __future__ import annotations

import os
import time
import uuid
from collections.abc import Callable, Iterator
from typing import Any

import boto3
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from moto import mock_aws

REGION = "ap-southeast-1"
ISSUER = "https://issuer.tenantgate.test/pool"
TENANT_A = "t-aaaaaaaaaaaa"
TENANT_B = "t-bbbbbbbbbbbb"

os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_SESSION_TOKEN", "testing")
os.environ["AWS_DEFAULT_REGION"] = REGION
os.environ["AWS_REGION"] = REGION
os.environ["POWERTOOLS_SERVICE_NAME"] = "tenantgate-tests"
os.environ["POWERTOOLS_LOG_LEVEL"] = "WARNING"
os.environ["POWERTOOLS_TRACE_DISABLED"] = "true"


def _pk_sk_table(name: str, *, gsi: bool) -> Any:
    ddb = boto3.resource("dynamodb", region_name=REGION)
    attrs = ["PK", "SK", "GSI1PK", "GSI1SK"] if gsi else ["PK", "SK"]
    kwargs: dict[str, Any] = {
        "TableName": name,
        "BillingMode": "PAY_PER_REQUEST",
        "KeySchema": [
            {"AttributeName": "PK", "KeyType": "HASH"},
            {"AttributeName": "SK", "KeyType": "RANGE"},
        ],
        "AttributeDefinitions": [{"AttributeName": a, "AttributeType": "S"} for a in attrs],
    }
    if gsi:
        kwargs["GlobalSecondaryIndexes"] = [
            {
                "IndexName": "GSI1",
                "KeySchema": [
                    {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ]
    return ddb.create_table(**kwargs)


def create_registry_table(name: str = "tenantgate-registry") -> Any:
    return _pk_sk_table(name, gsi=True)


def create_notes_table(name: str = "tenantgate-notes") -> Any:
    return _pk_sk_table(name, gsi=False)


def create_idempotency_table(name: str = "tenantgate-idempotency") -> Any:
    ddb = boto3.resource("dynamodb", region_name=REGION)
    return ddb.create_table(
        TableName=name,
        BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
    )


@pytest.fixture
def aws() -> Iterator[None]:
    from tenantgate.aws import reset_caches
    from tenantgate.settings import get_settings

    with mock_aws():
        reset_caches()
        get_settings.cache_clear()
        yield
    reset_caches()
    get_settings.cache_clear()


@pytest.fixture
def table(aws: None) -> Any:
    return create_registry_table()


@pytest.fixture
def registry(table: Any) -> Any:
    from tenantgate.registry import TenantRegistry

    return TenantRegistry(table)


@pytest.fixture
def user_pool(aws: None) -> dict[str, str]:
    idp = boto3.client("cognito-idp", region_name=REGION)
    pool = idp.create_user_pool(PoolName="tenantgate-test", UsernameAttributes=["email"])
    pool_id = pool["UserPool"]["Id"]
    idp.create_resource_server(
        UserPoolId=pool_id,
        Identifier="api",
        Name="api",
        Scopes=[
            {"ScopeName": "read", "ScopeDescription": "read"},
            {"ScopeName": "write", "ScopeDescription": "write"},
        ],
    )
    return {"pool_id": pool_id}


# --------------------------------------------------------------------- JWTs


class KeyPair:
    def __init__(self, kid: str) -> None:
        self.kid = kid
        self.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def jwk(self) -> dict[str, Any]:
        data: dict[str, Any] = RSAAlgorithm.to_jwk(self.private.public_key(), as_dict=True)
        data.update(kid=self.kid, alg="RS256", use="sig")
        return data


@pytest.fixture(scope="session")
def signing_key() -> KeyPair:
    return KeyPair("test-key-1")


@pytest.fixture(scope="session")
def other_key() -> KeyPair:
    return KeyPair("foreign-key")


@pytest.fixture
def jwks_doc(signing_key: KeyPair) -> dict[str, Any]:
    return {"keys": [signing_key.jwk()]}


TokenFactory = Callable[..., str]


@pytest.fixture
def make_token(signing_key: KeyPair) -> TokenFactory:
    def factory(
        *,
        sub: str | None = None,
        client_id: str = "client-a",
        tenant_id: str | None = TENANT_A,
        role: str | None = "admin",
        scope: str = "openid api/read api/write",
        token_use: str = "access",
        iss: str = ISSUER,
        exp_in: int = 3600,
        key: KeyPair | None = None,
        groups: list[str] | None = None,
        alg: str = "RS256",
        extra: dict[str, Any] | None = None,
    ) -> str:
        k = key or signing_key
        now = int(time.time())
        claims: dict[str, Any] = {
            "sub": sub or str(uuid.uuid4()),
            "iss": iss,
            "client_id": client_id,
            "token_use": token_use,
            "scope": scope,
            "iat": now,
            "exp": now + exp_in,
            "jti": str(uuid.uuid4()),
            "username": "user",
        }
        if tenant_id is not None:
            claims["tenant_id"] = tenant_id
        if role is not None:
            claims["tenant_role"] = role
        if groups is not None:
            claims["cognito:groups"] = groups
        claims.update(extra or {})
        if alg == "HS256":
            return jwt.encode(claims, "s" * 32, algorithm="HS256", headers={"kid": k.kid})
        return jwt.encode(claims, k.private, algorithm="RS256", headers={"kid": k.kid})

    return factory


@pytest.fixture
def validator(jwks_doc: dict[str, Any]) -> Any:
    from authlib_mt import JWKSCache, TokenValidator

    return TokenValidator(issuers=[ISSUER], jwks=JWKSCache(lambda: jwks_doc))
