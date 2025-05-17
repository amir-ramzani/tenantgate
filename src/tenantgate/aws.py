"""boto3 client factory with resilient defaults (plan §8).

* ``adaptive`` retry mode: client-side rate limiting when AWS throttles
  (including Cognito's ``TooManyRequestsException``).
* Explicit, tight connect/read timeouts so a slow dependency cannot eat a
  Cognito trigger's 5-second budget.

Clients are cached per (service, Region, profile) so warm Lambda invocations
reuse connections.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any, Literal

import boto3
from botocore.config import Config

Profile = Literal["api", "trigger"]

_CONFIGS: dict[str, Config] = {
    # Triggers: 3 attempts x 1 s keeps us well inside Cognito's 5 s limit.
    "trigger": Config(
        retries={"mode": "adaptive", "max_attempts": 3},
        connect_timeout=1,
        read_timeout=1,
    ),
    # APIs and scripts: a little more patience.
    "api": Config(
        retries={"mode": "adaptive", "max_attempts": 5},
        connect_timeout=2,
        read_timeout=5,
    ),
}


def config_for(profile: Profile) -> Config:
    return _CONFIGS[profile]


@lru_cache(maxsize=32)
def client(service: str, region: str | None = None, profile: Profile = "api") -> Any:
    return boto3.client(service, region_name=region, config=config_for(profile))  # type: ignore[call-overload]


@lru_cache(maxsize=32)
def dynamodb_table(name: str, region: str | None = None, profile: Profile = "api") -> Any:
    resource = boto3.resource("dynamodb", region_name=region, config=config_for(profile))
    return resource.Table(name)


def reset_caches() -> None:
    """Drop cached clients (tests call this after starting moto)."""
    client.cache_clear()
    dynamodb_table.cache_clear()
