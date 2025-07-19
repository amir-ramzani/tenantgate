"""Per-Region degraded-mode flag (plan §8).

``auth_mode`` lives in SSM Parameter Store (``AUTH_MODE_PARAM``) and is either
``normal`` or ``failover``. Writes are allowed only in the primary Region *and*
in ``normal`` mode; otherwise the control plane answers ``503`` with
``Retry-After`` and UIs hide sign-up, password reset and profile edits.

The value is cached briefly. If SSM can't be read the last known value is kept;
with no value at all we assume ``normal`` (the Region role still blocks writes
in the secondary).
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from tenantgate.settings import Settings

RETRY_AFTER_SECONDS = 60


class AuthMode(StrEnum):
    NORMAL = "normal"
    FAILOVER = "failover"


@dataclass(frozen=True)
class ModeStatus:
    region: str
    region_role: str
    auth_mode: AuthMode
    writes_allowed: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "region": self.region,
            "region_role": self.region_role,
            "auth_mode": self.auth_mode.value,
            "writes_allowed": self.writes_allowed,
        }


class AuthModeProvider:
    def __init__(
        self,
        settings: Settings,
        ssm: Any | None = None,
        *,
        ttl: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._settings = settings
        self._ssm = ssm
        self._ttl = ttl
        self._clock = clock
        self._cached: tuple[float, AuthMode] | None = None

    def current(self) -> AuthMode:
        param = self._settings.auth_mode_param
        if not param or self._ssm is None:
            return AuthMode.NORMAL
        now = self._clock()
        if self._cached and now - self._cached[0] < self._ttl:
            return self._cached[1]
        try:
            value = self._ssm.get_parameter(Name=param)["Parameter"]["Value"]
            mode = AuthMode(str(value).strip().lower())
        except Exception:
            # Keep the last known value (or NORMAL) and retry after the TTL.
            mode = self._cached[1] if self._cached else AuthMode.NORMAL
        self._cached = (now, mode)
        return mode

    def writes_allowed(self) -> bool:
        return self._settings.is_primary and self.current() is AuthMode.NORMAL

    def status(self) -> ModeStatus:
        mode = self.current()
        return ModeStatus(
            region=self._settings.region,
            region_role=self._settings.region_role.value,
            auth_mode=mode,
            writes_allowed=self._settings.is_primary and mode is AuthMode.NORMAL,
        )

    def set_mode(self, mode: AuthMode) -> None:
        """Operator/drill helper: flip the flag in this Region."""
        if not self._settings.auth_mode_param or self._ssm is None:
            raise RuntimeError("AUTH_MODE_PARAM is not configured")
        self._ssm.put_parameter(
            Name=self._settings.auth_mode_param, Value=mode.value, Type="String", Overwrite=True
        )
        self._cached = (self._clock(), mode)
