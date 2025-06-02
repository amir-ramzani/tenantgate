"""JWKS cache with stale-while-revalidate semantics (plan §8).

* Keys are refreshed after ``ttl`` seconds; if the refresh fails, the last good
  key set keeps serving (Cognito rotates keys rarely, an outage of the JWKS
  endpoint must not take every resource server down with it).
* An unknown ``kid`` triggers an immediate refresh, rate limited by
  ``min_refresh_interval`` so a flood of forged tokens can't hammer the endpoint.
* Only when there has never been a successful fetch does lookup raise
  ``JWKSUnavailable`` (the caller turns that into ``503``, not ``401``).
"""

from __future__ import annotations

import json
import threading
import time
import urllib.request
from collections.abc import Callable
from typing import Any

from jwt import PyJWK
from jwt.exceptions import PyJWKError, PyJWTError

Fetcher = Callable[[], dict[str, Any]]
Clock = Callable[[], float]


class JWKSUnavailable(Exception):
    """No key set could ever be loaded."""


class UnknownKey(Exception):
    """The token's ``kid`` isn't in the (freshly refreshed) key set."""


def http_fetcher(url: str, timeout: float = 2.0) -> Fetcher:
    if not url.startswith("https://"):
        raise ValueError("JWKS URL must use https")

    def fetch() -> dict[str, Any]:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})  # noqa: S310
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            doc: dict[str, Any] = json.loads(resp.read().decode("utf-8"))
        return doc

    return fetch


class JWKSCache:
    def __init__(
        self,
        fetcher: Fetcher,
        *,
        ttl: float = 3600.0,
        min_refresh_interval: float = 30.0,
        clock: Clock = time.monotonic,
    ) -> None:
        self._fetch = fetcher
        self._ttl = ttl
        self._min_interval = min_refresh_interval
        self._clock = clock
        self._keys: dict[str, PyJWK] = {}
        self._loaded_at: float | None = None
        self._last_attempt: float | None = None
        self._lock = threading.Lock()

    @property
    def kids(self) -> frozenset[str]:
        return frozenset(self._keys)

    def _refresh(self) -> bool:
        """Fetch and replace the key set. Returns False (keeping old keys) on failure."""
        self._last_attempt = self._clock()
        try:
            doc = self._fetch()
            keys: dict[str, PyJWK] = {}
            for raw in doc.get("keys", []):
                kid = raw.get("kid")
                if not kid or raw.get("use", "sig") != "sig":
                    continue
                try:
                    keys[str(kid)] = PyJWK.from_dict(raw)
                except (PyJWKError, PyJWTError, KeyError, ValueError, TypeError):
                    continue
            if not keys:
                return False
        except Exception:
            return False
        self._keys = keys
        self._loaded_at = self._clock()
        return True

    def _may_refresh_now(self) -> bool:
        return self._last_attempt is None or (
            self._clock() - self._last_attempt >= self._min_interval
        )

    def get(self, kid: str) -> PyJWK:
        with self._lock:
            now = self._clock()
            expired = self._loaded_at is None or now - self._loaded_at >= self._ttl
            if expired and self._may_refresh_now():
                self._refresh()
            if kid not in self._keys and self._may_refresh_now():
                self._refresh()
            if not self._keys:
                raise JWKSUnavailable("no signing keys available")
            key = self._keys.get(kid)
            if key is None:
                raise UnknownKey(kid)
            return key
