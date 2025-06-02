from __future__ import annotations

from typing import Any

import pytest

from authlib_mt import JWKSCache, JWKSUnavailable, UnknownKey, http_fetcher
from tests.conftest import KeyPair


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class Fetcher:
    def __init__(self, *docs: dict[str, Any]) -> None:
        self.docs = list(docs)
        self.calls = 0
        self.fail = False

    def __call__(self) -> dict[str, Any]:
        self.calls += 1
        if self.fail:
            raise OSError("jwks endpoint down")
        return self.docs[min(self.calls - 1, len(self.docs) - 1)]


def test_caches_within_ttl(signing_key: KeyPair) -> None:
    f = Fetcher({"keys": [signing_key.jwk()]})
    clock = Clock()
    cache = JWKSCache(f, ttl=60, clock=clock)
    cache.get(signing_key.kid)
    clock.now += 30
    cache.get(signing_key.kid)
    assert f.calls == 1


def test_refreshes_after_ttl(signing_key: KeyPair) -> None:
    f = Fetcher({"keys": [signing_key.jwk()]})
    clock = Clock()
    cache = JWKSCache(f, ttl=60, min_refresh_interval=10, clock=clock)
    cache.get(signing_key.kid)
    clock.now += 61
    cache.get(signing_key.kid)
    assert f.calls == 2


def test_keeps_last_good_keys_when_refresh_fails(signing_key: KeyPair) -> None:
    f = Fetcher({"keys": [signing_key.jwk()]})
    clock = Clock()
    cache = JWKSCache(f, ttl=60, min_refresh_interval=10, clock=clock)
    cache.get(signing_key.kid)
    f.fail = True
    clock.now += 3600
    assert cache.get(signing_key.kid) is not None  # stale but served


def test_unknown_kid_triggers_rate_limited_refresh(
    signing_key: KeyPair, other_key: KeyPair
) -> None:
    f = Fetcher({"keys": [signing_key.jwk()]}, {"keys": [signing_key.jwk(), other_key.jwk()]})
    clock = Clock()
    cache = JWKSCache(f, ttl=3600, min_refresh_interval=30, clock=clock)
    cache.get(signing_key.kid)
    # Rotation: new kid shows up, but we refreshed < 30 s ago.
    with pytest.raises(UnknownKey):
        cache.get(other_key.kid)
    assert f.calls == 1
    clock.now += 31
    assert cache.get(other_key.kid) is not None
    assert f.calls == 2
    # A forged kid doesn't cause another fetch inside the interval.
    with pytest.raises(UnknownKey):
        cache.get("forged")
    assert f.calls == 2


def test_never_loaded_is_unavailable() -> None:
    f = Fetcher({"keys": []})
    f.fail = True
    with pytest.raises(JWKSUnavailable):
        JWKSCache(f).get("any")


def test_skips_non_signing_and_broken_keys(signing_key: KeyPair) -> None:
    enc = dict(signing_key.jwk(), kid="enc", use="enc")
    broken = {"kid": "broken", "kty": "RSA"}
    cache = JWKSCache(Fetcher({"keys": [enc, broken, signing_key.jwk()]}))
    cache.get(signing_key.kid)
    assert cache.kids == {signing_key.kid}


def test_http_fetcher_requires_https() -> None:
    with pytest.raises(ValueError, match="https"):
        http_fetcher("http://example.test/jwks.json")
