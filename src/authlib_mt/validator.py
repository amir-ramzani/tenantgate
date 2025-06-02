"""Access-token validation for Cognito-issued JWTs (plan, Phase 4).

Checks, in order: header (``RS256`` only, ``kid`` present) -> signature against
the cached JWKS -> ``exp``/``iat`` -> ``iss`` in the accepted set of
issuers -> ``token_use == "access"`` -> ``client_id`` present (and
allowed, if an allow-list is configured).

Stateless: no per-request call to Cognito, so validation keeps working in any
Region during a failover.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import jwt

from authlib_mt.jwks import JWKSCache, JWKSUnavailable, UnknownKey

ALLOWED_ALGORITHMS = ("RS256",)


class InvalidToken(Exception):
    """The token must be rejected (401)."""


class AuthUnavailable(Exception):
    """Validation could not be performed (503) — not the caller's fault."""


class TokenValidator:
    def __init__(
        self,
        *,
        issuers: Iterable[str],
        jwks: JWKSCache,
        allowed_client_ids: Iterable[str] | None = None,
        leeway: int = 30,
    ) -> None:
        self._issuers = frozenset(i.rstrip("/") for i in issuers)
        if not self._issuers:
            raise ValueError("at least one issuer is required")
        self._jwks = jwks
        self._clients = frozenset(allowed_client_ids) if allowed_client_ids else None
        self._leeway = leeway

    def validate(self, token: str) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise InvalidToken("malformed token") from exc
        if header.get("alg") not in ALLOWED_ALGORITHMS:
            raise InvalidToken("unsupported algorithm")
        kid = header.get("kid")
        if not kid:
            raise InvalidToken("missing kid")
        try:
            key = self._jwks.get(str(kid))
        except UnknownKey as exc:
            raise InvalidToken("unknown signing key") from exc
        except JWKSUnavailable as exc:
            raise AuthUnavailable("signing keys unavailable") from exc

        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                key=key.key,
                algorithms=list(ALLOWED_ALGORITHMS),
                leeway=self._leeway,
                # Cognito access tokens carry no `aud`; client_id is checked below.
                options={"require": ["exp", "iat", "iss", "sub"], "verify_aud": False},
            )
        except jwt.ExpiredSignatureError as exc:
            raise InvalidToken("token expired") from exc
        except jwt.PyJWTError as exc:
            raise InvalidToken("invalid token") from exc

        if str(claims["iss"]).rstrip("/") not in self._issuers:
            raise InvalidToken("unexpected issuer")
        if claims.get("token_use") != "access":
            raise InvalidToken("not an access token")
        client_id = claims.get("client_id")
        if not client_id:
            raise InvalidToken("missing client_id")
        if self._clients is not None and client_id not in self._clients:
            raise InvalidToken("client not allowed")
        return claims
