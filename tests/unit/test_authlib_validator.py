from __future__ import annotations

from typing import Any

import pytest

from authlib_mt import AuthUnavailable, InvalidToken, JWKSCache, TokenValidator
from tests.conftest import ISSUER, KeyPair, TokenFactory


def test_valid_token(validator: TokenValidator, make_token: TokenFactory) -> None:
    claims = validator.validate(make_token(sub="u1"))
    assert claims["sub"] == "u1"
    assert claims["tenant_id"] == "t-aaaaaaaaaaaa"


def test_issuer_trailing_slash_is_tolerated(
    jwks_doc: dict[str, Any], make_token: TokenFactory
) -> None:
    v = TokenValidator(issuers=[ISSUER + "/"], jwks=JWKSCache(lambda: jwks_doc))
    assert v.validate(make_token())["iss"] == ISSUER


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"exp_in": -120}, "expired"),
        ({"iss": "https://cognito-idp.us-east-1.amazonaws.com/other-pool"}, "issuer"),
        ({"token_use": "id"}, "not an access token"),
        ({"client_id": ""}, "client_id"),
        ({"alg": "HS256"}, "algorithm"),
    ],
)
def test_rejections(
    validator: TokenValidator, make_token: TokenFactory, kwargs: dict[str, Any], message: str
) -> None:
    with pytest.raises(InvalidToken, match=message):
        validator.validate(make_token(**kwargs))


def test_token_from_another_pool_key(
    validator: TokenValidator, make_token: TokenFactory, other_key: KeyPair
) -> None:
    with pytest.raises(InvalidToken, match="unknown signing key"):
        validator.validate(make_token(key=other_key))


def test_forged_signature_with_known_kid(
    validator: TokenValidator, make_token: TokenFactory, signing_key: KeyPair, other_key: KeyPair
) -> None:
    forged = KeyPair(signing_key.kid)  # same kid, different private key
    with pytest.raises(InvalidToken, match="invalid token"):
        validator.validate(make_token(key=forged))


def test_garbage(validator: TokenValidator) -> None:
    with pytest.raises(InvalidToken, match="malformed"):
        validator.validate("not-a-jwt")


def test_client_allow_list(jwks_doc: dict[str, Any], make_token: TokenFactory) -> None:
    v = TokenValidator(
        issuers=[ISSUER], jwks=JWKSCache(lambda: jwks_doc), allowed_client_ids=["sys"]
    )
    assert v.validate(make_token(client_id="sys"))
    with pytest.raises(InvalidToken, match="client not allowed"):
        v.validate(make_token(client_id="client-a"))


def test_jwks_outage_is_unavailable_not_invalid(make_token: TokenFactory) -> None:
    def down() -> dict[str, Any]:
        raise OSError("down")

    v = TokenValidator(issuers=[ISSUER], jwks=JWKSCache(down))
    with pytest.raises(AuthUnavailable):
        v.validate(make_token())


def test_requires_issuer(jwks_doc: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        TokenValidator(issuers=[], jwks=JWKSCache(lambda: jwks_doc))
