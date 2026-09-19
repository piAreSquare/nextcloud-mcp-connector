"""The exchange token checker, spoken to directly: every rule of EXCH-02, one test each.

Keys are generated per test run, every key set answer is served by respx, and nothing
leaves the process: no server is started and no real provider is asked. The checker is
exercised without the transport boundary on purpose; the chain that wires it in is
phase 22, and the decoupling is part of the proof.

Claim times are built against the real wall clock, because PyJWT checks ``exp``, ``nbf``
and ``iat`` against its own wall clock and that one is not injectable. The injected wall
clock stand-in of the checker is used only where a rule is purely ours.

No test asserts a refusal text: the wordings are internal log phrases, not an interface.
Every refusal is the same :class:`exchange.ExchangeRefused` from the outside.
"""

import base64
import json
import time
from typing import Any

import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from mcp_connector.oauth import exchange

ISSUER = "https://idp.example.org/realms/f13"
JWKS_URL = f"{ISSUER}/protocol/openid-connect/certs"
AUDIENCE = "https://cloud.example.org/exapps/mcp_connector/mcp"
AZP = "f13-orchestrator"
KID = "key-1"
SUB = "service-account-f13"
SHARED_SECRET = "client-secret-long-enough-for-hmac-sha256-0123456789"

PRIVATE = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_PRIVATE = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def jwk_of(private: rsa.RSAPrivateKey, kid: str = KID, **extra: Any) -> dict[str, Any]:
    entry = json.loads(RSAAlgorithm.to_jwk(private.public_key()))
    entry.update({"kid": kid, "use": "sig", "alg": "RS256"}, **extra)
    return entry


class Clock:
    """A hand-turned clock, so cache expiry and cooldown are decided by the test."""

    def __init__(self, start: float = 1_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def serve(keys: list[dict[str, Any]] | None = None) -> respx.Route:
    payload = {"keys": keys if keys is not None else [jwk_of(PRIVATE)]}
    return respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json=payload))


def settings_for(**overrides: Any) -> exchange.ExchangeSettings:
    values: dict[str, Any] = {
        "issuer": ISSUER,
        "jwks_uri": JWKS_URL,
        "audience": AUDIENCE,
        "azp_allowed": (AZP,),
    }
    values.update(overrides)
    return exchange.ExchangeSettings(**values)


def checker_for(
    clock: Clock | None = None, now: Any = None, **overrides: Any
) -> exchange.ExchangeTokenChecker:
    return exchange.ExchangeTokenChecker(settings_for(**overrides), clock=clock or Clock(), now=now)


def claims(**overrides: Any) -> dict[str, Any]:
    now = int(time.time())
    values: dict[str, Any] = {
        "iss": ISSUER,
        "sub": SUB,
        "aud": AUDIENCE,
        "exp": now + 300,
        "iat": now,
        "typ": "Bearer",
        "azp": AZP,
    }
    values.update(overrides)
    return {key: value for key, value in values.items() if value is not None}


def token(
    private: Any = PRIVATE,
    *,
    algorithm: str = "RS256",
    kid: str | None = KID,
    headers: dict[str, Any] | None = None,
    **overrides: Any,
) -> str:
    header: dict[str, Any] = {} if kid is None else {"kid": kid}
    if headers:
        header.update(headers)
    return jwt.encode(claims(**overrides), private, algorithm=algorithm, headers=header)


def unsigned_token() -> str:
    """A token with ``alg: none`` and an empty signature."""

    def part(value: dict[str, Any]) -> str:
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()

    return f"{part({'alg': 'none', 'typ': 'JWT', 'kid': KID})}.{part(claims())}."


# --- settings ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        {"issuer": "http://idp.example.org/realms/f13"},
        {"issuer": f"{ISSUER}/"},
        {"jwks_uri": "https://elsewhere.example.org/certs"},
        {"jwks_uri": "http://idp.example.org/realms/f13/certs"},
        {"audience": ""},
        {"audience": ["one", "two"]},
        {"azp_allowed": ()},
        {"azp_allowed": ("",)},
        {"algorithms": ("HS256",)},
        {"algorithms": ("none",)},
        {"algorithms": ()},
        {"leeway_seconds": 0},
        {"max_lifetime_seconds": -1},
    ],
    ids=[
        "plain http issuer",
        "trailing slash issuer",
        "jwks off the issuer origin",
        "plain http jwks",
        "empty audience",
        "audience as a list",
        "empty azp allowlist",
        "empty azp entry",
        "symmetric algorithm",
        "no signature at all",
        "no algorithms",
        "zero leeway",
        "negative lifetime",
    ],
)
def test_a_bad_configuration_is_refused_on_construction(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match=r"."):
        settings_for(**overrides)


def test_a_named_second_origin_keeps_the_https_same_origin_rule() -> None:
    internal = "https://keys.internal.example.org"
    settings_for(jwks_origin=internal, jwks_uri=f"{internal}/certs")

    with pytest.raises(ValueError, match=r"."):
        settings_for(
            jwks_origin="http://keys.internal.example.org",
            jwks_uri="http://keys.internal.example.org/certs",
        )


# --- acceptance -------------------------------------------------------------------------


@respx.mock
@pytest.mark.anyio
async def test_a_complete_token_is_accepted_and_returns_its_claims() -> None:
    serve()

    found = await checker_for().claims_of(token())

    assert found["sub"] == SUB
    assert found["iss"] == ISSUER
    assert found["typ"] == "Bearer"


# --- refusals, one rule each ------------------------------------------------------------


@respx.mock
@pytest.mark.anyio
async def test_a_foreign_issuer_is_refused() -> None:
    serve()
    with pytest.raises(exchange.ExchangeRefused):
        await checker_for().claims_of(token(iss="https://evil.example.org/realms/f13"))


@respx.mock
@pytest.mark.anyio
async def test_a_signature_by_a_key_outside_the_jwks_is_refused() -> None:
    serve()
    with pytest.raises(exchange.ExchangeRefused):
        await checker_for().claims_of(token(OTHER_PRIVATE))


@respx.mock
@pytest.mark.anyio
async def test_hs256_with_a_shared_secret_is_refused() -> None:
    serve()
    bearer = jwt.encode(claims(), SHARED_SECRET, algorithm="HS256", headers={"kid": KID})
    with pytest.raises(exchange.ExchangeRefused):
        await checker_for().claims_of(bearer)


@respx.mock
@pytest.mark.anyio
async def test_an_unsigned_token_is_refused() -> None:
    serve()
    with pytest.raises(exchange.ExchangeRefused):
        await checker_for().claims_of(unsigned_token())


@respx.mock
@pytest.mark.anyio
async def test_a_jwks_carrying_only_a_symmetric_key_is_refused() -> None:
    serve([{"kty": "oct", "k": base64.urlsafe_b64encode(b"0" * 32).decode(), "kid": KID}])
    with pytest.raises(exchange.ExchangeRefused):
        await checker_for().claims_of(token())


@respx.mock
@pytest.mark.anyio
async def test_an_unknown_kid_is_refused() -> None:
    serve()
    with pytest.raises(exchange.ExchangeRefused):
        await checker_for().claims_of(token(kid="unknown-key"))


@respx.mock
@pytest.mark.anyio
async def test_a_token_without_a_kid_is_refused() -> None:
    serve()
    with pytest.raises(exchange.ExchangeRefused):
        await checker_for().claims_of(token(kid=None))


@respx.mock
@pytest.mark.anyio
async def test_an_expired_token_is_refused() -> None:
    serve()
    with pytest.raises(exchange.ExchangeRefused):
        await checker_for().claims_of(token(exp=int(time.time()) - 3600))


@respx.mock
@pytest.mark.anyio
async def test_a_token_not_yet_valid_is_refused() -> None:
    serve()
    with pytest.raises(exchange.ExchangeRefused):
        await checker_for().claims_of(token(nbf=int(time.time()) + 3600))


@respx.mock
@pytest.mark.anyio
async def test_a_token_without_an_audience_is_refused() -> None:
    serve()
    with pytest.raises(exchange.ExchangeRefused):
        await checker_for().claims_of(token(aud=None))


@respx.mock
@pytest.mark.anyio
async def test_a_token_without_iat_is_refused() -> None:
    serve()
    with pytest.raises(exchange.ExchangeRefused):
        await checker_for().claims_of(token(iat=None))


@respx.mock
@pytest.mark.anyio
async def test_a_token_without_exp_is_refused() -> None:
    serve()
    with pytest.raises(exchange.ExchangeRefused):
        await checker_for().claims_of(token(exp=None))


@respx.mock
@pytest.mark.anyio
async def test_an_empty_sub_is_refused() -> None:
    serve()
    with pytest.raises(exchange.ExchangeRefused):
        await checker_for().claims_of(token(sub=""))


@respx.mock
@pytest.mark.anyio
async def test_a_missing_sub_is_refused() -> None:
    serve()
    with pytest.raises(exchange.ExchangeRefused):
        await checker_for().claims_of(token(sub=None))


@respx.mock
@pytest.mark.anyio
async def test_a_padded_sub_is_refused() -> None:
    serve()
    with pytest.raises(exchange.ExchangeRefused):
        await checker_for().claims_of(token(sub=" padded"))


@respx.mock
@pytest.mark.anyio
async def test_an_empty_token_string_is_refused() -> None:
    serve()
    with pytest.raises(exchange.ExchangeRefused):
        await checker_for().claims_of("")


# --- an unusable key set is a refusal, never an acceptance -------------------------------


@respx.mock
@pytest.mark.anyio
async def test_an_unreachable_key_set_is_a_refusal_never_an_acceptance() -> None:
    respx.get(JWKS_URL).mock(side_effect=httpx.ConnectError("no route to the provider"))
    with pytest.raises(exchange.ExchangeRefused):
        await checker_for().claims_of(token())


@respx.mock
@pytest.mark.anyio
async def test_a_key_set_answering_500_is_a_refusal() -> None:
    respx.get(JWKS_URL).mock(return_value=httpx.Response(500))
    with pytest.raises(exchange.ExchangeRefused):
        await checker_for().claims_of(token())


# --- typ: the payload claim decides, the header is tolerated ------------------------------


@respx.mock
@pytest.mark.anyio
async def test_an_id_token_of_the_same_realm_is_refused() -> None:
    serve()
    with pytest.raises(exchange.ExchangeRefused):
        await checker_for().claims_of(token(typ=exchange.ID_TOKEN_TYP))


@respx.mock
@pytest.mark.anyio
async def test_a_token_without_a_typ_claim_is_refused() -> None:
    serve()
    with pytest.raises(exchange.ExchangeRefused):
        await checker_for().claims_of(token(typ=None))


@respx.mock
@pytest.mark.anyio
async def test_a_header_typ_of_at_jwt_is_accepted() -> None:
    serve()

    found = await checker_for().claims_of(token(headers={"typ": "at+jwt"}))

    assert found["sub"] == SUB


@respx.mock
@pytest.mark.anyio
async def test_the_header_typ_is_compared_without_case() -> None:
    serve()

    found = await checker_for().claims_of(token(headers={"typ": "AT+JWT"}))

    assert found["sub"] == SUB


@respx.mock
@pytest.mark.anyio
async def test_a_missing_header_typ_is_no_refusal() -> None:
    # PyJWT drops a falsy header typ from the header instead of writing it.
    serve()

    found = await checker_for().claims_of(token(headers={"typ": None}))

    assert found["sub"] == SUB


@respx.mock
@pytest.mark.anyio
async def test_a_foreign_header_typ_is_refused() -> None:
    serve()
    with pytest.raises(exchange.ExchangeRefused):
        await checker_for().claims_of(token(headers={"typ": "dpop+jwt"}))


# --- clock skew: inside the tolerance holds, beyond it falls, in both directions ----------


@respx.mock
@pytest.mark.anyio
async def test_an_exp_twenty_seconds_past_holds_inside_the_leeway() -> None:
    serve()

    found = await checker_for().claims_of(token(exp=int(time.time()) - 20))

    assert found["sub"] == SUB


@respx.mock
@pytest.mark.anyio
async def test_an_exp_forty_five_seconds_past_is_refused() -> None:
    serve()
    with pytest.raises(exchange.ExchangeRefused):
        await checker_for().claims_of(token(exp=int(time.time()) - 45))


@respx.mock
@pytest.mark.anyio
async def test_an_nbf_twenty_seconds_ahead_holds_inside_the_leeway() -> None:
    serve()

    found = await checker_for().claims_of(token(nbf=int(time.time()) + 20))

    assert found["sub"] == SUB


@respx.mock
@pytest.mark.anyio
async def test_an_nbf_forty_five_seconds_ahead_is_refused() -> None:
    serve()
    with pytest.raises(exchange.ExchangeRefused):
        await checker_for().claims_of(token(nbf=int(time.time()) + 45))


@respx.mock
@pytest.mark.anyio
async def test_a_missing_nbf_is_no_refusal() -> None:
    # nbf is checked when it is there and never required; the base token carries none.
    serve()

    found = await checker_for().claims_of(token())

    assert "nbf" not in found


# --- lifetime and age: rules PyJWT does not bring -----------------------------------------


@respx.mock
@pytest.mark.anyio
async def test_a_lifetime_beyond_the_maximum_is_refused_even_while_valid() -> None:
    serve()
    now = int(time.time())
    with pytest.raises(exchange.ExchangeRefused):
        await checker_for().claims_of(token(iat=now - 100, exp=now + 900))


@respx.mock
@pytest.mark.anyio
async def test_an_iat_older_than_the_maximum_age_is_refused() -> None:
    # Measured against the injected wall clock of the checker, not against PyJWT's own:
    # the token is still valid by exp, only its age breaks the rule.
    serve()
    ahead = time.time() + exchange.MAX_TOKEN_LIFETIME_SECONDS + 100
    with pytest.raises(exchange.ExchangeRefused):
        await checker_for(now=lambda: ahead).claims_of(token())


@respx.mock
@pytest.mark.anyio
async def test_a_non_numeric_iat_is_a_refusal_not_a_type_error() -> None:
    # PyJWT itself lets a numeric string through int(); the lifetime rules do not.
    serve()
    with pytest.raises(exchange.ExchangeRefused):
        await checker_for().claims_of(token(iat=str(int(time.time()))))


# --- the pre-filter: a foreign issuer never triggers an outgoing fetch --------------------


@respx.mock
@pytest.mark.anyio
async def test_a_foreign_issuer_causes_no_outgoing_fetch() -> None:
    route = serve()

    with pytest.raises(exchange.ExchangeRefused):
        await checker_for().claims_of(token(iss="https://evil.example.org/realms/f13"))

    assert route.call_count == 0, "the pre-filter refuses before any key is looked at"
