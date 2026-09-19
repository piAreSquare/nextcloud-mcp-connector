"""The key set layer, spoken to directly: cooldown, single-flight, fail-closed.

Keys are generated per test run, every provider answer is served by respx, and nothing
opens a socket. The layer is exercised without the browser identity flow on purpose: the
decoupling is part of the proof. The refusal is a tiny local exception handed in the way
every caller hands in its own, and it carries no detail, like the real ones.
"""

import asyncio
import base64
import json
from typing import Any

import httpx
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from mcp_connector.oauth import jwks

ORIGIN = "https://auth.example.com"
JWKS_URL = f"{ORIGIN}/oauth/v2/keys"
KID = "key-1"

PRIVATE = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_PRIVATE = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class Refused(Exception):
    """The stand-in for a caller's refusal. Carries no detail, like the real ones."""


def refuse(_reason: str) -> Exception:
    return Refused()


def jwk_of(private: rsa.RSAPrivateKey, kid: str = KID, **extra: Any) -> dict[str, Any]:
    entry = json.loads(RSAAlgorithm.to_jwk(private.public_key()))
    entry.update({"kid": kid, "use": "sig", "alg": "RS256"}, **extra)
    return entry


class Clock:
    """A hand-turned clock, so cooldown and expiry are decided by the test."""

    def __init__(self, start: float = 1_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def key_set(clock: Clock | None = None, *, url: str = JWKS_URL, **overrides: Any) -> jwks.KeySet:
    async def jwks_uri() -> str:
        return url

    values: dict[str, Any] = {
        "origin": ORIGIN,
        "jwks_uri": jwks_uri,
        "algorithms": ("RS256",),
        "refuse": refuse,
    }
    if clock is not None:
        values["clock"] = clock
    values.update(overrides)
    return jwks.KeySet(**values)


def serve(keys: list[dict[str, Any]] | None = None) -> respx.Route:
    payload = {"keys": keys if keys is not None else [jwk_of(PRIVATE)]}
    return respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json=payload))


# --- cooldown ----------------------------------------------------------------------------


@respx.mock
@pytest.mark.anyio
async def test_a_hundred_invented_kids_against_a_fresh_cache_cost_one_fetch() -> None:
    route = serve()
    keys = key_set(Clock())
    await keys.key(KID, "RS256")
    route.reset()

    for index in range(100):
        with pytest.raises(Refused):
            await keys.key(f"invented-{index}", "RS256")

    assert route.call_count == 1, "the first miss refetches once; the cooldown absorbs the rest"


@respx.mock
@pytest.mark.anyio
async def test_inside_the_cooldown_an_unknown_kid_is_refused_without_a_fetch() -> None:
    route = serve()
    keys = key_set(Clock())
    await keys.key(KID, "RS256")
    with pytest.raises(Refused) as after_fetch:
        await keys.key("unknown-1", "RS256")
    fetched = route.call_count

    with pytest.raises(Refused) as inside_cooldown:
        await keys.key("unknown-2", "RS256")

    assert route.call_count == fetched, "inside the cooldown no fetch goes out"
    assert type(inside_cooldown.value) is type(after_fetch.value)
    assert str(inside_cooldown.value) == str(after_fetch.value)


@respx.mock
@pytest.mark.anyio
async def test_after_the_cooldown_an_unknown_kid_costs_one_fetch_again() -> None:
    route = serve()
    clock = Clock()
    keys = key_set(clock)
    await keys.key(KID, "RS256")
    with pytest.raises(Refused):
        await keys.key("unknown", "RS256")
    fetched = route.call_count

    clock.advance(jwks.JWKS_KID_COOLDOWN_SECONDS + 1)
    with pytest.raises(Refused):
        await keys.key("still-unknown", "RS256")

    assert route.call_count == fetched + 1


@respx.mock
@pytest.mark.anyio
async def test_an_expired_cache_refreshes_regardless_of_the_cooldown() -> None:
    route = serve()
    clock = Clock()
    keys = key_set(clock, cooldown_seconds=10_000.0)
    await keys.key(KID, "RS256")
    with pytest.raises(Refused):
        await keys.key("unknown", "RS256")
    fetched = route.call_count

    clock.advance(jwks.JWKS_CACHE_SECONDS + 1)
    assert await keys.key(KID, "RS256") is not None

    assert route.call_count == fetched + 1, "expiry refreshes; the cooldown only brakes misses"


@respx.mock
@pytest.mark.anyio
async def test_a_failed_miss_reload_still_spends_the_cooldown() -> None:
    route = respx.get(JWKS_URL).mock(
        side_effect=[
            httpx.Response(200, json={"keys": [jwk_of(PRIVATE)]}),
            httpx.Response(500),
        ]
    )
    keys = key_set(Clock())
    await keys.key(KID, "RS256")

    with pytest.raises(Refused):
        await keys.key("unknown-1", "RS256")
    with pytest.raises(Refused):
        await keys.key("unknown-2", "RS256")

    assert route.call_count == 2, "the failing fetch spent the cooldown; no second one follows"


# --- the failure path is braked ----------------------------------------------------------


@respx.mock
@pytest.mark.anyio
async def test_a_failing_cold_fetch_is_not_repeated_for_every_caller() -> None:
    """A provider that just failed must not be asked again by every arriving call.

    This is the cold cache, the case an attacker creates most easily: without the brake
    every incoming request becomes an outgoing fetch, so the layer amplifies the load on
    an identity provider that is already struggling. The brake only makes refusals
    cheaper; none of the twenty-five calls is answered with a key.
    """
    route = respx.get(JWKS_URL).mock(return_value=httpx.Response(500))
    keys = key_set(Clock())

    for _ in range(25):
        with pytest.raises(Refused):
            await keys.key(KID, "RS256")

    assert route.call_count == 1, "the failed fetch brakes the ones that would follow it"


@respx.mock
@pytest.mark.anyio
async def test_after_the_retry_pause_a_cold_fetch_is_attempted_again() -> None:
    route = respx.get(JWKS_URL).mock(
        side_effect=[
            httpx.Response(500),
            httpx.Response(200, json={"keys": [jwk_of(PRIVATE)]}),
        ]
    )
    clock = Clock()
    keys = key_set(clock)
    with pytest.raises(Refused):
        await keys.key(KID, "RS256")

    clock.advance(jwks.JWKS_FAILURE_RETRY_SECONDS + 1)

    assert await keys.key(KID, "RS256") is not None, "the brake is a pause, not a shutdown"
    assert route.call_count == 2


# --- single-flight -----------------------------------------------------------------------


@respx.mock
@pytest.mark.anyio
async def test_twenty_concurrent_calls_cost_one_fetch_and_share_the_key() -> None:
    async def slow_answer(_request: httpx.Request) -> httpx.Response:
        for _ in range(5):
            await asyncio.sleep(0)
        return httpx.Response(200, json={"keys": [jwk_of(PRIVATE)]})

    route = respx.get(JWKS_URL).mock(side_effect=slow_answer)
    keys = key_set(Clock())

    found = await asyncio.gather(*(keys.key(KID, "RS256") for _ in range(20)))

    assert route.call_count == 1
    assert all(key is found[0] for key in found)
    # The counter a waiter behind the lock compares against. It is nailed down here
    # because the decision "share the refusal, do not start a second flight" rests on it:
    # one finished attempt must move it by exactly one, whatever the outcome was.
    assert keys._fetches == 1


@respx.mock
@pytest.mark.anyio
async def test_twenty_concurrent_calls_whose_fetch_fails_are_all_refused_by_one_fetch() -> None:
    async def slow_failure(_request: httpx.Request) -> httpx.Response:
        for _ in range(5):
            await asyncio.sleep(0)
        return httpx.Response(500)

    route = respx.get(JWKS_URL).mock(side_effect=slow_failure)
    keys = key_set(Clock())

    found = await asyncio.gather(
        *(keys.key(KID, "RS256") for _ in range(20)), return_exceptions=True
    )

    assert route.call_count == 1
    assert all(isinstance(outcome, Refused) for outcome in found)


# --- the failure path keeps the cache ----------------------------------------------------


@respx.mock
@pytest.mark.anyio
async def test_a_failed_reload_leaves_the_cache_standing() -> None:
    route = respx.get(JWKS_URL).mock(
        side_effect=[
            httpx.Response(200, json={"keys": [jwk_of(PRIVATE)]}),
            httpx.Response(500),
        ]
    )
    keys = key_set(Clock())
    first = await keys.key(KID, "RS256")

    with pytest.raises(Refused):
        await keys.key("unknown", "RS256")

    assert await keys.key(KID, "RS256") is first, "the known kid is still served, no new fetch"
    assert route.call_count == 2, "nothing was written over the usable entry"


@respx.mock
@pytest.mark.anyio
async def test_a_200_without_a_usable_key_leaves_the_cache_standing() -> None:
    """An answer with no usable key counts as a failed fetch, exactly like a 500.

    A provider that briefly serves an empty JWKS during a rolling restart would otherwise
    replace a working cache with nothing and lock every sign in out, healing in steps of
    the miss cooldown rather than at once.
    """
    route = respx.get(JWKS_URL).mock(
        side_effect=[
            httpx.Response(200, json={"keys": [jwk_of(PRIVATE)]}),
            httpx.Response(200, json={"keys": []}),
        ]
    )
    keys = key_set(Clock())
    first = await keys.key(KID, "RS256")

    with pytest.raises(Refused):
        await keys.key("unknown", "RS256")

    assert await keys.key(KID, "RS256") is first, "the empty answer did not wipe the cache"
    assert route.call_count == 2


# --- inherited hardening, proven at the layer itself --------------------------------------


@respx.mock
@pytest.mark.anyio
@pytest.mark.parametrize(
    "entry",
    [
        {"kty": "oct", "k": base64.urlsafe_b64encode(b"0" * 32).decode(), "kid": KID},
        jwk_of(PRIVATE, use="enc"),
        jwk_of(PRIVATE, key_ops=["encrypt"]),
        jwk_of(PRIVATE, alg="RS512"),
        {"kty": "RSA", "n": None, "e": "AQAB", "kid": KID},
        {"kty": "RSA", "n": [1, 2], "e": "AQAB", "kid": KID, "alg": "RS256"},
        {"kty": "OKP", "crv": "Ed25519", "x": 7, "kid": KID},
    ],
    ids=[
        "symmetric key",
        "encryption use",
        "encrypt-only key_ops",
        "unconfigured algorithm",
        "null modulus",
        "modulus as a list",
        "OKP coordinate as a number",
    ],
)
async def test_an_entry_that_may_not_verify_never_enters_the_cache(entry: dict[str, Any]) -> None:
    serve([entry])
    with pytest.raises(Refused):
        await key_set(Clock()).key(KID, "RS256")


@respx.mock
@pytest.mark.anyio
async def test_a_key_declared_for_another_algorithm_than_asked_is_refused() -> None:
    serve([jwk_of(PRIVATE, alg="RS384")])
    keys = key_set(Clock(), algorithms=("RS256", "RS384"))
    with pytest.raises(Refused):
        await keys.key(KID, "RS256")


@respx.mock
@pytest.mark.anyio
async def test_two_entries_with_the_same_kid_make_that_kid_unusable() -> None:
    serve([jwk_of(PRIVATE), jwk_of(OTHER_PRIVATE)])
    with pytest.raises(Refused):
        await key_set(Clock()).key(KID, "RS256")


@respx.mock
@pytest.mark.anyio
async def test_more_than_max_keys_entries_are_refused_as_a_whole() -> None:
    serve([jwk_of(PRIVATE, kid=f"key-{index}") for index in range(jwks.MAX_KEYS + 1)])
    with pytest.raises(Refused):
        await key_set(Clock()).key("key-0", "RS256")


@respx.mock
@pytest.mark.anyio
@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example.com/oauth/v2/keys",
        f"{JWKS_URL}#",
        "https://user:secret@auth.example.com/oauth/v2/keys",
    ],
    ids=["foreign origin", "fragment", "credentials"],
)
async def test_a_jwks_uri_off_the_issuer_origin_is_refused_without_a_fetch(url: str) -> None:
    route = respx.route().mock(return_value=httpx.Response(200, json={"keys": []}))

    with pytest.raises(Refused):
        await key_set(Clock(), url=url).key(KID, "RS256")

    assert route.call_count == 0, "the refusal happens before anything goes out"


@respx.mock
@pytest.mark.anyio
@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(302, headers={"location": "https://evil.example.com/"}),
        httpx.Response(500),
        httpx.Response(200, text="not json"),
        httpx.Response(200, content=b"{" + b" " * (jwks.MAX_RESPONSE_BYTES + 1) + b"}"),
    ],
    ids=["redirect", "server error", "not json", "too large"],
)
async def test_an_unusable_answer_is_refused(response: httpx.Response) -> None:
    respx.get(JWKS_URL).mock(return_value=response)
    with pytest.raises(Refused):
        await key_set(Clock()).key(KID, "RS256")


@respx.mock
@pytest.mark.anyio
async def test_an_expired_cache_never_serves_a_kid_when_the_reload_fails() -> None:
    route = respx.get(JWKS_URL).mock(
        side_effect=[
            httpx.Response(200, json={"keys": [jwk_of(PRIVATE)]}),
            httpx.Response(500),
            httpx.Response(200, json={"keys": [jwk_of(PRIVATE)]}),
        ]
    )
    clock = Clock()
    keys = key_set(clock)
    await keys.key(KID, "RS256")

    clock.advance(jwks.JWKS_CACHE_SECONDS + 1)
    with pytest.raises(Refused):
        # The kid sat in the old cache, but an expired cache is never served: no key
        # means refusal, and the convenient mistake (take the expired entry in an
        # emergency) would turn fail-closed into a barn door.
        await keys.key(KID, "RS256")

    # Past the pause the failed fetch put on the expiry branch, so the third answer is
    # reached at all; inside it the call would be refused without a fetch.
    clock.advance(jwks.JWKS_FAILURE_RETRY_SECONDS + 1)
    assert await keys.key(KID, "RS256") is not None, "the failure did not wipe the layer"
    assert route.call_count == 3
