"""The freestanding checker of a foreign Keycloak JWS: issuer, signature, claims, typ.

This module answers one question and wires nothing: is this token a currently valid
access token of the one configured foreign issuer, and what are its checked claims. The
chain that places it next to the store verifier is phase 22, the mapping of a claim set
onto a Nextcloud account is phase 23; this module reads nothing from the environment and
knows no account, which is what makes every one of its rules provable against self-made
keys, without a single answer from the real orchestrator.

**Where the keys come from.** Signature keys are fetched, cached and rotated by the one
key set layer in ``oauth/jwks.py``; this module holds a ``KeySet`` and asks it for the
key behind a ``kid``. A hardening that lands in only one of two copies is how a gap
survives a fix, so no second copy of that machinery exists here, and this module never
talks to the network itself.

**Why the tolerance is smaller than in the ID token flow.** The browser identity accepts
sixty seconds of clock skew on a token that lives for minutes. An exchanged Keycloak
token is short-lived by design, and a minute of tolerance on a one-minute token doubles
its validity; thirty seconds is enough for real clock drift and no more.

**Every refusal is the same from the outside.** One detail-free exception type, a fixed
phrase in the log, never a claim value, a token fragment or a principal in any line: a
caller who can tell a wrong signature from a wrong audience has been handed an oracle.
"""

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import jwt

from .jwks import ALLOWED_ALGORITHMS, KeySet, same_origin

__all__ = [
    "ACCEPTED_TYP_HEADERS",
    "ACCESS_TOKEN_TYP",
    "DEFAULT_EXCHANGE_ALGORITHMS",
    "EXCHANGE_LEEWAY_SECONDS",
    "ID_TOKEN_TYP",
    "MAX_TOKEN_LIFETIME_SECONDS",
    "REQUIRED_CLAIMS",
    "ExchangeRefused",
    "ExchangeSettings",
    "ExchangeTokenChecker",
]

#: RS256 alone unless the operator says otherwise: it is what Keycloak signs access
#: tokens with by default, and every additional algorithm is additional attack surface.
DEFAULT_EXCHANGE_ALGORITHMS = ("RS256",)

#: Deliberately half the sixty seconds of the ID token flow: an exchanged token is
#: short-lived on purpose, and a minute of tolerance on a one-minute token would double
#: its validity. Thirty seconds covers real clock drift and no more.
EXCHANGE_LEEWAY_SECONDS = 30

#: A token older or longer-lived than this is refused, never shortened. There is no
#: introspection and no revocation list in the hot path, so the lifetime is the only
#: bound on how long a leaked or revoked-at-the-provider token keeps working here.
MAX_TOKEN_LIFETIME_SECONDS = 900

#: Keycloak writes the token type as the payload claim ``typ``; this is its value on an
#: access token. The header ``typ`` is no substitute, see the comment in ``claims_of``.
ACCESS_TOKEN_TYP = "Bearer"  # noqa: S105 - the token type of RFC 6750, not a secret

#: The payload ``typ`` of an ID token of the same realm, signed by the same keys with
#: the same issuer. The claim is what tells the two apart, which is why the tests build
#: their ID token against exactly this value.
ID_TOKEN_TYP = "ID"  # noqa: S105 - a token type name, not a secret

#: Header ``typ`` values tolerated when present, compared without case, never required.
#: Keycloak sets JWT or at+jwt depending on the age of the client (Keycloak discussion
#: 19419), so requiring at+jwt in the header, as RFC 9068 suggests, would refuse every
#: real token; do not "correct" the payload check below into a header check. A header
#: type outside this set is a different artifact altogether (a DPoP proof, a logout
#: token) and falls.
ACCEPTED_TYP_HEADERS = frozenset({"JWT", "at+jwt"})

#: The case-folded form the comparison runs against.
_TYP_HEADERS_FOLDED = frozenset(value.lower() for value in ACCEPTED_TYP_HEADERS)

#: Handed to the decoder as its require list. ``aud`` stays in it although the value
#: comparison lands in plan 21-02: a token without an audience falls already now, and
#: a missing ``typ`` is a refusal before any comparison.
REQUIRED_CLAIMS = ["iss", "sub", "aud", "exp", "iat", "typ"]

logger = logging.getLogger("mcp_connector.oauth.exchange")


class ExchangeRefused(Exception):
    """The token, a claim or the key set did not meet the rules. Carries no detail.

    Callers answer every refusal the same way (oracle-free); the reason goes to the log
    as a fixed phrase, never with a value from the token.
    """


def _refused(reason: str) -> ExchangeRefused:
    logger.warning("exchange refused: %s", reason)
    return ExchangeRefused()


@dataclass(frozen=True, slots=True)
class ExchangeSettings:
    """What phase 22 will read from configuration. Validated on construction.

    Until that phase exists, configuration is exactly these parameters: nothing here
    reads the environment, and every violation is a :class:`ValueError` while building,
    never a silent default.
    """

    issuer: str
    jwks_uri: str
    audience: str
    azp_allowed: tuple[str, ...]
    # In split networks (openDesk, agency deployments) the issuer is public and the
    # certs URL internal. The same-origin rule is the default and is never switched
    # off: it is bound to an explicitly named second origin, which must still be
    # HTTPS. Do not "clean up" this field into a switch that disables the rule.
    jwks_origin: str | None = None
    algorithms: tuple[str, ...] = DEFAULT_EXCHANGE_ALGORITHMS
    leeway_seconds: float = EXCHANGE_LEEWAY_SECONDS
    max_lifetime_seconds: float = MAX_TOKEN_LIFETIME_SECONDS
    typ_expected: str = ACCESS_TOKEN_TYP

    def __post_init__(self) -> None:
        _require_https_url(self.issuer, "issuer")
        if self.issuer.endswith("/"):
            raise ValueError("the issuer is used exactly as configured; drop the trailing slash")
        if self.jwks_origin is not None:
            _require_https_url(self.jwks_origin, "jwks_origin")
        if not same_origin(self.jwks_uri, self.jwks_origin or self.issuer):
            raise ValueError("jwks_uri must live on the HTTPS origin of the issuer or jwks_origin")
        # Exactly one string, never a list: an expected audience that can be several
        # values turns the comparison of plan 21-02 into an OR, which is pitfall 2.
        if not isinstance(self.audience, str) or not self.audience.strip():
            raise ValueError("the audience is exactly one non-empty string")
        if not self.azp_allowed or not all(
            isinstance(party, str) and party.strip() for party in self.azp_allowed
        ):
            raise ValueError("azp_allowed must name at least one non-empty client id")
        if not self.algorithms or not set(self.algorithms) <= ALLOWED_ALGORITHMS:
            raise ValueError("only asymmetric algorithms of the key set layer are allowed")
        if not self.typ_expected.strip():
            raise ValueError("typ_expected must not be empty")
        if self.leeway_seconds <= 0:
            raise ValueError("leeway_seconds must be positive")
        if self.max_lifetime_seconds <= 0:
            raise ValueError("max_lifetime_seconds must be positive")


class ExchangeTokenChecker:
    """One configured foreign issuer. Holds only the key set cache of that issuer."""

    def __init__(
        self,
        settings: ExchangeSettings,
        *,
        clock: Callable[[], float] | None = None,
        now: Callable[[], float] | None = None,
    ) -> None:
        self._settings = settings
        # Two clocks, deliberately separate and separately injectable. ``clock`` is the
        # monotonic one and only measures elapsed time inside the key set layer (cache
        # expiry, cooldown, failure pause); ``now`` is the wall clock for the claim
        # rules that are ours alone. Whoever checks ``exp`` against a monotonic clock
        # checks it against the uptime of the process (pitfall 6, third part).
        self._clock = clock or time.monotonic
        self._now = now or time.time

        async def jwks_uri() -> str:
            return settings.jwks_uri

        # Cooldown, single-flight and the failure pause come from the layer and are not
        # rebuilt here. The refusal factory is handed in, so a key set problem surfaces
        # as the same exception as every other refusal.
        self._keys = KeySet(
            origin=settings.jwks_origin or settings.issuer,
            jwks_uri=jwks_uri,
            algorithms=settings.algorithms,
            refuse=_refused,
            clock=self._clock,
        )

    async def claims_of(self, token: str) -> dict[str, Any]:
        """The checked claim set of ``token``, or :class:`ExchangeRefused`.

        The order is deliberate: the cheap, local rules fall first, the outgoing key
        fetch happens only for a token that already looks like one of our issuer, and
        the signature-covered checks are the last word on everything the earlier steps
        read unverified.
        """
        if not token:
            raise _refused("the token is empty")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            raise _refused("the token header is unreadable") from None
        algorithm = header.get("alg")
        if algorithm not in self._settings.algorithms:
            # Decided before any other work, so ``none`` and every ``HS*`` fall here,
            # long before a key or a shared secret could be looked at.
            raise _refused("the token uses an algorithm that is not configured")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise _refused("the token names no key")
        header_typ = header.get("typ")
        if header_typ is not None and (
            not isinstance(header_typ, str) or header_typ.lower() not in _TYP_HEADERS_FOLDED
        ):
            # Tolerated, not required: see the comment on ACCEPTED_TYP_HEADERS. A missing
            # header type is no reason to refuse; a foreign one is.
            raise _refused("the token header names another type")
        # The pre-authentication cost guard: this checker sits in a path a stranger can
        # reach with nothing but an HTTP request, and without this filter an invented
        # kid in a self-made JWT makes this process fetch the provider's keys. The
        # issuer claim is read from the unverified payload, so this filter can only
        # refuse and never accept; the decoder below checks the issuer a second time,
        # signature-covered, through its issuer argument. From the outside the refusal
        # is the same as every other.
        try:
            unverified = jwt.decode(token, options={"verify_signature": False})
        except jwt.PyJWTError:
            raise _refused("the token payload is unreadable") from None
        if unverified.get("iss") != self._settings.issuer:
            raise _refused("the token comes from another issuer")
        key = await self._keys.key(kid, algorithm)
        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=list(self._settings.algorithms),
                issuer=self._settings.issuer,
                leeway=self._settings.leeway_seconds,
                # ``aud`` stays in the require list, so a token without an audience is
                # refused already now. The comparison of its value against the one
                # configured audience is plan 21-02 and happens there, together with
                # the ``azp`` allowlist.
                options={"require": REQUIRED_CLAIMS, "verify_aud": False},
            )
        except jwt.PyJWTError:
            raise _refused("the token did not meet the standard claims") from None
        if claims.get("typ") != self._settings.typ_expected:
            # The type lives in the payload: Keycloak marks an access token Bearer and
            # an ID token ID there, while the header varies by client. An ID token of
            # the same realm, same keys and same issuer falls exactly here (pitfall 9).
            raise _refused("the token is not an access token")
        iat = _number(claims.get("iat"))
        exp = _number(claims.get("exp"))
        if iat is None or exp is None:
            # A non-numeric time is a refusal, never a TypeError out of arithmetic.
            raise _refused("the token carries no numeric times")
        # Two rules the decoder does not bring, both refusals and never a shortening:
        # a bounded lifetime and a bounded age. They run on the injected wall clock;
        # the monotonic clock stays with the key set layer (pitfall 6, third part).
        if exp - iat > self._settings.max_lifetime_seconds:
            raise _refused("the token lives longer than allowed")
        if self._now() - iat > self._settings.max_lifetime_seconds:
            raise _refused("the token is older than allowed")
        sub = claims.get("sub")
        if not isinstance(sub, str) or not sub.strip() or sub != sub.strip():
            raise _refused("the token names no usable subject")
        return claims


def _number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def _require_https_url(url: str, name: str) -> None:
    try:
        parts = urlsplit(url)
        _ = parts.port
    except ValueError:
        raise ValueError(f"{name} is not a valid URL") from None
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError(f"{name} must be an https URL")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError(f"{name} must not carry credentials, a query or a fragment")
