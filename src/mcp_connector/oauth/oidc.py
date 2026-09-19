"""The OIDC client of the standalone browser identity: discovery, token exchange, ID token.

This module talks to exactly one identity provider, the one the operator configured. It is
the relying-party half of the standalone consent (design note, "OIDC consent flow"); the
browser routes and the store rows live elsewhere, so everything here is testable without a
browser.

**Where the transport and the key set live.** The hardened HTTP client and the JWKS
machinery (fetch, cache, rotation) are in ``oauth/jwks.py``, the one key set layer of this
package; this module hands in its issuer origin and its refusal factory, so the exception
type and the log line of a refusal stay the ones defined here.

**What an ID token has to be.** Signed with one of the configured algorithms by a key of the
issuer's JWKS (never a symmetric key), issued by the issuer, for this client, not expired,
carrying the nonce of this sign in, and, where it names an authorized party or several
audiences, authorized for this client. ``sub`` must be a non-empty string.

**The identity mapping** is a named strategy. ``user_oidc_unique_uid_sub_v1`` reproduces
how the Nextcloud ``user_oidc`` app derives a first-created account id with ``uniqueUid``
enabled and ``sub`` as the effective mapping claim. The operator asserts that profile; a
wrong assertion is caught when the derived id does not match the account id of the
authorization, which fails closed.
"""

import asyncio
import base64
import hashlib
import hmac
import logging
import secrets
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx
import jwt

from .jwks import (
    ALLOWED_ALGORITHMS,
    JWKS_FAILURE_RETRY_SECONDS,
    KeySet,
    fetch_json,
    same_origin,
)

__all__ = [
    "DEFAULT_ALGORITHMS",
    "STRATEGY_USER_OIDC_UNIQUE_UID_SUB_V1",
    "OidcClient",
    "OidcRefused",
    "OidcSettings",
    "ProviderMetadata",
    "code_challenge",
    "new_code_verifier",
    "user_oidc_unique_uid_sub_v1",
]

#: The algorithms an ID token may be signed with unless the operator says otherwise.
DEFAULT_ALGORITHMS = ("RS256",)

#: The one supported identity mapping profile.
STRATEGY_USER_OIDC_UNIQUE_UID_SUB_V1 = "user_oidc_unique_uid_sub_v1"

#: Clock skew tolerated on ``exp``, ``iat`` and ``nbf``.
_LEEWAY_SECONDS = 60

logger = logging.getLogger("mcp_connector.oauth.oidc")


class OidcRefused(Exception):
    """The provider, a response or a token did not meet the rules. Carries no detail.

    Callers answer every refusal the same way (oracle-free); the reason goes to the log as
    a fixed phrase, never with a value from the exchange.
    """


@dataclass(frozen=True, slots=True, repr=False)
class OidcSettings:
    """What the operator configures. Validated on construction; nothing is guessed."""

    issuer: str
    client_id: str
    redirect_uri: str
    provider_id: int
    strategy: str = STRATEGY_USER_OIDC_UNIQUE_UID_SUB_V1
    subject_type: str = "public"
    client_secret: str | None = None
    algorithms: tuple[str, ...] = DEFAULT_ALGORITHMS

    def __post_init__(self) -> None:
        _require_https_origin(self.issuer, "issuer", allow_path=True)
        if self.issuer.endswith("/"):
            raise ValueError("the issuer is used exactly as configured; drop the trailing slash")
        _require_https_origin(self.redirect_uri, "redirect_uri", allow_path=True)
        if not self.client_id.strip():
            raise ValueError("the client id is required")
        if isinstance(self.provider_id, bool) or self.provider_id <= 0:
            raise ValueError("provider_id is the positive numeric id of the user_oidc provider")
        if self.strategy != STRATEGY_USER_OIDC_UNIQUE_UID_SUB_V1:
            raise ValueError("unknown identity mapping strategy")
        if self.subject_type != "public":
            raise ValueError("only public subject identifiers are supported")
        if self.client_secret is not None and not self.client_secret:
            raise ValueError("an empty client secret is a configuration error")
        if not self.algorithms or not set(self.algorithms) <= ALLOWED_ALGORITHMS:
            raise ValueError("only asymmetric ID token algorithms are allowed")

    def __repr__(self) -> str:
        secret = "None" if self.client_secret is None else "'***'"
        return (
            f"OidcSettings(issuer={self.issuer!r}, client_id={self.client_id!r}, "
            f"redirect_uri={self.redirect_uri!r}, provider_id={self.provider_id!r}, "
            f"strategy={self.strategy!r}, algorithms={self.algorithms!r}, "
            f"client_secret={secret})"
        )


@dataclass(frozen=True, slots=True)
class ProviderMetadata:
    """The validated part of the discovery document."""

    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str


def new_code_verifier() -> str:
    """A PKCE verifier: 64 URL-safe characters (RFC 7636 allows 43 to 128)."""
    return secrets.token_urlsafe(48)


def code_challenge(verifier: str) -> str:
    """The S256 challenge of a verifier (RFC 7636, 4.2)."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def user_oidc_unique_uid_sub_v1(provider_id: int, sub: str) -> str:
    """The account id user_oidc creates for ``sub`` with ``uniqueUid`` on and claim ``sub``.

    Lowercase hex SHA-256 of ``"<provider_id>_0_<sub>"``. This describes first creation;
    existing accounts are matched by provider and ``sub`` in user_oidc, which is why the
    result is always compared with the account id Nextcloud reports and never trusted alone.
    """
    return hashlib.sha256(f"{provider_id}_0_{sub}".encode()).hexdigest()


class OidcClient:
    """One configured provider. Built once per application; holds only a JWKS cache."""

    def __init__(
        self,
        settings: OidcSettings,
        *,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._settings = settings
        # A monotonic clock, never the wall clock. The only thing measured here is elapsed
        # time (key cache expiry, the cooldown of the key set layer), and a wall clock that
        # jumps backwards (NTP correction after a container start, resume from suspend, a
        # restored snapshot) would freeze expiry and cooldown together: a key the provider
        # withdrew would stay valid for the length of the jump and a rotation would go
        # unnoticed in the same window. Tests hand in their own monotonic stand-in.
        self._clock = clock or time.monotonic
        self._metadata: ProviderMetadata | None = None
        # Discovery gets the two properties the key set layer already has: one flight at a
        # time, and a pause after a failure. Without them a burst of sign ins pulls the
        # document once per caller (``exchange()`` calls ``metadata()`` outside every
        # lock), and a provider that is down is asked again by every arriving call.
        self._metadata_lock = asyncio.Lock()
        self._metadata_failed_at = float("-inf")
        self._keys = KeySet(
            origin=settings.issuer,
            jwks_uri=self._jwks_uri,
            algorithms=settings.algorithms,
            refuse=_refused,
            clock=self._clock,
        )

    @property
    def settings(self) -> OidcSettings:
        return self._settings

    async def metadata(self) -> ProviderMetadata:
        """Discovery, validated once and then reused for the life of the process."""
        if self._metadata is not None:
            # The fast path takes no lock, exactly like the one of the key set layer.
            return self._metadata
        async with self._metadata_lock:
            if self._metadata is not None:
                # Whoever waited here takes the document the finished flight validated
                # instead of starting a second one.
                return self._metadata
            now = self._clock()
            if now - self._metadata_failed_at < JWKS_FAILURE_RETRY_SECONDS:
                raise _refused("discovery could not be fetched")
            try:
                self._metadata = await self._discover()
            except Exception:
                self._metadata_failed_at = now
                raise
            return self._metadata

    async def _discover(self) -> ProviderMetadata:
        document = await self._get_json(f"{self._settings.issuer}/.well-known/openid-configuration")
        if not isinstance(document, dict):
            raise _refused("discovery is not a JSON object")
        if document.get("issuer") != self._settings.issuer:
            raise _refused("discovery names another issuer")
        endpoints = {}
        for name in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            value = document.get(name)
            if not isinstance(value, str) or not same_origin(value, self._settings.issuer):
                raise _refused("a discovery endpoint leaves the issuer origin")
            endpoints[name] = value
        if "S256" not in _strings(document.get("code_challenge_methods_supported")):
            raise _refused("the provider does not offer S256")
        modes = document.get("response_modes_supported")
        if modes is not None and "query" not in _strings(modes):
            raise _refused("the provider does not offer response_mode=query")
        if "public" not in _strings(document.get("subject_types_supported")):
            raise _refused("the provider does not offer public subject identifiers")
        algorithms = document.get("id_token_signing_alg_values_supported")
        if algorithms is not None and not set(self._settings.algorithms) & set(
            _strings(algorithms)
        ):
            raise _refused("the provider signs with none of the configured algorithms")
        return ProviderMetadata(**endpoints)

    async def authorization_url(self, *, state: str, nonce: str, code_verifier: str) -> str:
        """Where the browser goes: code flow, PKCE S256, response_mode=query, scope openid."""
        metadata = await self.metadata()
        parts = urlsplit(metadata.authorization_endpoint)
        params = parse_qsl(parts.query, keep_blank_values=True)
        params.extend(
            [
                ("response_type", "code"),
                ("response_mode", "query"),
                ("client_id", self._settings.client_id),
                ("redirect_uri", self._settings.redirect_uri),
                ("scope", "openid"),
                ("state", state),
                ("nonce", nonce),
                ("code_challenge", code_challenge(code_verifier)),
                ("code_challenge_method", "S256"),
            ]
        )
        return urlunsplit(parts._replace(query=urlencode(params)))

    async def exchange(self, *, code: str, code_verifier: str, nonce: str) -> dict[str, Any]:
        """Redeem the code and return the claims of a fully validated ID token."""
        metadata = await self.metadata()
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self._settings.redirect_uri,
            "code_verifier": code_verifier,
            "client_id": self._settings.client_id,
        }
        auth = None
        if self._settings.client_secret is not None:
            auth = httpx.BasicAuth(self._settings.client_id, self._settings.client_secret)
        answer = await self._request("POST", metadata.token_endpoint, data=form, auth=auth)
        if not isinstance(answer, dict):
            raise _refused("the token answer is not a JSON object")
        id_token = answer.get("id_token")
        if not isinstance(id_token, str) or not id_token:
            raise _refused("the token answer carries no ID token")
        return await self.validate_id_token(id_token, nonce=nonce)

    async def validate_id_token(self, token: str, *, nonce: str) -> dict[str, Any]:
        """Every rule of the module docstring, or :class:`OidcRefused`."""
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            raise _refused("the ID token header is unreadable") from None
        algorithm = header.get("alg")
        if algorithm not in self._settings.algorithms:
            raise _refused("the ID token uses an algorithm that is not configured")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise _refused("the ID token names no key")
        key = await self._keys.key(kid, algorithm)
        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=list(self._settings.algorithms),
                audience=self._settings.client_id,
                issuer=self._settings.issuer,
                leeway=_LEEWAY_SECONDS,
                options={"require": ["iss", "sub", "aud", "exp", "iat"]},
            )
        except jwt.PyJWTError:
            raise _refused("the ID token did not validate") from None
        token_nonce = claims.get("nonce")
        # Compared as bytes, not as text: for ``str`` arguments ``compare_digest`` supports
        # ASCII only and raises ``TypeError`` otherwise. The nonce of the token comes from
        # a foreign provider, and although its signature is checked, an attacker who starts
        # an authorization of his own there picks its content, so a non-ASCII nonce must
        # end in a refusal like every other mismatch, not in a raw exception. Encoding
        # keeps the comparison constant time.
        if not isinstance(token_nonce, str) or not hmac.compare_digest(
            token_nonce.encode("utf-8"), nonce.encode("utf-8")
        ):
            raise _refused("the ID token carries another nonce")
        audience = claims.get("aud")
        azp = claims.get("azp")
        if isinstance(audience, list) and len(audience) > 1 and azp is None:
            raise _refused("a token for several audiences names no authorized party")
        if azp is not None and azp != self._settings.client_id:
            raise _refused("the ID token was issued to another party")
        sub = claims.get("sub")
        if not isinstance(sub, str) or not sub.strip() or sub != sub.strip():
            raise _refused("the ID token names no usable subject")
        return claims

    def account_id_for(self, claims: dict[str, Any]) -> str:
        """The Nextcloud account id the configured strategy derives from validated claims."""
        return user_oidc_unique_uid_sub_v1(self._settings.provider_id, str(claims["sub"]))

    # --- transport -------------------------------------------------------------------

    async def _jwks_uri(self) -> str:
        return (await self.metadata()).jwks_uri

    async def _get_json(self, url: str) -> Any:
        return await self._request("GET", url)

    async def _request(
        self,
        method: str,
        url: str,
        *,
        data: dict[str, str] | None = None,
        auth: httpx.Auth | None = None,
    ) -> Any:
        return await fetch_json(
            method, url, origin=self._settings.issuer, refuse=_refused, data=data, auth=auth
        )


def _refused(reason: str) -> OidcRefused:
    logger.warning("OIDC refused: %s", reason)
    return OidcRefused()


def _strings(value: object) -> Sequence[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _require_https_origin(url: str, name: str, *, allow_path: bool) -> None:
    try:
        parts = urlsplit(url)
        _ = parts.port
    except ValueError:
        raise ValueError(f"{name} is not a valid URL") from None
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError(f"{name} must be an https URL")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError(f"{name} must not carry credentials, a query or a fragment")
    if not allow_path and parts.path not in ("", "/"):
        raise ValueError(f"{name} must not carry a path")
