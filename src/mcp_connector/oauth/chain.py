"""The token exchange path of milestone v1.6: its configuration, read once at startup.

This file exists next to ``verifier.py`` instead of inside it. The ``StoreTokenVerifier``
answers for the tokens this server issued itself, and it stays byte for byte what it was:
that is the first success criterion of this phase, and a path that accepts tokens of a
foreign issuer has no business growing inside the class that answers for our own. Plan
22-02 adds the chain that asks one and then the other into this same file; what stands here
today is the configuration half alone.

The configuration is read here and not in ``exchange.py`` on purpose. That module promises
in its own docstring that it reads nothing from the environment, and that promise is what
makes every one of its rules provable against hand built settings in a test: it can be
handed a deliberately broken configuration and has to refuse it. A module that also read
the environment would have to be tested with the environment. So one module owns the rules
and this one owns the reading, and the seam between them is a :class:`ValueError` that
becomes a :class:`~mcp_connector.errors.ToolError` in exactly one place below.

The path is off in the factory state (CONF-01). Off means: no variable of the namespace is
read, no default is computed, and nothing about an installation that never heard of this
milestone changes. What an operator configures, and what this module defaults:

``config.ENV_EXCHANGE_ENABLED``
    The switch. Off unless set, and nothing below it is reached while it is off.
``config.ENV_EXCHANGE_ISSUER``
    Required. The realm URL of the provider, HTTPS, without a trailing slash. No default
    can be guessed: it decides whose signatures this server will trust.
``config.ENV_EXCHANGE_AZP``
    Required, comma separated. Which authorized parties may act at all. No default either,
    for the same reason read the other way round: it decides who may act.
``config.ENV_EXCHANGE_JWKS_URI``
    Defaults to the issuer plus :data:`DEFAULT_JWKS_PATH`.
``config.ENV_EXCHANGE_JWKS_ORIGIN``
    Defaults to nothing, which leaves the same origin rule of phase 21 on the issuer. Only
    a split network (openDesk, agency deployments with an internal certs host) needs it.
``config.ENV_EXCHANGE_AUDIENCE``
    Defaults to the resource URL of this instance, the same value this server writes into
    its own tokens. Never a generic name: a token minted for instance A must not hold at
    instance B (T-22-03).
``config.ENV_EXCHANGE_ACCOUNT_CLAIM``
    Defaults to ``config.DEFAULT_EXCHANGE_ACCOUNT_CLAIM``, which is the one claim every
    exchanged token of Keycloak carries.
``config.ENV_EXCHANGE_ALGORITHMS``
    Defaults to ``exchange.DEFAULT_EXCHANGE_ALGORITHMS``, comma separated when set.

Nothing that came out of the environment is logged or put into a message anywhere in this
module: not the issuer, not the audience, not the claim name. Refusals name variables. An
administrator's value can reach this process over HTTP through the settings overlay of the
ExApp, and a container log is read by everyone who can read container logs (T-22-04).
"""

import os
from collections.abc import Mapping
from dataclasses import dataclass

from .. import config
from ..errors import ToolError
from .exchange import DEFAULT_EXCHANGE_ALGORITHMS, ExchangeSettings
from .metadata import RESOURCE_SUFFIX

__all__ = ["DEFAULT_JWKS_PATH", "ExchangeConfig", "load_exchange_config"]

#: Where Keycloak publishes the key set of a realm, and the issuer is the realm URL, so
#: the default is a concatenation and never a discovery request. An outgoing call at
#: startup would turn an outage at the provider into a container that cannot start, and it
#: would buy nothing: the same origin rule of :class:`~mcp_connector.oauth.exchange.
#: ExchangeSettings` judges the value this module composes exactly as it judges one an
#: operator typed, so a wrong host is refused either way. A provider that publishes its
#: keys somewhere else is configured, not discovered.
DEFAULT_JWKS_PATH = "/protocol/openid-connect/certs"

#: What every refusal of this module tells an operator to do. Built from the constants of
#: ``config`` rather than spelled out, so that renaming a variable there cannot leave a
#: hint behind that names a variable nobody reads any more.
_HINT = (
    f"The token exchange path stays off until {config.ENV_EXCHANGE_ENABLED} arms it. "
    f"Armed, it requires {config.ENV_EXCHANGE_ISSUER} and {config.ENV_EXCHANGE_AZP}; "
    f"{config.ENV_EXCHANGE_JWKS_URI}, {config.ENV_EXCHANGE_JWKS_ORIGIN}, "
    f"{config.ENV_EXCHANGE_AUDIENCE}, {config.ENV_EXCHANGE_ACCOUNT_CLAIM} and "
    f"{config.ENV_EXCHANGE_ALGORITHMS} have defaults, documented in oauth/chain.py."
)


@dataclass(frozen=True, slots=True)
class ExchangeConfig:
    """The validated configuration of the exchange path, or nothing at all.

    Frozen like the settings it carries: an allowlist that a later line could widen would
    be no allowlist, and the start is the one moment at which this is decided.
    """

    settings: ExchangeSettings
    #: Which claim of an exchanged token names the account. Nobody evaluates it in this
    #: phase; MAP-01 in phase 23 maps it onto a Nextcloud account. It is read here anyway
    #: because CONF-01 makes it configuration with a documented default, and because a
    #: configuration value that is first read in the phase that needs it ends up living
    #: between mapping code instead of next to the other seven variables of its namespace.
    account_claim: str


def load_exchange_config(env: Mapping[str, str] | None = None) -> ExchangeConfig | None:
    """The environment as a validated configuration, as ``None``, or as a named refusal.

    ``None`` is the factory state and the only silent answer this function gives. Every
    other incomplete state is a :class:`~mcp_connector.errors.ToolError`, which both entry
    points let travel into their existing handler, where it becomes a named message and
    exit code 2. Half configured is never served (T-22-01, T-22-02).
    """
    source = os.environ if env is None else env
    if not config.exchange_enabled(source):
        _refuse_a_disarmed_configuration(source)
        return None

    issuer = _required(source, config.ENV_EXCHANGE_ISSUER)
    azp_allowed = _allowlist(_required(source, config.ENV_EXCHANGE_AZP), config.ENV_EXCHANGE_AZP)
    jwks_uri = _optional(source, config.ENV_EXCHANGE_JWKS_URI) or f"{issuer}{DEFAULT_JWKS_PATH}"
    jwks_origin = _optional(source, config.ENV_EXCHANGE_JWKS_ORIGIN)
    audience = (
        _optional(source, config.ENV_EXCHANGE_AUDIENCE)
        or f"{config.public_url(source)}{RESOURCE_SUFFIX}"
    )
    account_claim = (
        _optional(source, config.ENV_EXCHANGE_ACCOUNT_CLAIM)
        or config.DEFAULT_EXCHANGE_ACCOUNT_CLAIM
    )
    raw_algorithms = _optional(source, config.ENV_EXCHANGE_ALGORITHMS)
    algorithms = (
        _allowlist(raw_algorithms, config.ENV_EXCHANGE_ALGORITHMS)
        if raw_algorithms
        else DEFAULT_EXCHANGE_ALGORITHMS
    )

    try:
        settings = ExchangeSettings(
            issuer=issuer,
            jwks_uri=jwks_uri,
            audience=audience,
            azp_allowed=azp_allowed,
            jwks_origin=jwks_origin,
            algorithms=algorithms,
        )
    except ValueError as exc:
        # The rules are phase 21's and are not written a second time here: a copy would
        # drift and the drift would show as a configuration that passes one check and
        # fails the other. What this line owes an operator is the translation. A bare
        # ValueError in a container log names no variable and suggests a bug in this app
        # rather than a value that has to change. The text of the ValueError names the
        # field and never the value, which is why it can be carried over unchanged.
        raise ToolError(
            message=f"The token exchange configuration is invalid: {exc}.", hint=_HINT
        ) from None
    return ExchangeConfig(settings=settings, account_claim=account_claim)


def _refuse_a_disarmed_configuration(source: Mapping[str, str]) -> None:
    """Refuse a start that configured the path and never armed it (T-22-02).

    The opposite half of CONF-01, and the one that is easy to leave out: an operator who
    wrote six variables and forgot the switch gets a server that quietly serves without the
    path, and believes the opposite until somebody measures it. Every name of the namespace
    is walked, so a variable added to ``config`` later cannot fall through this check
    without being added to ``config.EXCHANGE_VARIABLES`` first, which is where a test holds
    it.
    """
    for name in config.EXCHANGE_VARIABLES:
        if name == config.ENV_EXCHANGE_ENABLED:
            continue
        if (source.get(name) or "").strip():
            raise ToolError(
                message=(
                    f"{name} is set, but {config.ENV_EXCHANGE_ENABLED} does not arm the "
                    "token exchange path."
                ),
                hint=(
                    "A configured path that nothing armed is the silent half state CONF-01 "
                    f"was written against. Either arm it with {config.ENV_EXCHANGE_ENABLED} "
                    "or remove the variables of this namespace from the deployment."
                ),
            )


def _required(source: Mapping[str, str], name: str) -> str:
    """A value the armed path cannot default, named in the refusal, never repeated in it."""
    value = (source.get(name) or "").strip()
    if not value:
        raise ToolError(
            message=f"{name} is not set, and the token exchange path is armed.", hint=_HINT
        )
    return value


def _optional(source: Mapping[str, str], name: str) -> str | None:
    """A value with a documented default, or ``None`` when the variable is not there.

    A variable that stands in the deployment and says nothing is refused rather than
    defaulted. It is a typo or a template that was filled in with an empty value, and every
    one of these values decides something: which host holds the keys, which audience a
    token must name, which claim names the account. Silently answering such a line with a
    default is the same half state this whole module exists to refuse.
    """
    if name not in source:
        return None
    value = (source[name] or "").strip()
    if not value:
        raise ToolError(
            message=f"{name} is set to an empty value.",
            hint=(
                f"Remove the variable to take the documented default, or give it a value. {_HINT}"
            ),
        )
    return value


def _allowlist(raw: str, name: str) -> tuple[str, ...]:
    """A comma separated list as a tuple of non-empty entries, never an empty allowlist.

    The shape ``entry_oauth.load_settings`` reads the OIDC algorithms with, for the two
    lists of this namespace. An empty result is refused and not passed on: phase 21 would
    refuse it as well, but one line later and with a message about a sequence rather than
    about the variable that has to change. An empty allowlist is also the configuration
    error that hides longest, because it refuses every token and therefore looks like a
    broken deployment rather than like a rule nobody wrote.
    """
    entries = tuple(part.strip() for part in raw.split(",") if part.strip())
    if not entries:
        raise ToolError(
            message=f"{name} names no value.",
            hint=f"Separate several values with commas. {_HINT}",
        )
    return entries
