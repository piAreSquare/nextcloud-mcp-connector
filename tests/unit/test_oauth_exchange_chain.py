"""The configuration half of the token exchange path: the off state, the defaults, the
refusals (CONF-01).

Nothing here opens a socket, and nothing here touches ``os.environ`` except the one test
that has to prove the process environment is read like everywhere else: every environment
is a dict that is handed in, which is what makes each of these cases a pure function of
its input.

No test asserts a whole message text. What is asserted is the one property every refusal
of this module owes an operator: the message names the variable that has to change, and no
message carries the value that was read, because that value can have travelled here over
HTTP (T-22-04).
"""

import pytest

from mcp_connector import config
from mcp_connector.errors import ToolError
from mcp_connector.oauth import chain, exchange
from mcp_connector.oauth.metadata import RESOURCE_SUFFIX

ISSUER = "https://idp.example.org/realms/f13"
AZP = "f13-orchestrator"
PUBLIC_URL = "https://mcp.example.org"

ARMED = {
    config.ENV_EXCHANGE_ENABLED: "1",
    config.ENV_EXCHANGE_ISSUER: ISSUER,
    config.ENV_EXCHANGE_AZP: AZP,
}


def armed(**overrides: str) -> dict[str, str]:
    return {**ARMED, config.ENV_PUBLIC_URL: PUBLIC_URL, **overrides}


# --- the off state -----------------------------------------------------------------------


def test_an_untouched_environment_configures_nothing() -> None:
    """The factory state of CONF-01, and the measurement behind "unchanged behaviour"."""
    assert chain.load_exchange_config({}) is None


def test_an_environment_of_other_variables_configures_nothing() -> None:
    assert chain.load_exchange_config({config.ENV_URL: "http://nc.test"}) is None


@pytest.mark.parametrize("blank", ["", "   "])
def test_a_blank_switch_alone_configures_nothing(blank: str) -> None:
    assert chain.load_exchange_config({config.ENV_EXCHANGE_ENABLED: blank}) is None


@pytest.mark.parametrize(
    "name",
    [name for name in config.EXCHANGE_VARIABLES if name != config.ENV_EXCHANGE_ENABLED],
)
def test_a_configured_but_disarmed_path_refuses_the_start(name: str) -> None:
    """T-22-02: a configured path that nothing armed is the silent half state itself.

    Any of the seven values is enough; an operator who set one and forgot the switch has to
    read which variable was seen and which one is missing, instead of running a server that
    ignores both.
    """
    with pytest.raises(ToolError) as excinfo:
        chain.load_exchange_config({name: "a-value-nobody-should-read"})

    assert name in excinfo.value.message
    assert config.ENV_EXCHANGE_ENABLED in excinfo.value.message
    assert "a-value-nobody-should-read" not in f"{excinfo.value.message} {excinfo.value.hint}"


def test_an_explicit_off_with_a_configured_value_refuses_as_well() -> None:
    """Off is off, and a value next to it is still the half state of T-22-02."""
    with pytest.raises(ToolError):
        chain.load_exchange_config(
            {config.ENV_EXCHANGE_ENABLED: "0", config.ENV_EXCHANGE_ISSUER: ISSUER}
        )


def test_a_blank_value_next_to_a_disarmed_switch_is_no_configuration() -> None:
    assert chain.load_exchange_config({config.ENV_EXCHANGE_ISSUER: "   "}) is None


# --- the required values -----------------------------------------------------------------


def test_an_armed_path_without_the_issuer_refuses() -> None:
    with pytest.raises(ToolError) as excinfo:
        chain.load_exchange_config({config.ENV_EXCHANGE_ENABLED: "1", config.ENV_EXCHANGE_AZP: AZP})

    assert config.ENV_EXCHANGE_ISSUER in excinfo.value.message


def test_an_armed_path_without_the_azp_allowlist_refuses() -> None:
    with pytest.raises(ToolError) as excinfo:
        chain.load_exchange_config(
            {config.ENV_EXCHANGE_ENABLED: "1", config.ENV_EXCHANGE_ISSUER: ISSUER}
        )

    assert config.ENV_EXCHANGE_AZP in excinfo.value.message


@pytest.mark.parametrize("raw", ["", "   ", ",", " , ,"])
def test_an_azp_allowlist_of_separators_alone_is_never_an_empty_allowlist(raw: str) -> None:
    """An empty allowlist would be a rule nobody wrote: it refuses every token, which looks
    like a broken deployment, and the next hand that fixes the symptom widens it."""
    with pytest.raises(ToolError) as excinfo:
        chain.load_exchange_config({**ARMED, config.ENV_EXCHANGE_AZP: raw})

    assert config.ENV_EXCHANGE_AZP in excinfo.value.message


# --- the documented defaults -------------------------------------------------------------


def test_the_defaults_of_an_armed_path_are_the_documented_ones() -> None:
    loaded = chain.load_exchange_config(armed())

    assert loaded is not None
    assert loaded.settings.issuer == ISSUER
    assert loaded.settings.jwks_uri == f"{ISSUER}{chain.DEFAULT_JWKS_PATH}"
    assert loaded.settings.audience == f"{PUBLIC_URL}{RESOURCE_SUFFIX}"
    assert loaded.settings.azp_allowed == (AZP,)
    assert loaded.settings.algorithms == exchange.DEFAULT_EXCHANGE_ALGORITHMS
    assert loaded.settings.jwks_origin is None
    assert loaded.account_claim == config.DEFAULT_EXCHANGE_ACCOUNT_CLAIM


def test_the_audience_default_is_the_resource_url_of_this_instance() -> None:
    """T-22-03: never a generic name that a token of another instance would hold against.

    The value is the one this server already writes into its own tokens, so an operator who
    takes the default takes the audience that is documented for this deployment.
    """
    loaded = chain.load_exchange_config(armed(**{config.ENV_PUBLIC_URL: "https://a.example.org"}))

    assert loaded is not None
    assert loaded.settings.audience == f"https://a.example.org{RESOURCE_SUFFIX}"


def test_every_value_can_be_configured_explicitly() -> None:
    loaded = chain.load_exchange_config(
        armed(
            **{
                config.ENV_EXCHANGE_JWKS_URI: "https://certs.internal.example.org/keys",
                config.ENV_EXCHANGE_JWKS_ORIGIN: "https://certs.internal.example.org",
                config.ENV_EXCHANGE_AUDIENCE: "https://cloud.example.org/exapps/mcp/mcp",
                config.ENV_EXCHANGE_ACCOUNT_CLAIM: "preferred_username",
                config.ENV_EXCHANGE_ALGORITHMS: "RS256, ES256",
            }
        )
    )

    assert loaded is not None
    assert loaded.settings.jwks_uri == "https://certs.internal.example.org/keys"
    assert loaded.settings.jwks_origin == "https://certs.internal.example.org"
    assert loaded.settings.audience == "https://cloud.example.org/exapps/mcp/mcp"
    assert loaded.settings.algorithms == ("RS256", "ES256")
    assert loaded.account_claim == "preferred_username"


def test_the_azp_allowlist_is_split_on_commas() -> None:
    loaded = chain.load_exchange_config(armed(**{config.ENV_EXCHANGE_AZP: "a, b ,c"}))

    assert loaded is not None
    assert loaded.settings.azp_allowed == ("a", "b", "c")


def test_a_single_azp_never_becomes_an_allowlist_of_its_characters() -> None:
    """The shape phase 21 refuses in the constructor, refused here where it is built."""
    loaded = chain.load_exchange_config(armed())

    assert loaded is not None
    assert loaded.settings.azp_allowed == (AZP,)


@pytest.mark.parametrize("blank", ["", "   "])
def test_a_blank_account_claim_refuses(blank: str) -> None:
    """A variable that stands there and says nothing is a typo, never a request for the
    default: the account claim decides which account an exchanged token acts as."""
    with pytest.raises(ToolError) as excinfo:
        chain.load_exchange_config(armed(**{config.ENV_EXCHANGE_ACCOUNT_CLAIM: blank}))

    assert config.ENV_EXCHANGE_ACCOUNT_CLAIM in excinfo.value.message


# --- every rule of phase 21 arrives as a named refusal -------------------------------------


@pytest.mark.parametrize(
    ("name", "value"),
    [
        (config.ENV_EXCHANGE_ISSUER, "http://idp.example.org/realms/f13"),
        (config.ENV_EXCHANGE_ISSUER, f"{ISSUER}/"),
        (config.ENV_EXCHANGE_ISSUER, "not-a-url"),
        (config.ENV_EXCHANGE_JWKS_URI, "https://elsewhere.example.org/certs"),
        (config.ENV_EXCHANGE_JWKS_ORIGIN, "http://certs.example.org"),
        (config.ENV_EXCHANGE_ALGORITHMS, "HS256"),
    ],
)
def test_a_rule_of_phase_21_arrives_as_a_tool_error_and_never_as_a_value_error(
    name: str, value: str
) -> None:
    """The rules live in ``exchange.ExchangeSettings`` and are not written a second time
    here. What this module owes is the translation: an operator reads a named refusal in
    the container log, not a bare ``ValueError`` out of a constructor.
    """
    with pytest.raises(ToolError) as excinfo:
        chain.load_exchange_config(armed(**{name: value}))

    assert excinfo.value.hint
    assert "NC_MCP_EXCHANGE_" in f"{excinfo.value.message} {excinfo.value.hint}"


@pytest.mark.parametrize(
    ("name", "value"),
    [
        (config.ENV_EXCHANGE_ISSUER, "http://idp.secret-tenant.example.org/realms/f13"),
        (config.ENV_EXCHANGE_JWKS_URI, "https://elsewhere.secret-tenant.example.org/certs"),
        (config.ENV_EXCHANGE_ALGORITHMS, "HS256-secret-tenant"),
    ],
)
def test_no_refusal_of_this_module_repeats_the_value_it_read(name: str, value: str) -> None:
    with pytest.raises(ToolError) as excinfo:
        chain.load_exchange_config(armed(**{name: value}))

    assert "secret-tenant" not in f"{excinfo.value.message} {excinfo.value.hint}"


def test_the_reader_reads_the_process_environment_when_no_mapping_is_given(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The shape every reader of ``config`` has, so that no caller is a special case."""
    for name in config.EXCHANGE_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    assert chain.load_exchange_config() is None

    monkeypatch.setenv(config.ENV_EXCHANGE_ENABLED, "1")
    monkeypatch.setenv(config.ENV_EXCHANGE_ISSUER, ISSUER)
    monkeypatch.setenv(config.ENV_EXCHANGE_AZP, AZP)
    loaded = chain.load_exchange_config()

    assert loaded is not None
    assert loaded.settings.issuer == ISSUER


def test_the_configuration_is_frozen() -> None:
    """Nothing downstream may widen an allowlist after the start has accepted it."""
    loaded = chain.load_exchange_config(armed())

    assert loaded is not None
    with pytest.raises(AttributeError):
        loaded.account_claim = "sub"  # type: ignore[misc]
