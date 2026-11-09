"""End-to-end tests for the OIDC provider over the real Home Assistant stack.

These drive the integration the way a real OAuth client (e.g. the hass-mcp-server
protected resource and Claude) would, with the component set up through HA's
config-entry machinery and every request made over the real aiohttp test client:

* Dynamic Client Registration (RFC 7591) at ``/oidc/register``, and the setup,
  options and migration paths that turn it on or off.
* The full authorization-code + PKCE flow: ``/oidc/authorize`` ->
  ``/oidc/continue`` (approve) -> ``/oidc/token``, ending in a signed access token.
* RFC 8707 audience binding: the issued token's ``aud`` is the requested
  resource, verified through the very ``validate_access_token`` helper that
  hass-mcp-server imports.

The flow is browser-free. The only thing the login panel does that a test cannot
is authenticate the HA user (the ``hass_client`` fixture already carries a real
token) and call ``/oidc/continue`` with the pending request id, which is read
back from the ``/oidc/authorize`` bounce page.

Per HA version in the CI matrix this proves the integration still boots (config
entry, HTTP views, frontend panel, static paths) and that DCR and issuance keep
working, catching HA runtime/API drift before it reaches users.
"""

import asyncio
import base64
import hashlib
import re
import secrets

import pytest
from homeassistant import config_entries
from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.setup import async_setup_component
from pytest_homeassistant_custom_component.common import MockConfigEntry
from pytest_homeassistant_custom_component.typing import ClientSessionGenerator

from custom_components.oidc_provider.config_flow import OIDCProviderConfigFlow
from custom_components.oidc_provider.const import CONF_ALLOW_DYNAMIC_REGISTRATION, DOMAIN
from custom_components.oidc_provider.token_validator import validate_access_token

# The issuer is derived from the request Host. Pin it with forwarded headers so
# the token's iss/aud are deterministic and independent of the test server port.
FORWARDED = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "mcp.example.com"}
ISSUER_BASE = "https://mcp.example.com"
EXPECTED_ISSUER = f"{ISSUER_BASE}/oidc"
RESOURCE = "https://mcp.example.com/api/mcp"
REDIRECT_URI = "https://mcp.example.com/auth/callback"
DISCOVERY_PATHS = (
    "/oidc/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server/oidc",
    "/oidc/.well-known/oauth-authorization-server",
)


async def _setup_entry(hass: HomeAssistant, **entry_kwargs) -> MockConfigEntry:
    """Add an OIDC provider config entry, set it up, and check it loaded."""
    assert await async_setup_component(hass, "http", {})

    entry = MockConfigEntry(domain=DOMAIN, data={}, **entry_kwargs)
    entry.add_to_hass(hass)

    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    # The whole integration loaded cleanly on this HA version.
    assert entry.state is ConfigEntryState.LOADED
    return entry


@pytest.fixture
async def setup_provider(enable_custom_integrations: None, hass: HomeAssistant) -> None:
    """Set the OIDC provider up via its config entry over the real HTTP stack.

    Only ``http`` is needed: ``async_register_built_in_panel`` registers into
    ``hass.data`` without the full ``frontend`` component (whose compiled
    ``hass_frontend`` assets are not installed in the test environment).
    """
    await _setup_entry(
        hass,
        minor_version=OIDCProviderConfigFlow.MINOR_VERSION,
        options={CONF_ALLOW_DYNAMIC_REGISTRATION: True},
    )


def _pkce_pair() -> tuple[str, str]:
    """Return a (code_verifier, code_challenge) S256 PKCE pair."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


async def _register_client(client: ClientSessionGenerator) -> dict:
    """Register a client via Dynamic Client Registration and return its metadata."""
    resp = await client.post(
        "/oidc/register",
        json={"client_name": "Test MCP Client", "redirect_uris": [REDIRECT_URI]},
        headers=FORWARDED,
    )
    assert resp.status == 201, await resp.text()
    return await resp.json()


async def _authorize_and_get_code(
    client: ClientSessionGenerator,
    *,
    client_id: str,
    code_challenge: str,
    resource: str | None,
) -> str:
    """Drive /authorize -> /continue browser-free and return the authorization code."""
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": REDIRECT_URI,
        "scope": "openid profile",
        "state": "test-state",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    if resource is not None:
        params["resource"] = resource

    # /authorize returns an HTML bounce page that stashes the pending request id
    # for the login panel. Read it back the same way the panel would.
    resp = await client.get("/oidc/authorize", params=params, headers=FORWARDED)
    assert resp.status == 200, await resp.text()
    match = re.search(r"oidc_request_id', '([^']+)'", await resp.text())
    assert match, "authorize did not hand back a request_id"
    request_id = match.group(1)

    # /oidc/continue requires an authenticated HA user; hass_client carries one.
    # Approving is what the consent screen posts.
    resp = await client.post(
        "/oidc/continue",
        json={"request_id": request_id, "approve": True},
        headers=FORWARDED,
    )
    assert resp.status == 200, await resp.text()
    redirect_url = (await resp.json())["redirect_url"]

    code_match = re.search(r"[?&]code=([^&]+)", redirect_url)
    assert code_match, f"no code in redirect: {redirect_url}"
    assert "state=test-state" in redirect_url
    return code_match.group(1)


async def _exchange_code(
    client: ClientSessionGenerator,
    *,
    code: str,
    client_id: str,
    client_secret: str,
    code_verifier: str,
    redirect_uri: str = REDIRECT_URI,
) -> tuple[int, dict]:
    """Exchange an authorization code at /oidc/token. Returns (status, json body)."""
    resp = await client.post(
        "/oidc/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "client_secret": client_secret,
            "code_verifier": code_verifier,
        },
        headers=FORWARDED,
    )
    return resp.status, await resp.json()


async def test_dynamic_client_registration(
    setup_provider: None, hass: HomeAssistant, hass_client: ClientSessionGenerator
) -> None:
    """DCR issues usable credentials and persists the client."""
    client = await hass_client()
    registration = await _register_client(client)

    assert registration["client_id"]
    assert registration["client_secret"]
    assert REDIRECT_URI in registration["redirect_uris"]
    # The registered client is live in the provider's runtime state.
    assert registration["client_id"] in hass.data[DOMAIN]["clients"]


async def test_dcr_rejects_missing_redirect_uris(
    setup_provider: None, hass_client: ClientSessionGenerator
) -> None:
    """DCR validates its input (RFC 7591 invalid_redirect_uri)."""
    client = await hass_client()
    resp = await client.post(
        "/oidc/register", json={"client_name": "No Redirects"}, headers=FORWARDED
    )
    assert resp.status == 400
    assert (await resp.json())["error"] == "invalid_redirect_uri"


async def test_authorization_code_flow_issues_audience_bound_token(
    setup_provider: None, hass: HomeAssistant, hass_client: ClientSessionGenerator
) -> None:
    """Full browser-free flow yields a token bound to the requested resource."""
    client = await hass_client()
    registration = await _register_client(client)
    client_id = registration["client_id"]
    client_secret = registration["client_secret"]

    verifier, challenge = _pkce_pair()
    code = await _authorize_and_get_code(
        client, client_id=client_id, code_challenge=challenge, resource=RESOURCE
    )
    status, body = await _exchange_code(
        client,
        code=code,
        client_id=client_id,
        client_secret=client_secret,
        code_verifier=verifier,
    )

    assert status == 200, body
    assert body["token_type"] == "Bearer"
    assert body["refresh_token"]
    assert body["id_token"]  # openid scope was granted

    # The access token validates through the exact helper hass-mcp-server uses,
    # and its audience is bound to the requested resource (RFC 8707).
    payload = validate_access_token(
        hass, body["access_token"], ISSUER_BASE, expected_audience=RESOURCE
    )
    assert payload is not None
    assert payload["iss"] == EXPECTED_ISSUER
    assert payload["aud"] == RESOURCE


async def test_token_audience_mismatch_is_rejected(
    setup_provider: None, hass: HomeAssistant, hass_client: ClientSessionGenerator
) -> None:
    """A token bound to one resource is not accepted for another (the contract).

    This is the seam hass-mcp-server depends on: a token whose aud is the
    requested resource must fail validation against a different resource.
    """
    client = await hass_client()
    registration = await _register_client(client)

    verifier, challenge = _pkce_pair()
    code = await _authorize_and_get_code(
        client,
        client_id=registration["client_id"],
        code_challenge=challenge,
        resource=RESOURCE,
    )
    _, body = await _exchange_code(
        client,
        code=code,
        client_id=registration["client_id"],
        client_secret=registration["client_secret"],
        code_verifier=verifier,
    )

    wrong_resource = "https://evil.example.com/api/mcp"
    assert (
        validate_access_token(
            hass, body["access_token"], ISSUER_BASE, expected_audience=wrong_resource
        )
        is None
    )


async def test_pkce_rejects_wrong_verifier(
    setup_provider: None, hass_client: ClientSessionGenerator
) -> None:
    """A mismatched PKCE code_verifier is rejected at the token endpoint."""
    client = await hass_client()
    registration = await _register_client(client)

    _, challenge = _pkce_pair()
    code = await _authorize_and_get_code(
        client,
        client_id=registration["client_id"],
        code_challenge=challenge,
        resource=RESOURCE,
    )
    status, body = await _exchange_code(
        client,
        code=code,
        client_id=registration["client_id"],
        client_secret=registration["client_secret"],
        code_verifier=secrets.token_urlsafe(64),  # does not match the challenge
    )

    assert status == 400
    assert body["error"] == "invalid_grant"


async def _issue_code(client: ClientSessionGenerator, registration: dict) -> tuple[str, str]:
    """Run the authorize step for a registered client. Returns (code, code_verifier)."""
    verifier, challenge = _pkce_pair()
    code = await _authorize_and_get_code(
        client,
        client_id=registration["client_id"],
        code_challenge=challenge,
        resource=RESOURCE,
    )
    return code, verifier


async def _refresh(client: ClientSessionGenerator, registration: dict, refresh_token: str) -> int:
    """Use a refresh token at /oidc/token. Returns the response status."""
    resp = await client.post(
        "/oidc/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": registration["client_id"],
            "client_secret": registration["client_secret"],
        },
        headers=FORWARDED,
    )
    return resp.status


async def test_replayed_code_is_refused_and_revokes_its_refresh_token(
    setup_provider: None, hass_client: ClientSessionGenerator
) -> None:
    """A redeemed code presented again is refused, and what it issued is revoked.

    RFC 6749 §4.1.2: the server must deny the request and should revoke the
    tokens previously issued with that code.
    """
    client = await hass_client()
    registration = await _register_client(client)
    code, verifier = await _issue_code(client, registration)
    exchange = {
        "code": code,
        "client_id": registration["client_id"],
        "client_secret": registration["client_secret"],
        "code_verifier": verifier,
    }

    first_status, first_body = await _exchange_code(client, **exchange)
    assert first_status == 200
    assert await _refresh(client, registration, first_body["refresh_token"]) == 200

    second_status, second_body = await _exchange_code(client, **exchange)

    assert second_status == 400
    assert second_body["error"] == "invalid_grant"
    assert await _refresh(client, registration, first_body["refresh_token"]) == 400


async def test_code_presented_during_its_redemption_issues_nothing(
    setup_provider: None,
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A code presented again while its first redemption is in flight voids both.

    The first request is held inside its refresh token write, where a real store
    yields to the disk, while the second request with the same code runs. The
    second is refused, and the first gives up the tokens it was issuing.
    """
    client = await hass_client()
    registration = await _register_client(client)
    code, verifier = await _issue_code(client, registration)
    exchange = {
        "code": code,
        "client_id": registration["client_id"],
        "client_secret": registration["client_secret"],
        "code_verifier": verifier,
    }

    store = hass.data[DOMAIN]["token_store"]
    save = store.async_save
    parked = asyncio.Event()
    release = asyncio.Event()

    async def held_save(data: dict) -> None:
        if not parked.is_set():
            parked.set()
            await release.wait()
        await save(data)

    monkeypatch.setattr(store, "async_save", held_save)

    first = asyncio.create_task(_exchange_code(client, **exchange))
    try:
        await asyncio.wait_for(parked.wait(), timeout=5)
        second_status, second_body = await _exchange_code(client, **exchange)
    finally:
        # Let the held request finish even when an assertion above fails, so
        # teardown does not hang on it and hide the failure.
        release.set()
    first_status, first_body = await first

    assert (first_status, first_body["error"]) == (400, "invalid_grant")
    assert (second_status, second_body["error"]) == (400, "invalid_grant")
    assert hass.data[DOMAIN]["refresh_tokens"] == {}


async def test_failed_redemption_consumes_code(
    setup_provider: None, hass_client: ClientSessionGenerator
) -> None:
    """A rejected redemption burns the code, so it cannot be retried with other values."""
    client = await hass_client()
    registration = await _register_client(client)
    code, verifier = await _issue_code(client, registration)
    exchange = {
        "code": code,
        "client_id": registration["client_id"],
        "client_secret": registration["client_secret"],
        "code_verifier": verifier,
    }

    mismatch_status, _ = await _exchange_code(
        client, **exchange, redirect_uri="https://mcp.example.com/other/callback"
    )
    retry_status, retry_body = await _exchange_code(client, **exchange)

    assert mismatch_status == 400
    assert retry_status == 400
    assert retry_body["error"] == "invalid_grant"


async def test_discovery_metadata_advertises_endpoints(
    setup_provider: None, hass_client: ClientSessionGenerator
) -> None:
    """OIDC discovery reflects the issuer derived from the request host."""
    client = await hass_client()
    resp = await client.get("/oidc/.well-known/openid-configuration", headers=FORWARDED)
    assert resp.status == 200
    discovery = await resp.json()
    assert discovery["issuer"] == EXPECTED_ISSUER
    assert discovery["authorization_endpoint"] == f"{ISSUER_BASE}/oidc/authorize"
    assert discovery["token_endpoint"] == f"{ISSUER_BASE}/oidc/token"
    assert discovery["registration_endpoint"] == f"{ISSUER_BASE}/oidc/register"


async def _assert_registration_refused(client: ClientSessionGenerator) -> None:
    """Check /oidc/register refuses and no discovery document advertises it."""
    resp = await client.post(
        "/oidc/register",
        json={"client_name": "Test MCP Client", "redirect_uris": [REDIRECT_URI]},
        headers=FORWARDED,
    )
    assert resp.status == 403
    assert (await resp.json())["error"] == "access_denied"

    for path in DISCOVERY_PATHS:
        resp = await client.get(path, headers=FORWARDED)
        assert resp.status == 200
        assert "registration_endpoint" not in await resp.json(), path


async def test_registration_refused_when_turned_off(
    enable_custom_integrations: None,
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
) -> None:
    """With registration off nobody can register and discovery does not offer it."""
    await _setup_entry(
        hass,
        minor_version=OIDCProviderConfigFlow.MINOR_VERSION,
        options={CONF_ALLOW_DYNAMIC_REGISTRATION: False},
    )

    await _assert_registration_refused(await hass_client())
    assert hass.data[DOMAIN]["clients"] == {}


async def test_entry_from_earlier_release_keeps_registration_on(
    enable_custom_integrations: None,
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
) -> None:
    """An entry from before the option existed is migrated with registration on."""
    entry = await _setup_entry(hass, minor_version=1, options={"require_pkce": True})

    assert entry.minor_version == OIDCProviderConfigFlow.MINOR_VERSION
    assert entry.options == {"require_pkce": True, CONF_ALLOW_DYNAMIC_REGISTRATION: True}

    client = await hass_client()
    await _register_client(client)
    resp = await client.get(DISCOVERY_PATHS[0], headers=FORWARDED)
    assert (await resp.json())["registration_endpoint"] == f"{ISSUER_BASE}/oidc/register"


async def test_entry_with_saved_choice_keeps_it_on_migration(
    enable_custom_integrations: None,
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
) -> None:
    """A minor version 1 entry that saved registration off, as forks do, stays off."""
    entry = await _setup_entry(
        hass, minor_version=1, options={CONF_ALLOW_DYNAMIC_REGISTRATION: False}
    )

    assert entry.minor_version == OIDCProviderConfigFlow.MINOR_VERSION
    assert entry.options == {CONF_ALLOW_DYNAMIC_REGISTRATION: False}
    await _assert_registration_refused(await hass_client())


@pytest.mark.parametrize("enabled", [True, False])
async def test_setup_flow_records_registration_choice(
    enable_custom_integrations: None, hass: HomeAssistant, enabled: bool
) -> None:
    """The setup form's registration choice is stored on the new entry."""
    assert await async_setup_component(hass, "http", {})

    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    assert result["type"] is FlowResultType.FORM

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_ALLOW_DYNAMIC_REGISTRATION: enabled}
    )
    await hass.async_block_till_done()

    assert result["type"] is FlowResultType.CREATE_ENTRY
    entry = result["result"]
    assert entry.state is ConfigEntryState.LOADED
    assert entry.minor_version == OIDCProviderConfigFlow.MINOR_VERSION
    assert entry.options == {CONF_ALLOW_DYNAMIC_REGISTRATION: enabled}
    assert hass.data[DOMAIN][CONF_ALLOW_DYNAMIC_REGISTRATION] is enabled


async def test_options_flow_turns_registration_off_without_reload(
    setup_provider: None, hass: HomeAssistant, hass_client: ClientSessionGenerator
) -> None:
    """Turning registration off in the options applies to the next request."""
    client = await hass_client()
    await _register_client(client)

    entry = hass.config_entries.async_entries(DOMAIN)[0]
    result = await hass.config_entries.options.async_init(entry.entry_id)
    assert result["type"] is FlowResultType.FORM
    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        {"require_pkce": True, CONF_ALLOW_DYNAMIC_REGISTRATION: False},
    )
    await hass.async_block_till_done()
    assert result["type"] is FlowResultType.CREATE_ENTRY

    await _assert_registration_refused(client)
    # The client that registered while it was on is still there
    assert len(hass.data[DOMAIN]["clients"]) == 1
