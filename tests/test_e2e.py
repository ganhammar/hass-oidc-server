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
import time
from urllib.parse import parse_qs, urlparse

import pytest
from homeassistant import config_entries
from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.setup import async_setup_component
from pytest_homeassistant_custom_component.common import MockConfigEntry
from pytest_homeassistant_custom_component.typing import ClientSessionGenerator

from custom_components.oidc_provider.config_flow import OIDCProviderConfigFlow
from custom_components.oidc_provider.const import (
    CONF_ALLOW_CLIENT_METADATA_DOCUMENTS,
    CONF_ALLOW_DYNAMIC_REGISTRATION,
    DOMAIN,
)
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


async def _start_authorization(
    client: ClientSessionGenerator,
    *,
    client_id: str,
    code_challenge: str,
    resource: str | None,
    redirect_uri: str = REDIRECT_URI,
) -> str:
    """Send an authorization request to /authorize and return the pending request id."""
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
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
    return match.group(1)


async def _decide(
    client: ClientSessionGenerator, request_id: str, *, approve: bool
) -> dict[str, list[str]]:
    """Post the consent decision and return the query of the redirect to the client."""
    # /oidc/continue requires an authenticated HA user; hass_client carries one.
    resp = await client.post(
        "/oidc/continue",
        json={"request_id": request_id, "approve": approve},
        headers=FORWARDED,
    )
    assert resp.status == 200, await resp.text()
    redirect_url = (await resp.json())["redirect_url"]
    assert redirect_url.startswith(f"{REDIRECT_URI}?"), redirect_url
    return parse_qs(urlparse(redirect_url).query)


async def _authorize_and_get_code(
    client: ClientSessionGenerator,
    *,
    client_id: str,
    code_challenge: str,
    resource: str | None,
) -> str:
    """Drive /authorize -> /continue browser-free and return the authorization code."""
    request_id = await _start_authorization(
        client, client_id=client_id, code_challenge=code_challenge, resource=resource
    )

    # Approving is what the consent screen posts.
    query = await _decide(client, request_id, approve=True)

    assert query["state"] == ["test-state"]
    # The response names the issuer that signs the tokens (RFC 9207).
    assert query["iss"] == [EXPECTED_ISSUER]
    assert "code" in query, f"no code in redirect: {query}"
    return query["code"][0]


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


async def test_dcr_prunes_stale_clients_and_limits_registrations(
    setup_provider: None, hass: HomeAssistant, hass_client: ClientSessionGenerator
) -> None:
    """Stale dynamic clients are pruned on registration and the hourly limit applies."""
    client = await hass_client()
    clients = hass.data[DOMAIN]["clients"]

    stale = await _register_client(client)
    kept = await _register_client(client)
    old = time.time() - 8 * 86400
    clients[stale["client_id"]]["created_at"] = old
    clients[kept["client_id"]]["created_at"] = old
    clients["operator"] = {"client_name": "Operator", "created_at": old}
    hass.data[DOMAIN]["refresh_tokens"]["live"] = {
        "client_id": kept["client_id"],
        "expires_at": time.time() + 1000,
    }

    fresh = await _register_client(client)

    assert stale["client_id"] not in clients
    assert kept["client_id"] in clients
    assert fresh["client_id"] in clients
    assert "operator" in clients
    assert clients[fresh["client_id"]]["registration"] == "dynamic"

    # 3 registrations so far; 17 more fill the hourly window.
    for _ in range(17):
        await _register_client(client)
    count = len(clients)
    resp = await client.post(
        "/oidc/register",
        json={"client_name": "One Too Many", "redirect_uris": [REDIRECT_URI]},
        headers=FORWARDED,
    )
    assert resp.status == 429
    assert (await resp.json())["error"] == "temporarily_unavailable"
    assert int(resp.headers["Retry-After"]) > 0
    assert len(clients) == count


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


async def test_denial_names_the_issuer(
    setup_provider: None, hass: HomeAssistant, hass_client: ClientSessionGenerator
) -> None:
    """A denied request sends access_denied with the issuer and no code (RFC 9207)."""
    client = await hass_client()
    registration = await _register_client(client)
    _, challenge = _pkce_pair()
    request_id = await _start_authorization(
        client,
        client_id=registration["client_id"],
        code_challenge=challenge,
        resource=RESOURCE,
    )

    query = await _decide(client, request_id, approve=False)

    assert query == {
        "error": ["access_denied"],
        "state": ["test-state"],
        "iss": [EXPECTED_ISSUER],
    }
    assert hass.data[DOMAIN]["authorization_codes"] == {}


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


async def _refresh(
    client: ClientSessionGenerator, registration: dict, refresh_token: str
) -> tuple[int, dict]:
    """Use a refresh token at /oidc/token. Returns (status, json body)."""
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
    return resp.status, await resp.json()


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
    refresh_status, refreshed = await _refresh(client, registration, first_body["refresh_token"])
    assert refresh_status == 200

    second_status, second_body = await _exchange_code(client, **exchange)

    assert second_status == 400
    assert second_body["error"] == "invalid_grant"
    # The token the code issued and the one that replaced it are both revoked
    assert (await _refresh(client, registration, first_body["refresh_token"]))[0] == 400
    assert (await _refresh(client, registration, refreshed["refresh_token"]))[0] == 400


async def test_refresh_racing_a_revocation_issues_nothing(
    setup_provider: None,
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A session revoked while a refresh is being answered gets invalid_grant, not tokens."""
    client = await hass_client()
    registration = await _register_client(client)
    code, verifier = await _issue_code(client, registration)
    _, body = await _exchange_code(
        client,
        code=code,
        client_id=registration["client_id"],
        client_secret=registration["client_secret"],
        code_verifier=verifier,
    )

    store = hass.data[DOMAIN]["token_store"]
    save = store.async_save

    async def save_then_revoke(data: dict) -> None:
        await save(data)
        hass.data[DOMAIN]["refresh_tokens"].clear()

    monkeypatch.setattr(store, "async_save", save_then_revoke)
    status, refreshed = await _refresh(client, registration, body["refresh_token"])

    assert (status, refreshed["error"]) == (400, "invalid_grant")


async def test_refresh_rotates_and_reuse_revokes_the_session(
    setup_provider: None, hass_client: ClientSessionGenerator, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each refresh replaces the refresh token; a replaced one used later ends the session."""
    client = await hass_client()
    registration = await _register_client(client)
    code, verifier = await _issue_code(client, registration)
    _, body = await _exchange_code(
        client,
        code=code,
        client_id=registration["client_id"],
        client_secret=registration["client_secret"],
        code_verifier=verifier,
    )
    first = body["refresh_token"]

    status, body = await _refresh(client, registration, first)
    assert status == 200
    second = body["refresh_token"]
    assert second != first

    # Within the grace period the replaced token is answered with its replacement
    status, body = await _refresh(client, registration, first)
    assert (status, body["refresh_token"]) == (200, second)

    status, body = await _refresh(client, registration, second)
    assert status == 200
    third = body["refresh_token"]

    # Past the grace period, the replaced token revokes every token of the session
    monkeypatch.setattr("custom_components.oidc_provider.http.REFRESH_TOKEN_REUSE_GRACE", -1)
    status, body = await _refresh(client, registration, second)
    assert (status, body["error"]) == (400, "invalid_grant")
    assert (await _refresh(client, registration, third))[0] == 400


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


async def test_discovery_advertises_authorization_response_iss(
    setup_provider: None, hass_client: ClientSessionGenerator
) -> None:
    """Every discovery document advertises the iss response parameter (RFC 9207)."""
    client = await hass_client()
    for path in DISCOVERY_PATHS:
        resp = await client.get(path, headers=FORWARDED)
        assert resp.status == 200
        metadata = await resp.json()
        assert metadata["authorization_response_iss_parameter_supported"] is True, path
        assert metadata["issuer"] == EXPECTED_ISSUER, path


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
    assert entry.options == {
        "require_pkce": True,
        CONF_ALLOW_DYNAMIC_REGISTRATION: True,
        CONF_ALLOW_CLIENT_METADATA_DOCUMENTS: True,
    }

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
    # Metadata documents follow, so the install still admits only its own clients
    assert entry.options == {
        CONF_ALLOW_DYNAMIC_REGISTRATION: False,
        CONF_ALLOW_CLIENT_METADATA_DOCUMENTS: False,
    }
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
    assert entry.options == {
        CONF_ALLOW_CLIENT_METADATA_DOCUMENTS: True,
        CONF_ALLOW_DYNAMIC_REGISTRATION: enabled,
    }
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


CIMD_CLIENT_ID = "https://claude.ai/oauth/claude-code-client-metadata"
CIMD_DOCUMENT = {
    "client_id": CIMD_CLIENT_ID,
    "client_name": "Claude Code",
    "client_uri": "https://claude.ai",
    "redirect_uris": ["http://localhost/callback", "http://127.0.0.1/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "none",
}
LOOPBACK_REDIRECT_URI = "http://localhost:53682/callback"


@pytest.fixture
def metadata_document(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Serve CIMD_DOCUMENT for every metadata fetch and record the URLs fetched."""
    fetched: list[str] = []

    async def fetch(client_id: str) -> tuple[dict, float]:
        fetched.append(client_id)
        return dict(CIMD_DOCUMENT), 300

    monkeypatch.setattr("custom_components.oidc_provider.cimd._fetch_document", fetch)
    return fetched


async def test_metadata_document_client_signs_in_without_registering(
    setup_provider: None,
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
    metadata_document: list[str],
) -> None:
    """Claude Code signs in with its metadata document URL as client_id and no secret."""
    client = await hass_client()

    resp = await client.get(DISCOVERY_PATHS[0], headers=FORWARDED)
    discovery = await resp.json()
    assert discovery["client_id_metadata_document_supported"] is True
    assert "none" in discovery["token_endpoint_auth_methods_supported"]

    verifier, challenge = _pkce_pair()
    resp = await client.get(
        "/oidc/authorize",
        params={
            "response_type": "code",
            "client_id": CIMD_CLIENT_ID,
            "redirect_uri": LOOPBACK_REDIRECT_URI,
            "scope": "openid profile",
            "state": "test-state",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "resource": RESOURCE,
        },
        headers=FORWARDED,
    )
    assert resp.status == 200, await resp.text()
    request_id = re.search(r"oidc_request_id', '([^']+)'", await resp.text()).group(1)
    assert metadata_document == [CIMD_CLIENT_ID]

    # The consent screen names the client and the host vouching for it
    resp = await client.get("/oidc/continue", params={"request_id": request_id})
    details = await resp.json()
    assert details["client_name"] == "Claude Code"
    assert details["client_host"] == "claude.ai"
    assert details["consent_required"] is True
    assert details["redirect_is_loopback"] is True

    resp = await client.post(
        "/oidc/continue", json={"request_id": request_id, "approve": True}, headers=FORWARDED
    )
    redirect_url = (await resp.json())["redirect_url"]
    assert redirect_url.startswith(f"{LOOPBACK_REDIRECT_URI}?code=")
    code = re.search(r"[?&]code=([^&]+)", redirect_url).group(1)

    status, body = await _exchange_code(
        client,
        code=code,
        client_id=CIMD_CLIENT_ID,
        client_secret="",
        code_verifier=verifier,
        redirect_uri=LOOPBACK_REDIRECT_URI,
    )
    assert status == 200, body
    payload = validate_access_token(
        hass, body["access_token"], ISSUER_BASE, expected_audience=RESOURCE
    )
    assert payload is not None

    resp = await client.post(
        "/oidc/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": body["refresh_token"],
            "client_id": CIMD_CLIENT_ID,
        },
        headers=FORWARDED,
    )
    assert resp.status == 200, await resp.text()


async def test_public_client_must_use_pkce_even_when_not_required(
    setup_provider: None,
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
    metadata_document: list[str],
) -> None:
    """Without a secret, PKCE is what binds the code, so public clients always need it."""
    hass.data[DOMAIN]["require_pkce"] = False
    client = await hass_client()

    resp = await client.get(
        "/oidc/authorize",
        params={
            "response_type": "code",
            "client_id": CIMD_CLIENT_ID,
            "redirect_uri": LOOPBACK_REDIRECT_URI,
            "scope": "openid",
        },
        headers=FORWARDED,
    )

    assert resp.status == 400
    assert "PKCE" in await resp.text()


async def test_metadata_documents_turned_off(
    setup_provider: None,
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
    metadata_document: list[str],
) -> None:
    """With the option off, URL client_ids are unknown and discovery does not offer them."""
    hass.data[DOMAIN][CONF_ALLOW_CLIENT_METADATA_DOCUMENTS] = False
    client = await hass_client()

    resp = await client.get(DISCOVERY_PATHS[0], headers=FORWARDED)
    assert "client_id_metadata_document_supported" not in await resp.json()

    _, challenge = _pkce_pair()
    resp = await client.get(
        "/oidc/authorize",
        params={
            "response_type": "code",
            "client_id": CIMD_CLIENT_ID,
            "redirect_uri": LOOPBACK_REDIRECT_URI,
            "scope": "openid",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        headers=FORWARDED,
    )

    assert resp.status == 400
    assert metadata_document == []


async def test_dynamically_registered_public_client(
    setup_provider: None, hass: HomeAssistant, hass_client: ClientSessionGenerator
) -> None:
    """A client registering with auth method none gets no secret and signs in with PKCE."""
    client = await hass_client()
    resp = await client.post(
        "/oidc/register",
        json={
            "client_name": "Public MCP Client",
            "redirect_uris": [REDIRECT_URI],
            "token_endpoint_auth_method": "none",
        },
        headers=FORWARDED,
    )
    assert resp.status == 201
    registration = await resp.json()
    assert "client_secret" not in registration

    verifier, challenge = _pkce_pair()
    code = await _authorize_and_get_code(
        client, client_id=registration["client_id"], code_challenge=challenge, resource=RESOURCE
    )
    status, body = await _exchange_code(
        client,
        code=code,
        client_id=registration["client_id"],
        client_secret="",
        code_verifier=verifier,
    )
    assert status == 200, body


async def test_pending_authorizations_are_capped(
    setup_provider: None,
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Anyone can start an authorization, so the oldest pending ones give way past the cap."""
    monkeypatch.setattr("custom_components.oidc_provider.http.MAX_PENDING_AUTH_REQUESTS", 2)
    client = await hass_client()
    registration = await _register_client(client)

    request_ids = []
    for _ in range(3):
        _, challenge = _pkce_pair()
        resp = await client.get(
            "/oidc/authorize",
            params={
                "response_type": "code",
                "client_id": registration["client_id"],
                "redirect_uri": REDIRECT_URI,
                "scope": "openid",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
            headers=FORWARDED,
        )
        request_ids.append(re.search(r"oidc_request_id', '([^']+)'", await resp.text()).group(1))

    assert list(hass.data[DOMAIN]["pending_auth_requests"]) == request_ids[1:]


async def _signed_in(client: ClientSessionGenerator) -> tuple[dict, dict]:
    """Register a client and sign in through it. Returns (registration, token response)."""
    registration = await _register_client(client)
    code, verifier = await _issue_code(client, registration)
    status, body = await _exchange_code(
        client,
        code=code,
        client_id=registration["client_id"],
        client_secret=registration["client_secret"],
        code_verifier=verifier,
    )
    assert status == 200, body
    return registration, body


async def test_client_revokes_its_session(
    setup_provider: None, hass_client: ClientSessionGenerator
) -> None:
    """A client revoking its refresh token at /oidc/revoke ends the session (RFC 7009)."""
    client = await hass_client()
    registration, tokens = await _signed_in(client)

    resp = await client.get(DISCOVERY_PATHS[0], headers=FORWARDED)
    assert (await resp.json())["revocation_endpoint"] == f"{ISSUER_BASE}/oidc/revoke"

    resp = await client.post(
        "/oidc/revoke",
        data={
            "token": tokens["refresh_token"],
            "token_type_hint": "refresh_token",
            "client_id": registration["client_id"],
            "client_secret": registration["client_secret"],
        },
        headers=FORWARDED,
    )
    assert resp.status == 200

    status, body = await _refresh(client, registration, tokens["refresh_token"])
    assert (status, body["error"]) == (400, "invalid_grant")


async def test_user_lists_and_ends_their_sessions(
    setup_provider: None, hass_client: ClientSessionGenerator
) -> None:
    """The signed-in user sees the applications using their account and can sign one out."""
    client = await hass_client()
    registration, tokens = await _signed_in(client)

    resp = await client.get("/oidc/sessions")
    [session] = (await resp.json())["sessions"]
    assert session["client_name"] == "Test MCP Client"
    assert session["client_id"] == registration["client_id"]
    assert session["scopes"] == ["openid", "profile"]

    resp = await client.delete(f"/oidc/sessions/{session['session_id']}")
    assert resp.status == 200

    assert (await _refresh(client, registration, tokens["refresh_token"]))[0] == 400
    resp = await client.get("/oidc/sessions")
    assert (await resp.json())["sessions"] == []


async def test_client_services_show_and_end_sessions(
    setup_provider: None,
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
    metadata_document: list[str],
) -> None:
    """list_clients counts sessions, metadata document clients too; revoke_client ends them."""
    assert await async_setup_component(hass, "persistent_notification", {})
    client = await hass_client()
    registration, tokens = await _signed_in(client)

    verifier, challenge = _pkce_pair()
    code = await _authorize_and_get_code(
        client,
        client_id=CIMD_CLIENT_ID,
        code_challenge=challenge,
        resource=RESOURCE,
        redirect_uri=LOOPBACK_REDIRECT_URI,
    )
    status, cimd_tokens = await _exchange_code(
        client,
        code=code,
        client_id=CIMD_CLIENT_ID,
        client_secret="",
        code_verifier=verifier,
        redirect_uri=LOOPBACK_REDIRECT_URI,
    )
    assert status == 200

    response = await hass.services.async_call(
        DOMAIN, "list_clients", {}, blocking=True, return_response=True
    )
    listed = {entry["client_id"]: entry for entry in response["clients"]}
    assert listed[registration["client_id"]]["active_sessions"] == 1
    assert listed[CIMD_CLIENT_ID] == {
        "client_id": CIMD_CLIENT_ID,
        "client_name": "Claude Code",
        "client_host": "claude.ai",
        "active_sessions": 1,
    }

    for client_id in (registration["client_id"], CIMD_CLIENT_ID):
        await hass.services.async_call(
            DOMAIN, "revoke_client", {"client_id": client_id}, blocking=True
        )

    assert registration["client_id"] not in hass.data[DOMAIN]["clients"]
    assert hass.data[DOMAIN]["refresh_tokens"] == {}
