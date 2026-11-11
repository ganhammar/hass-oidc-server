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

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from homeassistant import config_entries
from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import Context, HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.exceptions import HomeAssistantError, Unauthorized
from homeassistant.setup import async_setup_component
from pytest_homeassistant_custom_component.common import MockConfigEntry, MockUser
from pytest_homeassistant_custom_component.typing import ClientSessionGenerator

from custom_components.oidc_provider.config_flow import OIDCProviderConfigFlow
from custom_components.oidc_provider.const import (
    CONF_ALLOW_CLIENT_METADATA_DOCUMENTS,
    CONF_ALLOW_DYNAMIC_REGISTRATION,
    DOMAIN,
    STORAGE_KEY_KEYS,
    STORAGE_KEY_TOKENS,
)
from custom_components.oidc_provider.security import hash_client_secret
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
    scope: str = "openid profile",
) -> str:
    """Send an authorization request to /authorize and return the pending request id."""
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
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
    client: ClientSessionGenerator,
    request_id: str,
    *,
    approve: bool,
    redirect_uri: str = REDIRECT_URI,
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
    assert redirect_url.startswith(f"{redirect_uri}?"), redirect_url
    return parse_qs(urlparse(redirect_url).query)


async def _authorize_and_get_code(
    client: ClientSessionGenerator,
    *,
    client_id: str,
    code_challenge: str,
    resource: str | None,
    redirect_uri: str = REDIRECT_URI,
) -> str:
    """Drive /authorize -> /continue browser-free and return the authorization code."""
    request_id = await _start_authorization(
        client,
        client_id=client_id,
        code_challenge=code_challenge,
        resource=resource,
        redirect_uri=redirect_uri,
    )

    # Approving is what the consent screen posts.
    query = await _decide(client, request_id, approve=True, redirect_uri=redirect_uri)

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
    """Abandoned dynamic clients are pruned, used ones kept, and the hourly limit applies."""
    client = await hass_client()
    clients = hass.data[DOMAIN]["clients"]

    abandoned = await _register_client(client)
    used, _ = await _signed_in(client)
    old = time.time() - 2 * 86400
    clients[abandoned["client_id"]]["created_at"] = old
    clients[used["client_id"]]["created_at"] = old
    clients["operator"] = {"client_name": "Operator", "created_at": old}
    # Its session ended, but a user approved it, so it stays for its next sign-in
    hass.data[DOMAIN]["refresh_tokens"].clear()
    assert "used_at" in clients[used["client_id"]]

    fresh = await _register_client(client)

    assert abandoned["client_id"] not in clients
    assert used["client_id"] in clients
    assert fresh["client_id"] in clients
    assert "operator" in clients
    assert clients[fresh["client_id"]]["registration"] == "dynamic"

    # 3 registrations so far from this address; 2 more reach its hourly limit
    for _ in range(2):
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


async def _issue_tokens(client: ClientSessionGenerator) -> tuple[dict, dict]:
    """Register a client and run the whole flow. Returns (registration, token response)."""
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


async def _userinfo_status(client: ClientSessionGenerator, token: str) -> int:
    """Present a bearer token at /oidc/userinfo and return the response status."""
    resp = await client.get(
        "/oidc/userinfo", headers={**FORWARDED, "Authorization": f"Bearer {token}"}
    )
    return resp.status


async def test_access_token_follows_jwt_profile(
    setup_provider: None, hass: HomeAssistant, hass_client: ClientSessionGenerator
) -> None:
    """The access token is an RFC 9068 JWT that still carries token_use."""
    client = await hass_client()
    registration, body = await _issue_tokens(client)

    header = jwt.get_unverified_header(body["access_token"])
    assert header["typ"] == "at+jwt"
    assert header["kid"] == hass.data[DOMAIN]["jwt_kid"]

    payload = validate_access_token(
        hass, body["access_token"], ISSUER_BASE, expected_audience=RESOURCE
    )
    assert payload is not None
    assert payload["iss"] == EXPECTED_ISSUER
    assert payload["aud"] == RESOURCE
    assert payload["client_id"] == registration["client_id"]
    assert payload["scope"] == "openid profile"
    assert payload["token_use"] == "access"
    assert payload["sub"]
    assert payload["jti"]
    assert payload["exp"] - payload["iat"] == 3600


async def test_id_token_is_not_accepted_as_access_token(
    setup_provider: None,
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
    hass_client_no_auth: ClientSessionGenerator,
) -> None:
    """An ID token is refused by the validator and at /oidc/userinfo.

    Its aud is the registered client, so only its type keeps it from passing a
    validator that is not given an expected audience.
    """
    client = await hass_client()
    registration, body = await _issue_tokens(client)
    id_token = body["id_token"]
    assert jwt.decode(id_token, options={"verify_signature": False})["aud"] == (
        registration["client_id"]
    )

    assert validate_access_token(hass, id_token, ISSUER_BASE) is None
    assert validate_access_token(hass, id_token, ISSUER_BASE, expected_audience=RESOURCE) is None

    anonymous = await hass_client_no_auth()
    assert await _userinfo_status(anonymous, id_token) == 401
    assert await _userinfo_status(anonymous, body["access_token"]) == 200


async def test_access_token_without_jwt_profile_type_still_validates(
    setup_provider: None,
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
    hass_client_no_auth: ClientSessionGenerator,
) -> None:
    """An access token without typ at+jwt, client_id or jti is accepted by token_use.

    That is the shape of access tokens from releases without the RFC 9068
    profile, which stay valid until they expire.
    """
    client = await hass_client()
    _, body = await _issue_tokens(client)
    claims = validate_access_token(
        hass, body["access_token"], ISSUER_BASE, expected_audience=RESOURCE
    )
    legacy_claims = {
        name: value for name, value in claims.items() if name not in ("client_id", "jti")
    }
    legacy_token = jwt.encode(
        legacy_claims,
        hass.data[DOMAIN]["jwt_private_key"],
        algorithm="RS256",
        headers={"kid": hass.data[DOMAIN]["jwt_kid"]},
    )
    assert jwt.get_unverified_header(legacy_token)["typ"] == "JWT"

    payload = validate_access_token(hass, legacy_token, ISSUER_BASE, expected_audience=RESOURCE)
    assert payload is not None
    assert payload["sub"] == claims["sub"]
    assert await _userinfo_status(await hass_client_no_auth(), legacy_token) == 200


async def _published_kids(client: ClientSessionGenerator) -> list[str]:
    """Return the kids /oidc/jwks publishes, in order."""
    resp = await client.get("/oidc/jwks", headers=FORWARDED)
    assert resp.status == 200
    return [key["kid"] for key in (await resp.json())["keys"]]


def _is_valid(hass: HomeAssistant, access_token: str) -> bool:
    """Return whether the access token passes the validator hass-mcp-server uses."""
    payload = validate_access_token(hass, access_token, ISSUER_BASE, expected_audience=RESOURCE)
    return payload is not None


async def _rotate(hass: HomeAssistant, data: dict, **kwargs) -> None:
    """Call the rotate_signing_key action and wait for it to finish."""
    await hass.services.async_call(DOMAIN, "rotate_signing_key", data, blocking=True, **kwargs)


async def test_rotation_keeps_previous_key_until_next_rotation(
    setup_provider: None,
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
    hass_client_no_auth: ClientSessionGenerator,
    hass_storage: dict,
) -> None:
    """By default a rotation keeps the replaced key, so tokens it signed keep working."""
    client = await hass_client()
    anonymous = await hass_client_no_auth()
    _, before = await _issue_tokens(client)
    kid_a = hass.data[DOMAIN]["jwt_kid"]

    await _rotate(hass, {})

    kid_b = hass.data[DOMAIN]["jwt_kid"]
    assert kid_b != kid_a
    assert await _published_kids(client) == [kid_b, kid_a]
    assert _is_valid(hass, before["access_token"])
    assert await _userinfo_status(anonymous, before["access_token"]) == 200

    _, after = await _issue_tokens(client)
    assert jwt.get_unverified_header(after["access_token"])["kid"] == kid_b
    assert jwt.get_unverified_header(after["id_token"])["kid"] == kid_b
    assert _is_valid(hass, after["access_token"])

    stored = hass_storage[STORAGE_KEY_KEYS]["data"]
    assert stored["kid"] == kid_b
    assert stored["previous_key"]["kid"] == kid_a

    # The next rotation keeps only the key it replaces
    await _rotate(hass, {"keep_previous_key": True})

    kid_c = hass.data[DOMAIN]["jwt_kid"]
    assert await _published_kids(client) == [kid_c, kid_b]
    assert not _is_valid(hass, before["access_token"])
    assert await _userinfo_status(anonymous, before["access_token"]) == 401
    assert _is_valid(hass, after["access_token"])


async def test_rotation_dropping_previous_key_invalidates_its_tokens(
    setup_provider: None,
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
    hass_client_no_auth: ClientSessionGenerator,
    hass_storage: dict,
) -> None:
    """Dropping the replaced key, as after a leak, refuses every token it signed at once."""
    client = await hass_client()
    _, before = await _issue_tokens(client)

    await _rotate(hass, {"keep_previous_key": False})

    kid_b = hass.data[DOMAIN]["jwt_kid"]
    assert await _published_kids(client) == [kid_b]
    assert not _is_valid(hass, before["access_token"])
    assert await _userinfo_status(await hass_client_no_auth(), before["access_token"]) == 401
    assert "previous_key" not in hass_storage[STORAGE_KEY_KEYS]["data"]

    _, after = await _issue_tokens(client)
    assert _is_valid(hass, after["access_token"])


async def test_rotation_requires_an_admin(
    setup_provider: None, hass: HomeAssistant, hass_read_only_user: MockUser
) -> None:
    """A user who is not an administrator cannot rotate the signing key."""
    kid = hass.data[DOMAIN]["jwt_kid"]

    with pytest.raises(Unauthorized):
        await _rotate(hass, {}, context=Context(user_id=hass_read_only_user.id))

    assert hass.data[DOMAIN]["jwt_kid"] == kid


async def test_signing_key_stored_without_rotation_support_is_used(
    enable_custom_integrations: None,
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
    hass_storage: dict,
) -> None:
    """A key stored in the single-key format keeps signing and verifying, and rotates."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    hass_storage[STORAGE_KEY_KEYS] = {
        "version": 1,
        "minor_version": 1,
        "key": STORAGE_KEY_KEYS,
        "data": {
            "private_key_pem": private_pem.decode(),
            "kid": "kid-from-storage",
            "created_at": 1234567890.0,
        },
    }
    await _setup_entry(
        hass,
        minor_version=OIDCProviderConfigFlow.MINOR_VERSION,
        options={CONF_ALLOW_DYNAMIC_REGISTRATION: True},
    )
    client = await hass_client()

    assert hass.data[DOMAIN]["jwt_kid"] == "kid-from-storage"
    assert await _published_kids(client) == ["kid-from-storage"]
    _, body = await _issue_tokens(client)
    assert jwt.get_unverified_header(body["access_token"])["kid"] == "kid-from-storage"
    assert jwt.decode(
        body["access_token"],
        private_key.public_key(),
        algorithms=["RS256"],
        audience=RESOURCE,
        issuer=EXPECTED_ISSUER,
    )
    assert _is_valid(hass, body["access_token"])

    await _rotate(hass, {})

    stored = hass_storage[STORAGE_KEY_KEYS]["data"]
    assert stored["kid"] == hass.data[DOMAIN]["jwt_kid"] != "kid-from-storage"
    assert stored["previous_key"]["kid"] == "kid-from-storage"
    assert await _published_kids(client) == [stored["kid"], "kid-from-storage"]
    assert _is_valid(hass, body["access_token"])


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


@pytest.mark.parametrize(
    "cap", ["MAX_PENDING_AUTH_REQUESTS", "MAX_PENDING_AUTH_REQUESTS_PER_ADDRESS"]
)
async def test_pending_authorizations_are_capped(
    setup_provider: None,
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
    monkeypatch: pytest.MonkeyPatch,
    cap: str,
) -> None:
    """Past a cap new authorizations are refused, and the ones under way are kept."""
    monkeypatch.setattr(f"custom_components.oidc_provider.http.{cap}", 2)
    client = await hass_client()
    registration = await _register_client(client)

    statuses = []
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
        statuses.append(resp.status)

    assert statuses == [200, 200, 429]
    assert len(hass.data[DOMAIN]["pending_auth_requests"]) == 2


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

    resp = await client.get("/api/oidc_provider/sessions")
    [session] = (await resp.json())["sessions"]
    assert session["client_name"] == "Test MCP Client"
    assert session["client_id"] == registration["client_id"]
    assert session["scopes"] == ["openid", "profile"]
    # The same list is served without the /api prefix
    assert (await (await client.get("/oidc/sessions")).json())["sessions"] == [session]

    resp = await client.delete(f"/api/oidc_provider/sessions/{session['session_id']}")
    assert resp.status == 200
    # It is gone, which the path without the /api prefix reports too
    resp = await client.delete(f"/oidc/sessions/{session['session_id']}")
    assert resp.status == 404

    assert (await _refresh(client, registration, tokens["refresh_token"]))[0] == 400
    resp = await client.get("/api/oidc_provider/sessions")
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


CLIENTS_URL = "/api/oidc_provider/clients"
SESSIONS_URL = "/api/oidc_provider/sessions"


async def test_admin_manages_clients_from_the_page(
    setup_provider: None,
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
    metadata_document: list[str],
) -> None:
    """The Clients tab registers, edits and revokes over its API view, as the actions do."""
    client = await hass_client()

    resp = await client.post(
        CLIENTS_URL, json={"client_name": "Grafana", "redirect_uris": [REDIRECT_URI]}
    )
    assert resp.status == 201, await resp.text()
    registered = await resp.json()

    # The secret from the page signs a user in
    code, verifier = await _issue_code(client, registered)
    status, tokens = await _exchange_code(
        client,
        code=code,
        client_id=registered["client_id"],
        client_secret=registered["client_secret"],
        code_verifier=verifier,
    )
    assert status == 200, tokens

    # A metadata document client appears once it holds a session
    verifier, challenge = _pkce_pair()
    code = await _authorize_and_get_code(
        client,
        client_id=CIMD_CLIENT_ID,
        code_challenge=challenge,
        resource=RESOURCE,
        redirect_uri=LOOPBACK_REDIRECT_URI,
    )
    status, _ = await _exchange_code(
        client,
        code=code,
        client_id=CIMD_CLIENT_ID,
        client_secret="",
        code_verifier=verifier,
        redirect_uri=LOOPBACK_REDIRECT_URI,
    )
    assert status == 200

    resp = await client.get(CLIENTS_URL)
    listed = {entry["client_id"]: entry for entry in (await resp.json())["clients"]}
    assert listed[registered["client_id"]]["registration"] == "registered"
    assert listed[registered["client_id"]]["active_sessions"] == 1
    assert listed[CIMD_CLIENT_ID]["registration"] == "metadata_document"
    assert listed[CIMD_CLIENT_ID]["client_host"] == "claude.ai"

    resp = await client.patch(
        CLIENTS_URL,
        params={"client_id": registered["client_id"]},
        json={"redirect_uris": ["https://grafana.example.com/login"], "consent_required": True},
    )
    assert resp.status == 200, await resp.text()
    stored = hass.data[DOMAIN]["clients"][registered["client_id"]]
    assert stored["redirect_uris"] == ["https://grafana.example.com/login"]
    assert stored["consent_required"] is True

    # A URL client ID travels in the query string
    for client_id in (registered["client_id"], CIMD_CLIENT_ID):
        resp = await client.delete(CLIENTS_URL, params={"client_id": client_id})
        assert resp.status == 200, await resp.text()

    assert registered["client_id"] not in hass.data[DOMAIN]["clients"]
    assert hass.data[DOMAIN]["refresh_tokens"] == {}
    assert (await _refresh(client, registered, tokens["refresh_token"]))[0] in (400, 401)
    resp = await client.get(CLIENTS_URL)
    assert (await resp.json())["clients"] == []


async def test_client_management_page_requires_an_admin(
    setup_provider: None,
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
    hass_client_no_auth: ClientSessionGenerator,
    hass_read_only_access_token: str,
) -> None:
    """Other users keep their connected applications but cannot see or change clients."""
    admin = await hass_client()
    registration = await _register_client(admin)
    client = await hass_client(hass_read_only_access_token)
    query = {"client_id": registration["client_id"]}
    body = {"client_name": "X", "redirect_uris": [REDIRECT_URI]}

    for resp in (
        await client.get(CLIENTS_URL),
        await client.post(CLIENTS_URL, json=body),
        await client.patch(CLIENTS_URL, params=query, json=body),
        await client.delete(CLIENTS_URL, params=query),
    ):
        assert resp.status == 403, await resp.text()
    assert list(hass.data[DOMAIN]["clients"]) == [registration["client_id"]]

    assert (await client.get(SESSIONS_URL)).status == 200
    assert (await (await hass_client_no_auth()).get(CLIENTS_URL)).status == 401


async def test_options_dialog_links_to_client_management(
    setup_provider: None, hass: HomeAssistant
) -> None:
    """The Configure dialog points administrators at the Clients tab of the panel."""
    entry = hass.config_entries.async_entries(DOMAIN)[0]
    result = await hass.config_entries.options.async_init(entry.entry_id)

    assert result["description_placeholders"] == {"clients_url": "/oidc_login?tab=clients"}


@pytest.mark.parametrize(
    ("service", "data"),
    [
        ("register_client", {"client_name": "X", "redirect_uris": REDIRECT_URI}),
        ("revoke_client", {"client_id": CIMD_CLIENT_ID}),
        ("update_client", {"client_id": "x", "redirect_uris": REDIRECT_URI}),
        ("list_clients", {}),
    ],
)
async def test_client_actions_require_an_admin(
    setup_provider: None,
    hass: HomeAssistant,
    hass_read_only_user: MockUser,
    service: str,
    data: dict,
) -> None:
    """Users who are not administrators cannot manage clients or end others' sessions."""
    with pytest.raises(Unauthorized):
        await hass.services.async_call(
            DOMAIN, service, data, blocking=True, context=Context(user_id=hass_read_only_user.id)
        )


async def test_client_actions_run_for_an_admin_and_without_a_user(
    setup_provider: None, hass: HomeAssistant, hass_admin_user: MockUser
) -> None:
    """Administrators, and automations that run without a user, can list clients."""
    assert await async_setup_component(hass, "persistent_notification", {})
    for context in (Context(user_id=hass_admin_user.id), Context()):
        response = await hass.services.async_call(
            DOMAIN, "list_clients", {}, blocking=True, return_response=True, context=context
        )
        assert response == {"clients": []}


@pytest.mark.parametrize(
    "client_id", ["https://[evil.com]/x", "https://[::1/x", "https://ex\\ample.com/x"]
)
async def test_malformed_url_client_id_is_refused_cleanly(
    setup_provider: None, hass_client: ClientSessionGenerator, client_id: str
) -> None:
    """A client_id that is not a valid URL gets a 400, not a server error."""
    client = await hass_client()
    _, challenge = _pkce_pair()

    resp = await client.get(
        "/oidc/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": LOOPBACK_REDIRECT_URI,
            "scope": "openid",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        headers=FORWARDED,
    )

    assert resp.status == 400


async def test_register_client_returns_credentials_without_a_notification(
    setup_provider: None, hass: HomeAssistant, hass_admin_user: MockUser
) -> None:
    """Asked for a response, register_client returns the secret instead of posting it."""
    assert await async_setup_component(hass, "persistent_notification", {})
    posted: list[dict] = []
    hass.bus.async_listen(
        "call_service",
        lambda event: (
            posted.append(event.data)
            if event.data.get("domain") == "persistent_notification"
            else None
        ),
    )

    response = await hass.services.async_call(
        DOMAIN,
        "register_client",
        {"client_name": "Responder", "redirect_uris": REDIRECT_URI},
        blocking=True,
        return_response=True,
        context=Context(user_id=hass_admin_user.id),
    )
    await hass.async_block_till_done()

    assert response["client_secret"]
    assert response["client_id"] in hass.data[DOMAIN]["clients"]
    assert posted == []

    # Without a response to carry them, the credentials go to a notification
    await hass.services.async_call(
        DOMAIN,
        "register_client",
        {"client_name": "Notified", "redirect_uris": REDIRECT_URI},
        blocking=True,
        context=Context(user_id=hass_admin_user.id),
    )
    await hass.async_block_till_done()
    assert [call["service"] for call in posted] == ["create"]


async def test_register_client_failure_is_raised_when_a_response_is_asked_for(
    setup_provider: None, hass: HomeAssistant
) -> None:
    """A caller waiting for the credentials gets the error, not just a notification."""
    assert await async_setup_component(hass, "persistent_notification", {})

    with pytest.raises(HomeAssistantError, match="must use HTTPS"):
        await hass.services.async_call(
            DOMAIN,
            "register_client",
            {"client_name": "Bad", "redirect_uris": "http://app.example.com/cb"},
            blocking=True,
            return_response=True,
        )


async def test_concurrent_rotations_do_not_bring_back_the_replaced_key(
    setup_provider: None, hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two rotations at once run one after the other, so the oldest key stays gone."""
    from custom_components.oidc_provider import http as provider_http

    original = hass.data[DOMAIN]["jwt_kid"]
    # Keys made in advance, so both rotations have theirs at once
    new_keys = [provider_http._generate_signing_key() for _ in range(2)]
    monkeypatch.setattr(provider_http, "_generate_signing_key", new_keys.pop)
    store = hass.data[DOMAIN]["key_store"]
    save = store.async_save

    async def slow_save(data: dict) -> None:
        # A real store write yields to the disk, letting the other rotation run
        await asyncio.sleep(0.05)
        await save(data)

    monkeypatch.setattr(store, "async_save", slow_save)

    await asyncio.gather(_rotate(hass, {}), _rotate(hass, {}))

    keys = list(hass.data[DOMAIN]["jwt_verification_keys"])
    assert len(keys) == 2
    assert original not in keys


# --- Resource servers that describe the access they offer --------------------
#
# The stand-in integration under tests/stand_in ships an oidc_provider.py the
# way another integration would. Home Assistant hands it to the provider
# through its integration platforms, whichever of the two loads first.


async def _setup_stand_in(hass: HomeAssistant) -> None:
    assert await async_setup_component(hass, "oidc_stand_in", {})
    await hass.async_block_till_done()


def _described_domains(hass: HomeAssistant) -> list[str]:
    from custom_components.oidc_provider.resources import described_resources

    return [described.domain for described in described_resources(hass)]


async def test_description_is_collected_from_a_resource_loaded_after_the_provider(
    setup_provider: None, hass: HomeAssistant, stand_in
) -> None:
    assert _described_domains(hass) == []

    await _setup_stand_in(hass)

    assert _described_domains(hass) == ["oidc_stand_in"]


async def test_description_is_collected_from_a_resource_loaded_before_the_provider(
    enable_custom_integrations: None, hass: HomeAssistant, stand_in
) -> None:
    await _setup_stand_in(hass)

    await _setup_entry(
        hass,
        minor_version=OIDCProviderConfigFlow.MINOR_VERSION,
        options={CONF_ALLOW_DYNAMIC_REGISTRATION: True},
    )

    assert _described_domains(hass) == ["oidc_stand_in"]


async def test_reloading_the_provider_keeps_the_descriptions(
    setup_provider: None, hass: HomeAssistant, stand_in
) -> None:
    """Unloading the entry clears its data; the descriptions are kept for the next setup."""
    await _setup_stand_in(hass)
    entry = hass.config_entries.async_entries(DOMAIN)[0]

    assert await hass.config_entries.async_reload(entry.entry_id)
    await hass.async_block_till_done()

    assert entry.state is ConfigEntryState.LOADED
    assert _described_domains(hass) == ["oidc_stand_in"]


async def test_malformed_description_is_ignored_with_a_warning(
    setup_provider: None,
    hass: HomeAssistant,
    stand_in,
    caplog: pytest.LogCaptureFixture,
) -> None:
    stand_in.DESCRIPTION = {**stand_in.DESCRIPTION, "presets": []}

    await _setup_stand_in(hass)

    assert _described_domains(hass) == []
    assert "Ignoring the resource description of integration oidc_stand_in" in caplog.text


STAND_IN_RESOURCE = f"{ISSUER_BASE}/api/stand_in"
STAND_IN_LOOK_ONLY = {
    "lights": "read",
    "cameras": "read",
    "automations": "read",
    "templates": "read",
    "files": "none",
}


@pytest.fixture
async def setup_stand_in(setup_provider: None, hass: HomeAssistant, stand_in) -> None:
    """The provider and, after it, the stand-in resource server."""
    await _setup_stand_in(hass)


async def _consent_details(client: ClientSessionGenerator, request_id: str, **query) -> dict:
    """Fetch what the consent screen shows for a pending request."""
    resp = await client.get(
        "/oidc/continue", params={"request_id": request_id, **query}, headers=FORWARDED
    )
    assert resp.status == 200, await resp.text()
    return await resp.json()


async def _choose(
    client: ClientSessionGenerator, request_id: str, options: dict[str, str] | None
) -> tuple[int, dict | str]:
    """Approve a pending request with a choice of access."""
    body = {"request_id": request_id, "approve": True}
    if options is not None:
        body["access"] = {"options": options}
    resp = await client.post("/oidc/continue", json=body, headers=FORWARDED)
    if resp.content_type == "application/json":
        return resp.status, await resp.json()
    return resp.status, await resp.text()


async def test_consent_offers_the_access_a_resource_describes(
    setup_stand_in: None, hass: HomeAssistant, hass_client: ClientSessionGenerator, stand_in
) -> None:
    client = await hass_client()
    registration = await _register_client(client)
    _, challenge = _pkce_pair()

    request_id = await _start_authorization(
        client,
        client_id=registration["client_id"],
        code_challenge=challenge,
        resource=STAND_IN_RESOURCE,
    )
    details = await _consent_details(client, request_id, language="en")

    access = details["access"]
    assert details["consent_required"] is True
    assert access["resource"] == "oidc_stand_in"
    assert access["default_preset"] == "read"
    assert [preset["title"] for preset in access["presets"]] == [
        "Look only",
        "Control devices",
        "Edit the setup",
        "Administer",
    ]
    assert access["remembered"] is None

    choice = {**STAND_IN_LOOK_ONLY, "cameras": "none"}
    status, body = await _choose(client, request_id, choice)
    assert status == 200, body
    assert "code=" in body["redirect_url"]

    # The next sign-in of this client starts from the same choice
    request_id = await _start_authorization(
        client,
        client_id=registration["client_id"],
        code_challenge=challenge,
        resource=STAND_IN_RESOURCE,
    )
    assert (await _consent_details(client, request_id))["access"]["remembered"] == choice


async def test_consent_for_a_resource_without_a_description_is_unchanged(
    setup_stand_in: None, hass: HomeAssistant, hass_client: ClientSessionGenerator
) -> None:
    client = await hass_client()
    registration = await _register_client(client)
    _, challenge = _pkce_pair()

    for resource in (RESOURCE, None):
        request_id = await _start_authorization(
            client,
            client_id=registration["client_id"],
            code_challenge=challenge,
            resource=resource,
        )
        details = await _consent_details(client, request_id)
        assert "access" not in details
        assert details["consent_required"] is True

        status, body = await _choose(client, request_id, None)
        assert status == 200, body
        assert "code=" in body["redirect_url"]


async def test_consent_shows_ceilings_and_unavailable_areas(
    setup_stand_in: None,
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
    hass_admin_user: MockUser,
    stand_in,
) -> None:
    stand_in.UNAVAILABLE["files"] = "Turned off in the stand-in's options."
    stand_in.CEILINGS[hass_admin_user.id] = {
        "groups": {"lights": {"max": "read", "reason": "Limited to Read for your account."}},
        "reason": "Not available for your account.",
    }
    client = await hass_client()
    registration = await _register_client(client)
    _, challenge = _pkce_pair()
    request_id = await _start_authorization(
        client,
        client_id=registration["client_id"],
        code_challenge=challenge,
        resource=STAND_IN_RESOURCE,
    )

    access = (await _consent_details(client, request_id))["access"]

    assert access["unavailable"] == {"files": "Turned off in the stand-in's options."}
    assert access["ceiling"]["groups"]["lights"]["max"] == "read"

    # An unavailable area can still be chosen; one above the ceiling cannot
    status, _ = await _choose(client, request_id, {**STAND_IN_LOOK_ONLY, "files": "full"})
    assert status == 200
    request_id = await _start_authorization(
        client,
        client_id=registration["client_id"],
        code_challenge=challenge,
        resource=STAND_IN_RESOURCE,
    )
    status, text = await _choose(client, request_id, {**STAND_IN_LOOK_ONLY, "lights": "full"})
    assert status == 400
    assert "above the ceiling" in text


async def test_a_locked_preset_cannot_be_approved_by_its_options(
    setup_stand_in: None,
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
    hass_admin_user: MockUser,
    stand_in,
) -> None:
    """Locking a level locks its exact choice and its scope, wherever the choice is made."""
    admin = {**STAND_IN_LOOK_ONLY, "lights": "full", "automations": "full", "files": "full"}
    stand_in.CEILINGS[hass_admin_user.id] = {
        "locked_presets": ["admin"],
        "reason": "Not available for your account.",
    }
    client = await hass_client()
    registration = await _register_client(client)
    verifier, challenge = _pkce_pair()
    request_id = await _start_authorization(
        client,
        client_id=registration["client_id"],
        code_challenge=challenge,
        resource=STAND_IN_RESOURCE,
    )
    assert (await _consent_details(client, request_id))["access"]["ceiling"]["locked_presets"] == [
        "admin"
    ]

    status, text = await _choose(client, request_id, admin)

    assert status == 400
    assert "those of preset admin, which is locked" in text

    # The request is still pending, and a choice that is not the locked level is granted
    status, body = await _choose(client, request_id, {**admin, "cameras": "none"})
    assert status == 200, body
    code = parse_qs(urlparse(body["redirect_url"]).query)["code"][0]
    status, tokens = await _exchange_code(
        client,
        code=code,
        client_id=registration["client_id"],
        client_secret=registration["client_secret"],
        code_verifier=verifier,
    )
    assert status == 200, tokens
    assert "stand_in:admin" not in tokens["scope"].split()
    assert "stand_in:files:full" in tokens["scope"].split()


async def test_panel_strings_are_served_in_the_users_language(
    setup_provider: None, hass_client: ClientSessionGenerator
) -> None:
    client = await hass_client()

    resp = await client.get("/api/oidc_provider/strings", params={"language": "de"})

    assert resp.status == 200
    data = await resp.json()
    assert data["language"] == "de"
    # Only English ships, so it stands in for every language
    assert data["strings"]["consent.heading"] == "Approve access?"
    assert data["strings"]["access.back"] == "Back to levels"


async def _sign_in_with_choice(
    client: ClientSessionGenerator,
    registration: dict,
    options: dict[str, str] | None,
    *,
    resource: str = STAND_IN_RESOURCE,
    scope: str = "openid profile",
) -> tuple[int, dict]:
    """Authorize for a resource, the stand-in's by default, approve with a choice and
    redeem the code."""
    verifier, challenge = _pkce_pair()
    request_id = await _start_authorization(
        client,
        client_id=registration["client_id"],
        code_challenge=challenge,
        resource=resource,
        scope=scope,
    )
    status, body = await _choose(client, request_id, options)
    assert status == 200, body
    code = parse_qs(urlparse(body["redirect_url"]).query)["code"][0]
    return await _exchange_code(
        client,
        code=code,
        client_id=registration["client_id"],
        client_secret=registration["client_secret"],
        code_verifier=verifier,
    )


async def test_chosen_access_is_in_the_token_and_survives_refresh(
    setup_stand_in: None, hass: HomeAssistant, hass_client: ClientSessionGenerator
) -> None:
    client = await hass_client()
    registration = await _register_client(client)

    # Exactly a level: the level's own scope
    status, tokens = await _sign_in_with_choice(client, registration, STAND_IN_LOOK_ONLY)
    assert status == 200, tokens
    assert tokens["scope"] == "openid profile stand_in:read"

    # Anything else: the scope of each area's setting
    status, tokens = await _sign_in_with_choice(
        client, registration, {**STAND_IN_LOOK_ONLY, "cameras": "none", "files": "full"}
    )
    assert status == 200, tokens
    scope = (
        "openid profile stand_in:lights:read stand_in:automations:read "
        "stand_in:templates:read stand_in:files:full"
    )
    assert tokens["scope"] == scope

    # The token is still bound to its resource, and the resource reads the scope
    claims = validate_access_token(
        hass, tokens["access_token"], ISSUER_BASE, expected_audience=STAND_IN_RESOURCE
    )
    assert claims is not None
    assert claims["scope"] == scope
    assert (
        validate_access_token(hass, tokens["access_token"], ISSUER_BASE, expected_audience=RESOURCE)
        is None
    )

    status, refreshed = await _refresh(client, registration, tokens["refresh_token"])
    assert status == 200, refreshed
    assert refreshed["scope"] == scope
    claims = validate_access_token(
        hass, refreshed["access_token"], ISSUER_BASE, expected_audience=STAND_IN_RESOURCE
    )
    assert claims["scope"] == scope


async def test_choosing_nothing_grants_no_resource_scope(
    setup_stand_in: None, hass: HomeAssistant, hass_client: ClientSessionGenerator
) -> None:
    client = await hass_client()
    registration = await _register_client(client)
    nothing = dict.fromkeys(STAND_IN_LOOK_ONLY, "none")

    status, tokens = await _sign_in_with_choice(client, registration, nothing)

    assert status == 200, tokens
    assert tokens["scope"] == "openid profile"
    status, refreshed = await _refresh(client, registration, tokens["refresh_token"])
    assert status == 200, refreshed


async def test_resource_scopes_a_client_asks_for_are_not_granted_unless_chosen(
    setup_stand_in: None, hass: HomeAssistant, hass_client: ClientSessionGenerator
) -> None:
    """Asking for a resource's scopes at the authorize step grants none of them; the
    user's choice decides, and a resource without a description gets none at all."""
    client = await hass_client()
    registration = await _register_client(client)
    asked = "openid profile stand_in:admin stand_in:files:full"

    status, tokens = await _sign_in_with_choice(
        client, registration, STAND_IN_LOOK_ONLY, scope=asked
    )
    assert status == 200, tokens
    assert tokens["scope"] == "openid profile stand_in:read"

    status, tokens = await _sign_in_with_choice(
        client, registration, dict.fromkeys(STAND_IN_LOOK_ONLY, "none"), scope=asked
    )
    assert status == 200, tokens
    assert tokens["scope"] == "openid profile"

    status, tokens = await _sign_in_with_choice(
        client, registration, None, resource=RESOURCE, scope=asked
    )
    assert status == 200, tokens
    assert tokens["scope"] == "openid profile"
    assert jwt.decode(tokens["access_token"], options={"verify_signature": False})["scope"] == (
        "openid profile"
    )


STAND_IN_CONTROL = {**STAND_IN_LOOK_ONLY, "lights": "full"}


async def test_sessions_stored_before_resources_described_access_at_refresh(
    enable_custom_integrations: None,
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
    hass_storage: dict,
    hass_admin_user: MockUser,
    stand_in,
) -> None:
    """Sessions saved by a release without choices of access have no access key. Loaded
    from storage, one for a resource that now describes its access gets the access that
    resource names for such sessions at its next refresh, one whose user is gone ends
    there, and one for any other resource refreshes as before."""
    client_id = "stored-client"
    hass_storage[f"{DOMAIN}.clients"] = {
        "version": 1,
        "key": f"{DOMAIN}.clients",
        "data": {
            "clients": {
                client_id: {
                    "client_name": "Stored client",
                    "client_secret_hash": hash_client_secret("stored-secret"),
                    "redirect_uris": [REDIRECT_URI],
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                    "token_endpoint_auth_method": "client_secret_basic",
                    "consent_required": False,
                }
            }
        },
    }

    def session(family: str, resource: str, user_id: str = hass_admin_user.id) -> dict:
        return {
            "user_id": user_id,
            "client_id": client_id,
            "scope": "openid profile",
            "nonce": None,
            "auth_time": int(time.time()) - 60,
            "resource": resource,
            "client_name": "Stored client",
            "family": family,
            "issued_at": time.time() - 60,
            "expires_at": time.time() + 3600,
        }

    hass_storage[STORAGE_KEY_TOKENS] = {
        "version": 1,
        "key": STORAGE_KEY_TOKENS,
        "data": {
            "refresh_tokens": {
                "described.token": session("described", STAND_IN_RESOURCE),
                "gone.token": session("gone", STAND_IN_RESOURCE, user_id="someone-removed"),
                "other.token": session("other", RESOURCE),
            }
        },
    }
    await _setup_entry(
        hass,
        minor_version=OIDCProviderConfigFlow.MINOR_VERSION,
        options={CONF_ALLOW_DYNAMIC_REGISTRATION: True},
    )
    await _setup_stand_in(hass)
    client = await hass_client()
    registration = {"client_id": client_id, "client_secret": "stored-secret"}
    assert set(hass.data[DOMAIN]["refresh_tokens"]) == {
        "described.token",
        "gone.token",
        "other.token",
    }

    status, body = await _refresh(client, registration, "described.token")

    assert status == 200, body
    assert body["scope"] == "openid profile stand_in:control"
    claims = validate_access_token(
        hass, body["access_token"], ISSUER_BASE, expected_audience=STAND_IN_RESOURCE
    )
    assert claims["scope"] == "openid profile stand_in:control"

    status, body = await _refresh(client, registration, "gone.token")

    assert status == 400
    assert body["error"] == "invalid_grant"
    assert "sign in again" in body["error_description"]

    status, body = await _refresh(client, registration, "other.token")

    assert status == 200, body
    assert body["scope"] == "openid profile"
    assert jwt.decode(body["access_token"], options={"verify_signature": False})["aud"] == RESOURCE
    assert sorted(data["family"] for data in hass.data[DOMAIN]["refresh_tokens"].values()) == [
        "described",
        "other",
    ]

    # The session's access is saved with it
    await hass.async_block_till_done()
    saved = hass_storage[STORAGE_KEY_TOKENS]["data"]["refresh_tokens"]
    [described] = [data for data in saved.values() if data["family"] == "described"]
    assert described["access"] == {
        "resource": "oidc_stand_in",
        "options": STAND_IN_CONTROL,
        "scopes": ["stand_in:control"],
    }


async def _session_from_before(
    client: ClientSessionGenerator, hass: HomeAssistant
) -> tuple[dict, dict]:
    """Sign in for the stand-in's resource before it describes itself, then set it up.

    Returns the client's registration and the tokens of that sign-in.
    """
    registration = await _register_client(client)
    verifier, challenge = _pkce_pair()
    code = await _authorize_and_get_code(
        client,
        client_id=registration["client_id"],
        code_challenge=challenge,
        resource=STAND_IN_RESOURCE,
    )
    status, tokens = await _exchange_code(
        client,
        code=code,
        client_id=registration["client_id"],
        client_secret=registration["client_secret"],
        code_verifier=verifier,
    )
    assert status == 200, tokens
    assert tokens["scope"] == "openid profile"

    await _setup_stand_in(hass)
    return registration, tokens


async def test_session_from_before_the_resource_described_itself_gets_its_access(
    setup_provider: None,
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
    monkeypatch: pytest.MonkeyPatch,
    stand_in,
) -> None:
    """A session that began before its resource described the access it offers carries
    no choice. Its next refresh gives it the access the resource names for such sessions,
    which it keeps as if chosen, without it becoming the user's choice for next time."""
    client = await hass_client()
    registration, tokens = await _session_from_before(client, hass)

    status, refreshed = await _refresh(client, registration, tokens["refresh_token"])

    assert status == 200, refreshed
    scope = "openid profile stand_in:control"
    assert refreshed["scope"] == scope
    claims = validate_access_token(
        hass, refreshed["access_token"], ISSUER_BASE, expected_audience=STAND_IN_RESOURCE
    )
    assert claims["scope"] == scope
    # The access token the session held before carries none of the resource's scopes
    claims = validate_access_token(
        hass, tokens["access_token"], ISSUER_BASE, expected_audience=STAND_IN_RESOURCE
    )
    assert claims["scope"] == "openid profile"

    # Connected applications shows it like any access
    resp = await client.get("/oidc/sessions", params={"language": "en"})
    [session] = (await resp.json())["sessions"]
    assert session["access"] == {"resource": "oidc_stand_in", "options": STAND_IN_CONTROL}

    # Later refreshes keep it, and rotation and reuse detection work as for any session
    status, again = await _refresh(client, registration, refreshed["refresh_token"])
    assert status == 200, again
    assert again["scope"] == scope
    assert again["refresh_token"] != refreshed["refresh_token"]
    status, replayed = await _refresh(client, registration, refreshed["refresh_token"])
    assert (status, replayed["refresh_token"], replayed["scope"]) == (
        200,
        again["refresh_token"],
        scope,
    )
    monkeypatch.setattr("custom_components.oidc_provider.http.REFRESH_TOKEN_REUSE_GRACE", -1)
    assert (await _refresh(client, registration, tokens["refresh_token"]))[0] == 400
    assert (await _refresh(client, registration, again["refresh_token"]))[0] == 400

    # The next sign-in starts from the resource's default, not from this access
    _, challenge = _pkce_pair()
    request_id = await _start_authorization(
        client,
        client_id=registration["client_id"],
        code_challenge=challenge,
        resource=STAND_IN_RESOURCE,
    )
    assert (await _consent_details(client, request_id))["access"]["remembered"] is None


async def test_ceiling_lowers_the_access_of_a_session_from_before(
    setup_provider: None,
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
    hass_admin_user: MockUser,
    stand_in,
) -> None:
    client = await hass_client()
    registration, tokens = await _session_from_before(client, hass)
    stand_in.CEILINGS[hass_admin_user.id] = {
        "groups": {"cameras": {"max": "none", "reason": "Limited for your account."}},
        "reason": "Not available for your account.",
    }

    status, refreshed = await _refresh(client, registration, tokens["refresh_token"])

    assert status == 200, refreshed
    assert refreshed["scope"] == (
        "openid profile stand_in:lights:full stand_in:automations:read stand_in:templates:read"
    )


async def test_session_from_before_ends_when_its_access_is_locked(
    setup_provider: None,
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
    hass_admin_user: MockUser,
    stand_in,
) -> None:
    """The user may not have that access, so the client signs in again and the user
    chooses."""
    client = await hass_client()
    registration, tokens = await _session_from_before(client, hass)
    stand_in.CEILINGS[hass_admin_user.id] = {
        "locked_presets": ["control"],
        "reason": "Not available for your account.",
    }

    status, body = await _refresh(client, registration, tokens["refresh_token"])

    assert (status, body["error"]) == (400, "invalid_grant")
    assert hass.data[DOMAIN]["refresh_tokens"] == {}


async def test_session_from_before_ends_when_its_resource_names_no_access_for_it(
    setup_provider: None, hass: HomeAssistant, hass_client: ClientSessionGenerator, stand_in
) -> None:
    stand_in.DESCRIPTION = {
        key: value
        for key, value in stand_in.DESCRIPTION.items()
        if key != "existing_sessions_preset"
    }
    client = await hass_client()
    registration, tokens = await _session_from_before(client, hass)

    status, body = await _refresh(client, registration, tokens["refresh_token"])

    assert status == 400
    assert body["error"] == "invalid_grant"
    assert "sign in again" in body["error_description"]
    assert hass.data[DOMAIN]["refresh_tokens"] == {}


@pytest.mark.parametrize("breakage", ["raises", "hangs"])
async def test_session_from_before_is_kept_while_its_resource_cannot_answer(
    setup_provider: None,
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    stand_in,
    breakage: str,
) -> None:
    """The session is refreshed without the resource's scopes, and the next refresh,
    with the resource answering again, gives it its access."""
    client = await hass_client()
    registration, tokens = await _session_from_before(client, hass)

    async def fail(hass: HomeAssistant, user, language: str) -> None:
        if breakage == "hangs":
            await asyncio.Event().wait()
        raise RuntimeError("no ceiling today")

    with monkeypatch.context() as patched:
        patched.setattr("custom_components.oidc_provider.resources.CALL_TIMEOUT", 0.01)
        patched.setattr(stand_in, "async_get_ceiling", fail)
        status, refreshed = await _refresh(client, registration, tokens["refresh_token"])

    assert status == 200, refreshed
    assert refreshed["scope"] == "openid profile"
    claims = validate_access_token(
        hass, refreshed["access_token"], ISSUER_BASE, expected_audience=STAND_IN_RESOURCE
    )
    assert claims["scope"] == "openid profile"
    assert "until it gives the session its access for sessions from before" in caplog.text

    status, again = await _refresh(client, registration, refreshed["refresh_token"])

    assert status == 200, again
    assert again["scope"] == "openid profile stand_in:control"


async def test_described_resource_named_only_when_redeeming_the_code_is_refused(
    setup_stand_in: None, hass_client: ClientSessionGenerator
) -> None:
    client = await hass_client()
    registration = await _register_client(client)
    verifier, challenge = _pkce_pair()
    code = await _authorize_and_get_code(
        client, client_id=registration["client_id"], code_challenge=challenge, resource=None
    )

    resp = await client.post(
        "/oidc/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": registration["client_id"],
            "client_secret": registration["client_secret"],
            "code_verifier": verifier,
            "resource": STAND_IN_RESOURCE,
        },
        headers=FORWARDED,
    )

    assert resp.status == 400
    assert (await resp.json())["error"] == "invalid_target"


async def test_discovery_advertises_the_described_scopes(
    setup_stand_in: None, hass_client: ClientSessionGenerator
) -> None:
    client = await hass_client()
    for path in DISCOVERY_PATHS:
        resp = await client.get(path, headers=FORWARDED)
        scopes = (await resp.json())["scopes_supported"]
        assert scopes[:4] == ["openid", "profile", "email", "groups"], path
        assert {"stand_in:read", "stand_in:admin", "stand_in:lights:full"} <= set(scopes), path


async def test_connected_applications_show_the_access_granted(
    setup_stand_in: None, hass: HomeAssistant, hass_client: ClientSessionGenerator
) -> None:
    client = await hass_client()
    registration = await _register_client(client)
    choice = {**STAND_IN_LOOK_ONLY, "cameras": "none"}
    status, _ = await _sign_in_with_choice(client, registration, choice)
    assert status == 200

    resp = await client.get("/oidc/sessions", params={"language": "en"})

    data = await resp.json()
    [session] = data["sessions"]
    assert session["access"] == {"resource": "oidc_stand_in", "options": choice}
    assert data["resources"]["oidc_stand_in"]["presets"][0]["title"] == "Look only"
