"""Tests for choosing access on the consent screen, for a resource that describes it."""

import asyncio
import copy
import json
import logging
import time
from types import SimpleNamespace
from unittest.mock import ANY, AsyncMock, MagicMock, Mock, patch

import pytest
from homeassistant.core import HomeAssistant

from custom_components.oidc_provider import resources
from custom_components.oidc_provider.const import DOMAIN, STORAGE_KEY_ACCESS_CHOICES
from custom_components.oidc_provider.http import OIDCContinueView, _panel_language
from custom_components.oidc_provider.resources import (
    DATA_RESOURCES,
    DescribedResource,
    _async_access_choices,
    _async_collect,
    async_remember_choice,
    async_remembered_choice,
)

RESOURCE = "https://ha.example.com/api/stand_in"
CLIENT = "client123"
USER = "user123"

LOOK_ONLY = {
    "lights": "read",
    "cameras": "read",
    "automations": "read",
    "templates": "read",
    "files": "none",
}
CUSTOM = {**LOOK_ONLY, "cameras": "none", "files": "read"}


async def _hass(stand_in, *, consent_required=True, choices=None):
    """Return hass state with a pending request for the stand-in's resource."""
    hass = Mock()
    hass.config.language = "en"
    hass.data = {
        DATA_RESOURCES: {},
        DOMAIN: {
            "pending_auth_requests": {
                "req": {
                    "client_id": CLIENT,
                    "redirect_uri": "https://app.example.com/cb",
                    "scope": "openid profile",
                    "state": "s",
                    "code_challenge": "c",
                    "code_challenge_method": "S256",
                    "resource": RESOURCE,
                    "expires_at": time.time() + 600,
                }
            },
            "clients": {CLIENT: {"client_name": "App", "consent_required": consent_required}},
            "authorization_codes": {},
            "access_choices": choices if choices is not None else {},
            "access_choices_store": Mock(async_save=AsyncMock()),
        },
    }
    await _async_collect(hass, "oidc_stand_in", stand_in)
    return hass


def _request(hass, *, query=None, body=None):
    request = MagicMock()
    request.query = query or {}
    request.headers = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "ha.example.com"}
    request.app = {"hass": hass}
    request.__getitem__.return_value = Mock(id=USER)
    request.json = AsyncMock(return_value=body if body is not None else {})
    return request


async def _get(hass, **query):
    response = await OIDCContinueView().get(_request(hass, query={"request_id": "req", **query}))
    return response.status, json.loads(response.body)


async def _post(hass, body):
    response = await OIDCContinueView().post(_request(hass, body={"request_id": "req", **body}))
    if response.content_type == "application/json":
        return response.status, json.loads(response.body)
    return response.status, response.text


def _code(hass):
    [code] = hass.data[DOMAIN]["authorization_codes"].values()
    return code


async def test_consent_describes_the_access_in_the_users_language(stand_in):
    hass = await _hass(stand_in)
    stand_in.UNAVAILABLE["files"] = "Turned off in the stand-in's options."

    status, data = await _get(hass, language="sv")

    assert status == 200
    access = data["access"]
    assert access["resource"] == "oidc_stand_in"
    assert access["name"] == "Ersättaren"
    assert access["default_preset"] == "read"
    assert [preset["id"] for preset in access["presets"]] == [
        "read",
        "control",
        "configure",
        "admin",
    ]
    assert [section["id"] for section in access["sections"]] == ["devices", "setup", "system"]
    assert access["unavailable"] == {"files": "Turned off in the stand-in's options."}
    assert access["ceiling"] is None
    assert access["remembered"] is None
    # Scopes stay on the server
    assert "scopes" not in json.dumps(access)
    assert ("describe", "sv") in stand_in.CALLS
    assert ("availability", "sv") in stand_in.CALLS
    assert ("ceiling", "sv") in stand_in.CALLS
    # Nothing is consumed by looking
    assert "req" in hass.data[DOMAIN]["pending_auth_requests"]


async def test_a_language_home_assistant_does_not_know_falls_back_to_the_servers(stand_in):
    hass = await _hass(stand_in)
    hass.config.language = "de"

    await _get(hass, language="../../secrets")

    assert ("describe", "de") in stand_in.CALLS
    assert _panel_language(hass, "pt-BR") == "pt-BR"
    assert _panel_language(hass, None) == "de"


async def test_choosing_access_stops_on_the_screen_for_a_client_registered_without_consent(
    stand_in,
):
    """The level is the user's to choose, whoever registered the client."""
    hass = await _hass(stand_in, consent_required=False)

    _, data = await _get(hass)

    assert data["consent_required"] is True


async def test_the_resource_is_recognised_at_another_address_of_home_assistant(stand_in):
    """A client cannot skip the choice by naming an address the request did not arrive at."""
    hass = await _hass(stand_in, consent_required=False)
    hass.data[DOMAIN]["pending_auth_requests"]["req"][
        "resource"
    ] = "http://192.168.1.10:8123/api/stand_in"

    _, data = await _get(hass)

    assert data["consent_required"] is True
    assert data["access"]["resource"] == "oidc_stand_in"


async def test_ceiling_and_remembered_choice_are_shown(stand_in):
    ceiling = {
        "groups": {"files": {"max": "read", "reason": "Limited for your account."}},
        "reason": "Not available for your account.",
    }
    stand_in.CEILINGS[USER] = ceiling
    choices = {
        USER: {
            CLIENT: {
                "oidc_stand_in": {
                    "options": {**CUSTOM, "garden": "full", "cameras": "full"},
                    "chosen_at": 1,
                }
            }
        }
    }
    hass = await _hass(stand_in, choices=choices)

    _, data = await _get(hass)

    assert data["access"]["ceiling"] == {**ceiling, "locked_presets": []}
    # Only what the description still has is preselected
    remembered = dict(CUSTOM)
    del remembered["cameras"]
    assert data["access"]["remembered"] == remembered


@pytest.mark.parametrize(
    "breakage",
    [
        "description",
        "availability",
        "ceiling",
        "raises",
    ],
)
async def test_a_resource_that_cannot_answer_gets_the_plain_screen(
    stand_in, caplog, monkeypatch, breakage
):
    hass = await _hass(stand_in, consent_required=False)
    if breakage == "description":
        stand_in.DESCRIPTION = {**copy.deepcopy(stand_in.DESCRIPTION), "presets": []}
    elif breakage == "availability":
        stand_in.UNAVAILABLE["garden"] = "No garden."
    elif breakage == "ceiling":
        stand_in.CEILINGS[USER] = {"groups": {"files": {"max": "read", "reason": "r"}}}
    else:

        async def fail(hass, user, language):
            raise RuntimeError("no ceiling today")

        monkeypatch.setattr(stand_in, "async_get_ceiling", fail)

    with caplog.at_level(logging.WARNING):
        status, data = await _get(hass)

    assert status == 200
    assert "access" not in data
    assert data["consent_required"] is False
    assert (
        "Ignoring the resource description of integration oidc_stand_in (Stand-in) for this sign-in"
        in caplog.text
    )


async def test_a_resource_that_does_not_answer_in_time_is_treated_as_failing(
    stand_in, caplog, monkeypatch
):
    """The screen falls back to the plain one, and a choice can no longer be checked."""
    hass = await _hass(stand_in)
    monkeypatch.setattr(resources, "CALL_TIMEOUT", 0.01)

    async def hang(hass, user, language):
        await asyncio.Event().wait()

    monkeypatch.setattr(stand_in, "async_get_ceiling", hang)

    with caplog.at_level(logging.WARNING):
        status, data = await _get(hass)

    assert status == 200
    assert "access" not in data
    assert (
        "Ignoring the resource description of integration oidc_stand_in (Stand-in) for this "
        "sign-in: it did not answer within 0.01 seconds"
    ) in caplog.text

    status, text = await _post(hass, {"approve": True, "access": {"options": LOOK_ONLY}})
    assert status == 400
    assert "can no longer be checked" in text


async def test_a_resource_without_the_optional_functions_offers_no_limits(stand_in):
    hass = await _hass(stand_in)
    collected = hass.data[DATA_RESOURCES]["oidc_stand_in"]
    hass.data[DATA_RESOURCES]["oidc_stand_in"] = DescribedResource(
        "oidc_stand_in",
        SimpleNamespace(async_describe_resource=stand_in.async_describe_resource),
        collected.description,
    )

    _, data = await _get(hass)

    assert data["access"]["unavailable"] == {}
    assert data["access"]["ceiling"] is None


async def test_approving_records_the_choice_and_remembers_it(stand_in):
    hass = await _hass(stand_in)

    status, data = await _post(hass, {"approve": True, "access": {"options": CUSTOM}})

    assert status == 200
    assert "code=" in data["redirect_url"]
    assert _code(hass)["access"] == {
        "resource": "oidc_stand_in",
        "options": CUSTOM,
        "scopes": [
            "stand_in:lights:read",
            "stand_in:automations:read",
            "stand_in:templates:read",
            "stand_in:files:read",
        ],
    }
    assert await async_remembered_choice(hass, USER, CLIENT, "oidc_stand_in") == CUSTOM
    hass.data[DOMAIN]["access_choices_store"].async_save.assert_awaited_once()


async def test_a_preset_is_granted_as_its_own_scopes(stand_in):
    hass = await _hass(stand_in)

    await _post(hass, {"approve": True, "access": {"options": LOOK_ONLY}})

    assert _code(hass)["access"]["scopes"] == ["stand_in:read"]


@pytest.mark.parametrize(
    ("access", "message"),
    [
        (None, "Choose what the application may do"),
        ({"options": {"lights": "read"}}, "Invalid access choice: expected one option"),
        ({"options": {**LOOK_ONLY, "files": "full"}}, "above the ceiling"),
    ],
)
async def test_an_approval_without_a_fitting_choice_is_refused(stand_in, access, message):
    stand_in.CEILINGS[USER] = {
        "groups": {"files": {"max": "read", "reason": "Limited."}},
        "reason": "Not for you.",
    }
    hass = await _hass(stand_in)

    status, text = await _post(hass, {"approve": True, "access": access})

    assert status == 400
    assert message in text
    # The request is not used up, so the user can choose again
    assert "req" in hass.data[DOMAIN]["pending_auth_requests"]
    assert hass.data[DOMAIN]["authorization_codes"] == {}


async def test_approving_the_exact_choice_of_a_locked_preset_is_refused(stand_in):
    """Locking a level locks its choice, so its scope cannot be had from the detailed view."""
    admin = {**LOOK_ONLY, "lights": "full", "automations": "full", "files": "full"}
    stand_in.CEILINGS[USER] = {"locked_presets": ["admin"], "reason": "Not for you."}
    hass = await _hass(stand_in)

    status, text = await _post(hass, {"approve": True, "access": {"options": admin}})

    assert status == 400
    assert "those of preset admin, which is locked" in text
    assert "req" in hass.data[DOMAIN]["pending_auth_requests"]
    assert hass.data[DOMAIN]["authorization_codes"] == {}

    status, _ = await _post(
        hass, {"approve": True, "access": {"options": {**admin, "cameras": "none"}}}
    )
    assert status == 200
    assert "stand_in:admin" not in _code(hass)["access"]["scopes"]


async def test_a_denial_does_not_ask_the_resource(stand_in):
    hass = await _hass(stand_in)

    status, data = await _post(hass, {"approve": False})

    assert status == 200
    assert "error=access_denied" in data["redirect_url"]
    assert stand_in.CALLS == [("describe", "en")]  # only when it was collected


async def test_resource_failing_on_approval(stand_in):
    """A resource that cannot answer when the user approves gets a plain
    approval, unless the screen offered a choice, which can no longer be checked."""
    hass = await _hass(stand_in)
    stand_in.DESCRIPTION = None

    status, text = await _post(hass, {"approve": True, "access": {"options": LOOK_ONLY}})
    assert status == 400
    assert "can no longer be checked" in text

    status, data = await _post(hass, {"approve": True})
    assert status == 200
    assert _code(hass)["access"] is None


async def test_a_choice_for_a_resource_without_a_description_is_refused(stand_in):
    hass = await _hass(stand_in)
    hass.data[DATA_RESOURCES].clear()

    status, text = await _post(hass, {"approve": True, "access": {"options": LOOK_ONLY}})

    assert status == 400
    assert "can no longer be checked" in text


async def test_two_decisions_at_once_issue_one_code(stand_in):
    hass = await _hass(stand_in)
    gate = asyncio.Event()
    describe = stand_in.async_describe_resource

    async def slow_describe(hass, language):
        await gate.wait()
        return await describe(hass, language)

    stand_in.async_describe_resource = slow_describe
    try:
        approving = asyncio.create_task(
            _post(hass, {"approve": True, "access": {"options": LOOK_ONLY}})
        )
        await asyncio.sleep(0)
        denied = await _post(hass, {"approve": False})
        gate.set()
        approved = await approving
    finally:
        stand_in.async_describe_resource = describe

    assert denied[0] == 200
    assert approved == (400, "Invalid or expired request")
    assert hass.data[DOMAIN]["authorization_codes"] == {}


async def test_remembering_drops_choices_for_clients_that_are_gone(stand_in):
    metadata_client = "https://app.example.com/client.json"
    choices = {
        "someone": {"revoked_client": {"oidc_stand_in": {"options": LOOK_ONLY}}},
        USER: {metadata_client: {"oidc_stand_in": {"options": LOOK_ONLY}}},
    }
    hass = await _hass(stand_in, choices=choices)

    await async_remember_choice(hass, USER, CLIENT, "oidc_stand_in", CUSTOM)

    assert set(choices) == {USER}
    assert set(choices[USER]) == {metadata_client, CLIENT}
    assert choices[USER][CLIENT]["oidc_stand_in"]["options"] == CUSTOM
    assert await async_remembered_choice(hass, "nobody", CLIENT, "oidc_stand_in") is None


async def test_remembered_choices_are_stored(hass: HomeAssistant, hass_storage):
    """The choices are loaded once from Home Assistant's storage and saved back to it."""
    hass_storage[STORAGE_KEY_ACCESS_CHOICES] = {
        "version": 1,
        "key": STORAGE_KEY_ACCESS_CHOICES,
        "data": {"choices": {USER: {CLIENT: {"oidc_stand_in": {"options": LOOK_ONLY}}}}},
    }
    hass.data[DOMAIN] = {"clients": {CLIENT: {}}}

    assert await async_remembered_choice(hass, USER, CLIENT, "oidc_stand_in") == LOOK_ONLY
    assert await _async_access_choices(hass) is await _async_access_choices(hass)

    with patch("custom_components.oidc_provider.resources.time.time", return_value=1000):
        await async_remember_choice(hass, USER, CLIENT, "oidc_stand_in", CUSTOM)
    await hass.async_block_till_done()

    assert hass_storage[STORAGE_KEY_ACCESS_CHOICES]["data"] == {
        "choices": {USER: {CLIENT: {"oidc_stand_in": {"options": CUSTOM, "chosen_at": 1000}}}}
    }


async def test_nothing_remembered_yet(hass: HomeAssistant, hass_storage):
    hass.data[DOMAIN] = {}

    assert await async_remembered_choice(hass, USER, CLIENT, "oidc_stand_in") is None


# --- The chosen access in the tokens ------------------------------------------

ACCESS = {
    "resource": "oidc_stand_in",
    "options": CUSTOM,
    "scopes": ["stand_in:lights:read", "stand_in:files:read"],
}


async def _token_hass(stand_in):
    """Return hass state that can issue tokens, with the stand-in described."""
    from cryptography.hazmat.primitives.asymmetric import rsa

    from custom_components.oidc_provider.security import hash_client_secret

    hass = await _hass(stand_in)
    hass.data[DOMAIN].update(
        {
            "clients": {CLIENT: {"client_secret_hash": hash_client_secret("secret")}},
            "refresh_tokens": {},
            "rate_limit_attempts": {},
            "jwt_private_key": rsa.generate_private_key(public_exponent=65537, key_size=2048),
            "jwt_kid": "kid",
            "token_store": Mock(async_save=AsyncMock()),
            "store": Mock(async_save=AsyncMock()),
        }
    )
    hass.auth.async_get_user = AsyncMock(return_value=None)
    return hass


async def _token(hass, **form):
    from custom_components.oidc_provider.http import OIDCTokenView

    request = MagicMock()
    request.app = {"hass": hass}
    request.remote = "127.0.0.1"
    request.headers = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "ha.example.com"}
    request.post = AsyncMock(return_value={"client_id": CLIENT, "client_secret": "secret", **form})
    response = await OIDCTokenView().post(request)
    return response.status, json.loads(response.body)


def _code_for(hass, *, access, resource=RESOURCE):
    hass.data[DOMAIN]["authorization_codes"]["the-code"] = {
        "client_id": CLIENT,
        "redirect_uri": "https://app.example.com/cb",
        "scope": "openid profile",
        "user_id": USER,
        "nonce": None,
        "auth_time": 1,
        "code_challenge": None,
        "resource": resource,
        "access": access,
        "client_name": "App",
        "expires_at": time.time() + 600,
    }


def _claims(token):
    import jwt

    return jwt.decode(token, options={"verify_signature": False})


async def test_the_chosen_access_is_in_the_token_and_survives_refresh(stand_in):
    hass = await _token_hass(stand_in)
    _code_for(hass, access=ACCESS)

    status, body = await _token(
        hass,
        grant_type="authorization_code",
        code="the-code",
        redirect_uri="https://app.example.com/cb",
    )

    assert status == 200, body
    scope = "openid profile stand_in:lights:read stand_in:files:read"
    assert body["scope"] == scope
    claims = _claims(body["access_token"])
    assert claims["scope"] == scope
    # Still bound to the resource it was issued for
    assert claims["aud"] == RESOURCE
    stored = hass.data[DOMAIN]["refresh_tokens"][body["refresh_token"]]
    assert stored["access"] == ACCESS

    status, body = await _token(
        hass, grant_type="refresh_token", refresh_token=body["refresh_token"]
    )

    assert status == 200, body
    assert body["scope"] == scope
    assert _claims(body["access_token"])["scope"] == scope


CONTROL = {**LOOK_ONLY, "lights": "full"}


def _without_existing_sessions_preset(stand_in):
    stand_in.DESCRIPTION = {
        key: value
        for key, value in stand_in.DESCRIPTION.items()
        if key != "existing_sessions_preset"
    }


async def _hass_with_session_from_before(stand_in, user=USER):
    """Return hass state with a session for the stand-in's resource that has no access.

    It began before the stand-in described itself. With it is a session for
    a resource that has no description.
    """
    hass = await _token_hass(stand_in)
    hass.auth.async_get_user = AsyncMock(
        return_value=SimpleNamespace(id=user, name="Someone") if user else None
    )
    hass.data[DOMAIN]["refresh_tokens"] = {
        "fam.old": {
            "client_id": CLIENT,
            "user_id": USER,
            "scope": "openid profile",
            "resource": RESOURCE,
            "family": "fam",
            "issued_at": 10,
            "expires_at": time.time() + 3600,
        },
        "other.token": {
            "client_id": CLIENT,
            "user_id": USER,
            "scope": "openid",
            "resource": None,
            "family": "other",
            "expires_at": time.time() + 3600,
        },
    }
    return hass


def _session(hass, family="fam"):
    [data] = [
        data for data in hass.data[DOMAIN]["refresh_tokens"].values() if data["family"] == family
    ]
    return data


async def test_a_session_from_before_gets_the_access_its_resource_names(stand_in, caplog):
    """The session keeps the access it defaults to as if it had been chosen, but the
    user's choice for the next sign-in is not written."""
    hass = await _hass_with_session_from_before(stand_in)

    with caplog.at_level(logging.INFO):
        status, body = await _token(hass, grant_type="refresh_token", refresh_token="fam.old")

    assert status == 200, body
    scope = "openid profile stand_in:control"
    assert body["scope"] == scope
    assert _claims(body["access_token"])["scope"] == scope
    assert _claims(body["access_token"])["aud"] == RESOURCE
    assert _session(hass)["access"] == {
        "resource": "oidc_stand_in",
        "options": CONTROL,
        "scopes": ["stand_in:control"],
    }
    assert _session(hass)["scope"] == scope
    # Asked as an approval asks, in Home Assistant's language
    assert {("describe", "en"), ("ceiling", "en")} <= set(stand_in.CALLS)
    assert "the access it gives such sessions: stand_in:control" in caplog.text
    # The refresh token was rotated as for any refresh, and the session is saved
    assert body["refresh_token"] != "fam.old"
    assert "fam.old" in _session(hass)["retired"]
    hass.data[DOMAIN]["token_store"].async_save.assert_awaited()
    # Not the user's choice
    assert hass.data[DOMAIN]["access_choices"] == {}
    hass.data[DOMAIN]["access_choices_store"].async_save.assert_not_awaited()

    # Connected applications shows it like any access
    [listed] = [session for session in (await _sessions(hass))["sessions"] if session["access"]]
    assert listed["access"] == {"resource": "oidc_stand_in", "options": CONTROL}

    # Later refreshes carry it without asking the resource again
    stand_in.CALLS.clear()
    status, body = await _token(
        hass, grant_type="refresh_token", refresh_token=body["refresh_token"]
    )
    assert status == 200, body
    assert body["scope"] == scope
    assert _claims(body["access_token"])["scope"] == scope
    assert stand_in.CALLS == []

    # A session for a resource without a description refreshes as before
    status, body = await _token(hass, grant_type="refresh_token", refresh_token="other.token")
    assert status == 200, body
    assert body["scope"] == "openid"
    assert _session(hass, "other").get("access") is None


async def test_the_ceiling_lowers_the_access_of_a_session_from_before(stand_in):
    """Held at the ceiling, the preset's choice is no longer the preset, so the token
    carries the scope of each option."""
    stand_in.CEILINGS[USER] = {
        "groups": {"cameras": {"max": "none", "reason": "Limited for your account."}},
        "reason": "Not available for your account.",
    }
    hass = await _hass_with_session_from_before(stand_in)

    status, body = await _token(hass, grant_type="refresh_token", refresh_token="fam.old")

    assert status == 200, body
    scope = "openid profile stand_in:lights:full stand_in:automations:read stand_in:templates:read"
    assert body["scope"] == scope
    assert _claims(body["access_token"])["scope"] == scope
    assert _session(hass)["access"]["options"] == {**CONTROL, "cameras": "none"}


@pytest.mark.parametrize("why", ["no preset named", "locked", "user gone"])
async def test_a_session_from_before_ends_at_refresh_without_access_to_give_it(
    stand_in, caplog, why
):
    """The client signs in again and the user chooses."""
    if why == "no preset named":
        _without_existing_sessions_preset(stand_in)
    elif why == "locked":
        stand_in.CEILINGS[USER] = {"locked_presets": ["control"], "reason": "Not for you."}
    hass = await _hass_with_session_from_before(stand_in, user=None if why == "user gone" else USER)

    with caplog.at_level(logging.INFO):
        status, body = await _token(hass, grant_type="refresh_token", refresh_token="fam.old")

    assert status == 400
    assert body["error"] == "invalid_grant"
    assert "sign in again" in body["error_description"]
    # The whole session is gone; others are untouched
    assert list(hass.data[DOMAIN]["refresh_tokens"]) == ["other.token"]
    assert "granted before its resource described the access it offers, since" in caplog.text
    assert {
        "no preset named": "integration oidc_stand_in (Stand-in) gives such sessions no access",
        "locked": "the options are those of preset control, which is locked",
        "user gone": "its user no longer exists",
    }[why] in caplog.text
    # The resource is asked only when it names access for such sessions
    assert (("ceiling", "en") in stand_in.CALLS) is (why == "locked")


async def test_a_session_from_before_ends_when_the_resource_no_longer_names_its_access(
    stand_in,
):
    """The access is taken from the description asked for at the refresh."""
    hass = await _hass_with_session_from_before(stand_in)
    _without_existing_sessions_preset(stand_in)

    status, body = await _token(hass, grant_type="refresh_token", refresh_token="fam.old")

    assert (status, body["error"]) == (400, "invalid_grant")
    assert list(hass.data[DOMAIN]["refresh_tokens"]) == ["other.token"]


@pytest.mark.parametrize("breakage", ["raises", "hangs", "malformed"])
async def test_a_session_from_before_is_kept_while_its_resource_cannot_answer(
    stand_in, caplog, monkeypatch, breakage
):
    """It is refreshed without the resource's scopes, and the next refresh asks again."""
    hass = await _hass_with_session_from_before(stand_in)
    monkeypatch.setattr(resources, "CALL_TIMEOUT", 0.01)

    async def fail(hass, user, language):
        if breakage == "hangs":
            await asyncio.Event().wait()
        if breakage == "raises":
            raise RuntimeError("no ceiling today")
        return {"groups": {"garden": {"max": "none", "reason": "No garden."}}, "reason": "No."}

    with monkeypatch.context() as patched:
        patched.setattr(stand_in, "async_get_ceiling", fail)
        with caplog.at_level(logging.WARNING):
            status, body = await _token(hass, grant_type="refresh_token", refresh_token="fam.old")

    assert status == 200, body
    assert body["scope"] == "openid profile"
    assert _claims(body["access_token"])["scope"] == "openid profile"
    assert "access" not in _session(hass)
    assert _session(hass)["scope"] == "openid profile"
    assert (
        "Refreshing a session of client client123 without the scopes of integration "
        "oidc_stand_in (Stand-in) until it gives the session its access for sessions from "
        "before: "
        + {
            "raises": "asking it failed",
            "hangs": "it did not answer within 0.01 seconds",
            "malformed": "the ceiling names unknown group 'garden'",
        }[breakage]
    ) in caplog.text

    status, body = await _token(
        hass, grant_type="refresh_token", refresh_token=body["refresh_token"]
    )

    assert status == 200, body
    assert body["scope"] == "openid profile stand_in:control"
    assert _session(hass)["access"]["options"] == CONTROL


async def test_refreshes_racing_on_a_session_from_before_give_it_its_access_once(
    stand_in, monkeypatch
):
    """A replaced refresh token presented while the resource is asked is answered with
    the same session. The first answer to arrive settles its access, scope and all,
    even when a later answer would have locked it."""
    hass = await _hass_with_session_from_before(stand_in)
    answer = asyncio.Event()
    describe = stand_in.async_describe_resource
    ceilings = iter([None, {"locked_presets": ["control"], "reason": "Not for you."}])

    async def slow(hass, language):
        await answer.wait()
        return await describe(hass, language)

    async def ceiling(hass, user, language):
        return next(ceilings)

    monkeypatch.setattr(stand_in, "async_describe_resource", slow)
    monkeypatch.setattr(stand_in, "async_get_ceiling", ceiling)
    first = asyncio.create_task(_token(hass, grant_type="refresh_token", refresh_token="fam.old"))
    await asyncio.sleep(0)
    # The first has replaced the refresh token and is waiting for the resource
    [current] = [token for token in hass.data[DOMAIN]["refresh_tokens"] if token != "other.token"]
    assert current != "fam.old"
    second = asyncio.create_task(_token(hass, grant_type="refresh_token", refresh_token="fam.old"))
    await asyncio.sleep(0)
    answer.set()
    results = await asyncio.gather(first, second)

    scope = "openid profile stand_in:control"
    for status, body in results:
        assert status == 200, body
        assert body["refresh_token"] == current
        assert body["scope"] == scope
        assert _claims(body["access_token"])["scope"] == scope
    assert set(hass.data[DOMAIN]["refresh_tokens"]) == {current, "other.token"}
    assert _session(hass)["scope"] == scope
    assert _session(hass)["access"]["options"] == CONTROL
    # Both asked, the second while the first was still waiting
    assert next(ceilings, None) is None

    # The replaced token past its grace period still ends the session
    monkeypatch.setattr("custom_components.oidc_provider.http.REFRESH_TOKEN_REUSE_GRACE", -1)
    status, body = await _token(hass, grant_type="refresh_token", refresh_token="fam.old")
    assert (status, body["error"]) == (400, "invalid_grant")
    assert list(hass.data[DOMAIN]["refresh_tokens"]) == ["other.token"]


async def test_a_session_ended_while_its_resource_is_asked_gets_nothing(stand_in, monkeypatch):
    hass = await _hass_with_session_from_before(stand_in)

    async def ceiling_then_sign_out(hass_, user, language):
        hass.data[DOMAIN]["refresh_tokens"].clear()

    monkeypatch.setattr(stand_in, "async_get_ceiling", ceiling_then_sign_out)

    status, body = await _token(hass, grant_type="refresh_token", refresh_token="fam.old")

    assert (status, body["error"]) == (400, "invalid_grant")
    assert hass.data[DOMAIN]["refresh_tokens"] == {}


async def test_a_described_resource_named_only_at_the_token_endpoint_is_refused(stand_in):
    """The user was not asked what the client may do there."""
    hass = await _token_hass(stand_in)
    _code_for(hass, access=None, resource=None)

    status, body = await _token(
        hass,
        grant_type="authorization_code",
        code="the-code",
        redirect_uri="https://app.example.com/cb",
        resource=RESOURCE,
    )

    assert status == 400
    assert body["error"] == "invalid_target"
    assert hass.data[DOMAIN]["refresh_tokens"] == {}

    # Another resource named there still binds the token, as before
    _code_for(hass, access=None, resource=None)
    status, body = await _token(
        hass,
        grant_type="authorization_code",
        code="the-code",
        redirect_uri="https://app.example.com/cb",
        resource="https://ha.example.com/api/other",
    )
    assert status == 200
    assert _claims(body["access_token"])["aud"] == "https://ha.example.com/api/other"
    assert body["scope"] == "openid profile"


@pytest.mark.parametrize(
    "view",
    [
        "OIDCDiscoveryView",
        "OAuth2AuthorizationServerMetadataView",
        "OAuth2AuthorizationServerMetadataAlternateView",
    ],
)
async def test_discovery_advertises_the_scopes_resources_describe(stand_in, view):
    from custom_components.oidc_provider import http as provider_http

    hass = await _hass(stand_in)
    request = MagicMock()
    request.app = {"hass": hass}
    request.headers = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "ha.example.com"}

    response = await getattr(provider_http, view)().get(request)

    scopes = json.loads(response.body)["scopes_supported"]
    assert scopes[:4] == ["openid", "profile", "email", "groups"]
    assert "stand_in:read" in scopes
    assert "stand_in:files:full" in scopes


# --- What Connected applications shows ----------------------------------------


async def _sessions(hass, language="en"):
    from custom_components.oidc_provider.http import OIDCSessionsView

    request = MagicMock()
    request.app = {"hass": hass}
    request.query = {"language": language}
    request.__getitem__.return_value = Mock(id=USER)
    response = await OIDCSessionsView().get(request)
    return json.loads(response.body)


def _session_token(family, **overrides):
    return {
        "client_id": CLIENT,
        "user_id": USER,
        "scope": "openid",
        "family": family,
        "issued_at": 10,
        "expires_at": time.time() + 3600,
        **overrides,
    }


async def test_connected_applications_show_the_access_chosen(stand_in):
    hass = await _token_hass(stand_in)
    hass.data[DOMAIN]["refresh_tokens"] = {
        "a.1": _session_token("a", access=ACCESS),
        "b.1": _session_token("b", access={**ACCESS, "resource": "gone"}),
        "c.1": _session_token("c"),
    }

    data = await _sessions(hass, language="sv")

    by_family = {
        session["access"] and session["access"]["resource"]: session for session in data["sessions"]
    }
    assert by_family["oidc_stand_in"]["access"] == {"resource": "oidc_stand_in", "options": CUSTOM}
    # A session whose resource is no longer described is listed without its access
    assert set(by_family) == {"oidc_stand_in", None}
    assert len(data["sessions"]) == 3
    model = data["resources"]["oidc_stand_in"]
    assert model["name"] == "Ersättaren"
    assert [preset["id"] for preset in model["presets"]] == [
        "read",
        "control",
        "configure",
        "admin",
    ]
    assert "scopes" not in json.dumps(data["resources"])
    assert ("describe", "sv") in stand_in.CALLS


async def test_connected_applications_when_the_resource_cannot_describe_itself(stand_in, caplog):
    hass = await _token_hass(stand_in)
    hass.data[DOMAIN]["refresh_tokens"] = {"a.1": _session_token("a", access=ACCESS)}
    stand_in.DESCRIPTION = None

    with caplog.at_level(logging.WARNING):
        data = await _sessions(hass)

    assert data["sessions"][0]["access"] is None
    assert data["resources"] == {}
    assert (
        "Not showing the access granted at the resource of integration oidc_stand_in (Stand-in)"
        in caplog.text
    )


async def test_connected_applications_when_the_resource_does_not_answer_in_time(
    stand_in, caplog, monkeypatch
):
    hass = await _token_hass(stand_in)
    hass.data[DOMAIN]["refresh_tokens"] = {"a.1": _session_token("a", access=ACCESS)}
    monkeypatch.setattr(resources, "CALL_TIMEOUT", 0.01)

    async def hang(hass, language):
        await asyncio.Event().wait()

    monkeypatch.setattr(stand_in, "async_describe_resource", hang)

    with caplog.at_level(logging.WARNING):
        data = await _sessions(hass)

    assert data["sessions"][0]["access"] is None
    assert (
        "Not showing the access granted at the resource of integration oidc_stand_in "
        "(Stand-in): it did not answer within 0.01 seconds"
    ) in caplog.text


# --- Changing a session's access ----------------------------------------------

OTHER_USER = "user456"
ADMIN = {**CONTROL, "automations": "full", "files": "full"}
CUSTOM_SCOPES = [
    "stand_in:lights:read",
    "stand_in:automations:read",
    "stand_in:templates:read",
    "stand_in:files:read",
]
CUSTOM_SCOPE = "openid profile " + " ".join(CUSTOM_SCOPES)


async def _change_hass(stand_in):
    """Return hass state with sessions of the user and of another user.

    The user's session "fam" chose CUSTOM at the stand-in. Its retired token
    is still within the grace period. "before" began before the stand-in
    described itself, and "other" is for a resource without a description.
    The other user's session "theirs" chose CUSTOM too.
    """
    hass = await _token_hass(stand_in)
    hass.auth.async_get_user = AsyncMock(
        side_effect=lambda user_id: SimpleNamespace(id=user_id, name="Someone")
    )
    custom = {"resource": "oidc_stand_in", "options": CUSTOM, "scopes": CUSTOM_SCOPES}
    hass.data[DOMAIN]["refresh_tokens"] = {
        "fam.cur": _session_token(
            "fam",
            scope=CUSTOM_SCOPE,
            resource=RESOURCE,
            access=custom,
            retired={"fam.old": time.time()},
            auth_time=5,
        ),
        "before.1": _session_token("before", scope="openid email", resource=RESOURCE),
        "other.1": _session_token("other", resource=None),
        "theirs.1": _session_token(
            "theirs", user_id=OTHER_USER, scope=CUSTOM_SCOPE, resource=RESOURCE, access=custom
        ),
    }
    return hass


def _sid(family):
    from custom_components.oidc_provider.http import _session_id

    return _session_id(family)


async def _change(hass, family, method="get", body=None, *, user=USER, language="en"):
    """Ask the session access view about a session, as the given user."""
    from custom_components.oidc_provider.http import OIDCSessionAccessView

    request = MagicMock()
    request.app = {"hass": hass}
    request.query = {"language": language}
    request.__getitem__.return_value = Mock(id=user)
    if isinstance(body, Exception):
        request.json = AsyncMock(side_effect=body)
    else:
        request.json = AsyncMock(return_value=body)
    response = await getattr(OIDCSessionAccessView(), method)(request, _sid(family))
    return response.status, json.loads(response.body)


def _stored(hass, family):
    return copy.deepcopy(_session(hass, family))


async def test_changing_access_opens_on_the_sessions_own_choice(stand_in):
    hass = await _change_hass(stand_in)
    stand_in.UNAVAILABLE["files"] = "Turned off in the stand-in's options."
    ceiling = {
        "groups": {"files": {"max": "read", "reason": "Limited for your account."}},
        "reason": "Not available for your account.",
    }
    stand_in.CEILINGS[USER] = ceiling
    await async_remember_choice(hass, USER, CLIENT, "oidc_stand_in", LOOK_ONLY)

    status, data = await _change(hass, "fam", language="sv")

    assert status == 200, data
    assert data["client_name"] == "client123"
    assert data["client_host"] is None
    access = data["access"]
    assert access["resource"] == "oidc_stand_in"
    assert access["name"] == "Ersättaren"
    assert access["current"] == CUSTOM
    # The session's own choice, not the user's last choice for the client
    assert access["remembered"] is None
    # It is what the session has, and the ceiling still allows it
    assert (access["granted"], access["adjusted"]) == (CUSTOM, None)
    # Availability and the ceiling as they are now
    assert access["unavailable"] == {"files": "Turned off in the stand-in's options."}
    assert access["ceiling"] == {**ceiling, "locked_presets": []}
    assert "scopes" not in json.dumps(access)
    assert {("describe", "sv"), ("availability", "sv"), ("ceiling", "sv")} <= set(stand_in.CALLS)


async def test_a_session_without_a_choice_opens_on_the_access_it_would_get(stand_in):
    """That is the access its next refresh would give it, held at the ceiling."""
    hass = await _change_hass(stand_in)
    stand_in.CEILINGS[USER] = {
        "groups": {"cameras": {"max": "none", "reason": "Limited for your account."}},
        "reason": "Not available for your account.",
    }

    status, data = await _change(hass, "before")

    assert status == 200, data
    assert data["access"]["current"] == {**CONTROL, "cameras": "none"}
    assert data["access"]["remembered"] is None
    # It has no choice, so nothing is marked as what it has
    assert (data["access"]["granted"], data["access"]["adjusted"]) == (None, None)


async def test_without_access_for_sessions_from_before_the_choice_opens_as_on_consent(stand_in):
    """The session would end at its next refresh, so the choice opens where the
    consent screen would: on the user's last choice for the client, or the default."""
    _without_existing_sessions_preset(stand_in)
    hass = await _change_hass(stand_in)

    _, data = await _change(hass, "before")
    assert (data["access"]["current"], data["access"]["remembered"]) == (None, None)
    assert (data["access"]["granted"], data["access"]["adjusted"]) == (None, None)

    await async_remember_choice(hass, USER, CLIENT, "oidc_stand_in", CUSTOM)
    _, data = await _change(hass, "before")
    assert (data["access"]["current"], data["access"]["remembered"]) == (None, CUSTOM)


async def test_a_choice_the_ceiling_now_lowers_says_why(stand_in):
    """The choice still opens from the session's own options, as the panel on main
    reads them, with what the session has and why the user may no longer allow it."""
    hass = await _change_hass(stand_in)
    stand_in.CEILINGS[USER] = {
        "groups": {
            "cameras": {"max": "none", "reason": "Cameras are off for your account."},
            "files": {"max": "none", "reason": "Files are off for your account."},
        },
        "reason": "Not available for your account.",
    }

    status, data = await _change(hass, "fam")

    assert status == 200, data
    access = data["access"]
    assert access["current"] == access["granted"] == CUSTOM
    # Cameras are at None already, so only the files are lowered
    assert access["adjusted"] == ["Files are off for your account."]


async def test_a_choice_that_is_now_a_locked_level_says_why(stand_in):
    """Exactly a level the ceiling locks, as it is or once held at the ceiling."""
    hass = await _change_hass(stand_in)
    _session(hass, "fam")["access"] = {**_session(hass, "fam")["access"], "options": CONTROL}
    stand_in.CEILINGS[USER] = {
        "locked_presets": ["control"],
        "reason": "The stand-in is in read-only mode.",
    }

    _, data = await _change(hass, "fam")

    assert data["access"]["granted"] == CONTROL
    assert data["access"]["adjusted"] == ["The stand-in is in read-only mode."]

    stand_in.CEILINGS[USER] = {
        "groups": {"lights": {"max": "read", "reason": "Lights are read only."}},
        "locked_presets": ["read"],
        "reason": "The stand-in is in read-only mode.",
    }

    _, data = await _change(hass, "fam")

    assert data["access"]["granted"] == CONTROL
    assert data["access"]["adjusted"] == [
        "Lights are read only.",
        "The stand-in is in read-only mode.",
    ]


async def test_a_choice_at_another_resource_counts_as_none(stand_in):
    """A session's access names the integration it was chosen at, which may no longer
    be the one describing its resource."""
    hass = await _change_hass(stand_in)
    _session(hass, "fam")["access"] = {**_session(hass, "fam")["access"], "resource": "gone"}

    _, data = await _change(hass, "fam")

    assert data["access"]["current"] == CONTROL


async def test_saving_replaces_the_access_and_exactly_its_scopes(stand_in, caplog):
    hass = await _change_hass(stand_in)
    stand_in.CALLS.clear()

    with caplog.at_level(logging.INFO):
        status, data = await _change(hass, "fam", "put", {"options": CONTROL})

    assert status == 200, data
    assert data == {"access": {"resource": "oidc_stand_in", "options": CONTROL}}
    session = _session(hass, "fam")
    assert session["access"] == {
        "resource": "oidc_stand_in",
        "options": CONTROL,
        "scopes": ["stand_in:control"],
    }
    # The OpenID Connect scopes stay; every scope of the old choice is gone
    assert session["scope"] == "openid profile stand_in:control"
    # The session is otherwise as it was, its rotation state included
    assert set(session["retired"]) == {"fam.old"}
    assert session["family"] == "fam"
    assert "fam.cur" in hass.data[DOMAIN]["refresh_tokens"]
    hass.data[DOMAIN]["token_store"].async_save.assert_awaited()
    # It is the user's choice for the client next time
    assert await async_remembered_choice(hass, USER, CLIENT, "oidc_stand_in") == CONTROL
    # Checked as an approval is, in Home Assistant's language
    assert {("describe", "en"), ("ceiling", "en")} <= set(stand_in.CALLS)
    assert "changed the access of a session of client client123" in caplog.text
    # Other sessions are untouched
    assert _session(hass, "theirs")["scope"] == CUSTOM_SCOPE
    assert "access" not in _session(hass, "before")

    # A choice that grants nothing leaves only the OpenID Connect scopes
    nothing = dict.fromkeys(CONTROL, "none")
    status, _ = await _change(hass, "fam", "put", {"options": nothing})
    assert status == 200
    assert _session(hass, "fam")["scope"] == "openid profile"
    assert _session(hass, "fam")["access"]["scopes"] == []

    # Areas one by one grant the scope of each area, and nothing else
    status, _ = await _change(hass, "fam", "put", {"options": {**nothing, "files": "full"}})
    assert status == 200
    assert _session(hass, "fam")["scope"] == "openid profile stand_in:files:full"


async def test_only_the_sessions_own_user_finds_it(stand_in):
    hass = await _change_hass(stand_in)
    before = _stored(hass, "theirs")

    assert await _change(hass, "theirs") == (404, {"error": "not_found", "message": ANY})
    status, data = await _change(hass, "theirs", "put", {"options": CONTROL})
    assert (status, data["error"]) == (404, "not_found")
    status, data = await _change(hass, "nobody", "put", {"options": CONTROL})
    assert (status, data["error"]) == (404, "not_found")

    assert _session(hass, "theirs") == before
    assert hass.data[DOMAIN]["access_choices"] == {}
    # The resource is not even asked
    assert not any(call[0] == "ceiling" for call in stand_in.CALLS)

    # Its own user finds it
    status, _ = await _change(hass, "theirs", "put", {"options": CONTROL}, user=OTHER_USER)
    assert status == 200
    assert _session(hass, "theirs")["scope"] == "openid profile stand_in:control"


@pytest.mark.parametrize(
    ("options", "ceiling", "message"),
    [
        ({**CONTROL, "garden": "full"}, None, "expected one option for every group"),
        ({**CONTROL, "lights": "everything"}, None, "unknown option for group lights"),
        (
            ADMIN,
            {"groups": {"files": {"max": "read", "reason": "Limited."}}, "reason": "No."},
            "the option for group files is above the ceiling",
        ),
        (
            ADMIN,
            {"locked_presets": ["admin"], "reason": "Not for you."},
            "the options are those of preset admin, which is locked",
        ),
    ],
)
async def test_a_choice_that_does_not_fit_is_refused(stand_in, options, ceiling, message):
    hass = await _change_hass(stand_in)
    if ceiling:
        stand_in.CEILINGS[USER] = ceiling
    before = _stored(hass, "fam")

    status, data = await _change(hass, "fam", "put", {"options": options})

    assert status == 400
    assert data == {"error": "invalid_choice", "message": f"Invalid access choice: {message}"}
    assert _session(hass, "fam") == before
    hass.data[DOMAIN]["token_store"].async_save.assert_not_awaited()
    assert hass.data[DOMAIN]["access_choices"] == {}


@pytest.mark.parametrize("body", [None, ["options"], ValueError("not JSON")])
async def test_a_malformed_change_is_refused(stand_in, body):
    hass = await _change_hass(stand_in)
    before = _stored(hass, "fam")

    status, data = await _change(hass, "fam", "put", body)

    assert (status, data["error"]) == (400, "invalid_request")
    assert _session(hass, "fam") == before


async def test_a_session_whose_resource_offers_no_choice_cannot_be_changed(stand_in):
    hass = await _change_hass(stand_in)
    before = _stored(hass, "other")

    assert (await _change(hass, "other"))[1]["error"] == "not_offered"
    status, data = await _change(hass, "other", "put", {"options": CONTROL})

    assert (status, data["error"]) == (409, "not_offered")
    assert _session(hass, "other") == before


@pytest.mark.parametrize("breakage", ["raises", "hangs", "malformed"])
async def test_a_resource_that_cannot_answer_changes_nothing(
    stand_in, caplog, monkeypatch, breakage
):
    hass = await _change_hass(stand_in)
    monkeypatch.setattr(resources, "CALL_TIMEOUT", 0.01)

    async def fail(hass, user, language):
        if breakage == "hangs":
            await asyncio.Event().wait()
        if breakage == "raises":
            raise RuntimeError("no ceiling today")
        return {"groups": {"garden": {"max": "none", "reason": "No garden."}}, "reason": "No."}

    monkeypatch.setattr(stand_in, "async_get_ceiling", fail)
    before = _stored(hass, "fam")

    with caplog.at_level(logging.WARNING):
        get_status, _ = await _change(hass, "fam")
        status, data = await _change(hass, "fam", "put", {"options": CONTROL})

    assert get_status == 503
    assert (status, data["error"]) == (503, "unavailable")
    assert _session(hass, "fam") == before
    assert hass.data[DOMAIN]["access_choices"] == {}
    reason = {
        "raises": "asking it failed",
        "hangs": "it did not answer within 0.01 seconds",
        "malformed": "the ceiling names unknown group 'garden'",
    }[breakage]
    for what in ("Not offering to change", "Not changing"):
        assert (
            f"{what} the access of a session of client client123 at integration "
            f"oidc_stand_in (Stand-in): {reason}"
        ) in caplog.text


async def test_saving_gives_a_session_without_a_choice_its_access(stand_in):
    """Its next refresh carries that access, and the resource is not asked again."""
    hass = await _change_hass(stand_in)

    status, _ = await _change(hass, "before", "put", {"options": LOOK_ONLY})

    assert status == 200
    assert _session(hass, "before")["scope"] == "openid email stand_in:read"
    assert await async_remembered_choice(hass, USER, CLIENT, "oidc_stand_in") == LOOK_ONLY
    stand_in.CALLS.clear()

    status, body = await _token(hass, grant_type="refresh_token", refresh_token="before.1")

    assert status == 200, body
    assert body["scope"] == "openid email stand_in:read"
    assert _claims(body["access_token"])["scope"] == "openid email stand_in:read"
    assert stand_in.CALLS == []


async def test_the_next_refresh_carries_the_new_scopes_and_rotates_as_before(stand_in, monkeypatch):
    hass = await _change_hass(stand_in)
    await _change(hass, "fam", "put", {"options": LOOK_ONLY})
    scope = "openid profile stand_in:read"

    status, body = await _token(hass, grant_type="refresh_token", refresh_token="fam.cur")

    assert status == 200, body
    assert body["scope"] == scope
    assert _claims(body["access_token"])["scope"] == scope
    assert _claims(body["access_token"])["aud"] == RESOURCE
    # Rotated, with the replaced token answered within its grace period
    assert body["refresh_token"] != "fam.cur"
    status, again = await _token(hass, grant_type="refresh_token", refresh_token="fam.cur")
    assert (status, again["refresh_token"], again["scope"]) == (200, body["refresh_token"], scope)

    # and the session revoked when one is presented after it
    monkeypatch.setattr("custom_components.oidc_provider.http.REFRESH_TOKEN_REUSE_GRACE", -1)
    status, body = await _token(hass, grant_type="refresh_token", refresh_token="fam.old")
    assert (status, body["error"]) == (400, "invalid_grant")
    assert not [
        data for data in hass.data[DOMAIN]["refresh_tokens"].values() if data["family"] == "fam"
    ]


async def test_a_refresh_issuing_tokens_while_access_changes_issues_the_new_scopes(
    stand_in, monkeypatch
):
    """Tokens issued from the old scope after the change was saved are not handed out."""
    from custom_components.oidc_provider.http import OIDCTokenView

    hass = await _change_hass(stand_in)
    issuing, release = asyncio.Event(), asyncio.Event()
    generate = OIDCTokenView._generate_access_token
    scopes_issued = []

    async def slow(self, request, hass_, user_id, scope, client_id, audience=None):
        scopes_issued.append(scope)
        if len(scopes_issued) == 1:
            issuing.set()
            await release.wait()
        return await generate(self, request, hass_, user_id, scope, client_id, audience)

    monkeypatch.setattr(OIDCTokenView, "_generate_access_token", slow)
    refresh = asyncio.create_task(_token(hass, grant_type="refresh_token", refresh_token="fam.cur"))
    await issuing.wait()

    status, _ = await _change(hass, "fam", "put", {"options": CONTROL})
    assert status == 200
    release.set()
    status, body = await refresh

    scope = "openid profile stand_in:control"
    assert status == 200, body
    assert scopes_issued == [CUSTOM_SCOPE, scope]
    assert body["scope"] == scope
    assert _claims(body["access_token"])["scope"] == scope
    assert _session(hass, "fam")["scope"] == scope


async def test_a_change_lands_on_the_token_a_refresh_rotated_while_the_resource_was_asked(
    stand_in, monkeypatch
):
    hass = await _change_hass(stand_in)
    asked, answer = asyncio.Event(), asyncio.Event()
    ceiling = stand_in.async_get_ceiling

    async def slow(hass_, user, language):
        asked.set()
        await answer.wait()
        return await ceiling(hass_, user, language)

    monkeypatch.setattr(stand_in, "async_get_ceiling", slow)
    change = asyncio.create_task(_change(hass, "fam", "put", {"options": CONTROL}))
    await asked.wait()

    status, refreshed = await _token(hass, grant_type="refresh_token", refresh_token="fam.cur")
    assert status == 200, refreshed
    assert refreshed["scope"] == CUSTOM_SCOPE
    answer.set()
    status, _ = await change

    scope = "openid profile stand_in:control"
    assert status == 200
    # The old token did not come back; the current one has the new access
    assert set(hass.data[DOMAIN]["refresh_tokens"]) == {
        refreshed["refresh_token"],
        "before.1",
        "other.1",
        "theirs.1",
    }
    assert _session(hass, "fam")["scope"] == scope
    assert _session(hass, "fam")["access"]["options"] == CONTROL
    # The replaced token, presented again within its grace period, gets the new scope too
    status, again = await _token(hass, grant_type="refresh_token", refresh_token="fam.cur")
    assert (status, again["scope"]) == (200, scope)
    status, again = await _token(
        hass, grant_type="refresh_token", refresh_token=refreshed["refresh_token"]
    )
    assert (status, again["scope"]) == (200, scope)


async def test_a_change_while_a_session_from_before_is_settled_keeps_the_users_choice(
    stand_in, monkeypatch
):
    """The refresh finds the session with the access the user chose and gives it no
    other, whatever the resource answered it."""
    hass = await _change_hass(stand_in)
    asked, answer = asyncio.Event(), asyncio.Event()
    ceiling = stand_in.async_get_ceiling
    calls = 0

    async def first_slow(hass_, user, language):
        nonlocal calls
        calls += 1
        if calls == 1:
            asked.set()
            await answer.wait()
        return await ceiling(hass_, user, language)

    monkeypatch.setattr(stand_in, "async_get_ceiling", first_slow)
    refresh = asyncio.create_task(
        _token(hass, grant_type="refresh_token", refresh_token="before.1")
    )
    await asked.wait()

    status, _ = await _change(hass, "before", "put", {"options": LOOK_ONLY})
    assert status == 200
    answer.set()
    status, body = await refresh

    assert status == 200, body
    assert body["scope"] == "openid email stand_in:read"
    assert _session(hass, "before")["access"]["options"] == LOOK_ONLY
    assert _session(hass, "before")["scope"] == "openid email stand_in:read"


async def test_a_session_ended_while_its_resource_is_asked_is_not_changed(stand_in, monkeypatch):
    hass = await _change_hass(stand_in)
    ceiling = stand_in.async_get_ceiling

    async def ceiling_then_sign_out(hass_, user, language):
        del hass.data[DOMAIN]["refresh_tokens"]["fam.cur"]
        return await ceiling(hass_, user, language)

    monkeypatch.setattr(stand_in, "async_get_ceiling", ceiling_then_sign_out)

    status, data = await _change(hass, "fam", "put", {"options": CONTROL})

    assert (status, data["error"]) == (404, "not_found")
    assert hass.data[DOMAIN]["access_choices"] == {}
    assert "fam.cur" not in hass.data[DOMAIN]["refresh_tokens"]


async def test_connected_applications_say_where_access_can_be_changed(stand_in, monkeypatch):
    """Every session whose resource describes its access, also one without a choice yet."""
    hass = await _change_hass(stand_in)

    data = await _sessions(hass)

    offered = {session["session_id"]: session["access_offered_by"] for session in data["sessions"]}
    assert offered == {
        _sid("fam"): "oidc_stand_in",
        _sid("before"): "oidc_stand_in",
        _sid("other"): None,
    }
    assert set(data["resources"]) == {"oidc_stand_in"}

    # Not while the resource cannot describe itself
    stand_in.DESCRIPTION = None
    data = await _sessions(hass)
    assert [session["access_offered_by"] for session in data["sessions"]] == [None] * 3
