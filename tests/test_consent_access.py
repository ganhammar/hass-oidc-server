"""Tests for choosing access on the consent screen, for a resource that describes it."""

import asyncio
import copy
import json
import logging
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, Mock, patch

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
