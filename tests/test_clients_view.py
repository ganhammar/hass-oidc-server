"""Tests for the client management view behind the Clients tab of the login panel."""

import json
import time
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest

from custom_components.oidc_provider.client_manager import update_client
from custom_components.oidc_provider.const import DOMAIN, REGISTRATION_DYNAMIC
from custom_components.oidc_provider.http import OIDCClientsView, managed_clients, remove_client
from custom_components.oidc_provider.security import verify_client_secret

CIMD_CLIENT_ID = "https://claude.ai/oauth/claude-code-client-metadata"


def _refresh_token(client_id: str, family: str, **extra) -> dict:
    return {
        "client_id": client_id,
        "user_id": "user123",
        "family": family,
        "expires_at": time.time() + 3600,
        **extra,
    }


def _hass(clients=None, refresh_tokens=None):
    """Return hass state holding the given clients and refresh tokens."""
    hass = Mock()
    hass.data = {
        DOMAIN: {
            "clients": clients if clients is not None else {},
            "refresh_tokens": refresh_tokens or {},
            "store": Mock(async_save=AsyncMock()),
            "token_store": Mock(async_save=AsyncMock()),
        }
    }
    return hass


def _request(hass, body=None, client_id=None, is_admin=True):
    request = MagicMock()
    request.app = {"hass": hass}
    request.__getitem__.return_value = Mock(id="admin1", is_admin=is_admin)
    request.query = {} if client_id is None else {"client_id": client_id}
    if isinstance(body, Exception):
        request.json = AsyncMock(side_effect=body)
    else:
        request.json = AsyncMock(return_value=body)
    return request


def _json(response):
    return json.loads(response.body)


def _stored_client(**overrides) -> dict:
    return {
        "client_name": "Grafana",
        "client_secret_hash": "hash-of-the-secret",
        "redirect_uris": ["https://grafana.example.com/login"],
        "consent_required": False,
        "created_at": 1700000000.0,
        **overrides,
    }


@pytest.mark.parametrize("method", ["get", "post", "patch", "delete"])
async def test_client_management_is_for_administrators(method):
    hass = _hass({"abc": _stored_client()})
    request = _request(
        hass,
        {"client_name": "X", "redirect_uris": ["https://x.example.com/cb"]},
        client_id="abc",
        is_admin=False,
    )

    response = await getattr(OIDCClientsView(), method)(request)

    assert response.status == 403
    assert _json(response)["error"] == "forbidden"
    assert list(hass.data[DOMAIN]["clients"]) == ["abc"]
    hass.data[DOMAIN]["store"].async_save.assert_not_called()


async def test_list_names_how_each_client_identifies_itself():
    hass = _hass(
        {
            "zzz": _stored_client(client_name="zebra", registration=REGISTRATION_DYNAMIC),
            "abc": _stored_client(),
            # Stored by a release that had no consent setting
            "old": {"client_name": "Legacy", "redirect_uris": []},
        },
        {
            "fam1.a": _refresh_token("abc", "fam1"),
            "fam2.a": _refresh_token("abc", "fam2"),
            "fam3.a": _refresh_token(CIMD_CLIENT_ID, "fam3", client_name="Claude Code"),
        },
    )

    response = await OIDCClientsView().get(_request(hass))

    assert response.status == 200
    assert response.headers["Cache-Control"] == "no-store"
    clients = _json(response)["clients"]
    # Stored clients by name, then the ones known only through their sessions
    assert [c["client_name"] for c in clients] == ["Grafana", "Legacy", "zebra", "Claude Code"]
    assert clients[0] == {
        "client_id": "abc",
        "client_name": "Grafana",
        "client_host": None,
        "registration": "registered",
        "redirect_uris": ["https://grafana.example.com/login"],
        "consent_required": False,
        "created_at": 1700000000.0,
        "active_sessions": 2,
    }
    assert clients[1]["consent_required"] is True
    assert clients[1]["active_sessions"] == 0
    assert clients[2]["registration"] == "dynamic"
    assert clients[3] == {
        "client_id": CIMD_CLIENT_ID,
        "client_name": "Claude Code",
        "client_host": "claude.ai",
        "registration": "metadata_document",
        "active_sessions": 1,
    }
    # Nothing that could authenticate as the client leaves the server
    assert "secret" not in response.body.decode()


async def test_register_returns_the_secret_once():
    hass = _hass()
    request = _request(
        hass,
        {
            "client_name": " Grafana ",
            "redirect_uris": [" https://grafana.example.com/login ", ""],
            "consent_required": True,
        },
    )

    response = await OIDCClientsView().post(request)

    assert response.status == 201
    # The secret must not linger in a browser cache
    assert response.headers["Cache-Control"] == "no-store"
    registered = _json(response)
    [(client_id, stored)] = hass.data[DOMAIN]["clients"].items()
    assert registered == {
        "client_id": client_id,
        "client_secret": registered["client_secret"],
        "client_name": "Grafana",
        "redirect_uris": ["https://grafana.example.com/login"],
        "consent_required": True,
    }
    assert verify_client_secret(registered["client_secret"], stored["client_secret_hash"])
    assert "registration" not in stored
    assert stored["consent_required"] is True
    hass.data[DOMAIN]["store"].async_save.assert_awaited_once()
    assert managed_clients(hass)[0]["registration"] == "registered"


async def test_register_tolerates_a_stored_client_without_a_name():
    hass = _hass({"old": {"redirect_uris": []}})
    request = _request(hass, {"client_name": "App", "redirect_uris": ["https://a.example.com/cb"]})

    response = await OIDCClientsView().post(request)

    assert response.status == 201


async def test_register_skips_consent_unless_asked():
    hass = _hass()
    request = _request(hass, {"client_name": "App", "redirect_uris": ["https://a.example.com/cb"]})

    response = await OIDCClientsView().post(request)

    assert _json(response)["consent_required"] is False


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (ValueError("bad json"), "must be JSON"),
        (["not", "an", "object"], "JSON object"),
        ({"redirect_uris": ["https://a.example.com/cb"]}, "client_name"),
        ({"client_name": "A‮B", "redirect_uris": ["https://a.example.com/cb"]}, "control"),
        ({"client_name": "App"}, "list of strings"),
        ({"client_name": "App", "redirect_uris": "https://a.example.com/cb"}, "list of strings"),
        ({"client_name": "App", "redirect_uris": [1]}, "list of strings"),
        ({"client_name": "App", "redirect_uris": [" "]}, "At least one"),
        ({"client_name": "App", "redirect_uris": ["http://a.example.com/cb"]}, "HTTPS"),
        (
            {
                "client_name": "App",
                "redirect_uris": ["https://a.example.com/cb"],
                "consent_required": "yes",
            },
            "true or false",
        ),
    ],
)
async def test_register_refuses_invalid_input(body, message):
    hass = _hass()

    response = await OIDCClientsView().post(_request(hass, body))

    assert response.status == 400
    assert _json(response)["error"] == "invalid_request"
    assert message in _json(response)["message"]
    assert hass.data[DOMAIN]["clients"] == {}


async def test_register_refuses_a_name_already_in_use():
    hass = _hass({"abc": _stored_client()})
    request = _request(
        hass, {"client_name": "Grafana", "redirect_uris": ["https://other.example.com/cb"]}
    )

    response = await OIDCClientsView().post(request)

    assert response.status == 409
    assert _json(response)["error"] == "name_in_use"
    assert list(hass.data[DOMAIN]["clients"]) == ["abc"]


async def test_update_changes_redirect_uris_and_consent():
    hass = _hass({"abc": _stored_client()}, {"fam1.a": _refresh_token("abc", "fam1")})
    request = _request(
        hass,
        {"redirect_uris": ["https://new.example.com/cb"], "consent_required": True},
        client_id="abc",
    )

    response = await OIDCClientsView().patch(request)

    assert response.status == 200
    updated = _json(response)
    assert updated["redirect_uris"] == ["https://new.example.com/cb"]
    assert updated["consent_required"] is True
    assert "secret" not in response.body.decode()
    # Editing a client leaves its sessions alone
    assert updated["active_sessions"] == 1
    stored = hass.data[DOMAIN]["clients"]["abc"]
    assert stored["redirect_uris"] == ["https://new.example.com/cb"]
    assert stored["client_name"] == "Grafana"
    hass.data[DOMAIN]["store"].async_save.assert_awaited_once()


async def test_update_keeps_the_consent_setting_when_it_is_left_out():
    hass = _hass({"abc": _stored_client(consent_required=True)})
    request = _request(hass, {"redirect_uris": ["https://new.example.com/cb"]}, client_id="abc")

    response = await OIDCClientsView().patch(request)

    assert _json(response)["consent_required"] is True


@pytest.mark.parametrize(
    ("client_id", "body", "status", "error"),
    [
        ("missing", {"redirect_uris": ["https://new.example.com/cb"]}, 404, "not_found"),
        (None, {"redirect_uris": ["https://new.example.com/cb"]}, 404, "not_found"),
        # A metadata document client is not stored, so it has nothing to edit
        (CIMD_CLIENT_ID, {"redirect_uris": ["https://new.example.com/cb"]}, 404, "not_found"),
        ("abc", {"redirect_uris": ["ftp://new.example.com/cb"]}, 400, "invalid_request"),
        ("abc", {"redirect_uris": []}, 400, "invalid_request"),
        ("abc", ValueError("bad json"), 400, "invalid_request"),
        (
            "abc",
            {"redirect_uris": ["https://new.example.com/cb"], "consent_required": 1},
            400,
            "invalid_request",
        ),
    ],
)
async def test_update_refuses_unknown_clients_and_invalid_input(client_id, body, status, error):
    hass = _hass(
        {"abc": _stored_client()},
        {"fam1.a": _refresh_token(CIMD_CLIENT_ID, "fam1", client_name="Claude Code")},
    )

    response = await OIDCClientsView().patch(_request(hass, body, client_id=client_id))

    assert (response.status, _json(response)["error"]) == (status, error)
    assert hass.data[DOMAIN]["clients"] == {"abc": _stored_client()}
    hass.data[DOMAIN]["store"].async_save.assert_not_called()


async def test_revoke_removes_the_client_and_ends_its_sessions():
    hass = _hass(
        {"abc": _stored_client(), "other": _stored_client(client_name="Other")},
        {
            "fam1.a": _refresh_token("abc", "fam1"),
            "fam2.a": _refresh_token("abc", "fam2"),
            "fam3.a": _refresh_token("other", "fam3"),
        },
    )

    response = await OIDCClientsView().delete(_request(hass, client_id="abc"))

    assert response.status == 200
    assert _json(response) == {"removed": True, "ended_sessions": 2}
    assert list(hass.data[DOMAIN]["clients"]) == ["other"]
    assert list(hass.data[DOMAIN]["refresh_tokens"]) == ["fam3.a"]
    hass.data[DOMAIN]["store"].async_save.assert_awaited_once()
    hass.data[DOMAIN]["token_store"].async_save.assert_awaited_once()


async def test_revoke_ends_the_sessions_of_a_metadata_document_client():
    hass = _hass(
        {"abc": _stored_client()},
        {"fam1.a": _refresh_token(CIMD_CLIENT_ID, "fam1", client_name="Claude Code")},
    )

    response = await OIDCClientsView().delete(_request(hass, client_id=CIMD_CLIENT_ID))

    assert _json(response) == {"removed": False, "ended_sessions": 1}
    assert hass.data[DOMAIN]["refresh_tokens"] == {}
    assert list(hass.data[DOMAIN]["clients"]) == ["abc"]
    hass.data[DOMAIN]["store"].async_save.assert_not_called()


@pytest.mark.parametrize("client_id", ["missing", None])
async def test_revoke_of_an_unknown_client_is_not_found(client_id):
    hass = _hass({"abc": _stored_client()})

    response = await OIDCClientsView().delete(_request(hass, client_id=client_id))

    assert response.status == 404
    assert list(hass.data[DOMAIN]["clients"]) == ["abc"]


async def test_remove_client_without_sessions_saves_only_the_clients():
    hass = _hass({"abc": _stored_client()})

    assert await remove_client(hass, "abc") == (True, 0)

    hass.data[DOMAIN]["store"].async_save.assert_awaited_once_with({"clients": {}})
    hass.data[DOMAIN]["token_store"].async_save.assert_not_called()


async def test_update_client_validates_before_changing_anything():
    hass = _hass({"abc": _stored_client()})

    with pytest.raises(ValueError):
        await update_client(hass, "abc", ["https://ok.example.com/cb", "not a url"], True)
    with pytest.raises(KeyError):
        await update_client(hass, "missing", ["https://ok.example.com/cb"])

    assert hass.data[DOMAIN]["clients"]["abc"] == _stored_client()
