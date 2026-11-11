"""Tests for what the login panel reads besides the consent request: its text."""

import json
from unittest.mock import MagicMock

from homeassistant.core import HomeAssistant

from custom_components.oidc_provider.http import OIDCStringsView, async_panel_strings


async def test_panel_strings_come_from_the_translations(
    enable_custom_integrations: None, hass: HomeAssistant
):
    strings = await async_panel_strings(hass, "en")

    assert strings["consent.heading"] == "Approve access?"
    assert strings["consent.alert"] == (
        "You're about to give {client} access to your Home Assistant instance."
    )
    assert strings["access.choose_in_detail"] == "Choose in detail"
    assert all("." in key and not key.startswith("component.") for key in strings)


async def test_panel_strings_fall_back_to_english(
    enable_custom_integrations: None, hass: HomeAssistant
):
    """Only English ships, so every other language gets the English text."""
    assert await async_panel_strings(hass, "sv") == await async_panel_strings(hass, "en")


async def test_strings_view_answers_in_the_language_asked_for(
    enable_custom_integrations: None, hass: HomeAssistant
):
    request = MagicMock()
    request.app = {"hass": hass}
    request.query = {"language": "nl"}

    response = await OIDCStringsView().get(request)

    data = json.loads(response.body)
    assert data["language"] == "nl"
    assert data["strings"]["sessions.heading"] == "Connected applications"

    request.query = {"language": "klingon"}
    response = await OIDCStringsView().get(request)
    assert json.loads(response.body)["language"] == hass.config.language


def test_strings_view_needs_a_signed_in_user():
    assert OIDCStringsView.requires_auth is True
    assert OIDCStringsView.url == "/oidc/strings"
