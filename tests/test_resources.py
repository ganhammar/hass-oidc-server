"""Tests for collecting resource descriptions from other integrations."""

import copy
import logging
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from homeassistant.core import HomeAssistant
from homeassistant.setup import async_setup_component

from custom_components.oidc_provider.resources import (
    DATA_RESOURCES,
    _async_collect,
    async_setup_resources,
    described_resources,
    find_resource,
    resource_scopes,
)

BASE = "https://ha.example.com"


async def _load_stand_in(hass: HomeAssistant) -> None:
    assert await async_setup_component(hass, "oidc_stand_in", {})
    await hass.async_block_till_done()


async def test_collects_a_resource_that_loads_later(
    enable_custom_integrations: None, hass: HomeAssistant, stand_in
):
    """The provider is set up first and the resource server after it."""
    await async_setup_resources(hass)
    assert described_resources(hass) == []

    await _load_stand_in(hass)

    [described] = described_resources(hass)
    assert described.domain == "oidc_stand_in"
    assert described.platform is stand_in
    assert described.description["name"] == "Stand-in"
    assert ("describe", hass.config.language) in stand_in.CALLS


async def test_collects_a_resource_that_loaded_earlier(
    enable_custom_integrations: None, hass: HomeAssistant, stand_in
):
    """The resource server is set up first and the provider after it."""
    await _load_stand_in(hass)

    await async_setup_resources(hass)
    await hass.async_block_till_done()

    assert [described.domain for described in described_resources(hass)] == ["oidc_stand_in"]


async def test_collecting_starts_once(
    enable_custom_integrations: None, hass: HomeAssistant, stand_in
):
    """A second setup, as after the config entry reloads, keeps what was collected."""
    await async_setup_resources(hass)
    await _load_stand_in(hass)

    await async_setup_resources(hass)
    await hass.async_block_till_done()

    assert len(described_resources(hass)) == 1
    assert [call for call in stand_in.CALLS if call[0] == "describe"] == [
        ("describe", hass.config.language)
    ]


def _mock_hass():
    hass = Mock()
    hass.data = {DATA_RESOURCES: {}}
    hass.config.language = "en"
    return hass


async def test_module_without_a_description_is_ignored(caplog):
    hass = _mock_hass()

    with caplog.at_level(logging.WARNING):
        await _async_collect(hass, "garden", SimpleNamespace())

    assert described_resources(hass) == []
    assert "Ignoring the oidc_provider.py of integration garden" in caplog.text


async def test_malformed_description_is_ignored_with_the_reason(stand_in, caplog):
    hass = _mock_hass()
    stand_in.DESCRIPTION = {**copy.deepcopy(stand_in.DESCRIPTION), "name": ""}

    with caplog.at_level(logging.WARNING):
        await _async_collect(hass, "oidc_stand_in", stand_in)

    assert described_resources(hass) == []
    assert (
        "Ignoring the resource description of integration oidc_stand_in: "
        "expected text that is not empty at name"
    ) in caplog.text


async def test_failing_description_is_ignored(caplog):
    hass = _mock_hass()

    async def describe(hass, language):
        raise RuntimeError("no description today")

    with caplog.at_level(logging.WARNING):
        await _async_collect(hass, "garden", SimpleNamespace(async_describe_resource=describe))

    assert described_resources(hass) == []
    assert "Ignoring the resource description of integration garden: describing it failed" in (
        caplog.text
    )
    assert "no description today" in caplog.text


async def test_plain_function_and_a_second_claim_on_a_resource(stand_in, caplog):
    """A plain function works as well as a coroutine. A second integration
    claiming a resource another already describes is ignored, while the same
    integration may describe itself again."""
    hass = _mock_hass()
    await _async_collect(hass, "oidc_stand_in", stand_in)

    other = copy.deepcopy(stand_in.DESCRIPTION)
    other["resource"] = ["/api/other", "/api/stand_in_http"]
    with caplog.at_level(logging.WARNING):
        await _async_collect(
            hass, "other", SimpleNamespace(async_describe_resource=lambda hass, language: other)
        )
    assert [described.domain for described in described_resources(hass)] == ["oidc_stand_in"]
    assert (
        "Ignoring the resource description of integration other: integration oidc_stand_in "
        "already describes /api/stand_in_http"
    ) in caplog.text

    await _async_collect(hass, "oidc_stand_in", stand_in)
    assert len(described_resources(hass)) == 1


async def test_find_resource_and_scopes(stand_in):
    hass = _mock_hass()
    assert find_resource(hass, f"{BASE}/api/stand_in", BASE) is None
    assert resource_scopes(hass) == []

    await _async_collect(hass, "oidc_stand_in", stand_in)
    notes = copy.deepcopy(stand_in.DESCRIPTION)
    notes["resource"] = "https://notes.example.com/api"
    notes["scopes"]["notes:write"] = {"title": "Write notes", "description": "Write notes."}
    await _async_collect(
        hass, "notes", SimpleNamespace(async_describe_resource=lambda hass, language: notes)
    )

    assert find_resource(hass, f"{BASE}/api/stand_in_http", BASE).domain == "oidc_stand_in"
    assert find_resource(hass, "https://notes.example.com/api", BASE).domain == "notes"
    assert find_resource(hass, f"{BASE}/api/elsewhere", BASE) is None
    assert find_resource(hass, None, BASE) is None
    scopes = resource_scopes(hass)
    assert scopes[:2] == ["stand_in:read", "stand_in:control"]
    assert scopes[-1] == "notes:write"
    assert len(scopes) == len(set(scopes))


def test_nothing_is_described_before_collecting_starts():
    hass = Mock()
    hass.data = {}
    assert described_resources(hass) == []


@pytest.fixture(autouse=True)
def _restore_stand_in(stand_in):
    """Every test here starts from the stand-in's own description."""
    return stand_in
