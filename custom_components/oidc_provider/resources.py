"""Resource servers that describe the access they offer.

Another integration that accepts this provider's access tokens describes
itself by shipping a module named oidc_provider.py, which Home Assistant's
integration platforms hand to this one whether that integration loads before
or after it. The module provides:

- async_describe_resource(hass, language): the description (see
  resource_description), with its text in the given language. Required.
- async_get_availability(hass, language): which groups are unavailable right
  now and why. Optional.
- async_get_ceiling(hass, user, language): the most that user may grant.
  Optional.

A description is validated when it is collected. One that is malformed, or
whose module fails, is logged with the integration's name and ignored, so
sign-ins carry on as if the resource had not described itself.
"""

from __future__ import annotations

import inspect
import logging
from dataclasses import dataclass
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.integration_platform import async_process_integration_platforms

from .const import DOMAIN
from .resource_description import InvalidDescription, resource_matches, validate_description

_LOGGER = logging.getLogger(__name__)

# The module name another integration ships to describe its resource
PLATFORM = "oidc_provider"

# The descriptions collected, by integration domain. Kept apart from
# hass.data[DOMAIN], which is cleared when the config entry unloads, since
# integration platforms are collected once per Home Assistant run.
DATA_RESOURCES = f"{DOMAIN}_resources"


@dataclass(frozen=True)
class DescribedResource:
    """A resource server's module and the description collected from it.

    The description is in the server's language and is what resource
    indicators are matched against and discovery advertises. The consent
    screen asks the module again, in the user's language.
    """

    domain: str
    platform: Any
    description: dict[str, Any]


async def async_call(function: Any, *args: Any) -> Any:
    """Call a resource module's function, awaiting it if it is a coroutine."""
    result = function(*args)
    if inspect.isawaitable(result):
        result = await result
    return result


async def async_setup_resources(hass: HomeAssistant) -> None:
    """Collect the descriptions of every integration that ships the platform, now and later."""
    if DATA_RESOURCES in hass.data:
        return
    hass.data[DATA_RESOURCES] = {}
    await async_process_integration_platforms(hass, PLATFORM, _async_collect)


async def _async_collect(hass: HomeAssistant, domain: str, platform: Any) -> None:
    """Validate and keep one integration's description, or log why it is ignored."""
    describe = getattr(platform, "async_describe_resource", None)
    if not callable(describe):
        _LOGGER.warning(
            "Ignoring the %s.py of integration %s: it has no async_describe_resource",
            PLATFORM,
            domain,
        )
        return

    try:
        description = validate_description(await async_call(describe, hass, hass.config.language))
    except InvalidDescription as err:
        _LOGGER.warning("Ignoring the resource description of integration %s: %s", domain, err)
        return
    except Exception:
        _LOGGER.warning(
            "Ignoring the resource description of integration %s: describing it failed",
            domain,
            exc_info=True,
        )
        return

    registry: dict[str, DescribedResource] = hass.data[DATA_RESOURCES]
    for other in registry.values():
        shared = sorted(set(other.description["resource"]) & set(description["resource"]))
        if shared and other.domain != domain:
            _LOGGER.warning(
                "Ignoring the resource description of integration %s: integration %s "
                "already describes %s",
                domain,
                other.domain,
                ", ".join(shared),
            )
            return

    registry[domain] = DescribedResource(domain, platform, description)
    _LOGGER.debug(
        "Integration %s describes the access it offers at %s",
        domain,
        ", ".join(description["resource"]),
    )


def described_resources(hass: HomeAssistant) -> list[DescribedResource]:
    """Return every collected description."""
    return list(hass.data.get(DATA_RESOURCES, {}).values())


def find_resource(
    hass: HomeAssistant, indicator: str | None, base_url: str
) -> DescribedResource | None:
    """Return the description of the resource an indicator names, if one was collected."""
    return next(
        (
            described
            for described in described_resources(hass)
            if resource_matches(described.description["resource"], indicator, base_url)
        ),
        None,
    )


def resource_scopes(hass: HomeAssistant) -> list[str]:
    """Return every scope the collected descriptions declare, each once."""
    scopes: list[str] = []
    for described in described_resources(hass):
        scopes.extend(scope for scope in described.description["scopes"] if scope not in scopes)
    return scopes
