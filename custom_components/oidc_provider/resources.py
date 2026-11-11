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

import asyncio
import inspect
import logging
import time
from dataclasses import dataclass
from typing import Any

from homeassistant.auth.models import User
from homeassistant.core import HomeAssistant
from homeassistant.helpers.integration_platform import async_process_integration_platforms
from homeassistant.helpers.storage import Store

from .cimd import is_client_id_url
from .const import DOMAIN, STORAGE_KEY_ACCESS_CHOICES, STORAGE_VERSION
from .resource_description import (
    InvalidDescription,
    comparable_resource,
    consent_model,
    known_options,
    resource_matches,
    validate_availability,
    validate_ceiling,
    validate_description,
)

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
    claimed = {comparable_resource(resource) for resource in description["resource"]}
    for other in registry.values():
        shared = sorted(
            resource
            for resource in other.description["resource"]
            if comparable_resource(resource) in claimed
        )
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


async def _async_ask(
    hass: HomeAssistant, described: DescribedResource, user: User, language: str
) -> tuple[dict[str, Any], dict[str, str], dict[str, Any] | None] | None:
    """Ask a resource for its description, availability and this user's ceiling.

    Returns None, after logging why, when any answer is missing, malformed or
    fails, so the sign-in goes on as if the resource had not described itself.
    """
    platform = described.platform

    async def optional(name: str, *args: Any) -> Any:
        function = getattr(platform, name, None)
        return await async_call(function, hass, *args) if callable(function) else None

    try:
        description = validate_description(
            await async_call(platform.async_describe_resource, hass, language)
        )
        availability = validate_availability(
            description, await optional("async_get_availability", language)
        )
        ceiling = validate_ceiling(description, await optional("async_get_ceiling", user, language))
    except InvalidDescription as err:
        _LOGGER.warning(
            "Ignoring the resource description of integration %s for this sign-in: %s",
            described.domain,
            err,
        )
        return None
    except Exception:
        _LOGGER.warning(
            "Ignoring the resource description of integration %s for this sign-in: "
            "asking it failed",
            described.domain,
            exc_info=True,
        )
        return None
    return description, availability, ceiling


async def async_consent_access(
    hass: HomeAssistant,
    described: DescribedResource,
    user: User,
    client_id: str,
    language: str,
) -> dict[str, Any] | None:
    """Return what the consent screen shows of a resource, in the user's language.

    That is the description without its scopes, the groups unavailable right
    now, the user's ceiling and the choice the user made for this client last
    time. None when the resource cannot answer.
    """
    answers = await _async_ask(hass, described, user, language)
    if answers is None:
        return None
    description, availability, ceiling = answers
    remembered = await async_remembered_choice(hass, user.id, client_id, described.domain)
    return {
        "resource": described.domain,
        **consent_model(description),
        "unavailable": availability,
        "ceiling": ceiling,
        "remembered": known_options(description, remembered) or None,
    }


async def async_display_model(
    hass: HomeAssistant, domain: str, language: str
) -> dict[str, Any] | None:
    """Return a collected resource's description in a language, to show what was granted.

    None, after logging why, when the resource is no longer described or
    cannot describe itself now.
    """
    described = hass.data.get(DATA_RESOURCES, {}).get(domain)
    if described is None:
        return None
    try:
        description = validate_description(
            await async_call(described.platform.async_describe_resource, hass, language)
        )
    except Exception as err:
        _LOGGER.warning(
            "Not showing the access granted at the resource of integration %s: %s", domain, err
        )
        return None
    return consent_model(description)


async def async_access_rules(
    hass: HomeAssistant, described: DescribedResource, user: User
) -> tuple[dict[str, Any], dict[str, Any] | None] | None:
    """Return the description and ceiling a choice is checked against, or None."""
    answers = await _async_ask(hass, described, user, hass.config.language)
    if answers is None:
        return None
    description, _, ceiling = answers
    return description, ceiling


async def _async_access_choices(hass: HomeAssistant) -> dict[str, Any]:
    """Return the remembered choices, loading them on first use.

    They map user id, then client id, then the domain of the resource's
    integration, to the options chosen and when.
    """
    domain_data = hass.data[DOMAIN]
    async with domain_data.setdefault("access_choices_lock", asyncio.Lock()):
        if "access_choices" not in domain_data:
            store = Store(hass, STORAGE_VERSION, STORAGE_KEY_ACCESS_CHOICES)
            stored = await store.async_load()
            domain_data["access_choices_store"] = store
            domain_data["access_choices"] = (stored or {}).get("choices", {})
    return domain_data["access_choices"]


async def _async_save_access_choices(hass: HomeAssistant) -> None:
    domain_data = hass.data[DOMAIN]
    await domain_data["access_choices_store"].async_save({"choices": domain_data["access_choices"]})


async def async_remembered_choice(
    hass: HomeAssistant, user_id: str, client_id: str, resource: str
) -> dict[str, str] | None:
    """Return the options a user last chose for a client at a resource, if any."""
    choices = await _async_access_choices(hass)
    return choices.get(user_id, {}).get(client_id, {}).get(resource, {}).get("options")


async def async_remember_choice(
    hass: HomeAssistant, user_id: str, client_id: str, resource: str, options: dict[str, str]
) -> None:
    """Remember a user's choice for a client at a resource, for the next sign-in.

    Choices for clients that no longer exist are dropped at the same time. A
    client identified by a metadata document URL is never stored, so its
    choices are kept.
    """
    choices = await _async_access_choices(hass)
    choices.setdefault(user_id, {}).setdefault(client_id, {})[resource] = {
        "options": options,
        "chosen_at": int(time.time()),
    }
    clients = hass.data[DOMAIN].get("clients", {})
    for by_client in choices.values():
        for gone in [cid for cid in by_client if cid not in clients and not is_client_id_url(cid)]:
            del by_client[gone]
    for gone in [uid for uid, by_client in choices.items() if not by_client]:
        del choices[gone]
    await _async_save_access_choices(hass)
