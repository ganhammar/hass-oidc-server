"""A stand-in resource server for the tests: it only describes itself to the provider."""

from homeassistant.core import HomeAssistant

DOMAIN = "oidc_stand_in"


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up the stand-in. It has nothing to do; its oidc_provider.py is what counts."""
    return True
