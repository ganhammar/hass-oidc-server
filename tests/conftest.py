"""Pytest configuration and fixtures."""

import sys
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import pytest

# A stand-in resource server, found by Home Assistant as a custom integration
# named oidc_stand_in. It lives outside the repository's custom_components so
# that only the provider is validated and released.
sys.path.append(str(Path(__file__).parent / "stand_in"))


@pytest.fixture
def stand_in():
    """Return the stand-in's oidc_provider module, with its state reset afterwards."""
    from custom_components.oidc_stand_in import oidc_provider as module

    description = module.DESCRIPTION
    yield module
    module.DESCRIPTION = description
    module.UNAVAILABLE.clear()
    module.CEILINGS.clear()
    module.CALLS.clear()


@pytest.fixture
def mock_hass():
    """Create a mock Home Assistant instance."""
    hass = Mock()
    hass.data = {}
    hass.http = Mock()
    hass.http.register_view = Mock()
    hass.services = Mock()
    hass.services.async_register = AsyncMock()
    return hass


@pytest.fixture
def mock_user():
    """Create a mock user."""
    user = Mock()
    user.id = "test_user_id"
    user.name = "Test User"
    user.is_owner = False

    # Default to admin group
    admin_group = Mock()
    admin_group.id = "system-admin"
    user.groups = [admin_group]

    return user


@pytest.fixture
def mock_config_entry():
    """Create a mock config entry."""
    entry = Mock()
    entry.data = {}
    return entry
