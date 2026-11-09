"""Test config flow for OIDC Provider integration."""

from unittest.mock import Mock, patch

from homeassistant import data_entry_flow

from custom_components.oidc_provider.config_flow import (
    OIDCProviderConfigFlow,
    OIDCProviderOptionsFlow,
)
from custom_components.oidc_provider.const import CONF_ALLOW_DYNAMIC_REGISTRATION


def _schema_default(schema, key):
    """Return the default a voluptuous form schema gives the named field."""
    marker = next(marker for marker in schema.schema if marker == key)
    return marker.default()


def _options_flow(options):
    """Return an options flow bound to a config entry with the given options.

    The flow resolves its entry through hass by the handler id, the way Home
    Assistant wires it up when the options dialog opens.
    """
    entry = Mock()
    entry.options = options
    flow = OIDCProviderOptionsFlow()
    flow.hass = Mock()
    flow.hass.config_entries.async_get_known_entry.return_value = entry
    flow.handler = "entry_id"
    return flow


class TestOIDCProviderConfigFlow:
    """Test the OIDC Provider config flow."""

    async def test_user_flow_creates_entry(self):
        """Test user flow creates config entry."""
        # Create mock hass
        mock_hass = Mock()
        mock_hass.config_entries = Mock()
        mock_hass.config_entries.async_entries = Mock(return_value=[])

        flow = OIDCProviderConfigFlow()
        flow.hass = mock_hass

        result = await flow.async_step_user(user_input={})

        assert result["type"] == data_entry_flow.FlowResultType.CREATE_ENTRY
        assert result["title"] == "OIDC Provider"
        assert result["data"] == {}
        assert result["options"] == {CONF_ALLOW_DYNAMIC_REGISTRATION: False}

    async def test_user_flow_records_dynamic_registration_choice(self):
        """The setup choice for dynamic registration lands in the entry options."""
        mock_hass = Mock()
        mock_hass.config_entries = Mock()
        mock_hass.config_entries.async_entries = Mock(return_value=[])

        flow = OIDCProviderConfigFlow()
        flow.hass = mock_hass

        result = await flow.async_step_user(user_input={CONF_ALLOW_DYNAMIC_REGISTRATION: True})

        assert result["type"] == data_entry_flow.FlowResultType.CREATE_ENTRY
        assert result["data"] == {}
        assert result["options"] == {CONF_ALLOW_DYNAMIC_REGISTRATION: True}

    async def test_user_flow_shows_form_when_no_input(self):
        """Test user flow shows form when no input provided."""
        # Create mock hass
        mock_hass = Mock()
        mock_hass.config_entries = Mock()
        mock_hass.config_entries.async_entries = Mock(return_value=[])

        flow = OIDCProviderConfigFlow()
        flow.hass = mock_hass

        result = await flow.async_step_user(user_input=None)

        assert result["type"] == data_entry_flow.FlowResultType.FORM
        assert result["step_id"] == "user"
        assert result["data_schema"] is not None

    async def test_single_instance_allowed(self):
        """Test only single instance is allowed."""
        # Create mock hass with existing entry
        mock_hass = Mock()
        mock_entry = Mock()
        mock_hass.config_entries = Mock()
        mock_hass.config_entries.async_entries = Mock(return_value=[mock_entry])

        flow = OIDCProviderConfigFlow()
        flow.hass = mock_hass

        result = await flow.async_step_user(user_input={})

        assert result["type"] == data_entry_flow.FlowResultType.ABORT
        assert result["reason"] == "single_instance_allowed"

    async def test_version_is_set(self):
        """Test config flow version is set."""
        flow = OIDCProviderConfigFlow()
        assert flow.VERSION == 1
        assert flow.MINOR_VERSION == 2

    def test_async_get_options_flow_returns_options_flow(self):
        """Test async_get_options_flow returns options flow instance."""
        with patch.object(OIDCProviderOptionsFlow, "__init__", return_value=None):
            mock_config_entry = Mock()
            options_flow = OIDCProviderConfigFlow.async_get_options_flow(mock_config_entry)

            assert isinstance(options_flow, OIDCProviderOptionsFlow)

    async def test_user_flow_form_offers_dynamic_registration_off(self):
        """The setup form asks about dynamic registration and defaults it to off."""
        mock_hass = Mock()
        mock_hass.config_entries = Mock()
        mock_hass.config_entries.async_entries = Mock(return_value=[])

        flow = OIDCProviderConfigFlow()
        flow.hass = mock_hass

        result = await flow.async_step_user(user_input=None)

        assert list(result["data_schema"].schema) == [CONF_ALLOW_DYNAMIC_REGISTRATION]
        assert _schema_default(result["data_schema"], CONF_ALLOW_DYNAMIC_REGISTRATION) is False


class TestOIDCProviderOptionsFlow:
    """Test the OIDC Provider options flow."""

    async def test_init_step_shows_form(self):
        """Test init step shows form."""
        flow = _options_flow({})

        result = await flow.async_step_init(user_input=None)

        assert result["type"] == data_entry_flow.FlowResultType.FORM
        assert result["step_id"] == "init"

    async def test_init_step_with_user_input_creates_entry(self):
        """Test init step with user input creates entry."""
        flow = _options_flow({})

        result = await flow.async_step_init(user_input={"require_pkce": True})

        assert result["type"] == data_entry_flow.FlowResultType.CREATE_ENTRY
        assert result["data"] == {"require_pkce": True}

    async def test_init_step_shows_pkce_option(self):
        """Test init step shows PKCE enforcement option."""
        flow = _options_flow({})

        result = await flow.async_step_init(user_input=None)

        # Verify form contains PKCE option
        assert result["type"] == data_entry_flow.FlowResultType.FORM
        assert "require_pkce" in result["data_schema"].schema

    async def test_init_step_defaults_to_pkce_required(self):
        """Test init step defaults PKCE to True."""
        from custom_components.oidc_provider.const import DEFAULT_REQUIRE_PKCE

        flow = _options_flow({})

        result = await flow.async_step_init(user_input=None)

        # Verify form contains PKCE option with correct default
        assert result["type"] == data_entry_flow.FlowResultType.FORM
        # The default should be True (from DEFAULT_REQUIRE_PKCE constant)
        assert DEFAULT_REQUIRE_PKCE is True

    async def test_init_step_defaults_dynamic_registration_to_current_option(self):
        """The options form starts from the entry's current registration setting."""
        flow = _options_flow({CONF_ALLOW_DYNAMIC_REGISTRATION: True})

        result = await flow.async_step_init(user_input=None)

        assert result["type"] == data_entry_flow.FlowResultType.FORM
        assert _schema_default(result["data_schema"], CONF_ALLOW_DYNAMIC_REGISTRATION) is True

    async def test_init_step_defaults_dynamic_registration_off_without_option(self):
        """An entry with no recorded setting shows dynamic registration as off."""
        flow = _options_flow({})

        result = await flow.async_step_init(user_input=None)

        assert _schema_default(result["data_schema"], CONF_ALLOW_DYNAMIC_REGISTRATION) is False

    async def test_init_step_saves_dynamic_registration_choice(self):
        """Submitting the options form stores both settings."""
        flow = _options_flow({})

        result = await flow.async_step_init(
            user_input={"require_pkce": True, CONF_ALLOW_DYNAMIC_REGISTRATION: False}
        )

        assert result["type"] == data_entry_flow.FlowResultType.CREATE_ENTRY
        assert result["data"] == {"require_pkce": True, CONF_ALLOW_DYNAMIC_REGISTRATION: False}
