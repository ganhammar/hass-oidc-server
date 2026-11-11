"""Test __init__.py for OIDC Provider integration."""

import time
from unittest.mock import AsyncMock, Mock, patch

import pytest
import voluptuous as vol
from homeassistant.components.frontend import DATA_PANELS

from custom_components.oidc_provider import (
    DOMAIN,
    async_migrate_entry,
    async_setup,
    async_setup_entry,
    async_unload_entry,
    async_update_options,
)
from custom_components.oidc_provider.const import (
    CONF_ALLOW_CLIENT_METADATA_DOCUMENTS,
    CONF_ALLOW_DYNAMIC_REGISTRATION,
    CONF_REQUIRE_PKCE,
    PANEL_URL_PATH,
)


@pytest.fixture
def mock_hass():
    """Create a mock Home Assistant instance."""
    hass = Mock()
    hass.data = {}
    hass.config = Mock()
    hass.config.path = Mock(return_value="/config")
    hass.http = Mock()
    hass.http.async_register_static_paths = AsyncMock()
    hass.services = Mock()
    hass.services.async_register = Mock()
    hass.services.async_call = AsyncMock()
    # Service calls in these tests come from an administrator
    hass.auth = Mock()
    hass.auth.async_get_user = AsyncMock(return_value=Mock(is_admin=True))
    return hass


@pytest.fixture
def mock_config_entry():
    """Create a mock config entry."""
    entry = Mock()
    entry.data = {}
    return entry


@pytest.fixture
def mock_store():
    """Create a mock store."""
    store = Mock()
    store.async_load = AsyncMock(return_value=None)
    store.async_save = AsyncMock()
    return store


@pytest.fixture
def mock_token_store():
    """Create a mock token store."""
    store = Mock()
    store.async_load = AsyncMock(return_value=None)
    store.async_save = AsyncMock()
    return store


class TestAsyncSetup:
    """Test async_setup function."""

    @patch("custom_components.oidc_provider.async_setup_resources")
    async def test_async_setup_initializes_domain_data(self, mock_resources, mock_hass):
        """Test async_setup initializes domain data and starts collecting resources."""
        result = await async_setup(mock_hass, {})

        assert result is True
        assert DOMAIN in mock_hass.data
        assert mock_hass.data[DOMAIN] == {}
        mock_resources.assert_awaited_once_with(mock_hass)


class TestAsyncSetupEntry:
    """Test async_setup_entry function."""

    @patch("custom_components.oidc_provider.Store")
    @patch("custom_components.oidc_provider.setup_http_endpoints")
    @patch("custom_components.oidc_provider.async_register_built_in_panel")
    async def test_async_setup_entry_prunes_stale_dynamic_clients(
        self,
        mock_panel,
        mock_http,
        mock_store_class,
        mock_hass,
        mock_config_entry,
        mock_store,
        mock_token_store,
    ):
        """Dynamic clients that never got a token are pruned at setup."""
        now = time.time()
        old = now - 8 * 86400
        mock_store.async_load = AsyncMock(
            return_value={
                "clients": {
                    "stale": {"registration": "dynamic", "created_at": old},
                    "in_use": {"registration": "dynamic", "created_at": old, "used_at": old},
                    "manual": {"created_at": old},
                }
            }
        )
        mock_token_store.async_load = AsyncMock(
            return_value={
                "refresh_tokens": {"t": {"client_id": "in_use", "expires_at": now + 1000}}
            }
        )
        mock_store_class.side_effect = [mock_store, mock_token_store]

        assert await async_setup_entry(mock_hass, mock_config_entry) is True

        assert set(mock_hass.data[DOMAIN]["clients"]) == {"in_use", "manual"}
        mock_store.async_save.assert_awaited_once()

    @patch("custom_components.oidc_provider.Store")
    @patch("custom_components.oidc_provider.setup_http_endpoints")
    @patch("custom_components.oidc_provider.async_register_built_in_panel")
    async def test_async_setup_entry_initializes_data(
        self,
        mock_panel,
        mock_http,
        mock_store_class,
        mock_hass,
        mock_config_entry,
        mock_store,
        mock_token_store,
    ):
        """Test async_setup_entry initializes all data structures."""
        mock_store_class.side_effect = [mock_store, mock_token_store]

        result = await async_setup_entry(mock_hass, mock_config_entry)

        assert result is True
        assert DOMAIN in mock_hass.data
        assert "clients" in mock_hass.data[DOMAIN]
        assert "authorization_codes" in mock_hass.data[DOMAIN]
        assert "refresh_tokens" in mock_hass.data[DOMAIN]
        assert "store" in mock_hass.data[DOMAIN]
        assert "token_store" in mock_hass.data[DOMAIN]
        assert mock_hass.data[DOMAIN]["token_store"] is mock_token_store

    @patch("custom_components.oidc_provider.Store")
    @patch("custom_components.oidc_provider.setup_http_endpoints")
    @patch("custom_components.oidc_provider.async_register_built_in_panel")
    async def test_async_setup_entry_loads_stored_clients(
        self,
        mock_panel,
        mock_http,
        mock_store_class,
        mock_hass,
        mock_config_entry,
        mock_store,
        mock_token_store,
    ):
        """Test async_setup_entry loads stored clients."""
        mock_store.async_load = AsyncMock(
            return_value={"clients": {"test_id": {"client_name": "Test Client"}}}
        )
        mock_store_class.side_effect = [mock_store, mock_token_store]

        result = await async_setup_entry(mock_hass, mock_config_entry)

        assert result is True
        assert "test_id" in mock_hass.data[DOMAIN]["clients"]
        assert mock_hass.data[DOMAIN]["clients"]["test_id"]["client_name"] == "Test Client"

    @patch("custom_components.oidc_provider.Store")
    @patch("custom_components.oidc_provider.setup_http_endpoints")
    @patch("custom_components.oidc_provider.async_register_built_in_panel")
    async def test_async_setup_entry_loads_stored_refresh_tokens(
        self,
        mock_panel,
        mock_http,
        mock_store_class,
        mock_hass,
        mock_config_entry,
        mock_store,
        mock_token_store,
    ):
        """Test async_setup_entry loads refresh tokens from storage and filters expired ones."""
        mock_token_store.async_load = AsyncMock(
            return_value={
                "refresh_tokens": {
                    "valid_token": {
                        "user_id": "user1",
                        "client_id": "client1",
                        "scope": "openid",
                        "expires_at": time.time() + 86400,
                    },
                    "expired_token": {
                        "user_id": "user2",
                        "client_id": "client2",
                        "scope": "openid",
                        "expires_at": time.time() - 100,
                    },
                }
            }
        )
        mock_store_class.side_effect = [mock_store, mock_token_store]

        result = await async_setup_entry(mock_hass, mock_config_entry)

        assert result is True
        assert "valid_token" in mock_hass.data[DOMAIN]["refresh_tokens"]
        assert "expired_token" not in mock_hass.data[DOMAIN]["refresh_tokens"]

    @patch("custom_components.oidc_provider.Store")
    @patch("custom_components.oidc_provider.setup_http_endpoints")
    @patch("custom_components.oidc_provider.async_register_built_in_panel")
    async def test_async_setup_entry_registers_http_endpoints(
        self,
        mock_panel,
        mock_http,
        mock_store_class,
        mock_hass,
        mock_config_entry,
        mock_store,
        mock_token_store,
    ):
        """Test async_setup_entry registers HTTP endpoints."""
        mock_store_class.side_effect = [mock_store, mock_token_store]

        await async_setup_entry(mock_hass, mock_config_entry)

        mock_http.assert_called_once_with(mock_hass)

    @patch("custom_components.oidc_provider.Store")
    @patch("custom_components.oidc_provider.setup_http_endpoints")
    @patch("custom_components.oidc_provider.async_register_built_in_panel")
    async def test_async_setup_entry_registers_static_paths(
        self,
        mock_panel,
        mock_http,
        mock_store_class,
        mock_hass,
        mock_config_entry,
        mock_store,
        mock_token_store,
    ):
        """Test async_setup_entry registers static paths."""
        mock_store_class.side_effect = [mock_store, mock_token_store]

        await async_setup_entry(mock_hass, mock_config_entry)

        mock_hass.http.async_register_static_paths.assert_called_once()

    @patch("custom_components.oidc_provider.Store")
    @patch("custom_components.oidc_provider.setup_http_endpoints")
    @patch("custom_components.oidc_provider.async_register_built_in_panel")
    async def test_async_setup_entry_registers_frontend_panel(
        self,
        mock_panel,
        mock_http,
        mock_store_class,
        mock_hass,
        mock_config_entry,
        mock_store,
        mock_token_store,
    ):
        """Test async_setup_entry registers frontend panel."""
        mock_store_class.side_effect = [mock_store, mock_token_store]

        await async_setup_entry(mock_hass, mock_config_entry)

        mock_panel.assert_called_once()
        call_args = mock_panel.call_args
        assert call_args[0][0] == mock_hass
        assert call_args[1]["component_name"] == "custom"
        assert call_args[1]["frontend_url_path"] == "oidc_login"

    @patch("custom_components.oidc_provider.Store")
    @patch("custom_components.oidc_provider.setup_http_endpoints")
    @patch("custom_components.oidc_provider.async_register_built_in_panel")
    async def test_async_setup_entry_registers_services(
        self,
        mock_panel,
        mock_http,
        mock_store_class,
        mock_hass,
        mock_config_entry,
        mock_store,
        mock_token_store,
    ):
        """Test async_setup_entry registers all services."""
        mock_store_class.side_effect = [mock_store, mock_token_store]

        await async_setup_entry(mock_hass, mock_config_entry)

        assert mock_hass.services.async_register.call_count == 5
        registered_services = [
            call[0][1] for call in mock_hass.services.async_register.call_args_list
        ]
        assert "register_client" in registered_services
        assert "revoke_client" in registered_services
        assert "update_client" in registered_services
        assert "list_clients" in registered_services
        assert "rotate_signing_key" in registered_services


class TestAsyncUnloadEntry:
    """Test async_unload_entry function."""

    async def test_async_unload_entry_clears_data(self, mock_hass, mock_config_entry):
        """Test async_unload_entry clears domain data."""
        mock_hass.data[DOMAIN] = {"clients": {}, "authorization_codes": {}}

        result = await async_unload_entry(mock_hass, mock_config_entry)

        assert result is True
        assert len(mock_hass.data[DOMAIN]) == 0

    async def test_async_unload_entry_without_panel(self, mock_hass, mock_config_entry):
        """Test async_unload_entry succeeds when the panel was never registered."""
        mock_hass.data[DOMAIN] = {}

        result = await async_unload_entry(mock_hass, mock_config_entry)

        assert result is True


class TestReload:
    """Test the unload/setup cycle that a config entry reload performs."""

    @patch("custom_components.oidc_provider.Store")
    @patch("custom_components.oidc_provider.setup_http_endpoints")
    async def test_reload_re_registers_panel(
        self,
        mock_http,
        mock_store_class,
        mock_hass,
        mock_config_entry,
    ):
        """Test reloading does not trip Home Assistant's duplicate-panel guard.

        The frontend panel helpers are deliberately left unmocked so the real
        "Overwriting panel" guard runs against the real panel registry.
        """
        mock_store_class.side_effect = lambda *args, **kwargs: Mock(
            async_load=AsyncMock(return_value=None), async_save=AsyncMock()
        )

        assert await async_setup_entry(mock_hass, mock_config_entry) is True
        assert PANEL_URL_PATH in mock_hass.data[DATA_PANELS]

        assert await async_unload_entry(mock_hass, mock_config_entry) is True
        assert PANEL_URL_PATH not in mock_hass.data[DATA_PANELS]

        # Raises ValueError("Overwriting panel oidc_login") if unload leaves the
        # panel registered.
        assert await async_setup_entry(mock_hass, mock_config_entry) is True
        assert PANEL_URL_PATH in mock_hass.data[DATA_PANELS]


class TestRegisterClientService:
    """Test register_client service handler."""

    @patch("custom_components.oidc_provider.Store")
    @patch("custom_components.oidc_provider.setup_http_endpoints")
    @patch("custom_components.oidc_provider.async_register_built_in_panel")
    @patch("custom_components.oidc_provider.create_client")
    async def test_register_client_success(
        self,
        mock_create_client,
        mock_panel,
        mock_http,
        mock_store_class,
        mock_hass,
        mock_config_entry,
        mock_store,
        mock_token_store,
    ):
        """Test register_client service creates client and notification."""
        mock_store_class.side_effect = [mock_store, mock_token_store]
        mock_create_client.return_value = {
            "client_id": "test_id",
            "client_secret": "test_secret",
            "client_name": "Test Client",
            "redirect_uris": ["http://localhost:8080/callback"],
        }

        await async_setup_entry(mock_hass, mock_config_entry)

        # Get the registered service handler
        register_handler = mock_hass.services.async_register.call_args_list[0][0][2]

        # Call the service
        call = Mock()
        call.return_response = False
        call.data = {
            "client_name": "Test Client",
            "redirect_uris": "http://localhost:8080/callback",
        }
        await register_handler(call)

        mock_create_client.assert_called_once()
        mock_hass.services.async_call.assert_called_once()
        notification_call = mock_hass.services.async_call.call_args
        assert notification_call[0][0] == "persistent_notification"
        assert notification_call[0][1] == "create"
        assert "OIDC Client Registered" in notification_call[0][2]["title"]

    @patch("custom_components.oidc_provider.Store")
    @patch("custom_components.oidc_provider.setup_http_endpoints")
    @patch("custom_components.oidc_provider.async_register_built_in_panel")
    async def test_register_client_duplicate_name(
        self,
        mock_panel,
        mock_http,
        mock_store_class,
        mock_hass,
        mock_config_entry,
        mock_store,
        mock_token_store,
    ):
        """Test register_client service rejects duplicate client names."""
        mock_store_class.side_effect = [mock_store, mock_token_store]
        mock_store.async_load = AsyncMock(
            return_value={
                "clients": {"existing_id": {"client_name": "Existing Client", "redirect_uris": []}}
            }
        )

        await async_setup_entry(mock_hass, mock_config_entry)

        register_handler = mock_hass.services.async_register.call_args_list[0][0][2]

        call = Mock()
        call.return_response = False
        call.data = {
            "client_name": "Existing Client",
            "redirect_uris": "http://localhost:8080/callback",
        }
        await register_handler(call)

        # Should create error notification
        notification_call = mock_hass.services.async_call.call_args
        assert "Failed" in notification_call[0][2]["title"]

    @patch("custom_components.oidc_provider.Store")
    @patch("custom_components.oidc_provider.setup_http_endpoints")
    @patch("custom_components.oidc_provider.async_register_built_in_panel")
    async def test_register_client_invalid_redirect_uri(
        self,
        mock_panel,
        mock_http,
        mock_store_class,
        mock_hass,
        mock_config_entry,
        mock_store,
        mock_token_store,
    ):
        """A validation error from create_client surfaces as a failure notification."""
        mock_store_class.side_effect = [mock_store, mock_token_store]

        await async_setup_entry(mock_hass, mock_config_entry)

        register_handler = mock_hass.services.async_register.call_args_list[0][0][2]

        call = Mock()
        call.return_response = False
        call.data = {
            "client_name": "Spoof",
            "redirect_uris": "https://ha.example.com@attacker.example/callback",
        }
        await register_handler(call)

        notification_call = mock_hass.services.async_call.call_args
        assert "Failed" in notification_call[0][2]["title"]
        assert "userinfo" in notification_call[0][2]["message"]
        assert mock_hass.data[DOMAIN]["clients"] == {}


class TestRevokeClientService:
    """Test revoke_client service handler."""

    @patch("custom_components.oidc_provider.Store")
    @patch("custom_components.oidc_provider.setup_http_endpoints")
    @patch("custom_components.oidc_provider.async_register_built_in_panel")
    async def test_revoke_client_success(
        self,
        mock_panel,
        mock_http,
        mock_store_class,
        mock_hass,
        mock_config_entry,
        mock_store,
        mock_token_store,
    ):
        """Test revoke_client service removes client."""
        mock_store_class.side_effect = [mock_store, mock_token_store]
        mock_store.async_load = AsyncMock(
            return_value={"clients": {"test_id": {"client_name": "Test Client"}}}
        )

        await async_setup_entry(mock_hass, mock_config_entry)

        revoke_handler = mock_hass.services.async_register.call_args_list[1][0][2]

        call = Mock()
        call.data = {"client_id": "test_id"}
        await revoke_handler(call)

        assert "test_id" not in mock_hass.data[DOMAIN]["clients"]
        mock_store.async_save.assert_called_once()

    @patch("custom_components.oidc_provider.Store")
    @patch("custom_components.oidc_provider.setup_http_endpoints")
    @patch("custom_components.oidc_provider.async_register_built_in_panel")
    async def test_revoke_client_not_found(
        self,
        mock_panel,
        mock_http,
        mock_store_class,
        mock_hass,
        mock_config_entry,
        mock_store,
        mock_token_store,
    ):
        """Test revoke_client service handles non-existent client."""
        mock_store_class.side_effect = [mock_store, mock_token_store]

        await async_setup_entry(mock_hass, mock_config_entry)

        revoke_handler = mock_hass.services.async_register.call_args_list[1][0][2]

        call = Mock()
        call.data = {"client_id": "nonexistent_id"}
        await revoke_handler(call)

        # Should not raise error, just log warning
        mock_store.async_save.assert_not_called()


class TestUpdateClientService:
    """Test update_client service handler."""

    @patch("custom_components.oidc_provider.Store")
    @patch("custom_components.oidc_provider.setup_http_endpoints")
    @patch("custom_components.oidc_provider.async_register_built_in_panel")
    async def test_update_client_success(
        self,
        mock_panel,
        mock_http,
        mock_store_class,
        mock_hass,
        mock_config_entry,
        mock_store,
        mock_token_store,
    ):
        """Test update_client service updates redirect URIs."""
        mock_store_class.side_effect = [mock_store, mock_token_store]
        mock_store.async_load = AsyncMock(
            return_value={
                "clients": {
                    "test_id": {
                        "client_name": "Test Client",
                        "redirect_uris": ["http://localhost:8080/callback"],
                    }
                }
            }
        )

        await async_setup_entry(mock_hass, mock_config_entry)

        update_handler = mock_hass.services.async_register.call_args_list[2][0][2]

        call = Mock()
        call.data = {
            "client_id": "test_id",
            "redirect_uris": "http://localhost:9090/callback, http://localhost:9091/callback",
        }
        await update_handler(call)

        assert len(mock_hass.data[DOMAIN]["clients"]["test_id"]["redirect_uris"]) == 2
        mock_store.async_save.assert_called_once()
        mock_hass.services.async_call.assert_called_once()

    @patch("custom_components.oidc_provider.Store")
    @patch("custom_components.oidc_provider.setup_http_endpoints")
    @patch("custom_components.oidc_provider.async_register_built_in_panel")
    async def test_update_client_not_found(
        self,
        mock_panel,
        mock_http,
        mock_store_class,
        mock_hass,
        mock_config_entry,
        mock_store,
        mock_token_store,
    ):
        """Test update_client service handles non-existent client."""
        mock_store_class.side_effect = [mock_store, mock_token_store]

        await async_setup_entry(mock_hass, mock_config_entry)

        update_handler = mock_hass.services.async_register.call_args_list[2][0][2]

        call = Mock()
        call.data = {
            "client_id": "nonexistent_id",
            "redirect_uris": "http://localhost:8080/callback",
        }
        await update_handler(call)

        # Should create error notification
        notification_call = mock_hass.services.async_call.call_args
        assert "Failed" in notification_call[0][2]["title"]
        mock_store.async_save.assert_not_called()

    @patch("custom_components.oidc_provider.Store")
    @patch("custom_components.oidc_provider.setup_http_endpoints")
    @patch("custom_components.oidc_provider.async_register_built_in_panel")
    async def test_update_client_rejects_invalid_redirect_uri(
        self,
        mock_panel,
        mock_http,
        mock_store_class,
        mock_hass,
        mock_config_entry,
        mock_store,
        mock_token_store,
    ):
        """Updated redirect URIs get the same validation as registration."""
        mock_store_class.side_effect = [mock_store, mock_token_store]
        mock_store.async_load = AsyncMock(
            return_value={
                "clients": {
                    "test_id": {
                        "client_name": "Test Client",
                        "redirect_uris": ["https://app.example.com/callback"],
                    }
                }
            }
        )

        await async_setup_entry(mock_hass, mock_config_entry)

        update_handler = mock_hass.services.async_register.call_args_list[2][0][2]

        call = Mock()
        call.data = {
            "client_id": "test_id",
            "redirect_uris": "https://app.example.com@attacker.example/callback",
        }
        await update_handler(call)

        notification_call = mock_hass.services.async_call.call_args
        assert "Failed" in notification_call[0][2]["title"]
        assert "userinfo" in notification_call[0][2]["message"]
        assert mock_hass.data[DOMAIN]["clients"]["test_id"]["redirect_uris"] == [
            "https://app.example.com/callback"
        ]
        mock_store.async_save.assert_not_called()

    @patch("custom_components.oidc_provider.Store")
    @patch("custom_components.oidc_provider.setup_http_endpoints")
    @patch("custom_components.oidc_provider.async_register_built_in_panel")
    async def test_update_client_sets_consent_required(
        self,
        mock_panel,
        mock_http,
        mock_store_class,
        mock_hass,
        mock_config_entry,
        mock_store,
        mock_token_store,
    ):
        """Operators clear the consent flag on clients they trust without re-registering."""
        mock_store_class.side_effect = [mock_store, mock_token_store]
        mock_store.async_load = AsyncMock(
            return_value={
                "clients": {
                    "test_id": {
                        "client_name": "Test Client",
                        "redirect_uris": ["https://app.example.com/callback"],
                    }
                }
            }
        )

        await async_setup_entry(mock_hass, mock_config_entry)

        update_handler = mock_hass.services.async_register.call_args_list[2][0][2]

        call = Mock()
        call.data = {
            "client_id": "test_id",
            "redirect_uris": "https://app.example.com/callback",
            "consent_required": False,
        }
        await update_handler(call)

        assert mock_hass.data[DOMAIN]["clients"]["test_id"]["consent_required"] is False
        mock_store.async_save.assert_called_once()
        notification_call = mock_hass.services.async_call.call_args
        assert "Consent required:** no" in notification_call[0][2]["message"]

        # Leaving the field out keeps the stored setting
        call.data = {"client_id": "test_id", "redirect_uris": "https://app.example.com/callback"}
        await update_handler(call)
        assert mock_hass.data[DOMAIN]["clients"]["test_id"]["consent_required"] is False


class TestListClientsService:
    """Test list_clients service handler."""

    @patch("custom_components.oidc_provider.Store")
    @patch("custom_components.oidc_provider.setup_http_endpoints")
    @patch("custom_components.oidc_provider.async_register_built_in_panel")
    async def test_list_clients_with_clients(
        self,
        mock_panel,
        mock_http,
        mock_store_class,
        mock_hass,
        mock_config_entry,
        mock_store,
        mock_token_store,
    ):
        """Test list_clients service lists all clients."""
        mock_store_class.side_effect = [mock_store, mock_token_store]
        mock_store.async_load = AsyncMock(
            return_value={
                "clients": {
                    "test_id_1": {
                        "client_name": "Test Client 1",
                        "redirect_uris": ["http://localhost:8080/callback"],
                    },
                    "test_id_2": {
                        "client_name": "Test Client 2",
                        "redirect_uris": ["http://localhost:9090/callback"],
                    },
                }
            }
        )

        await async_setup_entry(mock_hass, mock_config_entry)

        list_handler = mock_hass.services.async_register.call_args_list[3][0][2]

        call = Mock()
        call.data = {}
        await list_handler(call)

        notification_call = mock_hass.services.async_call.call_args
        assert "OIDC Registered Clients" in notification_call[0][2]["title"]
        assert "Test Client 1" in notification_call[0][2]["message"]
        assert "Test Client 2" in notification_call[0][2]["message"]

    @patch("custom_components.oidc_provider.Store")
    @patch("custom_components.oidc_provider.setup_http_endpoints")
    @patch("custom_components.oidc_provider.async_register_built_in_panel")
    async def test_list_clients_empty(
        self,
        mock_panel,
        mock_http,
        mock_store_class,
        mock_hass,
        mock_config_entry,
        mock_store,
        mock_token_store,
    ):
        """Test list_clients service with no clients."""
        mock_store_class.side_effect = [mock_store, mock_token_store]

        await async_setup_entry(mock_hass, mock_config_entry)

        list_handler = mock_hass.services.async_register.call_args_list[3][0][2]

        call = Mock()
        call.data = {}
        await list_handler(call)

        notification_call = mock_hass.services.async_call.call_args
        assert "No clients registered" in notification_call[0][2]["message"]


class TestRotateSigningKeyService:
    """Test rotate_signing_key service registration and handler."""

    @pytest.mark.parametrize(
        ("data", "keep_previous_key"),
        [({}, True), ({"keep_previous_key": True}, True), ({"keep_previous_key": False}, False)],
    )
    @patch("custom_components.oidc_provider.async_rotate_signing_key", new_callable=AsyncMock)
    @patch("custom_components.oidc_provider.async_register_admin_service")
    @patch("custom_components.oidc_provider.Store")
    @patch("custom_components.oidc_provider.setup_http_endpoints")
    @patch("custom_components.oidc_provider.async_register_built_in_panel")
    async def test_rotate_signing_key_is_an_admin_service(
        self,
        mock_panel,
        mock_http,
        mock_store_class,
        mock_register_admin,
        mock_rotate,
        mock_hass,
        mock_config_entry,
        mock_store,
        mock_token_store,
        data,
        keep_previous_key,
    ):
        """Only admins can rotate, and the previous key is kept unless told otherwise."""
        mock_store_class.side_effect = [mock_store, mock_token_store]

        await async_setup_entry(mock_hass, mock_config_entry)

        mock_register_admin.assert_called_once()
        hass, domain, service, handler = mock_register_admin.call_args[0]
        schema = mock_register_admin.call_args[1]["schema"]
        assert (hass, domain, service) == (mock_hass, DOMAIN, "rotate_signing_key")

        call = Mock()
        call.data = schema(data)
        await handler(call)

        mock_rotate.assert_awaited_once_with(mock_hass, keep_previous_key=keep_previous_key)

    @patch("custom_components.oidc_provider.async_register_admin_service")
    @patch("custom_components.oidc_provider.Store")
    @patch("custom_components.oidc_provider.setup_http_endpoints")
    @patch("custom_components.oidc_provider.async_register_built_in_panel")
    async def test_rotate_signing_key_rejects_unknown_fields(
        self,
        mock_panel,
        mock_http,
        mock_store_class,
        mock_register_admin,
        mock_hass,
        mock_config_entry,
        mock_store,
        mock_token_store,
    ):
        """The schema refuses fields it does not define and values that are not booleans."""
        mock_store_class.side_effect = [mock_store, mock_token_store]

        await async_setup_entry(mock_hass, mock_config_entry)

        schema = mock_register_admin.call_args[1]["schema"]
        with pytest.raises(vol.Invalid):
            schema({"keep_old_key": True})
        with pytest.raises(vol.Invalid):
            schema({"keep_previous_key": "sometimes"})


class TestKeyPersistence:
    """Test RSA key persistence."""

    async def test_keys_are_saved_on_first_setup(self, mock_hass, mock_config_entry, mock_store):
        """Test that RSA keys are saved to storage on first setup."""
        mock_config_entry.options = {}

        mock_token_store = Mock()
        mock_token_store.async_load = AsyncMock(return_value=None)
        mock_token_store.async_save = AsyncMock()

        with patch(
            "custom_components.oidc_provider.Store",
            side_effect=[mock_store, mock_token_store],
        ):
            with patch("custom_components.oidc_provider.http.Store", return_value=mock_store):
                result = await async_setup_entry(mock_hass, mock_config_entry)

        assert result is True
        # Verify store was called to save keys
        mock_store.async_save.assert_called_once()
        saved_data = mock_store.async_save.call_args[0][0]
        assert "private_key_pem" in saved_data
        assert "kid" in saved_data
        assert "created_at" in saved_data

    async def test_keys_are_loaded_from_storage(self, mock_hass, mock_config_entry):
        """Test that RSA keys are loaded from storage if they exist."""
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        # Generate a key to store
        test_private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        test_private_pem = test_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        mock_store = Mock()
        mock_store.async_load = AsyncMock(
            return_value={
                "private_key_pem": test_private_pem.decode(),
                "kid": "test-existing-kid",
                "created_at": 1234567890.0,
            }
        )
        mock_store.async_save = AsyncMock()

        mock_token_store = Mock()
        mock_token_store.async_load = AsyncMock(return_value=None)
        mock_token_store.async_save = AsyncMock()

        mock_config_entry.options = {}

        with patch(
            "custom_components.oidc_provider.Store",
            side_effect=[mock_store, mock_token_store],
        ):
            with patch("custom_components.oidc_provider.http.Store", return_value=mock_store):
                result = await async_setup_entry(mock_hass, mock_config_entry)

        assert result is True
        # Verify store was not called to save (keys already exist)
        mock_store.async_save.assert_not_called()
        # Verify the kid matches what was loaded
        assert mock_hass.data[DOMAIN]["jwt_kid"] == "test-existing-kid"
        # The stored key is the only one tokens are verified with
        assert mock_hass.data[DOMAIN]["jwt_verification_keys"] == {
            "test-existing-kid": mock_hass.data[DOMAIN]["jwt_public_key"]
        }
        assert mock_hass.data[DOMAIN]["key_store"] is mock_store


class TestMigrateEntry:
    """Test async_migrate_entry."""

    def _entry(self, version, minor_version, options):
        entry = Mock()
        entry.version = version
        entry.minor_version = minor_version
        entry.options = options
        return entry

    async def test_minor_version_1_keeps_dynamic_registration_on(self, mock_hass):
        """Entries from before the option existed had registration on and keep it."""
        mock_hass.config_entries = Mock()
        entry = self._entry(1, 1, {CONF_REQUIRE_PKCE: False})

        assert await async_migrate_entry(mock_hass, entry) is True

        mock_hass.config_entries.async_update_entry.assert_called_once_with(
            entry,
            options={
                CONF_REQUIRE_PKCE: False,
                CONF_ALLOW_DYNAMIC_REGISTRATION: True,
                CONF_ALLOW_CLIENT_METADATA_DOCUMENTS: True,
            },
            minor_version=3,
        )

    @pytest.mark.parametrize("saved", [True, False])
    async def test_minor_version_1_keeps_a_saved_choice(self, mock_hass, saved):
        """A minor version 1 entry that already saved the option, as forks do, keeps it."""
        mock_hass.config_entries = Mock()
        entry = self._entry(1, 1, {CONF_ALLOW_DYNAMIC_REGISTRATION: saved})

        assert await async_migrate_entry(mock_hass, entry) is True

        mock_hass.config_entries.async_update_entry.assert_called_once_with(
            entry,
            options={
                CONF_ALLOW_DYNAMIC_REGISTRATION: saved,
                CONF_ALLOW_CLIENT_METADATA_DOCUMENTS: saved,
            },
            minor_version=3,
        )

    @pytest.mark.parametrize("dynamic_registration", [True, False])
    async def test_minor_version_2_follows_dynamic_registration(
        self, mock_hass, dynamic_registration
    ):
        """Metadata documents start as the entry's dynamic registration choice."""
        mock_hass.config_entries = Mock()
        entry = self._entry(1, 2, {CONF_ALLOW_DYNAMIC_REGISTRATION: dynamic_registration})

        assert await async_migrate_entry(mock_hass, entry) is True

        mock_hass.config_entries.async_update_entry.assert_called_once_with(
            entry,
            options={
                CONF_ALLOW_DYNAMIC_REGISTRATION: dynamic_registration,
                CONF_ALLOW_CLIENT_METADATA_DOCUMENTS: dynamic_registration,
            },
            minor_version=3,
        )

    async def test_minor_version_2_keeps_a_saved_metadata_document_choice(self, mock_hass):
        """A saved metadata document choice is kept."""
        mock_hass.config_entries = Mock()
        entry = self._entry(
            1,
            2,
            {CONF_ALLOW_DYNAMIC_REGISTRATION: False, CONF_ALLOW_CLIENT_METADATA_DOCUMENTS: True},
        )

        assert await async_migrate_entry(mock_hass, entry) is True

        assert (
            mock_hass.config_entries.async_update_entry.call_args.kwargs["options"][
                CONF_ALLOW_CLIENT_METADATA_DOCUMENTS
            ]
            is True
        )

    async def test_minor_version_2_without_a_saved_choice_migrates(self, mock_hass):
        """An entry saved by a release before 1.7.0 after a downgrade lacks the choice."""
        mock_hass.config_entries = Mock()
        entry = self._entry(1, 2, {CONF_REQUIRE_PKCE: True})

        assert await async_migrate_entry(mock_hass, entry) is True

        mock_hass.config_entries.async_update_entry.assert_called_once_with(
            entry,
            options={CONF_REQUIRE_PKCE: True, CONF_ALLOW_CLIENT_METADATA_DOCUMENTS: False},
            minor_version=3,
        )

    async def test_current_entry_is_left_alone(self, mock_hass):
        """An entry already at minor version 3 keeps its recorded choices."""
        mock_hass.config_entries = Mock()
        entry = self._entry(1, 3, {CONF_ALLOW_DYNAMIC_REGISTRATION: False})

        assert await async_migrate_entry(mock_hass, entry) is True

        mock_hass.config_entries.async_update_entry.assert_not_called()

    async def test_newer_major_version_is_refused(self, mock_hass):
        """An entry written by a newer major version cannot be read."""
        mock_hass.config_entries = Mock()
        entry = self._entry(2, 1, {})

        assert await async_migrate_entry(mock_hass, entry) is False

        mock_hass.config_entries.async_update_entry.assert_not_called()


class TestOptions:
    """Test that entry options reach the runtime state."""

    @pytest.mark.parametrize("enabled", [True, False])
    @patch("custom_components.oidc_provider.Store")
    @patch("custom_components.oidc_provider.setup_http_endpoints")
    @patch("custom_components.oidc_provider.async_register_built_in_panel")
    async def test_setup_entry_applies_dynamic_registration_option(
        self,
        mock_panel,
        mock_http,
        mock_store_class,
        enabled,
        mock_hass,
        mock_config_entry,
        mock_store,
        mock_token_store,
    ):
        """The registration option is read into hass.data at setup."""
        mock_store_class.side_effect = [mock_store, mock_token_store]
        mock_config_entry.options = {CONF_ALLOW_DYNAMIC_REGISTRATION: enabled}

        assert await async_setup_entry(mock_hass, mock_config_entry) is True

        assert mock_hass.data[DOMAIN][CONF_ALLOW_DYNAMIC_REGISTRATION] is enabled

    @patch("custom_components.oidc_provider.Store")
    @patch("custom_components.oidc_provider.setup_http_endpoints")
    @patch("custom_components.oidc_provider.async_register_built_in_panel")
    async def test_setup_entry_defaults_dynamic_registration_off(
        self,
        mock_panel,
        mock_http,
        mock_store_class,
        mock_hass,
        mock_config_entry,
        mock_store,
        mock_token_store,
    ):
        """An entry with no recorded setting does not allow registration."""
        mock_store_class.side_effect = [mock_store, mock_token_store]
        mock_config_entry.options = {}

        assert await async_setup_entry(mock_hass, mock_config_entry) is True

        assert mock_hass.data[DOMAIN][CONF_ALLOW_DYNAMIC_REGISTRATION] is False

    async def test_update_options_applies_both_settings(self, mock_hass, mock_config_entry):
        """Saving the options form updates the runtime state without a reload."""
        mock_hass.data = {DOMAIN: {CONF_REQUIRE_PKCE: True, CONF_ALLOW_DYNAMIC_REGISTRATION: True}}
        mock_config_entry.options = {
            CONF_REQUIRE_PKCE: False,
            CONF_ALLOW_DYNAMIC_REGISTRATION: False,
        }

        await async_update_options(mock_hass, mock_config_entry)

        assert mock_hass.data[DOMAIN][CONF_REQUIRE_PKCE] is False
        assert mock_hass.data[DOMAIN][CONF_ALLOW_DYNAMIC_REGISTRATION] is False


def test_markdown_text_cannot_add_links_or_formatting():
    """Client-supplied text is escaped before it goes into a notification."""
    from custom_components.oidc_provider import _markdown_text

    assert _markdown_text("[Claude](https://evil.example) *now*") == (
        "`[Claude](https://evil.example) *now*`"
    )
    # Neither a backtick nor a line break can end the code span
    assert _markdown_text("a`b\n# Heading") == "`a'b # Heading`"


@pytest.fixture
async def service_handlers(mock_hass, mock_config_entry, mock_store, mock_token_store):
    """Set the entry up on a mock hass and return its service handlers by name."""
    with (
        patch("custom_components.oidc_provider.Store", side_effect=[mock_store, mock_token_store]),
        patch("custom_components.oidc_provider.setup_http_endpoints"),
        patch("custom_components.oidc_provider.async_register_built_in_panel"),
    ):
        await async_setup_entry(mock_hass, mock_config_entry)
    return {
        call_args[0][1]: call_args[0][2]
        for call_args in mock_hass.services.async_register.call_args_list
    }


def _service_call(data, return_response=False):
    call = Mock()
    call.data = data
    call.return_response = return_response
    call.context.user_id = None
    return call


class TestServiceEdgeCases:
    """Service paths the main flows do not reach."""

    async def test_admin_check_refuses_unknown_and_non_admin_users(self, mock_hass):
        from homeassistant.exceptions import Unauthorized, UnknownUser

        from custom_components.oidc_provider import _admin_only

        handler = AsyncMock(return_value=None)
        checked = _admin_only(mock_hass, handler)
        call = _service_call({})
        call.context.user_id = "someone"

        mock_hass.auth.async_get_user = AsyncMock(return_value=None)
        with pytest.raises(UnknownUser):
            await checked(call)
        mock_hass.auth.async_get_user = AsyncMock(return_value=Mock(is_admin=False))
        with pytest.raises(Unauthorized):
            await checked(call)
        handler.assert_not_awaited()

    async def test_register_client_returns_credentials_for_a_response(
        self, service_handlers, mock_hass
    ):
        response = await service_handlers["register_client"](
            _service_call(
                {"client_name": "Responder", "redirect_uris": "https://app.example.com/cb"},
                return_response=True,
            )
        )

        assert response["client_secret"]
        assert response["redirect_uris"] == ["https://app.example.com/cb"]
        mock_hass.services.async_call.assert_not_awaited()

    @pytest.mark.parametrize(
        ("data", "message"),
        [
            ({"client_name": "Bad", "redirect_uris": "http://app.example.com/cb"}, "HTTPS"),
            ({"client_name": "Taken", "redirect_uris": "https://app.example.com/cb"}, "exists"),
        ],
    )
    async def test_register_client_failures_raise_for_a_response(
        self, service_handlers, mock_hass, data, message
    ):
        from homeassistant.exceptions import HomeAssistantError

        mock_hass.data[DOMAIN]["clients"]["existing"] = {"client_name": "Taken"}

        with pytest.raises(HomeAssistantError, match=message):
            await service_handlers["register_client"](_service_call(data, return_response=True))

    async def test_register_client_survives_a_failed_notification(
        self, service_handlers, mock_hass
    ):
        mock_hass.services.async_call = AsyncMock(side_effect=RuntimeError("no notifications"))

        result = await service_handlers["register_client"](
            _service_call({"client_name": "Quiet", "redirect_uris": "https://app.example.com/cb"})
        )

        assert result is None
        assert [c["client_name"] for c in mock_hass.data[DOMAIN]["clients"].values()] == ["Quiet"]

    async def test_register_client_logs_unexpected_errors(self, service_handlers, caplog):
        with patch(
            "custom_components.oidc_provider.create_client", side_effect=RuntimeError("boom")
        ):
            result = await service_handlers["register_client"](
                _service_call({"client_name": "X", "redirect_uris": "https://app.example.com/cb"})
            )

        assert result is None
        assert "boom" in caplog.text

    async def test_revoke_client_ends_sessions_of_a_client_that_is_not_stored(
        self, service_handlers, mock_hass
    ):
        client_id = "https://claude.ai/oauth/claude-code-client-metadata"
        mock_hass.data[DOMAIN]["refresh_tokens"] = {
            "fam1.a": {"client_id": client_id, "family": "fam1", "expires_at": time.time() + 60},
            "fam2.b": {"client_id": "other", "family": "fam2", "expires_at": time.time() + 60},
        }

        await service_handlers["revoke_client"](_service_call({"client_id": client_id}))

        assert list(mock_hass.data[DOMAIN]["refresh_tokens"]) == ["fam2.b"]

    async def test_list_clients_includes_metadata_document_clients(
        self, service_handlers, mock_hass
    ):
        client_id = "https://claude.ai/oauth/claude-code-client-metadata"
        mock_hass.data[DOMAIN]["refresh_tokens"] = {
            "fam1.a": {
                "client_id": client_id,
                "client_name": "Claude Code",
                "family": "fam1",
                "expires_at": time.time() + 60,
            }
        }

        response = await service_handlers["list_clients"](_service_call({}, return_response=True))

        assert response == {
            "clients": [
                {
                    "client_id": client_id,
                    "client_name": "Claude Code",
                    "client_host": "claude.ai",
                    "active_sessions": 1,
                }
            ]
        }
        message = mock_hass.services.async_call.call_args[0][2]["message"]
        assert "Signed in through a metadata document" in message
        assert "`Claude Code`" in message
