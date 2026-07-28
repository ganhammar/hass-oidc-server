"""Test __init__.py for OIDC Provider integration."""

import time
from unittest.mock import AsyncMock, Mock, patch

import pytest
from homeassistant.components.frontend import DATA_PANELS

from custom_components.oidc_provider import (
    DOMAIN,
    async_setup,
    async_setup_entry,
    async_unload_entry,
)
from custom_components.oidc_provider.const import PANEL_URL_PATH


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

    async def test_async_setup_initializes_domain_data(self, mock_hass):
        """Test async_setup initializes domain data."""
        result = await async_setup(mock_hass, {})

        assert result is True
        assert DOMAIN in mock_hass.data
        assert mock_hass.data[DOMAIN] == {}


class TestAsyncSetupEntry:
    """Test async_setup_entry function."""

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

        assert mock_hass.services.async_register.call_count == 4
        registered_services = [
            call[0][1] for call in mock_hass.services.async_register.call_args_list
        ]
        assert "register_client" in registered_services
        assert "revoke_client" in registered_services
        assert "update_client" in registered_services
        assert "list_clients" in registered_services


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
        call.data = {
            "client_name": "Existing Client",
            "redirect_uris": "http://localhost:8080/callback",
        }
        await register_handler(call)

        # Should create error notification
        notification_call = mock_hass.services.async_call.call_args
        assert "Failed" in notification_call[0][2]["title"]


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
