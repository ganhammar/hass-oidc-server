"""OIDC Provider integration for Home Assistant."""

import logging
import re
import time

import voluptuous as vol
from homeassistant.components.frontend import (
    async_register_built_in_panel,
    async_remove_panel,
)
from homeassistant.components.http import StaticPathConfig
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, ServiceCall, SupportsResponse
from homeassistant.exceptions import HomeAssistantError, Unauthorized, UnknownUser
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.service import async_register_admin_service
from homeassistant.helpers.storage import Store

from .client_manager import create_client, prune_dynamic_clients, validate_redirect_uris
from .const import (
    CONF_ALLOW_CLIENT_METADATA_DOCUMENTS,
    CONF_ALLOW_DYNAMIC_REGISTRATION,
    CONF_REQUIRE_PKCE,
    DEFAULT_ALLOW_CLIENT_METADATA_DOCUMENTS,
    DEFAULT_ALLOW_DYNAMIC_REGISTRATION,
    DEFAULT_REQUIRE_PKCE,
    DOMAIN,
    PANEL_URL_PATH,
    STORAGE_KEY_TOKENS,
)
from .http import (
    async_rotate_signing_key,
    client_sessions,
    revoke_client_sessions,
    setup_http_endpoints,
)
from .resources import async_setup_resources

_LOGGER = logging.getLogger(__name__)


def _admin_only(hass: HomeAssistant, handler):
    """Wrap a service handler so only administrators can call it.

    The client actions create and remove clients, end the sessions of every
    user and list every client, so they are for administrators only.
    Calls without a user, such as from automations, are allowed, as with Home
    Assistant's own admin services; a script runs as the user who started it.
    That helper cannot return a response on every supported Home Assistant
    release, so the check is done here.
    """

    async def checked(call: ServiceCall):
        if call.context.user_id:
            user = await hass.auth.async_get_user(call.context.user_id)
            if user is None:
                raise UnknownUser(context=call.context)
            if not user.is_admin:
                raise Unauthorized(context=call.context)
        return await handler(call)

    return checked


def _markdown_text(value: str) -> str:
    """Return a value as a Markdown code span for a notification.

    Client names and redirect URIs come from whoever registered the client,
    which with dynamic registration or metadata documents can be anyone. In a
    code span Markdown adds no links, headings or formatting, bare URLs
    included. Backticks and line breaks, which could end the span, become
    plain characters.
    """
    text = re.sub(r"[\r\n]+", " ", value).replace("`", "'")
    return f"`{text}`"


STORAGE_VERSION = 1
STORAGE_KEY = f"{DOMAIN}.clients"

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)

ATTR_KEEP_PREVIOUS_KEY = "keep_previous_key"
ROTATE_SIGNING_KEY_SCHEMA = vol.Schema(
    {vol.Optional(ATTR_KEEP_PREVIOUS_KEY, default=True): cv.boolean}
)


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up the OIDC Provider component.

    Resource descriptions are collected here rather than with the config
    entry, since an integration platform is processed once per Home
    Assistant run and an entry can be reloaded.
    """
    hass.data.setdefault(DOMAIN, {})
    await async_setup_resources(hass)
    return True


async def async_migrate_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Bring an older config entry up to the current version."""
    if entry.version > 1:
        # Written by a newer release whose schema this one cannot read
        return False

    if entry.minor_version >= 3:
        return True

    options = dict(entry.options)
    if entry.minor_version < 2:
        # Minor version 1 entries come from releases where dynamic registration
        # was always on, so an entry without a saved choice keeps it on and
        # clients that register themselves keep connecting after an upgrade.
        # A saved choice wins: forks of this integration store the same option
        # in minor version 1 entries.
        options = {CONF_ALLOW_DYNAMIC_REGISTRATION: True, **options}
    # Minor version 2 entries come from releases without client metadata
    # documents. They follow the entry's dynamic registration choice, so an
    # install that admitted only clients its operator registered keeps doing
    # so until the operator turns metadata documents on.
    options = {
        CONF_ALLOW_CLIENT_METADATA_DOCUMENTS: options.get(
            CONF_ALLOW_DYNAMIC_REGISTRATION, DEFAULT_ALLOW_DYNAMIC_REGISTRATION
        ),
        **options,
    }
    hass.config_entries.async_update_entry(entry, options=options, minor_version=3)
    _LOGGER.info(
        "Migrated config entry to minor version 3; dynamic client registration %s, "
        "client metadata documents %s",
        # An entry saved by a release before 1.7.0 after a downgrade can lack
        # the dynamic registration choice; it then has the default.
        (
            "enabled"
            if options.get(CONF_ALLOW_DYNAMIC_REGISTRATION, DEFAULT_ALLOW_DYNAMIC_REGISTRATION)
            else "disabled"
        ),
        "enabled" if options[CONF_ALLOW_CLIENT_METADATA_DOCUMENTS] else "disabled",
    )

    return True


def _apply_options(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Copy the entry options into the runtime state the HTTP views read."""
    hass.data[DOMAIN][CONF_REQUIRE_PKCE] = entry.options.get(
        CONF_REQUIRE_PKCE, DEFAULT_REQUIRE_PKCE
    )
    hass.data[DOMAIN][CONF_ALLOW_DYNAMIC_REGISTRATION] = entry.options.get(
        CONF_ALLOW_DYNAMIC_REGISTRATION, DEFAULT_ALLOW_DYNAMIC_REGISTRATION
    )
    hass.data[DOMAIN][CONF_ALLOW_CLIENT_METADATA_DOCUMENTS] = entry.options.get(
        CONF_ALLOW_CLIENT_METADATA_DOCUMENTS, DEFAULT_ALLOW_CLIENT_METADATA_DOCUMENTS
    )


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up OIDC Provider from a config entry."""
    hass.data.setdefault(DOMAIN, {})

    # Initialize storage
    store = Store(hass, STORAGE_VERSION, STORAGE_KEY)
    stored_data = await store.async_load()

    # Store clients and tokens
    hass.data[DOMAIN]["clients"] = stored_data.get("clients", {}) if stored_data else {}
    hass.data[DOMAIN]["authorization_codes"] = {}
    hass.data[DOMAIN]["store"] = store

    # Load refresh tokens from persistent storage, filtering expired ones
    token_store = Store(hass, STORAGE_VERSION, STORAGE_KEY_TOKENS)
    stored_tokens = await token_store.async_load()
    current_time = time.time()
    if stored_tokens and "refresh_tokens" in stored_tokens:
        hass.data[DOMAIN]["refresh_tokens"] = {
            token: data
            for token, data in stored_tokens["refresh_tokens"].items()
            if data.get("expires_at", 0) > current_time
        }
    else:
        hass.data[DOMAIN]["refresh_tokens"] = {}
    hass.data[DOMAIN]["token_store"] = token_store

    await prune_dynamic_clients(hass)

    # Store configuration options
    _apply_options(hass, entry)

    # Listen for options updates
    entry.async_on_unload(entry.add_update_listener(async_update_options))

    # Register HTTP endpoints
    await setup_http_endpoints(hass)

    # Register static path for panel JS
    await hass.http.async_register_static_paths(
        [
            StaticPathConfig(
                "/oidc_provider",
                str(hass.config.path(f"custom_components/{DOMAIN}/www")),
                cache_headers=False,
            )
        ]
    )

    # Register frontend panel for OIDC auth flow (hidden from sidebar)
    cache_buster = int(time.time())
    async_register_built_in_panel(
        hass,
        component_name="custom",
        sidebar_title=None,  # Hidden from sidebar
        sidebar_icon=None,
        frontend_url_path=PANEL_URL_PATH,
        config={
            "_panel_custom": {
                "name": "oidc-auth-panel",
                "embed_iframe": False,
                "js_url": f"/oidc_provider/oidc-auth-panel.js?v={cache_buster}",
            }
        },
        require_admin=False,
    )

    # Register services
    async def handle_register_client(call):
        """Handle register_client service.

        Called for a response, as from Developer Tools, it returns the client
        ID and secret there. Otherwise it shows them in a notification, which
        every Home Assistant user can read, so that is only the fallback.
        """

        async def fail(message: str, notification_id: str) -> None:
            await hass.services.async_call(
                "persistent_notification",
                "create",
                {
                    "title": "OIDC Client Registration Failed",
                    "message": f"❌ {message}",
                    "notification_id": notification_id,
                },
            )
            if call.return_response:
                raise HomeAssistantError(message)

        try:
            _LOGGER.debug("handle_register_client called with data: %s", call.data)

            client_name = call.data.get("client_name")
            redirect_uris = call.data.get("redirect_uris", "").split(",")
            redirect_uris = [uri.strip() for uri in redirect_uris if uri.strip()]
            consent_required = bool(call.data.get("consent_required", False))

            # Check if client with same name already exists
            existing_clients = hass.data[DOMAIN].get("clients", {})
            for existing_client in existing_clients.values():
                if existing_client["client_name"] == client_name:
                    error_msg = f"Client with name '{client_name}' already exists"
                    _LOGGER.error(error_msg)
                    await fail(
                        f"{error_msg}. Please choose a different client name.",
                        f"oidc_client_error_{client_name}",
                    )
                    return None

            # Create client using shared client_manager
            client_info = await create_client(
                hass,
                client_name=client_name,
                redirect_uris=redirect_uris,
                consent_required=consent_required,
            )
            client_id = client_info["client_id"]
            client_secret = client_info["client_secret"]

            _LOGGER.info(
                "Registered OIDC client: %s | Client ID: %s | Redirect URIs: %s",
                client_name,
                client_id,
                redirect_uris,
            )
            if call.return_response:
                return {
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "client_name": client_info["client_name"],
                    "redirect_uris": redirect_uris,
                    "consent_required": consent_required,
                }

            # Create persistent notification with credentials
            try:
                await hass.services.async_call(
                    "persistent_notification",
                    "create",
                    {
                        "title": "OIDC Client Registered",
                        "message": (
                            f"**OIDC Client Registered: {client_name}**\n\n"
                            f"**Client ID:** `{client_id}`\n\n"
                            f"**Client Secret:** `{client_secret}`\n\n"
                            f"**Redirect URIs:** {', '.join(redirect_uris)}\n\n"
                            f"⚠️ **Important:** Save these credentials now. "
                            f"The client secret cannot be retrieved later."
                        ),
                        "notification_id": f"oidc_client_{client_id}",
                    },
                )
                _LOGGER.info("Notification created for client registration")
            except Exception as notif_error:
                _LOGGER.error("Failed to create notification: %s", notif_error)
            return None
        except ValueError as e:
            _LOGGER.error("Error registering OIDC client: %s", e)
            await fail(str(e), "oidc_client_error_invalid")
            return None
        except HomeAssistantError:
            raise
        except Exception as e:
            _LOGGER.error("Error registering OIDC client: %s", e, exc_info=True)

    async def handle_revoke_client(call):
        """Handle revoke_client service.

        Removes a registered client and ends every session it holds. A client
        identified by a metadata document URL is not stored, so revoking it ends
        its sessions; it can sign in again unless metadata documents are off.
        """
        client_id = call.data.get("client_id")
        ended = await revoke_client_sessions(hass, client_id)

        if client_id in hass.data[DOMAIN]["clients"]:
            del hass.data[DOMAIN]["clients"][client_id]

            # Save to storage
            store = hass.data[DOMAIN]["store"]
            await store.async_save({"clients": hass.data[DOMAIN]["clients"]})

            _LOGGER.info("Revoked OIDC client %s and ended %d sessions", client_id, ended)
        elif ended:
            _LOGGER.info("Ended %d sessions of OIDC client %s", ended, client_id)
        else:
            _LOGGER.warning("Client ID not found: %s", client_id)

    async def handle_update_client(call):
        """Handle update_client service."""
        client_id = call.data.get("client_id")
        redirect_uris_input = call.data.get("redirect_uris", "")
        redirect_uris = [uri.strip() for uri in redirect_uris_input.split(",") if uri.strip()]
        consent_required = call.data.get("consent_required")

        async def fail(error_msg: str) -> None:
            _LOGGER.error(error_msg)
            await hass.services.async_call(
                "persistent_notification",
                "create",
                {
                    "title": "OIDC Client Update Failed",
                    "message": f"❌ {error_msg}",
                    "notification_id": f"oidc_update_error_{client_id}",
                },
            )

        if client_id not in hass.data[DOMAIN]["clients"]:
            await fail(f"Client ID '{client_id}' not found")
            return

        # The redirect host is shown on the consent screen, so updated URIs
        # get the same validation as registration.
        try:
            validate_redirect_uris(redirect_uris)
        except ValueError as e:
            await fail(str(e))
            return

        # Update redirect URIs and, when given, the consent setting
        client = hass.data[DOMAIN]["clients"][client_id]
        client["redirect_uris"] = redirect_uris
        if consent_required is not None:
            client["consent_required"] = bool(consent_required)
        consent_label = "yes" if client.get("consent_required", True) else "no"

        # Save to storage
        store = hass.data[DOMAIN]["store"]
        await store.async_save({"clients": hass.data[DOMAIN]["clients"]})

        client_name = hass.data[DOMAIN]["clients"][client_id]["client_name"]

        await hass.services.async_call(
            "persistent_notification",
            "create",
            {
                "title": "OIDC Client Updated",
                "message": (
                    f"**Updated Client: {client_name}**\n\n"
                    f"**Client ID:** `{client_id}`\n\n"
                    f"**New Redirect URIs:** {', '.join(redirect_uris)}\n\n"
                    f"**Consent required:** {consent_label}"
                ),
                "notification_id": f"oidc_update_{client_id}",
            },
        )
        _LOGGER.info("Updated OIDC client: %s with new redirect URIs: %s", client_id, redirect_uris)

    async def handle_list_clients(call):
        """Handle list_clients service.

        Shows a notification, and returns the same listing when the caller asks
        for a response.
        """
        clients = hass.data[DOMAIN].get("clients", {})
        sessions = client_sessions(hass)
        # Clients that are not stored, such as metadata document clients, are
        # known only through their sessions.
        unstored = {
            client_id: info for client_id, info in sessions.items() if client_id not in clients
        }
        listing = [
            {
                "client_id": client_id,
                "client_name": client_data["client_name"],
                "redirect_uris": client_data["redirect_uris"],
                "consent_required": bool(client_data.get("consent_required", True)),
                "active_sessions": sessions.get(client_id, {}).get("active_sessions", 0),
            }
            for client_id, client_data in clients.items()
        ] + [
            {
                "client_id": client_id,
                "client_name": info["client_name"],
                "client_host": info["client_host"],
                "active_sessions": info["active_sessions"],
            }
            for client_id, info in unstored.items()
        ]

        if not clients and not unstored:
            await hass.services.async_call(
                "persistent_notification",
                "create",
                {
                    "title": "OIDC Registered Clients",
                    "message": "No clients registered.",
                    "notification_id": "oidc_list_clients",
                },
            )
            return {"clients": []} if call.return_response else None

        message_parts = ["**Registered OIDC Clients:**\n"] if clients else []
        for client_id, client_data in clients.items():
            consent_label = "yes" if client_data.get("consent_required", True) else "no"
            active = sessions.get(client_id, {}).get("active_sessions", 0)
            redirect_uris = ", ".join(client_data["redirect_uris"])
            message_parts.append(
                f"\n**{_markdown_text(client_data['client_name'])}**\n"
                f"- Client ID: {_markdown_text(client_id)}\n"
                f"- Redirect URIs: {_markdown_text(redirect_uris)}\n"
                f"- Consent required: {consent_label}\n"
                f"- Active sessions: {active}\n"
                f"- ⚠️ Client Secret: Hidden (cannot be retrieved)\n"
            )
        if unstored:
            message_parts.append("\n**Signed in through a metadata document:**\n")
            for client_id, info in unstored.items():
                message_parts.append(
                    f"\n**{_markdown_text(info['client_name'])}**\n"
                    f"- Client ID: {_markdown_text(client_id)}\n"
                    f"- Active sessions: {info['active_sessions']}\n"
                )

        await hass.services.async_call(
            "persistent_notification",
            "create",
            {
                "title": "OIDC Registered Clients",
                "message": "\n".join(message_parts),
                "notification_id": "oidc_list_clients",
            },
        )
        _LOGGER.info("Listed %d OIDC clients", len(listing))
        return {"clients": listing} if call.return_response else None

    async def handle_rotate_signing_key(call):
        """Handle rotate_signing_key service."""
        await async_rotate_signing_key(hass, keep_previous_key=call.data[ATTR_KEEP_PREVIOUS_KEY])

    hass.services.async_register(
        DOMAIN,
        "register_client",
        _admin_only(hass, handle_register_client),
        supports_response=SupportsResponse.OPTIONAL,
    )
    hass.services.async_register(DOMAIN, "revoke_client", _admin_only(hass, handle_revoke_client))
    hass.services.async_register(DOMAIN, "update_client", _admin_only(hass, handle_update_client))
    hass.services.async_register(
        DOMAIN,
        "list_clients",
        _admin_only(hass, handle_list_clients),
        supports_response=SupportsResponse.OPTIONAL,
    )
    async_register_admin_service(
        hass,
        DOMAIN,
        "rotate_signing_key",
        handle_rotate_signing_key,
        schema=ROTATE_SIGNING_KEY_SCHEMA,
    )

    _LOGGER.info("OIDC Provider initialized")
    return True


async def async_update_options(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Handle options update."""
    _apply_options(hass, entry)
    _LOGGER.info(
        "Options updated: PKCE required %s, dynamic client registration %s, "
        "client metadata documents %s",
        hass.data[DOMAIN][CONF_REQUIRE_PKCE],
        hass.data[DOMAIN][CONF_ALLOW_DYNAMIC_REGISTRATION],
        hass.data[DOMAIN][CONF_ALLOW_CLIENT_METADATA_DOCUMENTS],
    )


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    # Home Assistant rejects a duplicate panel registration, so the panel has to
    # go for the next setup to succeed. It is absent when unload runs against a
    # setup that never registered one.
    async_remove_panel(hass, PANEL_URL_PATH, warn_if_unknown=False)
    hass.data[DOMAIN].clear()
    return True
