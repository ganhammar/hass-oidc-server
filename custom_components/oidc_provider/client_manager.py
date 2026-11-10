"""Client management utilities for OIDC provider."""

import logging
import secrets
import unicodedata
from typing import Any
from urllib.parse import urlparse

from homeassistant.core import HomeAssistant

from .security import hash_client_secret

_LOGGER = logging.getLogger(__name__)
DOMAIN = "oidc_provider"


MAX_CLIENT_NAME_LENGTH = 100


def validate_client_name(client_name: Any) -> str:
    """Return the client name if it is a usable display string.

    The name is shown on the consent screen and in notifications, and anyone
    can choose it through dynamic registration or a metadata document. So it
    must be a non-empty string of bounded length on one line, without control
    or formatting characters: a right-to-left override could reorder the text
    around it, and a line break could add headings to a notification.

    Raises:
        ValueError: If the name is not a string, is blank, too long, or holds
            control, formatting or line separator characters
    """
    if not isinstance(client_name, str) or not client_name.strip():
        raise ValueError("client_name must be a non-empty string")
    if len(client_name) > MAX_CLIENT_NAME_LENGTH:
        raise ValueError(f"client_name must be at most {MAX_CLIENT_NAME_LENGTH} characters")
    if any(
        unicodedata.category(c)[0] == "C" or unicodedata.category(c) in ("Zl", "Zp")
        for c in client_name
    ):
        raise ValueError("client_name must not contain control or formatting characters")
    return client_name.strip()


def validate_redirect_uris(redirect_uris: list[Any]) -> None:
    """Check that every redirect URI is an absolute http(s) URL we can display safely.

    Raises:
        ValueError: If any URI is malformed, not ASCII, uses a disallowed scheme,
            carries userinfo or a fragment, or has an out-of-range port
    """
    for uri in redirect_uris:
        if not isinstance(uri, str):
            raise ValueError("Each redirect_uri must be a string")
        # The host is shown on the consent screen, where a Unicode look-alike
        # of another domain would read as that domain. International domain
        # names are accepted in their ASCII (punycode) form.
        if not uri.isascii():
            raise ValueError(f"Redirect URI must be ASCII, with punycode host names: {uri}")
        # RFC 6749 §3.1.2: a redirection endpoint must not include a fragment
        if "#" in uri:
            raise ValueError(f"Redirect URI must not contain a fragment: {uri}")
        try:
            parsed = urlparse(uri)
        except Exception as e:
            raise ValueError(f"Invalid redirect_uri: {uri}") from e
        # Must have scheme and netloc (host)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"Invalid redirect_uri: {uri}")
        # Enforce HTTPS except for localhost (RFC 8252 §8.3)
        if parsed.scheme == "http":
            if parsed.hostname not in ["localhost", "127.0.0.1", "::1"]:
                raise ValueError(
                    f"Redirect URI must use HTTPS (HTTP only allowed for localhost): {uri}"
                )
        elif parsed.scheme != "https":
            raise ValueError(f"Redirect URI must use http or https: {uri}")
        # Userinfo has no place in a redirect URI and lets the authority
        # masquerade as another host on the consent screen.
        if parsed.username is not None or parsed.password is not None:
            raise ValueError(f"Redirect URI must not contain userinfo: {uri}")
        # Accessing .port raises for a port outside 0-65535
        try:
            parsed.port
        except ValueError as e:
            raise ValueError(f"Redirect URI has an invalid port: {uri}") from e


async def create_client(
    hass: HomeAssistant,
    client_name: str = "OIDC Client",
    redirect_uris: list[str] = None,
    grant_types: list[str] = None,
    response_types: list[str] = None,
    token_endpoint_auth_method: str = "client_secret_basic",
    consent_required: bool = False,
) -> dict[str, Any]:
    """
    Create and register a new OAuth client.

    Args:
        hass: Home Assistant instance
        client_name: Human-readable client name
        redirect_uris: List of allowed redirect URIs
        grant_types: List of allowed grant types
        response_types: List of allowed response types
        token_endpoint_auth_method: Token endpoint authentication method
        consent_required: Whether the user must approve each authorization on a
            consent screen. Clients the operator registered are first-party and
            default to no prompt; dynamically registered clients always prompt.

    Returns:
        Dictionary with client_id, client_secret, and other metadata

    Raises:
        ValueError: If the client name or redirect URIs are invalid
    """
    if redirect_uris is None:
        redirect_uris = []

    if grant_types is None:
        grant_types = ["authorization_code", "refresh_token"]

    if response_types is None:
        response_types = ["code"]

    client_name = validate_client_name(client_name)
    validate_redirect_uris(redirect_uris)

    # Generate client credentials. A public client (token_endpoint_auth_method
    # none) gets no secret; it proves its grants with PKCE.
    client_id = secrets.token_urlsafe(32)
    client_secret = None
    if token_endpoint_auth_method != "none":
        client_secret = secrets.token_urlsafe(48)

    # Store client in hass.data
    if "clients" not in hass.data[DOMAIN]:
        hass.data[DOMAIN]["clients"] = {}

    hass.data[DOMAIN]["clients"][client_id] = {
        "client_name": client_name,
        "redirect_uris": redirect_uris,
        "grant_types": grant_types,
        "response_types": response_types,
        "token_endpoint_auth_method": token_endpoint_auth_method,
        "consent_required": consent_required,
    }
    if client_secret is not None:
        hass.data[DOMAIN]["clients"][client_id]["client_secret_hash"] = hash_client_secret(
            client_secret
        )

    # Persist to storage
    store = hass.data[DOMAIN]["store"]
    await store.async_save({"clients": hass.data[DOMAIN]["clients"]})

    _LOGGER.info("Registered client: %s (%s)", client_name, client_id)

    # Return client information including the plain text secret
    # (only time it's available)
    client_info = {
        "client_id": client_id,
        "client_name": client_name,
        "redirect_uris": redirect_uris,
        "grant_types": grant_types,
        "response_types": response_types,
        "token_endpoint_auth_method": token_endpoint_auth_method,
        "consent_required": consent_required,
    }
    if client_secret is not None:
        client_info["client_secret"] = client_secret
    return client_info
