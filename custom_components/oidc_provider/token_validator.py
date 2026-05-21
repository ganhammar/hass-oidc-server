"""Token validation helper for OIDC provider."""

import logging
from typing import Any

import jwt
from aiohttp import web
from cryptography.hazmat.primitives import serialization
from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)
DOMAIN = "oidc_provider"


def get_issuer_from_request(request: web.Request) -> str:
    """
    Get the expected issuer URL from a request.

    Respects X-Forwarded headers if present (for reverse proxy setups).
    Falls back to Home Assistant's configured external URL when headers
    are absent, before using the raw request origin.

    Args:
        request: The aiohttp web request

    Returns:
        The base URL for this server
    """
    # Check for X-Forwarded headers (proxy setup)
    forwarded_proto = request.headers.get("X-Forwarded-Proto")
    forwarded_host = request.headers.get("X-Forwarded-Host")

    if forwarded_proto and forwarded_host:
        # Use forwarded headers from proxy
        base_url = f"{forwarded_proto}://{forwarded_host}"
    else:
        # Try Home Assistant's configured external URL
        external_url = _get_ha_external_url(request)
        if external_url:
            base_url = external_url.rstrip("/")
        else:
            # Direct connection, use request URL
            base_url = str(request.url.origin())

    return base_url


def _get_ha_external_url(request: web.Request) -> str | None:
    """Try to get Home Assistant's configured external URL."""
    try:
        hass = request.app.get("hass")
        if not hass:
            return None

        from homeassistant.helpers.network import get_url

        if not isinstance(hass, HomeAssistant):
            return None

        return get_url(hass, allow_internal=False, prefer_external=True)
    except Exception:
        return None


def validate_access_token(
    hass: HomeAssistant, token: str, expected_issuer: str
) -> dict[str, Any] | None:
    """
    Validate an OAuth access token issued by this OIDC provider.

    Args:
        hass: Home Assistant instance
        token: The access token to validate
        expected_issuer: Expected issuer URL

    Returns:
        Token payload if valid, None otherwise
    """
    try:
        if DOMAIN not in hass.data:
            _LOGGER.error("OIDC provider not loaded")
            return None

        public_key = hass.data[DOMAIN].get("jwt_public_key")
        if not public_key:
            _LOGGER.error("JWT public key not found")
            return None

        # Convert public key to PEM format for JWT library
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # The issuer signed into tokens always has the /oidc suffix (RFC 8414).
        # External callers (e.g. hass-mcp-server) typically pass the base URL
        # without the suffix; tolerate both forms so they don't have to change
        # in lockstep.
        if not expected_issuer.rstrip("/").endswith("/oidc"):
            expected_issuer = expected_issuer.rstrip("/") + "/oidc"

        # Verify and decode the token with issuer verification
        payload = jwt.decode(
            token,
            public_key_pem,
            algorithms=["RS256"],
            issuer=expected_issuer,
            options={
                "verify_aud": False,  # We verify manually below
            },
        )

        # Verify the audience claim exists and matches a registered client
        aud = payload.get("aud")
        if not aud:
            _LOGGER.warning("Token missing audience claim")
            return None

        clients = hass.data[DOMAIN].get("clients", {})
        if aud not in clients:
            # Token audience doesn't match any registered client
            _LOGGER.warning("Token with invalid audience: %s", aud)
            return None

        return payload
    except jwt.ExpiredSignatureError:
        _LOGGER.warning("Token expired")
        return None
    except jwt.InvalidTokenError as e:
        _LOGGER.warning("Invalid token: %s", e)
        return None
    except Exception as e:
        _LOGGER.error("Error validating token: %s", e)
        return None
