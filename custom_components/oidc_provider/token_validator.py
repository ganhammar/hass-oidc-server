"""Token validation helper for OIDC provider."""

import ipaddress
import logging
from typing import Any

import jwt
from aiohttp import web
from cryptography.hazmat.primitives import serialization
from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)
DOMAIN = "oidc_provider"


def _describe_token(token: str) -> str:
    """Return safe-to-log metadata about a bearer token.

    Logs structural shape (length, segment count) and the unverified JWS header
    fields (alg, kid, typ). The signing key is not used and the payload is never
    decoded, so this is safe to call on tokens that fail validation. The token
    string itself is never logged.
    """
    if not token:
        return "token=<empty>"
    parts: list[str] = [f"length={len(token)}", f"segments={token.count('.') + 1}"]
    try:
        header = jwt.get_unverified_header(token)
    except Exception:
        parts.append("header=<unparseable>")
        return " ".join(parts)
    for key in ("alg", "kid", "typ"):
        value = header.get(key)
        if value is not None:
            parts.append(f"{key}={value!r}")
    return " ".join(parts)


def _is_ip_host(host: str) -> bool:
    """Return True when host (optionally host:port) is a bare IP address."""
    bare = host.rsplit(":", 1)[0] if ":" in host and not host.endswith("]") else host
    try:
        ipaddress.ip_address(bare.strip("[]"))
    except ValueError:
        return False
    return True


def get_issuer_from_request(request: web.Request) -> str:
    """
    Get the expected issuer URL from a request.

    Resolution order: a domain host from X-Forwarded-Host or Host wins
    (for reverse proxy setups). When the host is missing or a bare IP
    address, Home Assistant's configured external URL is preferred,
    followed by the IP host and finally the raw request origin.

    Args:
        request: The aiohttp web request

    Returns:
        The base URL for this server
    """
    # Derive the host the client actually used. X-Forwarded-Host is preferred,
    # but some proxies (e.g. Cloudflare Tunnel) forward the original Host header
    # and X-Forwarded-Proto without setting X-Forwarded-Host, so fall back to the
    # Host header. The protocol comes from X-Forwarded-Proto when the proxy
    # terminates TLS, otherwise from the request scheme.
    host = request.headers.get("X-Forwarded-Host") or request.headers.get("Host")
    proto = request.headers.get("X-Forwarded-Proto") or request.url.scheme

    if host and not _is_ip_host(host):
        return f"{proto}://{host}"

    # The host is missing or is an IP address. Some proxies (e.g. Keenetic)
    # rewrite Host to the internal IP without setting X-Forwarded-Host, which
    # would leak the internal address into the issuer and endpoint metadata.
    # Prefer HA's configured external URL in that case; keep the IP host as a
    # fallback so LAN-only installs without an external URL keep working.
    external_url = _get_ha_external_url(request)
    if external_url:
        return external_url.rstrip("/")

    if host:
        return f"{proto}://{host}"

    return str(request.url.origin())


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
    hass: HomeAssistant,
    token: str,
    expected_issuer: str,
    expected_audience: str | None = None,
) -> dict[str, Any] | None:
    """
    Validate an OAuth access token issued by this OIDC provider.

    Args:
        hass: Home Assistant instance
        token: The access token to validate
        expected_issuer: Expected issuer URL
        expected_audience: The resource this token must be bound to (RFC 8707).
            When provided, the token is accepted if its aud contains this value.
            Tokens whose aud is a registered client_id are also accepted, so
            tokens issued before resource binding (or by clients that don't send
            a resource indicator) keep working.

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

        # Verify the audience claim exists.
        aud = payload.get("aud")
        if not aud:
            _LOGGER.warning("Token missing audience claim")
            return None

        audiences = aud if isinstance(aud, list) else [aud]

        # Accept the token when its audience is bound to the expected resource
        # (RFC 8707) or, for backward compatibility, to a registered client_id.
        if expected_audience is not None and expected_audience in audiences:
            return payload

        clients = hass.data[DOMAIN].get("clients", {})
        if any(audience in clients for audience in audiences):
            return payload

        _LOGGER.warning("Token with invalid audience: %s", aud)
        return None
    except jwt.ExpiredSignatureError:
        _LOGGER.warning("Token expired (%s)", _describe_token(token))
        return None
    except jwt.InvalidTokenError as e:
        _LOGGER.warning("Invalid token: %s (%s)", e, _describe_token(token))
        return None
    except Exception as e:
        _LOGGER.error("Error validating token: %s (%s)", e, _describe_token(token))
        return None
