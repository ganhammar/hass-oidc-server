"""Token validation helper for OIDC provider."""

import ipaddress
import logging
import re
from typing import Any

import jwt
from aiohttp import web
from homeassistant.core import HomeAssistant

from .const import ACCESS_TOKEN_TYPE, TOKEN_USE_ACCESS

_LOGGER = logging.getLogger(__name__)
DOMAIN = "oidc_provider"

# RFC 9068 §4 accepts the media type with or without its application/ prefix
_ACCESS_TOKEN_TYPES = {ACCESS_TOKEN_TYPE, f"application/{ACCESS_TOKEN_TYPE}"}


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


# A host as a request may name it: a name or an address, with or without a port.
# A name may hold underscores, as container names do, and end in a dot. Anything
# else in a host header, such as a path, is not a host.
_HOST_PATTERN = re.compile(
    r"(?:[A-Za-z0-9_](?:[A-Za-z0-9._-]*[A-Za-z0-9_])?\.?|\[[0-9A-Fa-f:.]+\])(?::\d{1,5})?"
)
_HOST_HEADERS = ("X-Forwarded-Host", "Host")


def _named_host(request: web.Request) -> str | None:
    """Return the host the request names, from X-Forwarded-Host or else Host.

    A header that holds anything but a host is passed over, so a client cannot
    put a path or another URL into the issuer and the addresses built from it.
    """
    for header in _HOST_HEADERS:
        host = request.headers.get(header)
        if isinstance(host, str) and _HOST_PATTERN.fullmatch(host):
            return host
    return None


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
    followed by the IP host. A header that holds anything but a host is
    passed over, and the request's own origin stands in only when no host
    header was sent.

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
    host = _named_host(request)
    proto = request.headers.get("X-Forwarded-Proto")
    proto = proto.lower() if isinstance(proto, str) else None
    if proto not in ("http", "https"):
        proto = request.url.scheme

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

    # No header names a host. The request's own origin is built from the Host
    # header as it was sent, so it stands in only when no host header came at
    # all; one that holds something else never reaches the issuer.
    if any(
        isinstance(sent := request.headers.get(header), str) and sent for header in _HOST_HEADERS
    ):
        return _get_ha_internal_url(request) or f"{proto}://localhost"

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


def _get_ha_internal_url(request: web.Request) -> str | None:
    """Try to get the URL Home Assistant is configured to be reached at inside the network."""
    try:
        hass = request.app.get("hass")
        if not isinstance(hass, HomeAssistant):
            return None

        from homeassistant.helpers.network import get_url

        return get_url(hass, allow_external=False, allow_cloud=False).rstrip("/")
    except Exception:
        return None


def _is_access_token(header: dict[str, Any], payload: dict[str, Any]) -> bool:
    """Return whether a verified token's header and claims make it an access token.

    An access token carries the RFC 9068 typ at+jwt. A token without that typ
    counts as one only when its token_use claim says it is an access token, so
    an ID token is never accepted in place of an access token.
    """
    token_use = payload.get("token_use")
    typ = header.get("typ")
    if isinstance(typ, str) and typ.lower() in _ACCESS_TOKEN_TYPES:
        return token_use in (None, TOKEN_USE_ACCESS)
    return token_use == TOKEN_USE_ACCESS


def decode_access_token(
    domain_data: dict[str, Any], token: str, expected_issuer: str
) -> dict[str, Any]:
    """Verify an access token signed by this provider and return its claims.

    Checks the signature, expiry and issuer, and that the token is an access
    token rather than an ID token. The audience is left to the caller.

    The signature is checked with the published key named by the token's kid
    header, or with the current signing key when the token has no kid.

    Raises:
        jwt.InvalidTokenError: The token fails one of those checks.
    """
    kid = jwt.get_unverified_header(token).get("kid")
    if kid is None:
        public_key = domain_data["jwt_public_key"]
    else:
        public_key = domain_data.get("jwt_verification_keys", {}).get(kid)
        if public_key is None:
            raise jwt.InvalidTokenError("Signed with a key that is not published")

    decoded = jwt.decode_complete(
        token,
        public_key,
        algorithms=["RS256"],
        issuer=expected_issuer,
        options={"verify_aud": False},
    )
    if not _is_access_token(decoded["header"], decoded["payload"]):
        raise jwt.InvalidTokenError("Not an access token")
    return decoded["payload"]


def validate_access_token(
    hass: HomeAssistant,
    token: str,
    expected_issuer: str,
    expected_audience: str | None = None,
) -> dict[str, Any] | None:
    """
    Validate an OAuth access token issued by this OIDC provider.

    An ID token is refused even though this provider signed it.

    Args:
        hass: Home Assistant instance
        token: The access token to validate
        expected_issuer: Expected issuer URL
        expected_audience: The resource this token must be bound to (RFC 8707).
            When provided, the token is accepted only if its aud contains this
            value; a token bound to a client_id or another resource is rejected.
            When omitted, any registered client_id is accepted as the audience.

    Returns:
        Token payload if valid, None otherwise
    """
    try:
        if DOMAIN not in hass.data:
            _LOGGER.error("OIDC provider not loaded")
            return None

        if not hass.data[DOMAIN].get("jwt_public_key"):
            _LOGGER.error("JWT public key not found")
            return None

        # The issuer signed into tokens always has the /oidc suffix (RFC 8414).
        # External callers (e.g. hass-mcp-server) typically pass the base URL
        # without the suffix; tolerate both forms so they don't have to change
        # in lockstep.
        if not expected_issuer.rstrip("/").endswith("/oidc"):
            expected_issuer = expected_issuer.rstrip("/") + "/oidc"

        payload = decode_access_token(hass.data[DOMAIN], token, expected_issuer)

        # Verify the audience claim exists.
        aud = payload.get("aud")
        if not aud:
            _LOGGER.warning("Token missing audience claim")
            return None

        audiences = aud if isinstance(aud, list) else [aud]

        # A resource server that names itself only accepts tokens bound to it
        # (RFC 8707). A client_id audience is not a substitute: any registered
        # client can obtain one, so accepting it would let a token minted for
        # one client pass at every resource server.
        if expected_audience is not None:
            if expected_audience in audiences:
                return payload
            _LOGGER.warning("Token audience %s is not bound to resource %s", aud, expected_audience)
            return None

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
