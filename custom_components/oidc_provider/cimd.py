"""Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document).

A client whose client_id is an HTTPS URL is not registered here. Its metadata
is fetched from that URL when it starts an authorization, so clients such as
Claude can sign in without dynamic client registration. Such clients have no
secret: they authenticate at the token endpoint with PKCE alone.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import socket
import time
from typing import Any
from urllib.parse import urlsplit

import aiohttp
from aiohttp.abc import AbstractResolver, ResolveResult
from aiohttp.resolver import ThreadedResolver
from homeassistant.core import HomeAssistant
from homeassistant.util.ssl import client_context
from yarl import URL

from .client_manager import validate_client_name, validate_redirect_uris
from .const import (
    CIMD_CACHE_DEFAULT_TTL,
    CIMD_CACHE_MAX_ENTRIES,
    CIMD_CACHE_MAX_TTL,
    CIMD_CACHE_MIN_TTL,
    CIMD_FETCH_TIMEOUT,
    CIMD_FETCHES_PER_MINUTE,
    CIMD_FETCHES_PER_MINUTE_PER_ADDRESS,
    CIMD_MAX_DOCUMENT_BYTES,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

_MAX_AGE = re.compile(r"(?:^|,)\s*max-age\s*=\s*(\d+)", re.IGNORECASE)
# A DNS host name: dot-separated labels of letters, digits and inner hyphens
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOST_NAME = re.compile(rf"{_LABEL}(?:\.{_LABEL})*")


class ClientMetadataError(Exception):
    """The client_id URL or the document it serves cannot be used."""


def is_client_id_url(client_id: str | None) -> bool:
    """Return whether a client_id names a metadata document rather than a stored client."""
    return isinstance(client_id, str) and client_id.startswith("https://")


def client_id_host(client_id: str) -> str:
    """Return the host, and port if given, a metadata document client_id belongs to."""
    parts = urlsplit(client_id)
    host = parts.hostname or ""
    try:
        port = parts.port
    except ValueError:
        port = None
    return f"{host}:{port}" if port else host


def _is_ip_literal(host: str) -> bool:
    """Return whether a host is an IP address in any form a connection accepts.

    Besides the canonical forms, the system resolver and older aiohttp releases
    take shorthand IPv4 such as 127.1, 2130706433 or 0x7f.0.0.1 as an address
    without a lookup.
    """
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return True
    try:
        socket.inet_aton(host)
    except OSError:
        return False
    return True


def _check_client_id_url(client_id: str) -> None:
    """Enforce the client_id URL rules of the draft (§3)."""
    # The host is shown on the consent screen as the client's identity, where
    # a Unicode look-alike of another domain would read as that domain.
    if not client_id.isascii():
        raise ClientMetadataError("client_id must be ASCII, with a punycode host name")
    try:
        _check_client_id_parts(client_id)
    except ValueError as err:
        # urllib and yarl raise for malformed hosts such as [evil.com]
        raise ClientMetadataError("client_id is not a valid URL") from err


def _check_client_id_parts(client_id: str) -> None:
    """Check the parts of a client_id URL. Malformed URLs raise ValueError."""
    parts = urlsplit(client_id)
    if parts.scheme != "https" or not parts.hostname:
        raise ClientMetadataError("client_id must be an https URL with a host")
    if parts.username is not None or parts.password is not None:
        raise ClientMetadataError("client_id must not contain userinfo")
    if parts.fragment or "#" in client_id:
        raise ClientMetadataError("client_id must not contain a fragment")
    if parts.query:
        raise ClientMetadataError("client_id must not contain a query")
    if not parts.path or parts.path == "/":
        raise ClientMetadataError("client_id must contain a path")
    if any(segment in (".", "..") for segment in parts.path.split("/")):
        raise ClientMetadataError("client_id must not contain dot segments")
    parts.port  # raises ValueError for a port outside 0-65535
    # Some URL parsers accept characters no host name has, such as a
    # backslash, and leave it to the connection to fail.
    if not _HOST_NAME.fullmatch(parts.hostname):
        raise ClientMetadataError("client_id must use a valid host name")
    # aiohttp connects to IP literals without consulting the resolver, so the
    # public-address check below cannot cover them.
    if _is_ip_literal(parts.hostname):
        raise ClientMetadataError("client_id must use a host name, not an IP address")
    # The document is fetched from the URL as the HTTP client normalizes it.
    # Refusing any client_id that normalization would change, such as one with
    # encoded dot segments, keeps the fetched URL equal to the client_id.
    if str(URL(client_id)) != client_id:
        raise ClientMetadataError("client_id must be in normalized form")


# IPv6 prefixes that carry an IPv4 address in their last 32 bits, which is
# where such an address really leads: NAT64 (RFC 6052) and the deprecated
# IPv4-compatible form (RFC 4291 §2.5.5.1)
_IPV4_EMBEDDING_NETWORKS = (
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("::/96"),
)
# Not reachable from the internet, though Python counts them as global:
# local-use NAT64 (RFC 8215) and site-local addresses (RFC 3879)
_NON_PUBLIC_NETWORKS = (
    ipaddress.ip_network("64:ff9b:1::/48"),
    ipaddress.ip_network("fec0::/10"),
)


def _is_public_address(address: str) -> bool:
    """Return whether an address is reachable on the public internet.

    An IPv6 address that embeds an IPv4 address counts as that IPv4 address,
    so 64:ff9b::a00:5 is treated as the private 10.0.0.5 it translates to.
    """
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address):
        if any(ip in network for network in _NON_PUBLIC_NETWORKS):
            return False
        embedded = ip.ipv4_mapped or ip.sixtofour
        if embedded is None and any(ip in network for network in _IPV4_EMBEDDING_NETWORKS):
            embedded = ipaddress.IPv4Address(ip.packed[-4:])
        if embedded is not None:
            return embedded.is_global
    return ip.is_global


class PublicAddressResolver(AbstractResolver):
    """Resolve host names to public addresses only.

    The draft forbids fetching a document from special-use addresses (RFC 6890).
    Filtering at resolution time, inside the connection, means a host name that
    resolves differently between a check and the connect cannot reach the
    local network.
    """

    def __init__(self) -> None:
        self._resolver = ThreadedResolver()

    async def resolve(
        self, host: str, port: int = 0, family: socket.AddressFamily = socket.AF_INET
    ) -> list[ResolveResult]:
        results = await self._resolver.resolve(host, port, family)
        public = [result for result in results if _is_public_address(result["host"])]
        if not public:
            raise OSError(f"{host} does not resolve to a public address")
        return public

    async def close(self) -> None:
        await self._resolver.close()


def _cache_ttl(cache_control: str | None) -> float:
    """Return how long to keep a document, honoring Cache-Control within bounds.

    A document marked no-store or no-cache is not kept at all.
    """
    if cache_control:
        if "no-store" in cache_control.lower() or "no-cache" in cache_control.lower():
            return 0
        match = _MAX_AGE.search(cache_control)
        if match:
            return min(max(int(match.group(1)), CIMD_CACHE_MIN_TTL), CIMD_CACHE_MAX_TTL)
    return CIMD_CACHE_DEFAULT_TTL


def _client_from_document(client_id: str, document: Any) -> dict[str, Any]:
    """Validate a fetched document and return the client it describes (§4)."""
    if not isinstance(document, dict):
        raise ClientMetadataError("metadata document must be a JSON object")
    if document.get("client_id") != client_id:
        raise ClientMetadataError("metadata document client_id does not match its URL")
    if "client_secret" in document or "client_secret_expires_at" in document:
        raise ClientMetadataError("metadata document must not contain a client secret")
    auth_method = document.get("token_endpoint_auth_method", "none")
    if auth_method != "none":
        raise ClientMetadataError("unsupported token_endpoint_auth_method")
    for field, required in (("grant_types", "authorization_code"), ("response_types", "code")):
        values = document.get(field, [required])
        if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
            raise ClientMetadataError(f"metadata document {field} must be a list of strings")
        if required not in values:
            raise ClientMetadataError(f"metadata document {field} does not include {required}")

    redirect_uris = document.get("redirect_uris")
    if not isinstance(redirect_uris, list) or not redirect_uris:
        raise ClientMetadataError("metadata document has no redirect_uris")
    try:
        validate_redirect_uris(redirect_uris)
    except ValueError as err:
        raise ClientMetadataError(str(err)) from err

    try:
        client_name = validate_client_name(document.get("client_name"))
    except ValueError:
        client_name = client_id_host(client_id)

    return {
        "client_name": client_name,
        "redirect_uris": list(redirect_uris),
        "token_endpoint_auth_method": "none",
        "consent_required": True,
        "metadata_document": True,
    }


async def _fetch_document(client_id: str) -> tuple[Any, float]:
    """Fetch a metadata document. Returns the parsed JSON and how long to cache it."""
    connector = aiohttp.TCPConnector(resolver=PublicAddressResolver(), ssl=client_context())
    timeout = aiohttp.ClientTimeout(total=CIMD_FETCH_TIMEOUT)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        async with session.get(
            client_id,
            allow_redirects=False,
            headers={"Accept": "application/json", "User-Agent": "HomeAssistant-OIDC-Provider"},
        ) as response:
            if response.status != 200:
                raise ClientMetadataError(f"metadata document returned HTTP {response.status}")
            # read(n) returns what has arrived so far, so a document sent in
            # several pieces is read until it ends or passes the limit.
            body = b""
            while len(body) <= CIMD_MAX_DOCUMENT_BYTES:
                chunk = await response.content.read(CIMD_MAX_DOCUMENT_BYTES + 1 - len(body))
                if not chunk:
                    break
                body += chunk
            if len(body) > CIMD_MAX_DOCUMENT_BYTES:
                raise ClientMetadataError("metadata document is too large")
            try:
                document = json.loads(body)
            except ValueError as err:
                raise ClientMetadataError("metadata document is not valid JSON") from err
            return document, _cache_ttl(response.headers.get("Cache-Control"))


def _take_fetch_slot(hass: HomeAssistant, remote: str | None, now: float) -> None:
    """Count a fetch against the per-minute limits, or raise when one is reached.

    Anyone can start an authorization, so fetches that miss the cache are
    limited overall and per remote address. The per-address limit keeps one
    caller from using up the overall one with documents that do not exist.
    """
    recent: list[float] = hass.data[DOMAIN].setdefault("cimd_fetch_times", [])
    recent[:] = [t for t in recent if t > now - 60]
    by_address: dict[str, list[float]] = hass.data[DOMAIN].setdefault(
        "cimd_fetch_times_by_address", {}
    )
    for address in list(by_address):
        by_address[address] = [t for t in by_address[address] if t > now - 60]
        if not by_address[address]:
            del by_address[address]

    address_recent = by_address.get(remote or "", [])
    if (
        len(recent) >= CIMD_FETCHES_PER_MINUTE
        or len(address_recent) >= CIMD_FETCHES_PER_MINUTE_PER_ADDRESS
    ):
        raise ClientMetadataError("too many metadata document fetches, try again later")
    recent.append(now)
    by_address.setdefault(remote or "", []).append(now)


async def async_resolve_client(
    hass: HomeAssistant, client_id: str, remote: str | None = None
) -> dict[str, Any]:
    """Return the client a metadata document client_id describes.

    Documents are cached in memory for their Cache-Control lifetime, within
    bounds. Errors are not cached (§5.2). Fetches that miss the cache are
    limited per minute, overall and for the remote address that started the
    authorization. Why a fetch failed is only logged: the response to the
    caller stays the same, so it cannot probe what the server can reach.

    Raises:
        ClientMetadataError: If the URL or the document cannot be used
    """
    _check_client_id_url(client_id)

    now = time.time()
    cache: dict[str, tuple[float, dict[str, Any]]] = hass.data[DOMAIN].setdefault("cimd_cache", {})
    cached = cache.get(client_id)
    if cached and cached[0] > now:
        # Moving a used entry to the end keeps it from being the next evicted,
        # so documents nobody uses cannot push out the ones that are
        cache[client_id] = cache.pop(client_id)
        return cached[1]

    _take_fetch_slot(hass, remote, now)

    try:
        document, ttl = await _fetch_document(client_id)
    except (ClientMetadataError, aiohttp.ClientError, OSError, TimeoutError) as err:
        _LOGGER.debug("Fetching metadata document %s failed: %s", client_id, err)
        raise ClientMetadataError("metadata document could not be fetched") from err

    client = _client_from_document(client_id, document)

    # Re-inserting moves the entry to the end, so the oldest fetch goes first
    cache.pop(client_id, None)
    if ttl > 0:
        cache[client_id] = (now + ttl, client)
    while len(cache) > CIMD_CACHE_MAX_ENTRIES:
        del cache[next(iter(cache))]
    return client
