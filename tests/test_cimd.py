"""Tests for Client ID Metadata Document resolution."""

import json
import socket
from unittest.mock import AsyncMock, Mock, patch

import aiohttp
import pytest

from custom_components.oidc_provider import cimd
from custom_components.oidc_provider.cimd import (
    ClientMetadataError,
    PublicAddressResolver,
    _cache_ttl,
    _check_client_id_url,
    _client_from_document,
    async_resolve_client,
    client_id_host,
    is_client_id_url,
)
from custom_components.oidc_provider.const import (
    CIMD_CACHE_DEFAULT_TTL,
    CIMD_CACHE_MAX_ENTRIES,
    CIMD_CACHE_MAX_TTL,
    CIMD_CACHE_MIN_TTL,
    CIMD_FETCHES_PER_MINUTE,
    CIMD_FETCHES_PER_MINUTE_PER_ADDRESS,
    CIMD_MAX_DOCUMENT_BYTES,
    DOMAIN,
)

CLIENT_ID = "https://claude.ai/oauth/claude-code-client-metadata"

# The document Claude Code serves at its client_id
CLAUDE_CODE_DOCUMENT = {
    "client_id": CLIENT_ID,
    "client_name": "Claude Code",
    "client_uri": "https://claude.ai",
    "redirect_uris": ["http://localhost/callback", "http://127.0.0.1/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "none",
}


def _hass():
    hass = Mock()
    hass.data = {DOMAIN: {}}
    return hass


class TestClientIdUrl:
    """The client_id URL rules (draft §3)."""

    def test_metadata_client_ids_are_https_urls(self):
        assert is_client_id_url(CLIENT_ID)
        assert not is_client_id_url("abc123")
        assert not is_client_id_url("http://example.com/client")
        assert not is_client_id_url(None)

    def test_host(self):
        assert client_id_host(CLIENT_ID) == "claude.ai"
        assert client_id_host("https://example.com:8443/client") == "example.com:8443"

    def test_valid_url_passes(self):
        _check_client_id_url(CLIENT_ID)
        _check_client_id_url("https://example.com:8443/client.json")

    @pytest.mark.parametrize(
        "client_id",
        [
            "https://user:pw@example.com/client",
            "https://example.com/client#frag",
            "https://example.com/client?x=1",
            "https://example.com",
            "https://example.com/",
            "https://example.com/a/../client",
            "https://example.com/./client",
            "https://example.com:99999/client",
            "https://10.0.0.5/client",
            "https://8.8.8.8/client",
            "https://[::1]/client",
            # Shorthand IPv4 that the system resolver and older aiohttp take as
            # an address without a lookup
            "https://127.1/client",
            "https://2130706433/client",
            "https://0177.0.0.1/client",
            "https://0x7f.0.0.1/client",
            "https://3232235777:22/client",
            # A look-alike of claude.ai (Cyrillic es)
            "https://\u0441laude.ai/oauth/claude-code-client-metadata",
            # Encoded dot segments that normalization would resolve
            "https://example.com/trusted/%2e%2e/attacker/client",
        ],
    )
    def test_invalid_urls_are_refused(self, client_id):
        with pytest.raises(ClientMetadataError):
            _check_client_id_url(client_id)


class TestDocument:
    """Validation of the fetched document (draft §4)."""

    def test_claude_code_document(self):
        client = _client_from_document(CLIENT_ID, CLAUDE_CODE_DOCUMENT)

        assert client == {
            "client_name": "Claude Code",
            "redirect_uris": ["http://localhost/callback", "http://127.0.0.1/callback"],
            "token_endpoint_auth_method": "none",
            "consent_required": True,
            "metadata_document": True,
        }

    def test_missing_name_falls_back_to_host(self):
        document = {k: v for k, v in CLAUDE_CODE_DOCUMENT.items() if k != "client_name"}

        assert _client_from_document(CLIENT_ID, document)["client_name"] == "claude.ai"

    def test_auth_method_defaults_to_none(self):
        document = {
            k: v for k, v in CLAUDE_CODE_DOCUMENT.items() if k != "token_endpoint_auth_method"
        }

        assert _client_from_document(CLIENT_ID, document)["token_endpoint_auth_method"] == "none"

    @pytest.mark.parametrize(
        "changes",
        [
            {"client_id": "https://evil.example.com/client"},
            {"client_secret": "s3cret"},
            {"client_secret_expires_at": 0},
            {"token_endpoint_auth_method": "client_secret_basic"},
            {"token_endpoint_auth_method": "private_key_jwt"},
            {"redirect_uris": []},
            {"redirect_uris": "http://localhost/callback"},
            {"redirect_uris": ["http://evil.example.com/callback"]},
            {"grant_types": ["client_credentials"]},
            {"response_types": ["token"]},
            {"grant_types": None},
            {"grant_types": 5},
            {"response_types": "code"},
            {"redirect_uris": ["http://localhost/callback#fragment"]},
            {"redirect_uris": ["https://\u0441laude.ai/callback"]},
        ],
    )
    def test_unusable_documents_are_refused(self, changes):
        with pytest.raises(ClientMetadataError):
            _client_from_document(CLIENT_ID, {**CLAUDE_CODE_DOCUMENT, **changes})

    def test_non_object_is_refused(self):
        with pytest.raises(ClientMetadataError):
            _client_from_document(CLIENT_ID, ["not", "an", "object"])


class TestCacheTtl:
    """Cache lifetime follows Cache-Control within bounds (draft §5.2)."""

    def test_max_age_is_honored(self):
        assert _cache_ttl("public, max-age=300") == 300

    def test_max_age_is_bounded(self):
        assert _cache_ttl("max-age=1") == CIMD_CACHE_MIN_TTL
        assert _cache_ttl("max-age=99999999") == CIMD_CACHE_MAX_TTL

    def test_default_without_header(self):
        assert _cache_ttl(None) == CIMD_CACHE_DEFAULT_TTL
        assert _cache_ttl("public") == CIMD_CACHE_DEFAULT_TTL

    def test_no_store_is_not_kept(self):
        assert _cache_ttl("no-store") == 0
        assert _cache_ttl("private, no-cache") == 0


class TestPublicAddressResolver:
    """Documents are never fetched from special-use addresses (draft §8.6)."""

    @staticmethod
    def _result(address):
        return {
            "hostname": "example.com",
            "host": address,
            "port": 443,
            "family": socket.AF_INET,
            "proto": 0,
            "flags": 0,
        }

    async def test_keeps_only_public_addresses(self):
        resolver = PublicAddressResolver()
        results = [self._result(a) for a in ("10.0.0.1", "93.184.215.14", "127.0.0.1")]
        with patch.object(resolver._resolver, "resolve", AsyncMock(return_value=results)):
            resolved = await resolver.resolve("example.com", 443)

        assert [r["host"] for r in resolved] == ["93.184.215.14"]

    @pytest.mark.parametrize(
        "address",
        ["127.0.0.1", "10.1.2.3", "192.168.1.10", "169.254.1.1", "100.64.0.1", "::1", "fd00::1"]
        + ["::ffff:192.168.1.10"],
    )
    async def test_refuses_names_resolving_only_to_special_use_addresses(self, address):
        resolver = PublicAddressResolver()
        with patch.object(
            resolver._resolver, "resolve", AsyncMock(return_value=[self._result(address)])
        ):
            with pytest.raises(OSError):
                await resolver.resolve("internal.example.com", 443)


class _FakeResponse:
    """A response whose body arrives in pieces of at most `chunk` bytes, like a stream."""

    def __init__(self, status=200, body=b"", headers=None, chunk=None):
        self.status = status
        self.headers = headers or {}
        remaining = bytearray(body)

        async def read(n):
            size = min(n, chunk or n, len(remaining))
            piece = bytes(remaining[:size])
            del remaining[:size]
            return piece

        self.content = Mock()
        self.content.read = read

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


class _FakeSession:
    def __init__(self, response, calls):
        self._response = response
        self._calls = calls

    def get(self, url, **kwargs):
        self._calls.append((url, kwargs))
        return self._response

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


def _session_returning(response, calls):
    return patch.object(
        cimd.aiohttp, "ClientSession", lambda **kwargs: _FakeSession(response, calls)
    )


class TestFetch:
    """The HTTP fetch of a document (draft §5)."""

    async def test_fetches_without_following_redirects(self):
        calls = []
        response = _FakeResponse(
            body=json.dumps(CLAUDE_CODE_DOCUMENT).encode(),
            headers={"Cache-Control": "max-age=300"},
        )
        with _session_returning(response, calls):
            document, ttl = await cimd._fetch_document(CLIENT_ID)

        assert document == CLAUDE_CODE_DOCUMENT
        assert ttl == 300
        assert calls[0][0] == CLIENT_ID
        assert calls[0][1]["allow_redirects"] is False

    async def test_document_arriving_in_pieces_is_read_whole(self):
        body = json.dumps(CLAUDE_CODE_DOCUMENT).encode()
        with _session_returning(_FakeResponse(body=body, chunk=50), []):
            document, _ = await cimd._fetch_document(CLIENT_ID)

        assert document == CLAUDE_CODE_DOCUMENT

    @pytest.mark.parametrize("status", [301, 404, 500])
    async def test_non_200_is_an_error(self, status):
        with _session_returning(_FakeResponse(status=status), []):
            with pytest.raises(ClientMetadataError):
                await cimd._fetch_document(CLIENT_ID)

    async def test_oversized_document_is_an_error(self):
        body = b"{" + b" " * CIMD_MAX_DOCUMENT_BYTES + b"}"
        with _session_returning(_FakeResponse(body=body, chunk=1000), []):
            with pytest.raises(ClientMetadataError, match="too large"):
                await cimd._fetch_document(CLIENT_ID)

    async def test_fetch_goes_through_the_public_address_resolver(self):
        """A real fetch of a name for a loopback address never connects."""
        with pytest.raises((aiohttp.ClientError, OSError)) as raised:
            await cimd._fetch_document("https://localhost:1/client")

        assert "does not resolve to a public address" in str(raised.value.__cause__)

    async def test_invalid_json_is_an_error(self):
        with _session_returning(_FakeResponse(body=b"<html>"), []):
            with pytest.raises(ClientMetadataError, match="JSON"):
                await cimd._fetch_document(CLIENT_ID)


class TestResolveClient:
    """Resolution with caching and fetch limits."""

    async def test_resolves_and_caches(self):
        hass = _hass()
        fetch = AsyncMock(return_value=(CLAUDE_CODE_DOCUMENT, 300))
        with patch.object(cimd, "_fetch_document", fetch):
            first = await async_resolve_client(hass, CLIENT_ID)
            second = await async_resolve_client(hass, CLIENT_ID)

        assert first["client_name"] == "Claude Code"
        assert second is first
        fetch.assert_awaited_once()

    async def test_expired_cache_entry_is_fetched_again(self):
        hass = _hass()
        fetch = AsyncMock(return_value=(CLAUDE_CODE_DOCUMENT, 300))
        with patch.object(cimd, "_fetch_document", fetch):
            await async_resolve_client(hass, CLIENT_ID)
            expires, client = hass.data[DOMAIN]["cimd_cache"][CLIENT_ID]
            hass.data[DOMAIN]["cimd_cache"][CLIENT_ID] = (0, client)
            await async_resolve_client(hass, CLIENT_ID)

        assert fetch.await_count == 2

    async def test_invalid_documents_are_not_cached(self):
        hass = _hass()
        bad = {**CLAUDE_CODE_DOCUMENT, "client_secret": "x"}
        with patch.object(cimd, "_fetch_document", AsyncMock(return_value=(bad, 300))):
            with pytest.raises(ClientMetadataError):
                await async_resolve_client(hass, CLIENT_ID)

        assert hass.data[DOMAIN]["cimd_cache"] == {}

    @pytest.mark.parametrize(
        "error",
        [
            aiohttp.ClientConnectionError("Connect call failed ('10.0.0.1', 22)"),
            ClientMetadataError("metadata document returned HTTP 404"),
            TimeoutError(),
        ],
    )
    async def test_fetch_failures_do_not_say_why(self, error):
        """The caller gets the same message whatever went wrong, so it cannot probe."""
        hass = _hass()
        with patch.object(cimd, "_fetch_document", AsyncMock(side_effect=error)):
            with pytest.raises(ClientMetadataError) as raised:
                await async_resolve_client(hass, CLIENT_ID)

        assert str(raised.value) == "metadata document could not be fetched"

    async def test_no_store_documents_are_not_cached(self):
        hass = _hass()
        fetch = AsyncMock(return_value=(CLAUDE_CODE_DOCUMENT, 0))
        with patch.object(cimd, "_fetch_document", fetch):
            await async_resolve_client(hass, CLIENT_ID)
            await async_resolve_client(hass, CLIENT_ID)

        assert fetch.await_count == 2

    async def test_invalid_url_is_refused_without_fetching(self):
        hass = _hass()
        fetch = AsyncMock()
        with patch.object(cimd, "_fetch_document", fetch):
            with pytest.raises(ClientMetadataError):
                await async_resolve_client(hass, "https://192.168.1.2/client")

        fetch.assert_not_awaited()

    async def test_fetches_are_limited_per_address(self):
        """One caller cannot use up the fetches everyone shares."""
        hass = _hass()
        fetch = AsyncMock(side_effect=lambda client_id: ({**CLAUDE_CODE_DOCUMENT}, 300))
        with patch.object(cimd, "_fetch_document", fetch):
            for i in range(CIMD_FETCHES_PER_MINUTE_PER_ADDRESS):
                with pytest.raises(ClientMetadataError):
                    # Each URL is distinct, so each misses the cache; the
                    # document's client_id does not match, so none is cached.
                    await async_resolve_client(hass, f"https://example.com/c{i}", "198.51.100.7")
            with pytest.raises(ClientMetadataError, match="too many"):
                await async_resolve_client(hass, CLIENT_ID, "198.51.100.7")

            client = await async_resolve_client(hass, CLIENT_ID, "203.0.113.9")

        assert client["client_name"] == "Claude Code"

    async def test_fetches_are_limited_overall(self):
        hass = _hass()
        fetch = AsyncMock(side_effect=lambda client_id: ({**CLAUDE_CODE_DOCUMENT}, 300))
        with patch.object(cimd, "_fetch_document", fetch):
            for i in range(CIMD_FETCHES_PER_MINUTE):
                with pytest.raises(ClientMetadataError):
                    await async_resolve_client(hass, f"https://example.com/c{i}", f"192.0.2.{i}")
            with pytest.raises(ClientMetadataError, match="too many"):
                await async_resolve_client(hass, CLIENT_ID, "203.0.113.9")

        assert fetch.await_count == CIMD_FETCHES_PER_MINUTE

    async def test_cache_is_bounded(self):
        hass = _hass()
        cache = hass.data[DOMAIN].setdefault("cimd_cache", {})
        for i in range(CIMD_CACHE_MAX_ENTRIES):
            cache[f"https://example.com/c{i}"] = (10_000_000_000 + i, {})
        with patch.object(
            cimd, "_fetch_document", AsyncMock(return_value=(CLAUDE_CODE_DOCUMENT, 300))
        ):
            await async_resolve_client(hass, CLIENT_ID)

        assert len(cache) == CIMD_CACHE_MAX_ENTRIES
        assert CLIENT_ID in cache
