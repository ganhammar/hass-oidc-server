"""Tests for client manager."""

from unittest.mock import AsyncMock, Mock

import pytest

from custom_components.oidc_provider.client_manager import create_client
from custom_components.oidc_provider.const import DOMAIN


@pytest.fixture
async def mock_hass(hass):
    """Create a mock Home Assistant instance with OIDC provider data."""
    hass.data[DOMAIN] = {}

    # Mock the store
    mock_store = Mock()
    mock_store.async_save = AsyncMock()
    hass.data[DOMAIN]["store"] = mock_store

    return hass


async def test_create_client_with_defaults(mock_hass):
    """Test creating a client with default values."""
    result = await create_client(
        mock_hass, client_name="Test Client", redirect_uris=["http://localhost/callback"]
    )

    # Verify returned data
    assert result["client_name"] == "Test Client"
    assert result["redirect_uris"] == ["http://localhost/callback"]
    assert result["grant_types"] == ["authorization_code", "refresh_token"]
    assert result["response_types"] == ["code"]
    assert result["token_endpoint_auth_method"] == "client_secret_basic"

    # Verify client_id and client_secret are generated
    assert "client_id" in result
    assert "client_secret" in result
    assert len(result["client_id"]) > 20
    assert len(result["client_secret"]) > 20

    # Verify client is stored in hass.data
    client_id = result["client_id"]
    assert client_id in mock_hass.data[DOMAIN]["clients"]

    stored_client = mock_hass.data[DOMAIN]["clients"][client_id]
    assert stored_client["client_name"] == "Test Client"
    assert stored_client["redirect_uris"] == ["http://localhost/callback"]
    assert "client_secret_hash" in stored_client
    assert "client_secret" not in stored_client  # Plain text not stored
    # Operator-registered clients are first-party and skip the consent screen
    assert stored_client["consent_required"] is False
    assert result["consent_required"] is False


async def test_create_client_with_consent_required(mock_hass):
    """consent_required is stored and returned when set."""
    result = await create_client(
        mock_hass,
        client_name="Third Party",
        redirect_uris=["https://example.com/callback"],
        consent_required=True,
    )

    assert result["consent_required"] is True
    stored_client = mock_hass.data[DOMAIN]["clients"][result["client_id"]]
    assert stored_client["consent_required"] is True


async def test_create_client_generates_unique_id(mock_hass):
    """Test that create_client generates a unique client ID."""
    result = await create_client(
        mock_hass,
        client_name="Generated ID Client",
        redirect_uris=["https://example.com/callback"],
    )

    # Verify client ID is generated and non-empty
    assert "client_id" in result
    assert len(result["client_id"]) > 20
    assert result["client_id"] in mock_hass.data[DOMAIN]["clients"]


async def test_create_client_with_custom_grant_types(mock_hass):
    """Test creating a client with custom grant types."""
    result = await create_client(
        mock_hass,
        client_name="Custom Grant Client",
        redirect_uris=["http://localhost/callback"],
        grant_types=["authorization_code"],
        response_types=["code"],
    )

    assert result["grant_types"] == ["authorization_code"]
    assert result["response_types"] == ["code"]

    stored = mock_hass.data[DOMAIN]["clients"][result["client_id"]]
    assert stored["grant_types"] == ["authorization_code"]


async def test_create_client_secret_is_hashed(mock_hass):
    """Test that client secret is hashed in storage."""
    result = await create_client(
        mock_hass, client_name="Hash Test Client", redirect_uris=["http://localhost/callback"]
    )

    client_id = result["client_id"]

    stored = mock_hass.data[DOMAIN]["clients"][client_id]

    # Verify secret is not stored in plain text
    assert "client_secret" not in stored
    assert "client_secret_hash" in stored

    # Verify the hash format (should be salt:hash)
    secret_hash = stored["client_secret_hash"]
    assert ":" in secret_hash
    parts = secret_hash.split(":")
    assert len(parts) == 2
    assert len(parts[0]) == 64  # Salt hex length
    assert len(parts[1]) == 64  # Hash hex length


async def test_create_client_initializes_clients_dict(mock_hass):
    """Test that create_client initializes clients dict if it doesn't exist."""
    # Don't pre-initialize clients
    assert "clients" not in mock_hass.data[DOMAIN]

    await create_client(
        mock_hass, client_name="Init Test Client", redirect_uris=["http://localhost/callback"]
    )

    # Verify clients dict was created
    assert "clients" in mock_hass.data[DOMAIN]
    assert isinstance(mock_hass.data[DOMAIN]["clients"], dict)


async def test_create_client_multiple_clients(mock_hass):
    """Test creating multiple clients."""
    client1 = await create_client(
        mock_hass, client_name="Client 1", redirect_uris=["http://localhost:8001/callback"]
    )

    client2 = await create_client(
        mock_hass, client_name="Client 2", redirect_uris=["http://localhost:8002/callback"]
    )

    # Verify both clients are stored
    assert client1["client_id"] in mock_hass.data[DOMAIN]["clients"]
    assert client2["client_id"] in mock_hass.data[DOMAIN]["clients"]

    # Verify they have different IDs and secrets
    assert client1["client_id"] != client2["client_id"]
    assert client1["client_secret"] != client2["client_secret"]


async def test_create_client_with_multiple_redirect_uris(mock_hass):
    """Test creating a client with multiple redirect URIs."""
    redirect_uris = [
        "http://localhost:8080/callback",
        "http://localhost:3000/callback",
        "https://example.com/callback",
    ]

    result = await create_client(
        mock_hass, client_name="Multi Redirect Client", redirect_uris=redirect_uris
    )

    assert result["redirect_uris"] == redirect_uris
    stored = mock_hass.data[DOMAIN]["clients"][result["client_id"]]
    assert stored["redirect_uris"] == redirect_uris


async def test_create_client_with_empty_redirect_uris(mock_hass):
    """Test creating a client with empty redirect URIs list."""
    result = await create_client(mock_hass, client_name="No Redirect Client", redirect_uris=[])

    assert result["redirect_uris"] == []


async def test_create_client_with_client_secret_post(mock_hass):
    """Test creating a client with client_secret_post auth method."""
    result = await create_client(
        mock_hass,
        client_name="Post Auth Client",
        redirect_uris=["http://localhost/callback"],
        token_endpoint_auth_method="client_secret_post",
    )

    assert result["token_endpoint_auth_method"] == "client_secret_post"
    stored = mock_hass.data[DOMAIN]["clients"][result["client_id"]]
    assert stored["token_endpoint_auth_method"] == "client_secret_post"


async def test_create_client_id_uniqueness(mock_hass):
    """Test that generated client IDs are unique."""
    client_ids = set()

    for i in range(100):
        result = await create_client(
            mock_hass, client_name=f"Client {i}", redirect_uris=["http://localhost/callback"]
        )
        client_ids.add(result["client_id"])

    # All 100 client IDs should be unique
    assert len(client_ids) == 100


async def test_create_client_secret_uniqueness(mock_hass):
    """Test that generated client secrets are unique."""
    secrets = set()

    for i in range(100):
        result = await create_client(
            mock_hass, client_name=f"Client {i}", redirect_uris=["http://localhost/callback"]
        )
        secrets.add(result["client_secret"])

    # All 100 client secrets should be unique
    assert len(secrets) == 100


async def test_create_client_invalid_redirect_uri(mock_hass):
    """Test that create_client rejects invalid redirect URIs."""
    with pytest.raises(ValueError, match="Invalid redirect_uri"):
        await create_client(
            mock_hass,
            client_name="Invalid URI Client",
            redirect_uris=["not-a-valid-url"],
        )


async def test_create_client_redirect_uri_missing_scheme(mock_hass):
    """Test that create_client rejects URIs without scheme."""
    with pytest.raises(ValueError, match="Invalid redirect_uri"):
        await create_client(
            mock_hass,
            client_name="No Scheme Client",
            redirect_uris=["example.com/callback"],
        )


async def test_create_client_redirect_uri_invalid_scheme(mock_hass):
    """Test that create_client rejects non-http(s) schemes."""
    with pytest.raises(ValueError, match="must use http or https"):
        await create_client(
            mock_hass,
            client_name="FTP Client",
            redirect_uris=["ftp://example.com/callback"],
        )


async def test_create_client_redirect_uri_non_string(mock_hass):
    """Test that create_client rejects non-string redirect URIs."""
    with pytest.raises(ValueError, match="must be a string"):
        await create_client(
            mock_hass,
            client_name="Non-String Client",
            redirect_uris=[123],
        )


async def test_create_client_valid_https_redirect_uri(mock_hass):
    """Test that create_client accepts valid HTTPS URIs."""
    result = await create_client(
        mock_hass,
        client_name="HTTPS Client",
        redirect_uris=["https://example.com/callback"],
    )

    assert result["redirect_uris"] == ["https://example.com/callback"]


async def test_create_client_mixed_valid_invalid_uris(mock_hass):
    """Test that create_client rejects if any URI is invalid."""
    with pytest.raises(ValueError, match="Invalid redirect_uri"):
        await create_client(
            mock_hass,
            client_name="Mixed Client",
            redirect_uris=[
                "https://example.com/callback",
                "invalid-url",
                "http://localhost/callback",
            ],
        )


async def test_create_client_http_non_localhost_rejected(mock_hass):
    """Test that HTTP redirect URIs are rejected for non-localhost hosts (RFC 8252 §8.3)."""
    with pytest.raises(ValueError, match="must use HTTPS"):
        await create_client(
            mock_hass,
            client_name="HTTP Non-Localhost Client",
            redirect_uris=["http://example.com/callback"],
        )


async def test_create_client_http_localhost_allowed(mock_hass):
    """Test that HTTP redirect URIs are allowed for localhost."""
    result = await create_client(
        mock_hass,
        client_name="HTTP Localhost Client",
        redirect_uris=["http://localhost/callback"],
    )
    assert result["redirect_uris"] == ["http://localhost/callback"]


async def test_create_client_http_127_0_0_1_allowed(mock_hass):
    """Test that HTTP redirect URIs are allowed for 127.0.0.1."""
    result = await create_client(
        mock_hass,
        client_name="HTTP 127.0.0.1 Client",
        redirect_uris=["http://127.0.0.1:8080/callback"],
    )
    assert result["redirect_uris"] == ["http://127.0.0.1:8080/callback"]


async def test_create_client_http_ipv6_localhost_allowed(mock_hass):
    """Test that HTTP redirect URIs are allowed for IPv6 localhost (::1)."""
    result = await create_client(
        mock_hass,
        client_name="HTTP IPv6 Localhost Client",
        redirect_uris=["http://[::1]:8080/callback"],
    )
    assert result["redirect_uris"] == ["http://[::1]:8080/callback"]


async def test_create_client_http_production_domain_rejected(mock_hass):
    """Test that HTTP redirect URIs are rejected for production domains."""
    with pytest.raises(ValueError, match="must use HTTPS"):
        await create_client(
            mock_hass,
            client_name="HTTP Production Client",
            redirect_uris=["http://app.example.com/callback"],
        )


async def test_create_client_rejects_userinfo_in_redirect_uri(mock_hass):
    """A redirect URI with userinfo could spoof the host shown on the consent screen."""
    with pytest.raises(ValueError, match="userinfo"):
        await create_client(
            mock_hass,
            client_name="Spoof",
            redirect_uris=["https://ha.example.com@attacker.example/callback"],
        )


async def test_create_client_rejects_out_of_range_port(mock_hass):
    """An out-of-range port would raise later when the host is displayed."""
    with pytest.raises(ValueError, match="invalid port"):
        await create_client(
            mock_hass,
            client_name="Bad Port",
            redirect_uris=["https://example.com:99999/callback"],
        )


@pytest.mark.parametrize(
    "client_name",
    [None, 42, "", "   ", "x" * 101],
    ids=["none", "int", "empty", "blank", "too-long"],
)
async def test_create_client_rejects_bad_client_name(mock_hass, client_name):
    """The client name is rendered on the consent screen and must be a bounded string."""
    with pytest.raises(ValueError, match="client_name"):
        await create_client(
            mock_hass,
            client_name=client_name,
            redirect_uris=["https://example.com/callback"],
        )


async def test_create_client_strips_client_name(mock_hass):
    """Surrounding whitespace is not part of the display name."""
    result = await create_client(
        mock_hass, client_name="  Padded  ", redirect_uris=["https://example.com/callback"]
    )
    assert result["client_name"] == "Padded"


@pytest.mark.parametrize(
    "uri",
    [
        "https://сlaude.ai/callback",
        "https://app.example.com/callback#section",
        "http://localhost/callback#",
    ],
)
def test_redirect_uris_must_be_ascii_without_fragment(uri):
    """Look-alike hosts would mislead the consent screen; fragments are not allowed (RFC 6749)."""
    from custom_components.oidc_provider.client_manager import validate_redirect_uris

    with pytest.raises(ValueError):
        validate_redirect_uris([uri])


@pytest.mark.parametrize(
    "name",
    ["Claude\nInjected", "Evil\u202eedoc", "Zero\u200bWidth", "Tab\there", "Line\u2028sep"],
)
def test_client_name_rejects_control_and_formatting_characters(name):
    """Names anyone can choose must not reorder or break the text around them."""
    from custom_components.oidc_provider.client_manager import validate_client_name

    with pytest.raises(ValueError):
        validate_client_name(name)


def test_client_name_allows_ordinary_unicode():
    from custom_components.oidc_provider.client_manager import validate_client_name

    assert validate_client_name("Café Assistant 日本") == "Café Assistant 日本"
