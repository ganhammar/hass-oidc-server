"""Tests for HTTP endpoints."""

import json
import time
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import jwt
import pytest

from custom_components.oidc_provider.const import DOMAIN
from custom_components.oidc_provider.http import (
    OAuth2AuthorizationServerMetadataAlternateView,
    OAuth2AuthorizationServerMetadataView,
    OIDCContinueView,
    OIDCDiscoveryView,
    OIDCJWKSView,
    OIDCRegisterView,
)
from custom_components.oidc_provider.token_validator import (
    _get_ha_external_url,
    get_issuer_from_request,
)


def test_get_base_url_with_forwarded_headers():
    """Test get_issuer_from_request with X-Forwarded headers (proxy setup)."""
    # Create a mock request with X-Forwarded headers
    request = Mock()
    request.headers = {
        "X-Forwarded-Proto": "https",
        "X-Forwarded-Host": "example.com",
    }
    request.url.origin.return_value = "http://localhost:8123"

    result = get_issuer_from_request(request)

    assert result == "https://example.com"
    # Verify that request.url.origin() was not called when headers are present
    request.url.origin.assert_not_called()


def test_get_base_url_without_forwarded_headers():
    """Test get_issuer_from_request without X-Forwarded headers (direct connection)."""
    # Create a mock request without X-Forwarded headers
    request = Mock()
    request.headers = {}
    request.url.origin.return_value = "http://192.168.1.100:8123"

    result = get_issuer_from_request(request)

    assert result == "http://192.168.1.100:8123"
    # Verify that request.url.origin() was called
    request.url.origin.assert_called_once()


def test_get_base_url_with_partial_forwarded_headers():
    """Test get_issuer_from_request with only one X-Forwarded header (should use fallback)."""
    # Create a mock request with only X-Forwarded-Proto
    request = Mock()
    request.headers = {
        "X-Forwarded-Proto": "https",
    }
    request.url.origin.return_value = "http://localhost:8123"

    result = get_issuer_from_request(request)

    assert result == "http://localhost:8123"
    # Should fall back to origin() when both headers aren't present
    request.url.origin.assert_called_once()


def test_get_base_url_with_only_host_header():
    """Test get_issuer_from_request with only X-Forwarded-Host (should use fallback)."""
    # Create a mock request with only X-Forwarded-Host
    request = Mock()
    request.headers = {
        "X-Forwarded-Host": "example.com",
    }
    request.url.origin.return_value = "http://localhost:8123"

    result = get_issuer_from_request(request)

    assert result == "http://localhost:8123"
    # Should fall back to origin() when both headers aren't present
    request.url.origin.assert_called_once()


def test_get_base_url_uses_ha_external_url():
    """Test get_issuer_from_request uses HA external URL when no forwarded headers."""
    request = Mock()
    request.headers = {}
    request.url.origin.return_value = "http://192.168.1.100:8123"

    with patch(
        "custom_components.oidc_provider.token_validator._get_ha_external_url",
        return_value="https://my-ha.example.com",
    ):
        result = get_issuer_from_request(request)

    assert result == "https://my-ha.example.com"
    request.url.origin.assert_not_called()


def test_get_base_url_strips_trailing_slash_from_external_url():
    """Test that trailing slash is stripped from HA external URL."""
    request = Mock()
    request.headers = {}
    request.url.origin.return_value = "http://192.168.1.100:8123"

    with patch(
        "custom_components.oidc_provider.token_validator._get_ha_external_url",
        return_value="https://my-ha.example.com/",
    ):
        result = get_issuer_from_request(request)

    assert result == "https://my-ha.example.com"


def test_get_base_url_falls_back_to_origin_when_no_external_url():
    """Test fallback to request origin when HA external URL is not configured."""
    request = Mock()
    request.headers = {}
    request.url.origin.return_value = "http://192.168.1.100:8123"

    with patch(
        "custom_components.oidc_provider.token_validator._get_ha_external_url",
        return_value=None,
    ):
        result = get_issuer_from_request(request)

    assert result == "http://192.168.1.100:8123"
    request.url.origin.assert_called_once()


def test_get_ha_external_url_returns_none_when_no_hass():
    """Test _get_ha_external_url returns None when hass is not in app."""
    request = Mock()
    request.app.get.return_value = None

    assert _get_ha_external_url(request) is None


def test_get_ha_external_url_returns_none_when_hass_is_not_ha_instance():
    """Test _get_ha_external_url returns None when hass is not a HomeAssistant instance."""
    request = Mock()
    request.app.get.return_value = "not a HomeAssistant instance"

    assert _get_ha_external_url(request) is None


def test_get_ha_external_url_returns_url_from_ha(hass):
    """Test _get_ha_external_url returns external URL from HA config."""
    request = Mock()
    request.app.get.return_value = hass

    with patch(
        "homeassistant.helpers.network.get_url",
        return_value="https://my-ha.example.com",
    ):
        result = _get_ha_external_url(request)

    assert result == "https://my-ha.example.com"


def test_get_ha_external_url_returns_none_on_exception(hass):
    """Test _get_ha_external_url returns None when get_url raises."""
    request = Mock()
    request.app.get.return_value = hass

    with patch(
        "homeassistant.helpers.network.get_url",
        side_effect=Exception("no external url configured"),
    ):
        assert _get_ha_external_url(request) is None


@pytest.mark.asyncio
async def test_oidc_discovery_endpoint():
    """Test OIDC discovery endpoint returns correct metadata."""
    # Create a mock request
    request = Mock()
    request.headers = {}
    request.url.origin.return_value = "https://homeassistant.local"

    # Create the view and call get
    view = OIDCDiscoveryView()
    response = await view.get(request)

    # Verify response
    assert response.status == 200
    assert response.content_type == "application/json"

    # Parse JSON response
    import json

    body = response.body.decode("utf-8")
    data = json.loads(body)

    # Verify required OIDC fields
    assert data["issuer"] == "https://homeassistant.local"
    assert data["authorization_endpoint"] == "https://homeassistant.local/oidc/authorize"
    assert data["token_endpoint"] == "https://homeassistant.local/oidc/token"
    assert data["userinfo_endpoint"] == "https://homeassistant.local/oidc/userinfo"
    assert data["jwks_uri"] == "https://homeassistant.local/oidc/jwks"
    assert data["registration_endpoint"] == "https://homeassistant.local/oidc/register"

    # Verify supported features
    assert "code" in data["response_types_supported"]
    assert "S256" in data["code_challenge_methods_supported"]
    assert "openid" in data["scopes_supported"]
    assert "client_secret_post" in data["token_endpoint_auth_methods_supported"]
    assert "client_secret_basic" in data["token_endpoint_auth_methods_supported"]


@pytest.mark.asyncio
async def test_oidc_discovery_with_proxy():
    """Test OIDC discovery endpoint with proxy headers."""
    # Create a mock request with X-Forwarded headers
    request = Mock()
    request.headers = {
        "X-Forwarded-Proto": "https",
        "X-Forwarded-Host": "ha.example.com",
    }
    request.url.origin.return_value = "http://localhost:8123"

    # Create the view and call get
    view = OIDCDiscoveryView()
    response = await view.get(request)

    # Parse response
    body = response.body.decode("utf-8")
    data = json.loads(body)

    # Verify URLs use the proxy host
    assert data["issuer"] == "https://ha.example.com"
    assert data["authorization_endpoint"] == "https://ha.example.com/oidc/authorize"
    assert data["token_endpoint"] == "https://ha.example.com/oidc/token"


@pytest.mark.asyncio
async def test_oauth2_authorization_server_metadata():
    """Test OAuth 2.0 Authorization Server Metadata endpoint."""
    request = Mock()
    request.headers = {}
    request.url.origin.return_value = "https://homeassistant.local"

    view = OAuth2AuthorizationServerMetadataView()
    response = await view.get(request)

    assert response.status == 200
    body = response.body.decode("utf-8")
    data = json.loads(body)

    # Verify required fields
    assert data["issuer"] == "https://homeassistant.local"
    assert data["authorization_endpoint"] == "https://homeassistant.local/oidc/authorize"
    assert data["token_endpoint"] == "https://homeassistant.local/oidc/token"
    assert data["registration_endpoint"] == "https://homeassistant.local/oidc/register"
    assert "authorization_code" in data["grant_types_supported"]
    assert "refresh_token" in data["grant_types_supported"]


@pytest.mark.asyncio
async def test_oauth2_authorization_server_metadata_alternate_path():
    """Test OAuth 2.0 Authorization Server Metadata at alternate path."""
    request = Mock()
    request.headers = {}
    request.url.origin.return_value = "https://homeassistant.local"

    view = OAuth2AuthorizationServerMetadataAlternateView()
    assert view.url == "/oidc/.well-known/oauth-authorization-server"

    response = await view.get(request)

    assert response.status == 200
    body = response.body.decode("utf-8")
    data = json.loads(body)

    # Should return the same metadata as the primary endpoint
    assert data["issuer"] == "https://homeassistant.local"
    assert data["authorization_endpoint"] == "https://homeassistant.local/oidc/authorize"
    assert data["token_endpoint"] == "https://homeassistant.local/oidc/token"
    assert data["registration_endpoint"] == "https://homeassistant.local/oidc/register"
    assert "authorization_code" in data["grant_types_supported"]
    assert "refresh_token" in data["grant_types_supported"]


@pytest.mark.asyncio
async def test_oidc_jwks_endpoint():
    """Test OIDC JWKS endpoint returns public key."""
    # Create mock hass with RSA keys
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()

    request = Mock()
    request.app = {"hass": Mock()}
    request.app["hass"].data = {
        DOMAIN: {
            "jwt_public_key": public_key,
            "jwt_kid": "test-kid-1",
        }
    }

    view = OIDCJWKSView()
    response = await view.get(request)

    assert response.status == 200
    body = response.body.decode("utf-8")
    data = json.loads(body)

    # Verify JWKS structure
    assert "keys" in data
    assert len(data["keys"]) == 1
    key = data["keys"][0]
    assert key["kty"] == "RSA"
    assert key["use"] == "sig"
    assert key["alg"] == "RS256"
    assert key["kid"] == "test-kid-1"
    assert "n" in key  # modulus
    assert "e" in key  # exponent


@pytest.mark.asyncio
async def test_oidc_continue_view_missing_request_id():
    """Test continue view with missing request_id."""
    request = MagicMock()
    request.query = {}
    request.app = {"hass": Mock()}

    view = OIDCContinueView()
    response = await view.get(request)

    assert response.status == 400
    assert b"Missing request_id" in response.body


@pytest.mark.asyncio
async def test_oidc_continue_view_invalid_request_id():
    """Test continue view with invalid request_id."""
    hass = Mock()
    hass.data = {DOMAIN: {"pending_auth_requests": {}}}

    request = MagicMock()
    request.query = {"request_id": "invalid"}
    request.app = {"hass": hass}
    request.__getitem__.return_value = Mock(id="user123")

    view = OIDCContinueView()
    response = await view.get(request)

    assert response.status == 400
    assert b"Invalid or expired request" in response.body


@pytest.mark.asyncio
async def test_oidc_continue_view_expired_request():
    """Test continue view with expired request."""
    hass = Mock()
    hass.data = {
        DOMAIN: {
            "pending_auth_requests": {
                "req123": {
                    "client_id": "client123",
                    "redirect_uri": "https://example.com/callback",
                    "scope": "openid",
                    "state": "state123",
                    "expires_at": time.time() - 100,  # Expired
                }
            },
            "authorization_codes": {},
        }
    }

    request = MagicMock()
    request.query = {"request_id": "req123"}
    request.app = {"hass": hass}
    request.__getitem__.return_value = Mock(id="user123")

    view = OIDCContinueView()
    response = await view.get(request)

    assert response.status == 400
    assert b"Request expired" in response.body
    # Verify expired request was cleaned up
    assert "req123" not in hass.data[DOMAIN]["pending_auth_requests"]


@pytest.mark.asyncio
async def test_oidc_continue_view_success():
    """Test successful continue flow."""
    hass = Mock()
    hass.data = {
        DOMAIN: {
            "pending_auth_requests": {
                "req123": {
                    "client_id": "client123",
                    "redirect_uri": "https://example.com/callback",
                    "scope": "openid profile",
                    "state": "state123",
                    "code_challenge": "challenge123",
                    "code_challenge_method": "S256",
                    "expires_at": time.time() + 600,
                }
            },
            "authorization_codes": {},
        }
    }

    request = MagicMock()
    request.query = {"request_id": "req123"}
    request.app = {"hass": hass}
    request.__getitem__.return_value = Mock(id="user123")

    view = OIDCContinueView()
    response = await view.get(request)

    assert response.status == 200
    body = response.body.decode("utf-8")
    data = json.loads(body)

    # Verify redirect URL
    assert "redirect_url" in data
    assert data["redirect_url"].startswith("https://example.com/callback?code=")
    assert "state=state123" in data["redirect_url"]

    # Verify authorization code was created
    assert len(hass.data[DOMAIN]["authorization_codes"]) == 1

    # Verify pending request was cleaned up
    assert "req123" not in hass.data[DOMAIN]["pending_auth_requests"]


@pytest.mark.asyncio
async def test_oidc_register_view_success():
    """Test successful dynamic client registration."""
    from unittest.mock import patch

    hass = Mock()
    hass.data = {DOMAIN: {"clients": {}, "store": Mock()}}
    hass.data[DOMAIN]["store"].async_save = MagicMock(return_value=None)

    request = Mock()
    request.app = {"hass": hass}
    request.json = AsyncMock(
        return_value={
            "client_name": "Test Client",
            "redirect_uris": ["https://example.com/callback"],
        }
    )

    view = OIDCRegisterView()

    # Mock create_client to avoid actual implementation
    with patch("custom_components.oidc_provider.http.create_client") as mock_create:
        mock_create.return_value = {
            "client_id": "test_client_id",
            "client_secret": "test_client_secret",
            "client_name": "Test Client",
            "redirect_uris": ["https://example.com/callback"],
        }

        response = await view.post(request)

    body = response.body.decode("utf-8")
    data = json.loads(body)

    # Debug: print error if not 201
    if response.status != 201:
        print(f"Status: {response.status}, Body: {data}")

    assert response.status == 201
    assert data["client_id"] == "test_client_id"
    assert data["client_secret"] == "test_client_secret"
    assert data["client_name"] == "Test Client"


@pytest.mark.asyncio
async def test_oidc_register_view_minimal():
    """Test client registration with minimal valid data."""
    hass = Mock()
    store = Mock()
    store.async_save = AsyncMock(return_value=None)
    hass.data = {DOMAIN: {"clients": {}, "store": store}}

    request = Mock()
    request.app = {"hass": hass}
    request.json = AsyncMock(
        return_value={
            "redirect_uris": ["https://example.com/callback"],
        }
    )

    view = OIDCRegisterView()
    response = await view.post(request)

    # Should succeed with default client name
    assert response.status == 201
    body = response.body.decode("utf-8")
    data = json.loads(body)
    assert "client_id" in data
    assert "client_secret" in data


@pytest.mark.asyncio
async def test_oidc_register_view_invalid_redirect_uri():
    """Test client registration rejects invalid redirect URI."""
    hass = Mock()
    store = Mock()
    store.async_save = AsyncMock(return_value=None)
    hass.data = {DOMAIN: {"clients": {}, "store": store}}

    request = Mock()
    request.app = {"hass": hass}
    request.json = AsyncMock(
        return_value={
            "client_name": "Test Client",
            "redirect_uris": ["not-a-valid-url"],
        }
    )

    view = OIDCRegisterView()
    response = await view.post(request)

    assert response.status == 400
    body = response.body.decode("utf-8")
    data = json.loads(body)
    assert data["error"] == "invalid_redirect_uri"
    assert "not-a-valid-url" in data["error_description"]


@pytest.mark.asyncio
async def test_oidc_authorization_view_success():
    """Test authorization endpoint with valid parameters."""
    hass = Mock()
    hass.data = {
        DOMAIN: {
            "clients": {
                "test_client": {
                    "redirect_uris": ["https://example.com/callback"],
                }
            },
            "pending_auth_requests": {},
        }
    }

    request = Mock()
    request.app = {"hass": hass}
    request.query = {
        "client_id": "test_client",
        "redirect_uri": "https://example.com/callback",
        "response_type": "code",
        "scope": "openid",
        "state": "abc123",
        "code_challenge": "test_challenge",
        "code_challenge_method": "S256",
    }

    from custom_components.oidc_provider.http import OIDCAuthorizationView

    view = OIDCAuthorizationView()
    response = await view.get(request)

    assert response.status == 200
    assert response.content_type == "text/html"
    body = response.body.decode("utf-8")
    assert "sessionStorage.setItem" in body
    assert "oidc_request_id" in body
    assert "/oidc_login" in body

    # Verify pending request was stored
    assert len(hass.data[DOMAIN]["pending_auth_requests"]) == 1


@pytest.mark.asyncio
async def test_oidc_authorization_view_missing_client_id():
    """Test authorization endpoint without client_id."""
    request = Mock()
    request.app = {"hass": Mock()}
    request.query = {
        "redirect_uri": "https://example.com/callback",
        "response_type": "code",
    }

    from custom_components.oidc_provider.http import OIDCAuthorizationView

    view = OIDCAuthorizationView()
    response = await view.get(request)

    assert response.status == 400
    assert b"Invalid request" in response.body


@pytest.mark.asyncio
async def test_oidc_authorization_view_invalid_response_type():
    """Test authorization endpoint with invalid response_type."""
    request = Mock()
    request.app = {"hass": Mock()}
    request.query = {
        "client_id": "test_client",
        "redirect_uri": "https://example.com/callback",
        "response_type": "token",  # Invalid, should be 'code'
    }

    from custom_components.oidc_provider.http import OIDCAuthorizationView

    view = OIDCAuthorizationView()
    response = await view.get(request)

    assert response.status == 400
    assert b"Invalid request" in response.body


@pytest.mark.asyncio
async def test_oidc_authorization_view_invalid_client():
    """Test authorization endpoint with non-existent client."""
    hass = Mock()
    hass.data = {DOMAIN: {"clients": {}, "require_pkce": False}}

    request = Mock()
    request.app = {"hass": hass}
    request.query = {
        "client_id": "nonexistent",
        "redirect_uri": "https://example.com/callback",
        "response_type": "code",
        "scope": "openid",
    }

    from custom_components.oidc_provider.http import OIDCAuthorizationView

    view = OIDCAuthorizationView()
    response = await view.get(request)

    assert response.status == 400
    assert b"Invalid client_id" in response.body


@pytest.mark.asyncio
async def test_oidc_authorization_view_invalid_redirect_uri():
    """Test authorization endpoint with unregistered redirect_uri."""
    hass = Mock()
    hass.data = {
        DOMAIN: {
            "clients": {
                "test_client": {
                    "redirect_uris": ["https://example.com/callback"],
                }
            },
            "require_pkce": False,
        }
    }

    request = Mock()
    request.app = {"hass": hass}
    request.query = {
        "client_id": "test_client",
        "redirect_uri": "https://evil.com/callback",  # Not registered
        "response_type": "code",
        "scope": "openid",
    }

    from custom_components.oidc_provider.http import OIDCAuthorizationView

    view = OIDCAuthorizationView()
    response = await view.get(request)

    assert response.status == 400
    assert b"Invalid redirect_uri" in response.body


@pytest.mark.asyncio
async def test_oidc_authorization_view_unsupported_code_challenge_method():
    """Test authorization endpoint with unsupported code_challenge_method."""
    hass = Mock()
    hass.data = {
        DOMAIN: {
            "clients": {
                "test_client": {
                    "redirect_uris": ["https://example.com/callback"],
                }
            },
            "pending_auth_requests": {},
        }
    }

    request = Mock()
    request.app = {"hass": hass}
    request.query = {
        "client_id": "test_client",
        "redirect_uri": "https://example.com/callback",
        "response_type": "code",
        "scope": "openid",
        "code_challenge": "test_challenge",
        "code_challenge_method": "plain",  # Not supported
    }

    from custom_components.oidc_provider.http import OIDCAuthorizationView

    view = OIDCAuthorizationView()
    response = await view.get(request)

    assert response.status == 400
    assert b"Unsupported code_challenge_method" in response.body


@pytest.mark.asyncio
async def test_oidc_token_view_invalid_client():
    """Test token endpoint with invalid client credentials."""
    hass = Mock()
    hass.data = {
        DOMAIN: {
            "clients": {},
            "rate_limit_attempts": {},
        }
    }

    request = MagicMock()
    request.app = {"hass": hass}
    request.remote = "127.0.0.1"
    request.headers = {}
    request.post = AsyncMock(
        return_value={
            "grant_type": "authorization_code",
            "client_id": "nonexistent",
            "client_secret": "secret",
            "code": "code123",
        }
    )

    from custom_components.oidc_provider.http import OIDCTokenView

    view = OIDCTokenView()
    response = await view.post(request)

    assert response.status == 401
    body = response.body.decode("utf-8")
    data = json.loads(body)
    assert data["error"] == "invalid_client"


@pytest.mark.asyncio
async def test_oidc_token_view_invalid_grant():
    """Test token endpoint with invalid authorization code."""
    from custom_components.oidc_provider.security import hash_client_secret

    hass = Mock()
    hass.data = {
        DOMAIN: {
            "clients": {
                "test_client": {
                    "client_secret_hash": hash_client_secret("test_secret"),
                }
            },
            "authorization_codes": {},
            "rate_limit_attempts": {},
        }
    }

    request = MagicMock()
    request.app = {"hass": hass}
    request.remote = "127.0.0.1"
    request.headers = {}
    request.post = AsyncMock(
        return_value={
            "grant_type": "authorization_code",
            "client_id": "test_client",
            "client_secret": "test_secret",
            "code": "invalid_code",
            "redirect_uri": "https://example.com/callback",
        }
    )

    from custom_components.oidc_provider.http import OIDCTokenView

    view = OIDCTokenView()
    response = await view.post(request)

    assert response.status == 400
    body = response.body.decode("utf-8")
    data = json.loads(body)
    assert data["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_oidc_token_view_unsupported_grant_type():
    """Test token endpoint with unsupported grant type."""
    from custom_components.oidc_provider.security import hash_client_secret

    hass = Mock()
    hass.data = {
        DOMAIN: {
            "clients": {
                "test_client": {
                    "client_secret_hash": hash_client_secret("test_secret"),
                }
            },
            "rate_limit_attempts": {},
        }
    }

    request = MagicMock()
    request.app = {"hass": hass}
    request.remote = "127.0.0.1"
    request.headers = {}
    request.post = AsyncMock(
        return_value={
            "grant_type": "client_credentials",
            "client_id": "test_client",
            "client_secret": "test_secret",
        }
    )

    from custom_components.oidc_provider.http import OIDCTokenView

    view = OIDCTokenView()
    response = await view.post(request)

    assert response.status == 400
    body = response.body.decode("utf-8")
    data = json.loads(body)
    assert data["error"] == "unsupported_grant_type"


@pytest.mark.asyncio
async def test_oidc_token_view_basic_auth():
    """Test token endpoint with HTTP Basic authentication."""
    import base64

    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa

    from custom_components.oidc_provider.security import hash_client_secret

    # Generate RSA keys for JWT
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    mock_token_store = AsyncMock()

    mock_auth = Mock()
    mock_auth.async_get_user = AsyncMock(return_value=None)

    hass = Mock()
    hass.auth = mock_auth
    hass.data = {
        DOMAIN: {
            "clients": {
                "test_client": {
                    "client_secret_hash": hash_client_secret("test_secret"),
                }
            },
            "authorization_codes": {
                "valid_code": {
                    "client_id": "test_client",
                    "redirect_uri": "https://example.com/callback",
                    "user_id": "user123",
                    "scope": "openid",
                    "expires_at": time.time() + 600,
                }
            },
            "refresh_tokens": {},
            "rate_limit_attempts": {},
            "jwt_private_key": private_key,
            "jwt_kid": "test-kid-1",
            "token_store": mock_token_store,
        }
    }

    # Encode credentials as Basic auth
    credentials = base64.b64encode(b"test_client:test_secret").decode("utf-8")

    request = MagicMock()
    request.app = {"hass": hass}
    request.remote = "127.0.0.1"
    request.headers = {"Authorization": f"Basic {credentials}"}
    request.post = AsyncMock(
        return_value={
            "grant_type": "authorization_code",
            "code": "valid_code",
            "redirect_uri": "https://example.com/callback",
        }
    )

    from custom_components.oidc_provider.http import OIDCTokenView

    view = OIDCTokenView()
    response = await view.post(request)

    assert response.status == 200
    body = response.body.decode("utf-8")
    data = json.loads(body)
    assert "access_token" in data
    assert "id_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "Bearer"

    # Verify refresh tokens were persisted
    mock_token_store.async_save.assert_called_once()
    saved_data = mock_token_store.async_save.call_args[0][0]
    assert "refresh_tokens" in saved_data


@pytest.mark.asyncio
async def test_oidc_token_view_invalid_basic_auth():
    """Test token endpoint with malformed Basic auth."""
    hass = Mock()
    hass.data = {
        DOMAIN: {
            "clients": {},
            "rate_limit_attempts": {},
        }
    }

    request = MagicMock()
    request.app = {"hass": hass}
    request.remote = "127.0.0.1"
    request.headers = {"Authorization": "Basic invalid!!!"}
    request.post = AsyncMock(
        return_value={
            "grant_type": "authorization_code",
        }
    )

    from custom_components.oidc_provider.http import OIDCTokenView

    view = OIDCTokenView()
    response = await view.post(request)

    assert response.status == 401
    body = response.body.decode("utf-8")
    data = json.loads(body)
    assert data["error"] == "invalid_client"


@pytest.mark.asyncio
async def test_oidc_token_view_rate_limiting():
    """Test token endpoint rate limiting after failed attempts."""
    from custom_components.oidc_provider.security import hash_client_secret

    hass = Mock()
    hass.data = {
        DOMAIN: {
            "clients": {
                "test_client": {
                    "client_secret_hash": hash_client_secret("correct_secret"),
                }
            },
            "rate_limit_attempts": {},
        }
    }

    from custom_components.oidc_provider.http import OIDCTokenView

    view = OIDCTokenView()

    # Make multiple failed attempts
    for i in range(5):
        request = MagicMock()
        request.app = {"hass": hass}
        request.remote = "127.0.0.1"
        request.headers = {}
        request.post = AsyncMock(
            return_value={
                "grant_type": "authorization_code",
                "client_id": "test_client",
                "client_secret": "wrong_secret",
                "code": "code123",
            }
        )

        response = await view.post(request)
        assert response.status == 401

    # Next attempt should be rate limited
    request = MagicMock()
    request.app = {"hass": hass}
    request.remote = "127.0.0.1"
    request.headers = {}
    request.post = AsyncMock(
        return_value={
            "grant_type": "authorization_code",
            "client_id": "test_client",
            "client_secret": "wrong_secret",
            "code": "code123",
        }
    )

    response = await view.post(request)
    assert response.status == 429
    body = response.body.decode("utf-8")
    data = json.loads(body)
    assert data["error"] == "invalid_client"
    assert "Too many failed attempts" in data["error_description"]


@pytest.mark.asyncio
async def test_oidc_token_view_expired_code():
    """Test token endpoint with expired authorization code."""
    from custom_components.oidc_provider.security import hash_client_secret

    hass = Mock()
    hass.data = {
        DOMAIN: {
            "clients": {
                "test_client": {
                    "client_secret_hash": hash_client_secret("test_secret"),
                }
            },
            "authorization_codes": {
                "expired_code": {
                    "client_id": "test_client",
                    "redirect_uri": "https://example.com/callback",
                    "user_id": "user123",
                    "scope": "openid",
                    "expires_at": time.time() - 100,  # Expired
                }
            },
            "rate_limit_attempts": {},
        }
    }

    request = MagicMock()
    request.app = {"hass": hass}
    request.remote = "127.0.0.1"
    request.headers = {}
    request.post = AsyncMock(
        return_value={
            "grant_type": "authorization_code",
            "client_id": "test_client",
            "client_secret": "test_secret",
            "code": "expired_code",
            "redirect_uri": "https://example.com/callback",
        }
    )

    from custom_components.oidc_provider.http import OIDCTokenView

    view = OIDCTokenView()
    response = await view.post(request)

    assert response.status == 400
    body = response.body.decode("utf-8")
    data = json.loads(body)
    assert data["error"] == "invalid_grant"

    # Verify code was deleted
    assert "expired_code" not in hass.data[DOMAIN]["authorization_codes"]


@pytest.mark.asyncio
async def test_oidc_token_view_wrong_redirect_uri():
    """Test token endpoint with mismatched redirect_uri."""
    from custom_components.oidc_provider.security import hash_client_secret

    hass = Mock()
    hass.data = {
        DOMAIN: {
            "clients": {
                "test_client": {
                    "client_secret_hash": hash_client_secret("test_secret"),
                }
            },
            "authorization_codes": {
                "valid_code": {
                    "client_id": "test_client",
                    "redirect_uri": "https://example.com/callback",
                    "user_id": "user123",
                    "scope": "openid",
                    "expires_at": time.time() + 600,
                }
            },
            "rate_limit_attempts": {},
        }
    }

    request = MagicMock()
    request.app = {"hass": hass}
    request.remote = "127.0.0.1"
    request.headers = {}
    request.post = AsyncMock(
        return_value={
            "grant_type": "authorization_code",
            "client_id": "test_client",
            "client_secret": "test_secret",
            "code": "valid_code",
            "redirect_uri": "https://evil.com/callback",  # Wrong!
        }
    )

    from custom_components.oidc_provider.http import OIDCTokenView

    view = OIDCTokenView()
    response = await view.post(request)

    assert response.status == 400
    body = response.body.decode("utf-8")
    data = json.loads(body)
    assert data["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_oidc_token_view_missing_code_verifier():
    """Test token endpoint with PKCE but missing code_verifier."""
    from custom_components.oidc_provider.security import hash_client_secret

    hass = Mock()
    hass.data = {
        DOMAIN: {
            "clients": {
                "test_client": {
                    "client_secret_hash": hash_client_secret("test_secret"),
                }
            },
            "authorization_codes": {
                "valid_code": {
                    "client_id": "test_client",
                    "redirect_uri": "https://example.com/callback",
                    "user_id": "user123",
                    "scope": "openid",
                    "expires_at": time.time() + 600,
                    "code_challenge": "test_challenge",
                    "code_challenge_method": "S256",
                }
            },
            "rate_limit_attempts": {},
        }
    }

    request = MagicMock()
    request.app = {"hass": hass}
    request.remote = "127.0.0.1"
    request.headers = {}
    request.post = AsyncMock(
        return_value={
            "grant_type": "authorization_code",
            "client_id": "test_client",
            "client_secret": "test_secret",
            "code": "valid_code",
            "redirect_uri": "https://example.com/callback",
            # Missing code_verifier!
        }
    )

    from custom_components.oidc_provider.http import OIDCTokenView

    view = OIDCTokenView()
    response = await view.post(request)

    assert response.status == 400
    body = response.body.decode("utf-8")
    data = json.loads(body)
    assert data["error"] == "invalid_grant"
    assert "code_verifier required" in data["error_description"]


@pytest.mark.asyncio
async def test_oidc_token_view_invalid_code_verifier():
    """Test token endpoint with invalid PKCE code_verifier."""
    import base64
    import hashlib

    from custom_components.oidc_provider.security import hash_client_secret

    # Generate a valid code challenge
    code_verifier = "valid_verifier_1234567890"
    verifier_hash = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(verifier_hash).decode("ascii").rstrip("=")

    hass = Mock()
    hass.data = {
        DOMAIN: {
            "clients": {
                "test_client": {
                    "client_secret_hash": hash_client_secret("test_secret"),
                }
            },
            "authorization_codes": {
                "valid_code": {
                    "client_id": "test_client",
                    "redirect_uri": "https://example.com/callback",
                    "user_id": "user123",
                    "scope": "openid",
                    "expires_at": time.time() + 600,
                    "code_challenge": code_challenge,
                    "code_challenge_method": "S256",
                }
            },
            "rate_limit_attempts": {},
        }
    }

    request = MagicMock()
    request.app = {"hass": hass}
    request.remote = "127.0.0.1"
    request.headers = {}
    request.post = AsyncMock(
        return_value={
            "grant_type": "authorization_code",
            "client_id": "test_client",
            "client_secret": "test_secret",
            "code": "valid_code",
            "redirect_uri": "https://example.com/callback",
            "code_verifier": "wrong_verifier",  # Wrong!
        }
    )

    from custom_components.oidc_provider.http import OIDCTokenView

    view = OIDCTokenView()
    response = await view.post(request)

    assert response.status == 400
    body = response.body.decode("utf-8")
    data = json.loads(body)
    assert data["error"] == "invalid_grant"
    assert "Invalid code_verifier" in data["error_description"]

    # Verify code was deleted
    assert "valid_code" not in hass.data[DOMAIN]["authorization_codes"]


@pytest.mark.asyncio
async def test_oidc_token_view_valid_pkce():
    """Test token endpoint with valid PKCE flow."""
    import base64
    import hashlib

    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa

    from custom_components.oidc_provider.security import hash_client_secret

    # Generate a valid code challenge
    code_verifier = "valid_verifier_1234567890_abcdefghijklmnop"
    verifier_hash = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(verifier_hash).decode("ascii").rstrip("=")

    # Generate RSA keys for JWT
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    mock_token_store = AsyncMock()

    mock_auth = Mock()
    mock_auth.async_get_user = AsyncMock(return_value=None)

    hass = Mock()
    hass.auth = mock_auth
    hass.data = {
        DOMAIN: {
            "clients": {
                "test_client": {
                    "client_secret_hash": hash_client_secret("test_secret"),
                }
            },
            "authorization_codes": {
                "valid_code": {
                    "client_id": "test_client",
                    "redirect_uri": "https://example.com/callback",
                    "user_id": "user123",
                    "scope": "openid profile",
                    "expires_at": time.time() + 600,
                    "code_challenge": code_challenge,
                    "code_challenge_method": "S256",
                }
            },
            "refresh_tokens": {},
            "rate_limit_attempts": {},
            "jwt_private_key": private_key,
            "jwt_kid": "test-kid-1",
            "token_store": mock_token_store,
        }
    }

    request = MagicMock()
    request.app = {"hass": hass}
    request.remote = "127.0.0.1"
    request.headers = {}
    request.post = AsyncMock(
        return_value={
            "grant_type": "authorization_code",
            "client_id": "test_client",
            "client_secret": "test_secret",
            "code": "valid_code",
            "redirect_uri": "https://example.com/callback",
            "code_verifier": code_verifier,
        }
    )

    from custom_components.oidc_provider.http import OIDCTokenView

    view = OIDCTokenView()
    response = await view.post(request)

    assert response.status == 200
    body = response.body.decode("utf-8")
    data = json.loads(body)
    assert "access_token" in data
    assert "id_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "Bearer"
    assert data["scope"] == "openid profile"

    # Verify code was deleted
    assert "valid_code" not in hass.data[DOMAIN]["authorization_codes"]

    # Verify refresh token was created
    assert len(hass.data[DOMAIN]["refresh_tokens"]) == 1

    # Verify refresh tokens were persisted
    mock_token_store.async_save.assert_called_once()


@pytest.mark.asyncio
async def test_oidc_token_view_includes_groups_in_access_token():
    """Test token endpoint includes groups claim in JWT when groups scope is requested."""
    import base64
    import hashlib

    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    from custom_components.oidc_provider.security import hash_client_secret

    code_verifier = "valid_verifier_1234567890_abcdefghijklmnop"
    verifier_hash = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(verifier_hash).decode("ascii").rstrip("=")

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()

    mock_user = Mock()
    mock_user.id = "user123"
    mock_user.name = "Test User"
    mock_user.is_owner = True
    admin_group = Mock()
    admin_group.id = "system-admin"
    mock_user.groups = [admin_group]

    mock_auth = Mock()
    mock_auth.async_get_user = AsyncMock(return_value=mock_user)

    mock_token_store = AsyncMock()

    hass = Mock()
    hass.auth = mock_auth
    hass.data = {
        DOMAIN: {
            "clients": {
                "test_client": {
                    "client_secret_hash": hash_client_secret("test_secret"),
                }
            },
            "authorization_codes": {
                "valid_code": {
                    "client_id": "test_client",
                    "redirect_uri": "https://example.com/callback",
                    "user_id": "user123",
                    "scope": "openid groups",
                    "expires_at": time.time() + 600,
                    "code_challenge": code_challenge,
                    "code_challenge_method": "S256",
                }
            },
            "refresh_tokens": {},
            "rate_limit_attempts": {},
            "jwt_private_key": private_key,
            "jwt_kid": "test-kid-1",
            "token_store": mock_token_store,
        }
    }

    request = MagicMock()
    request.app = {"hass": hass}
    request.remote = "127.0.0.1"
    request.headers = {}
    request.post = AsyncMock(
        return_value={
            "grant_type": "authorization_code",
            "client_id": "test_client",
            "client_secret": "test_secret",
            "code": "valid_code",
            "redirect_uri": "https://example.com/callback",
            "code_verifier": code_verifier,
        }
    )

    from custom_components.oidc_provider.http import OIDCTokenView

    view = OIDCTokenView()
    response = await view.post(request)

    assert response.status == 200
    data = json.loads(response.body.decode("utf-8"))

    # Decode the access token and verify groups claim
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    token_payload = jwt.decode(
        data["access_token"], public_pem, algorithms=["RS256"], options={"verify_aud": False}
    )
    assert token_payload["groups"] == ["owner", "admin"]


@pytest.mark.asyncio
async def test_oidc_token_view_excludes_groups_without_scope():
    """Test token endpoint does not include groups claim when groups scope is not requested."""
    import base64
    import hashlib

    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    from custom_components.oidc_provider.security import hash_client_secret

    code_verifier = "valid_verifier_1234567890_abcdefghijklmnop"
    verifier_hash = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(verifier_hash).decode("ascii").rstrip("=")

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()

    mock_token_store = AsyncMock()

    mock_auth = Mock()
    mock_auth.async_get_user = AsyncMock(return_value=None)

    hass = Mock()
    hass.auth = mock_auth
    hass.data = {
        DOMAIN: {
            "clients": {
                "test_client": {
                    "client_secret_hash": hash_client_secret("test_secret"),
                }
            },
            "authorization_codes": {
                "valid_code": {
                    "client_id": "test_client",
                    "redirect_uri": "https://example.com/callback",
                    "user_id": "user123",
                    "scope": "openid profile",
                    "expires_at": time.time() + 600,
                    "code_challenge": code_challenge,
                    "code_challenge_method": "S256",
                }
            },
            "refresh_tokens": {},
            "rate_limit_attempts": {},
            "jwt_private_key": private_key,
            "jwt_kid": "test-kid-1",
            "token_store": mock_token_store,
        }
    }

    request = MagicMock()
    request.app = {"hass": hass}
    request.remote = "127.0.0.1"
    request.headers = {}
    request.post = AsyncMock(
        return_value={
            "grant_type": "authorization_code",
            "client_id": "test_client",
            "client_secret": "test_secret",
            "code": "valid_code",
            "redirect_uri": "https://example.com/callback",
            "code_verifier": code_verifier,
        }
    )

    from custom_components.oidc_provider.http import OIDCTokenView

    view = OIDCTokenView()
    response = await view.post(request)

    assert response.status == 200
    data = json.loads(response.body.decode("utf-8"))

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    token_payload = jwt.decode(
        data["access_token"], public_pem, algorithms=["RS256"], options={"verify_aud": False}
    )
    assert "groups" not in token_payload


@pytest.mark.asyncio
async def test_oidc_token_view_refresh_token():
    """Test token endpoint with refresh token grant."""
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa

    from custom_components.oidc_provider.security import hash_client_secret

    # Generate RSA keys for JWT
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    mock_token_store = AsyncMock()

    mock_auth = Mock()
    mock_auth.async_get_user = AsyncMock(return_value=None)

    hass = Mock()
    hass.auth = mock_auth
    hass.data = {
        DOMAIN: {
            "clients": {
                "test_client": {
                    "client_secret_hash": hash_client_secret("test_secret"),
                }
            },
            "refresh_tokens": {
                "valid_refresh_token": {
                    "client_id": "test_client",
                    "user_id": "user123",
                    "scope": "openid email",
                    "expires_at": time.time() + 3600,
                }
            },
            "rate_limit_attempts": {},
            "jwt_private_key": private_key,
            "jwt_kid": "test-kid-1",
            "token_store": mock_token_store,
        }
    }

    mock_url = Mock()
    mock_url.origin.return_value = "http://localhost"

    request = MagicMock()
    request.app = {"hass": hass}
    request.remote = "127.0.0.1"
    request.headers = {}
    request.url = mock_url
    request.post = AsyncMock(
        return_value={
            "grant_type": "refresh_token",
            "client_id": "test_client",
            "client_secret": "test_secret",
            "refresh_token": "valid_refresh_token",
        }
    )

    from custom_components.oidc_provider.http import OIDCTokenView

    view = OIDCTokenView()
    response = await view.post(request)

    assert response.status == 200
    body = response.body.decode("utf-8")
    data = json.loads(body)
    assert "access_token" in data
    assert "id_token" in data
    assert data["token_type"] == "Bearer"
    assert data["scope"] == "openid email"


@pytest.mark.asyncio
async def test_oidc_token_view_invalid_refresh_token():
    """Test token endpoint with invalid refresh token."""
    from custom_components.oidc_provider.security import hash_client_secret

    hass = Mock()
    hass.data = {
        DOMAIN: {
            "clients": {
                "test_client": {
                    "client_secret_hash": hash_client_secret("test_secret"),
                }
            },
            "refresh_tokens": {},
            "rate_limit_attempts": {},
        }
    }

    request = MagicMock()
    request.app = {"hass": hass}
    request.remote = "127.0.0.1"
    request.headers = {}
    request.post = AsyncMock(
        return_value={
            "grant_type": "refresh_token",
            "client_id": "test_client",
            "client_secret": "test_secret",
            "refresh_token": "invalid_token",
        }
    )

    from custom_components.oidc_provider.http import OIDCTokenView

    view = OIDCTokenView()
    response = await view.post(request)

    assert response.status == 400
    body = response.body.decode("utf-8")
    data = json.loads(body)
    assert data["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_oidc_token_view_expired_refresh_token():
    """Test token endpoint with expired refresh token."""
    from custom_components.oidc_provider.security import hash_client_secret

    mock_token_store = Mock()
    mock_token_store.async_save = AsyncMock()

    hass = Mock()
    hass.data = {
        DOMAIN: {
            "clients": {
                "test_client": {
                    "client_secret_hash": hash_client_secret("test_secret"),
                }
            },
            "refresh_tokens": {
                "expired_token": {
                    "client_id": "test_client",
                    "user_id": "user123",
                    "scope": "openid",
                    "expires_at": time.time() - 100,  # Expired
                }
            },
            "rate_limit_attempts": {},
            "token_store": mock_token_store,
        }
    }

    request = MagicMock()
    request.app = {"hass": hass}
    request.remote = "127.0.0.1"
    request.headers = {}
    request.post = AsyncMock(
        return_value={
            "grant_type": "refresh_token",
            "client_id": "test_client",
            "client_secret": "test_secret",
            "refresh_token": "expired_token",
        }
    )

    from custom_components.oidc_provider.http import OIDCTokenView

    view = OIDCTokenView()
    response = await view.post(request)

    assert response.status == 400
    body = response.body.decode("utf-8")
    data = json.loads(body)
    assert data["error"] == "invalid_grant"

    # Verify token was deleted
    assert "expired_token" not in hass.data[DOMAIN]["refresh_tokens"]

    # Verify deletion was persisted
    mock_token_store.async_save.assert_called_once()
    saved_data = mock_token_store.async_save.call_args[0][0]
    assert "expired_token" not in saved_data["refresh_tokens"]


@pytest.mark.asyncio
async def test_oidc_userinfo_endpoint():
    """Test UserInfo endpoint with valid token."""
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    # Generate RSA keys
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()

    # Create a valid token with profile and email scopes
    payload = {
        "sub": "user123",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "iss": "http://localhost",
        "aud": "test_client",
        "scope": "openid profile email",
    }

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    token = jwt.encode(payload, private_key_pem, algorithm="RS256")

    # Mock user
    mock_user = Mock()
    mock_user.id = "user123"
    mock_user.name = "Test User"
    mock_user.is_owner = False
    admin_group = Mock()
    admin_group.id = "system-admin"
    mock_user.groups = [admin_group]

    # Mock hass.auth
    mock_auth = Mock()
    mock_auth.async_get_user = AsyncMock(return_value=mock_user)

    hass = Mock()
    hass.auth = mock_auth
    hass.data = {
        DOMAIN: {
            "jwt_public_key": public_key,
            "jwt_kid": "test-kid-1",
            "clients": {"test_client": {}},  # Required for audience verification
        }
    }

    # Mock request with proper URL
    mock_url = Mock()
    mock_url.origin.return_value = "http://localhost"

    request = Mock()
    request.app = {"hass": hass}
    request.headers = {"Authorization": f"Bearer {token}"}
    request.url = mock_url

    from custom_components.oidc_provider.http import OIDCUserInfoView

    view = OIDCUserInfoView()
    response = await view.get(request)

    assert response.status == 200
    body = response.body.decode("utf-8")
    data = json.loads(body)
    assert data["sub"] == "user123"
    assert data["name"] == "Test User"
    assert "email" not in data  # "Test User" doesn't look like an email
    assert "groups" not in data


@pytest.mark.asyncio
async def test_oidc_userinfo_includes_groups_when_scope_requested():
    """Test UserInfo endpoint includes groups when groups scope is requested."""
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    # Generate RSA keys
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()

    # Create a valid token with groups scope
    payload = {
        "sub": "user123",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "iss": "http://localhost",
        "aud": "test_client",
        "scope": "openid profile groups",
    }

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    token = jwt.encode(payload, private_key_pem, algorithm="RS256")

    # Mock admin user
    mock_user = Mock()
    mock_user.id = "user123"
    mock_user.name = "Test User"
    mock_user.is_owner = False
    admin_group = Mock()
    admin_group.id = "system-admin"
    mock_user.groups = [admin_group]

    mock_auth = Mock()
    mock_auth.async_get_user = AsyncMock(return_value=mock_user)

    hass = Mock()
    hass.auth = mock_auth
    hass.data = {
        DOMAIN: {
            "jwt_public_key": public_key,
            "jwt_kid": "test-kid-1",
            "clients": {"test_client": {}},
        }
    }

    mock_url = Mock()
    mock_url.origin.return_value = "http://localhost"

    request = Mock()
    request.app = {"hass": hass}
    request.headers = {"Authorization": f"Bearer {token}"}
    request.url = mock_url

    from custom_components.oidc_provider.http import OIDCUserInfoView

    view = OIDCUserInfoView()
    response = await view.get(request)

    assert response.status == 200
    data = json.loads(response.body.decode("utf-8"))
    assert data["groups"] == ["admin"]


@pytest.mark.asyncio
async def test_oidc_userinfo_groups_for_owner():
    """Test UserInfo endpoint includes owner in groups for owner users."""
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()

    payload = {
        "sub": "owner123",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "iss": "http://localhost",
        "aud": "test_client",
        "scope": "openid groups",
    }

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    token = jwt.encode(payload, private_key_pem, algorithm="RS256")

    # Mock owner user (owner is also in admin group)
    mock_user = Mock()
    mock_user.id = "owner123"
    mock_user.name = "Owner User"
    mock_user.is_owner = True
    admin_group = Mock()
    admin_group.id = "system-admin"
    mock_user.groups = [admin_group]

    mock_auth = Mock()
    mock_auth.async_get_user = AsyncMock(return_value=mock_user)

    hass = Mock()
    hass.auth = mock_auth
    hass.data = {
        DOMAIN: {
            "jwt_public_key": public_key,
            "jwt_kid": "test-kid-1",
            "clients": {"test_client": {}},
        }
    }

    mock_url = Mock()
    mock_url.origin.return_value = "http://localhost"

    request = Mock()
    request.app = {"hass": hass}
    request.headers = {"Authorization": f"Bearer {token}"}
    request.url = mock_url

    from custom_components.oidc_provider.http import OIDCUserInfoView

    view = OIDCUserInfoView()
    response = await view.get(request)

    assert response.status == 200
    data = json.loads(response.body.decode("utf-8"))
    assert data["groups"] == ["owner", "admin"]


@pytest.mark.asyncio
async def test_oidc_userinfo_groups_for_regular_user():
    """Test UserInfo endpoint returns correct groups for regular user."""
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()

    payload = {
        "sub": "regular123",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "iss": "http://localhost",
        "aud": "test_client",
        "scope": "openid groups",
    }

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    token = jwt.encode(payload, private_key_pem, algorithm="RS256")

    mock_user = Mock()
    mock_user.id = "regular123"
    mock_user.name = "Regular User"
    mock_user.is_owner = False
    user_group = Mock()
    user_group.id = "system-users"
    mock_user.groups = [user_group]

    mock_auth = Mock()
    mock_auth.async_get_user = AsyncMock(return_value=mock_user)

    hass = Mock()
    hass.auth = mock_auth
    hass.data = {
        DOMAIN: {
            "jwt_public_key": public_key,
            "jwt_kid": "test-kid-1",
            "clients": {"test_client": {}},
        }
    }

    mock_url = Mock()
    mock_url.origin.return_value = "http://localhost"

    request = Mock()
    request.app = {"hass": hass}
    request.headers = {"Authorization": f"Bearer {token}"}
    request.url = mock_url

    from custom_components.oidc_provider.http import OIDCUserInfoView

    view = OIDCUserInfoView()
    response = await view.get(request)

    assert response.status == 200
    data = json.loads(response.body.decode("utf-8"))
    assert data["groups"] == ["user"]


@pytest.mark.asyncio
async def test_oidc_userinfo_groups_for_read_only_user():
    """Test UserInfo endpoint returns correct groups for read-only user."""
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()

    payload = {
        "sub": "readonly123",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "iss": "http://localhost",
        "aud": "test_client",
        "scope": "openid groups",
    }

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    token = jwt.encode(payload, private_key_pem, algorithm="RS256")

    mock_user = Mock()
    mock_user.id = "readonly123"
    mock_user.name = "Read Only User"
    mock_user.is_owner = False
    ro_group = Mock()
    ro_group.id = "system-read-only"
    mock_user.groups = [ro_group]

    mock_auth = Mock()
    mock_auth.async_get_user = AsyncMock(return_value=mock_user)

    hass = Mock()
    hass.auth = mock_auth
    hass.data = {
        DOMAIN: {
            "jwt_public_key": public_key,
            "jwt_kid": "test-kid-1",
            "clients": {"test_client": {}},
        }
    }

    mock_url = Mock()
    mock_url.origin.return_value = "http://localhost"

    request = Mock()
    request.app = {"hass": hass}
    request.headers = {"Authorization": f"Bearer {token}"}
    request.url = mock_url

    from custom_components.oidc_provider.http import OIDCUserInfoView

    view = OIDCUserInfoView()
    response = await view.get(request)

    assert response.status == 200
    data = json.loads(response.body.decode("utf-8"))
    assert data["groups"] == ["read-only"]


@pytest.mark.asyncio
async def test_oidc_userinfo_only_returns_sub_without_scopes():
    """Test UserInfo endpoint only returns sub when no optional scopes requested."""
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()

    payload = {
        "sub": "user123",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "iss": "http://localhost",
        "aud": "test_client",
        "scope": "openid",
    }

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    token = jwt.encode(payload, private_key_pem, algorithm="RS256")

    mock_user = Mock()
    mock_user.id = "user123"
    mock_user.name = "Test User"
    mock_user.is_owner = False
    admin_group = Mock()
    admin_group.id = "system-admin"
    mock_user.groups = [admin_group]

    mock_auth = Mock()
    mock_auth.async_get_user = AsyncMock(return_value=mock_user)

    hass = Mock()
    hass.auth = mock_auth
    hass.data = {
        DOMAIN: {
            "jwt_public_key": public_key,
            "jwt_kid": "test-kid-1",
            "clients": {"test_client": {}},
        }
    }

    mock_url = Mock()
    mock_url.origin.return_value = "http://localhost"

    request = Mock()
    request.app = {"hass": hass}
    request.headers = {"Authorization": f"Bearer {token}"}
    request.url = mock_url

    from custom_components.oidc_provider.http import OIDCUserInfoView

    view = OIDCUserInfoView()
    response = await view.get(request)

    assert response.status == 200
    data = json.loads(response.body.decode("utf-8"))
    assert data["sub"] == "user123"
    assert "name" not in data
    assert "email" not in data
    assert "groups" not in data


@pytest.mark.asyncio
async def test_oidc_userinfo_returns_email_when_username_is_email():
    """Test UserInfo endpoint returns email when username looks like an email address."""
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()

    payload = {
        "sub": "user123",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "iss": "http://localhost",
        "aud": "test_client",
        "scope": "openid email",
    }

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    token = jwt.encode(payload, private_key_pem, algorithm="RS256")

    mock_user = Mock()
    mock_user.id = "user123"
    mock_user.name = "john@example.com"
    mock_user.is_owner = False
    mock_user.groups = []

    mock_auth = Mock()
    mock_auth.async_get_user = AsyncMock(return_value=mock_user)

    hass = Mock()
    hass.auth = mock_auth
    hass.data = {
        DOMAIN: {
            "jwt_public_key": public_key,
            "jwt_kid": "test-kid-1",
            "clients": {"test_client": {}},
        }
    }

    mock_url = Mock()
    mock_url.origin.return_value = "http://localhost"

    request = Mock()
    request.app = {"hass": hass}
    request.headers = {"Authorization": f"Bearer {token}"}
    request.url = mock_url

    from custom_components.oidc_provider.http import OIDCUserInfoView

    view = OIDCUserInfoView()
    response = await view.get(request)

    assert response.status == 200
    data = json.loads(response.body.decode("utf-8"))
    assert data["email"] == "john@example.com"
    assert data["email_verified"] is False


@pytest.mark.asyncio
async def test_oidc_authorize_rejects_missing_openid_scope():
    """Test authorization endpoint rejects requests without openid scope."""
    hass = Mock()
    hass.data = {
        DOMAIN: {
            "clients": {
                "test_client": {
                    "redirect_uris": ["https://example.com/callback"],
                }
            },
            "pending_auth_requests": {},
            "require_pkce": False,
        }
    }

    request = Mock()
    request.app = {"hass": hass}
    request.query = {
        "client_id": "test_client",
        "redirect_uri": "https://example.com/callback",
        "response_type": "code",
        "scope": "profile",
    }

    from custom_components.oidc_provider.http import OIDCAuthorizationView

    view = OIDCAuthorizationView()
    response = await view.get(request)

    assert response.status == 400
    assert b"openid scope is required" in response.body


@pytest.mark.asyncio
async def test_oidc_authorize_rejects_empty_scope():
    """Test authorization endpoint rejects requests with empty scope."""
    hass = Mock()
    hass.data = {
        DOMAIN: {
            "clients": {
                "test_client": {
                    "redirect_uris": ["https://example.com/callback"],
                }
            },
            "pending_auth_requests": {},
            "require_pkce": False,
        }
    }

    request = Mock()
    request.app = {"hass": hass}
    request.query = {
        "client_id": "test_client",
        "redirect_uri": "https://example.com/callback",
        "response_type": "code",
    }

    from custom_components.oidc_provider.http import OIDCAuthorizationView

    view = OIDCAuthorizationView()
    response = await view.get(request)

    assert response.status == 400
    assert b"openid scope is required" in response.body


@pytest.mark.asyncio
async def test_oidc_userinfo_endpoint_missing_token():
    """Test UserInfo endpoint without token."""
    request = Mock()
    request.app = {"hass": Mock()}
    request.headers = {}

    from custom_components.oidc_provider.http import OIDCUserInfoView

    view = OIDCUserInfoView()
    response = await view.get(request)

    assert response.status == 401
    body = response.body.decode("utf-8")
    data = json.loads(body)
    assert data["error"] == "unauthorized"


@pytest.mark.asyncio
async def test_oidc_userinfo_endpoint_invalid_token():
    """Test UserInfo endpoint with invalid token."""
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa

    # Generate RSA keys
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()

    hass = Mock()
    hass.data = {
        DOMAIN: {
            "jwt_public_key": public_key,
            "jwt_kid": "test-kid-1",
        }
    }

    request = Mock()
    request.app = {"hass": hass}
    request.headers = {"Authorization": "Bearer invalid.token.here"}

    from custom_components.oidc_provider.http import OIDCUserInfoView

    view = OIDCUserInfoView()
    response = await view.get(request)

    assert response.status == 401
    body = response.body.decode("utf-8")
    data = json.loads(body)
    assert data["error"] == "invalid_token"


@pytest.mark.asyncio
async def test_oidc_authorization_view_pkce_required():
    """Test authorization endpoint rejects requests without PKCE when required."""
    hass = Mock()
    hass.data = {
        DOMAIN: {
            "clients": {
                "test_client": {
                    "redirect_uris": ["https://example.com/callback"],
                }
            },
            "pending_auth_requests": {},
            "require_pkce": True,  # PKCE is required
        }
    }

    request = Mock()
    request.app = {"hass": hass}
    request.query = {
        "client_id": "test_client",
        "redirect_uri": "https://example.com/callback",
        "response_type": "code",
        "scope": "openid",
        "state": "abc123",
        # Missing code_challenge - should be rejected
    }

    from custom_components.oidc_provider.http import OIDCAuthorizationView

    view = OIDCAuthorizationView()
    response = await view.get(request)

    assert response.status == 400
    assert b"PKCE is required" in response.body


@pytest.mark.asyncio
async def test_oidc_authorization_view_pkce_optional():
    """Test authorization endpoint allows requests without PKCE when optional."""
    hass = Mock()
    hass.data = {
        DOMAIN: {
            "clients": {
                "test_client": {
                    "redirect_uris": ["https://example.com/callback"],
                }
            },
            "pending_auth_requests": {},
            "require_pkce": False,  # PKCE is optional
        }
    }

    request = Mock()
    request.app = {"hass": hass}
    request.query = {
        "client_id": "test_client",
        "redirect_uri": "https://example.com/callback",
        "response_type": "code",
        "scope": "openid",
        "state": "abc123",
        # No code_challenge - should be allowed when PKCE is optional
    }

    from custom_components.oidc_provider.http import OIDCAuthorizationView

    view = OIDCAuthorizationView()
    response = await view.get(request)

    # Should not error about PKCE, should show login form
    assert response.status == 200
    assert b"PKCE is required" not in response.body


@pytest.mark.asyncio
async def test_oidc_token_view_rejects_plain_pkce_method():
    """Test token endpoint rejects plain PKCE method (OAuth 2.1 compliance)."""
    from custom_components.oidc_provider.security import hash_client_secret

    hass = Mock()
    hass.data = {
        DOMAIN: {
            "clients": {
                "test_client": {
                    "client_secret_hash": hash_client_secret("test_secret"),
                }
            },
            "authorization_codes": {
                "test_code": {
                    "client_id": "test_client",
                    "redirect_uri": "https://example.com/callback",
                    "scope": "openid",
                    "user_id": "user123",
                    "code_challenge": "plain_challenge_value",
                    "code_challenge_method": "plain",  # Plain method
                    "expires_at": time.time() + 600,
                }
            },
            "refresh_tokens": {},
            "rate_limit_attempts": {},
        }
    }

    request = Mock()
    request.app = {"hass": hass}
    request.remote = "127.0.0.1"
    request.headers = {}
    request.post = AsyncMock(
        return_value={
            "grant_type": "authorization_code",
            "code": "test_code",
            "redirect_uri": "https://example.com/callback",
            "client_id": "test_client",
            "client_secret": "test_secret",
            "code_verifier": "plain_challenge_value",  # Matches challenge in plain method
        }
    )

    from custom_components.oidc_provider.http import OIDCTokenView

    view = OIDCTokenView()
    response = await view.post(request)

    # Should reject plain method even if verifier matches challenge
    assert response.status == 400
    body = response.body.decode("utf-8")
    data = json.loads(body)
    assert data["error"] == "invalid_grant"
    assert "S256" in data["error_description"]
    # Authorization code should be deleted
    assert "test_code" not in hass.data[DOMAIN]["authorization_codes"]


@pytest.mark.asyncio
async def test_oidc_userinfo_rejects_token_without_audience():
    """Test userinfo endpoint rejects tokens without audience claim."""
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    # Generate RSA keys
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()

    # Create a token WITHOUT audience claim
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    token_payload = {
        "sub": "user123",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        # Missing "aud" claim
    }
    invalid_token = jwt.encode(token_payload, private_pem, algorithm="RS256")

    hass = Mock()
    hass.data = {
        DOMAIN: {
            "jwt_public_key": public_key,
            "jwt_kid": "test-kid-1",
            "clients": {"test_client": {}},
        }
    }

    request = Mock()
    request.app = {"hass": hass}
    request.headers = {"Authorization": f"Bearer {invalid_token}"}

    from custom_components.oidc_provider.http import OIDCUserInfoView

    view = OIDCUserInfoView()
    response = await view.get(request)

    assert response.status == 401
    body = response.body.decode("utf-8")
    data = json.loads(body)
    assert data["error"] == "invalid_token"


@pytest.mark.asyncio
async def test_oidc_userinfo_rejects_token_with_invalid_audience():
    """Test userinfo endpoint rejects tokens with unregistered audience."""
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    # Generate RSA keys
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()

    # Create a token with audience that doesn't match any registered client
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    token_payload = {
        "sub": "user123",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "aud": "nonexistent_client",  # Not registered
    }
    invalid_token = jwt.encode(token_payload, private_pem, algorithm="RS256")

    hass = Mock()
    hass.data = {
        DOMAIN: {
            "jwt_public_key": public_key,
            "clients": {"test_client": {}},  # Only test_client is registered
        }
    }

    request = Mock()
    request.app = {"hass": hass}
    request.headers = {"Authorization": f"Bearer {invalid_token}"}

    from custom_components.oidc_provider.http import OIDCUserInfoView

    view = OIDCUserInfoView()
    response = await view.get(request)

    assert response.status == 401
    body = response.body.decode("utf-8")
    data = json.loads(body)
    assert data["error"] == "invalid_token"
