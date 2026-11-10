"""Tests for HTTP endpoints."""

import json
import time
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import jwt
import pytest

from custom_components.oidc_provider.const import CONF_ALLOW_DYNAMIC_REGISTRATION, DOMAIN
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


def test_get_base_url_with_only_forwarded_host():
    """X-Forwarded-Host without X-Forwarded-Proto uses the request scheme."""
    request = Mock()
    request.headers = {
        "X-Forwarded-Host": "example.com",
    }
    request.url.scheme = "https"
    request.url.origin.return_value = "http://localhost:8123"

    result = get_issuer_from_request(request)

    assert result == "https://example.com"
    request.url.origin.assert_not_called()


def test_get_base_url_with_host_header_and_forwarded_proto():
    """A proxy that forwards the Host header and X-Forwarded-Proto (e.g. a
    Cloudflare Tunnel) but omits X-Forwarded-Host still yields the client host."""
    request = Mock()
    request.headers = {
        "X-Forwarded-Proto": "https",
        "Host": "hem.example.com",
    }
    request.url.scheme = "http"
    request.url.origin.return_value = "http://localhost:8123"

    result = get_issuer_from_request(request)

    assert result == "https://hem.example.com"
    request.url.origin.assert_not_called()


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


def test_get_base_url_ip_host_prefers_external_url():
    """A proxy that rewrites Host to the internal IP (no X-Forwarded-Host)
    must not leak the internal address; the configured external URL wins."""
    request = Mock()
    request.headers = {
        "Host": "192.168.2.20:8123",
    }
    request.url.scheme = "http"
    request.url.origin.return_value = "http://192.168.2.20:8123"

    with patch(
        "custom_components.oidc_provider.token_validator._get_ha_external_url",
        return_value="https://ha.example.com",
    ):
        result = get_issuer_from_request(request)

    assert result == "https://ha.example.com"
    request.url.origin.assert_not_called()


def test_get_base_url_forwarded_ip_host_prefers_external_url():
    """X-Forwarded-Host set to an IP is treated the same as a rewritten Host."""
    request = Mock()
    request.headers = {
        "X-Forwarded-Proto": "https",
        "X-Forwarded-Host": "192.168.2.20",
    }
    request.url.scheme = "http"
    request.url.origin.return_value = "http://192.168.2.20:8123"

    with patch(
        "custom_components.oidc_provider.token_validator._get_ha_external_url",
        return_value="https://ha.example.com",
    ):
        result = get_issuer_from_request(request)

    assert result == "https://ha.example.com"


def test_get_base_url_ip_host_kept_without_external_url():
    """LAN-only installs with no external URL keep the IP host as issuer."""
    request = Mock()
    request.headers = {
        "Host": "192.168.2.20:8123",
    }
    request.url.scheme = "http"
    request.url.origin.return_value = "http://192.168.2.20:8123"

    with patch(
        "custom_components.oidc_provider.token_validator._get_ha_external_url",
        return_value=None,
    ):
        result = get_issuer_from_request(request)

    assert result == "http://192.168.2.20:8123"
    request.url.origin.assert_not_called()


def test_get_base_url_ipv6_host_prefers_external_url():
    """Bracketed IPv6 hosts are recognized as IP addresses."""
    request = Mock()
    request.headers = {
        "Host": "[fd00::20]:8123",
    }
    request.url.scheme = "http"
    request.url.origin.return_value = "http://[fd00::20]:8123"

    with patch(
        "custom_components.oidc_provider.token_validator._get_ha_external_url",
        return_value="https://ha.example.com",
    ):
        result = get_issuer_from_request(request)

    assert result == "https://ha.example.com"


def test_get_base_url_domain_host_ignores_external_url():
    """A real domain in Host keeps winning over the external URL (no behavior
    change for tunnels that forward the original Host)."""
    request = Mock()
    request.headers = {
        "X-Forwarded-Proto": "https",
        "Host": "hem.example.com",
    }
    request.url.scheme = "http"
    request.url.origin.return_value = "http://localhost:8123"

    with patch(
        "custom_components.oidc_provider.token_validator._get_ha_external_url",
        return_value="https://other.example.com",
    ) as mock_external:
        result = get_issuer_from_request(request)

    assert result == "https://hem.example.com"
    mock_external.assert_not_called()


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


def _app_with_registration(enabled: bool) -> dict:
    """Return a request app whose hass has dynamic registration on or off."""
    hass = Mock()
    hass.data = {DOMAIN: {CONF_ALLOW_DYNAMIC_REGISTRATION: enabled}}
    return {"hass": hass}


@pytest.mark.asyncio
async def test_oidc_discovery_endpoint():
    """Test OIDC discovery endpoint returns correct metadata."""
    # Create a mock request
    request = Mock()
    request.headers = {}
    request.url.origin.return_value = "https://homeassistant.local"
    request.app = _app_with_registration(True)

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

    # Verify required OIDC fields. The issuer carries the /oidc suffix per
    # RFC 8414 so it resolves to /oidc/.well-known/openid-configuration.
    assert data["issuer"] == "https://homeassistant.local/oidc"
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

    # ID token claims advertised after id_token issuance was added
    for claim in ("auth_time", "nonce", "at_hash"):
        assert claim in data["claims_supported"]


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
    request.app = _app_with_registration(True)

    # Create the view and call get
    view = OIDCDiscoveryView()
    response = await view.get(request)

    # Parse response
    body = response.body.decode("utf-8")
    data = json.loads(body)

    # Verify URLs use the proxy host
    assert data["issuer"] == "https://ha.example.com/oidc"
    assert data["authorization_endpoint"] == "https://ha.example.com/oidc/authorize"
    assert data["token_endpoint"] == "https://ha.example.com/oidc/token"


@pytest.mark.asyncio
async def test_oauth2_authorization_server_metadata():
    """Test OAuth 2.0 Authorization Server Metadata endpoint."""
    request = Mock()
    request.headers = {}
    request.url.origin.return_value = "https://homeassistant.local"
    request.app = _app_with_registration(True)

    view = OAuth2AuthorizationServerMetadataView()
    response = await view.get(request)

    assert response.status == 200
    body = response.body.decode("utf-8")
    data = json.loads(body)

    # Verify required fields
    assert data["issuer"] == "https://homeassistant.local/oidc"
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
    request.app = _app_with_registration(True)

    view = OAuth2AuthorizationServerMetadataAlternateView()
    assert view.url == "/oidc/.well-known/oauth-authorization-server"

    response = await view.get(request)

    assert response.status == 200
    body = response.body.decode("utf-8")
    data = json.loads(body)

    # Should return the same metadata as the primary endpoint
    assert data["issuer"] == "https://homeassistant.local/oidc"
    assert data["authorization_endpoint"] == "https://homeassistant.local/oidc/authorize"
    assert data["token_endpoint"] == "https://homeassistant.local/oidc/token"
    assert data["registration_endpoint"] == "https://homeassistant.local/oidc/register"
    assert "authorization_code" in data["grant_types_supported"]
    assert "refresh_token" in data["grant_types_supported"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "view_class",
    [
        OIDCDiscoveryView,
        OAuth2AuthorizationServerMetadataView,
        OAuth2AuthorizationServerMetadataAlternateView,
    ],
)
async def test_discovery_omits_registration_endpoint_when_registration_is_off(view_class):
    """Clients that discover endpoints are not pointed at a registration endpoint that refuses."""
    request = Mock()
    request.headers = {}
    request.url.origin.return_value = "https://homeassistant.local"
    request.app = _app_with_registration(False)

    response = await view_class().get(request)

    assert response.status == 200
    data = json.loads(response.body.decode("utf-8"))
    assert "registration_endpoint" not in data
    assert data["issuer"] == "https://homeassistant.local/oidc"
    assert data["token_endpoint"] == "https://homeassistant.local/oidc/token"


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


def _continue_hass(pending=None, clients=None):
    hass = Mock()
    hass.data = {
        DOMAIN: {
            "pending_auth_requests": pending or {},
            "clients": (
                clients if clients is not None else {"client123": {"client_name": "Test App"}}
            ),
            "authorization_codes": {},
        }
    }
    return hass


def _continue_request(hass, *, query=None, body=None):
    request = MagicMock()
    request.query = query or {}
    request.app = {"hass": hass}
    request.__getitem__.return_value = Mock(id="user123")
    request.json = AsyncMock(return_value=body if body is not None else {})
    return request


def _pending(**overrides):
    data = {
        "client_id": "client123",
        "redirect_uri": "https://example.com/callback",
        "scope": "openid profile",
        "state": "state123",
        "code_challenge": "challenge123",
        "code_challenge_method": "S256",
        "expires_at": time.time() + 600,
    }
    data.update(overrides)
    return data


@pytest.mark.asyncio
async def test_oidc_continue_view_missing_request_id():
    """Both GET and POST reject a missing request_id."""
    hass = _continue_hass()
    view = OIDCContinueView()

    response = await view.get(_continue_request(hass))
    assert response.status == 400
    assert b"Missing request_id" in response.body

    response = await view.post(_continue_request(hass, body={"approve": True}))
    assert response.status == 400
    assert b"Missing request_id" in response.body


@pytest.mark.asyncio
async def test_oidc_continue_view_invalid_request_id():
    """Test continue view with invalid request_id."""
    hass = _continue_hass()
    view = OIDCContinueView()

    response = await view.post(
        _continue_request(hass, body={"request_id": "invalid", "approve": True})
    )

    assert response.status == 400
    assert b"Invalid or expired request" in response.body


@pytest.mark.asyncio
async def test_oidc_continue_view_expired_request():
    """Test continue view with expired request."""
    hass = _continue_hass(pending={"req123": _pending(expires_at=time.time() - 100)})
    view = OIDCContinueView()

    response = await view.post(
        _continue_request(hass, body={"request_id": "req123", "approve": True})
    )

    assert response.status == 400
    assert b"Request expired" in response.body
    # Verify expired request was cleaned up
    assert "req123" not in hass.data[DOMAIN]["pending_auth_requests"]


@pytest.mark.asyncio
async def test_oidc_continue_view_rejects_revoked_client():
    """A pending request for a client that was revoked meanwhile is dropped."""
    hass = _continue_hass(pending={"req123": _pending()}, clients={})
    view = OIDCContinueView()

    response = await view.get(_continue_request(hass, query={"request_id": "req123"}))

    assert response.status == 400
    assert b"Client no longer registered" in response.body
    assert "req123" not in hass.data[DOMAIN]["pending_auth_requests"]


@pytest.mark.asyncio
async def test_oidc_continue_view_rejects_invalid_json():
    """POST without a JSON object body is rejected."""
    hass = _continue_hass(pending={"req123": _pending()})
    view = OIDCContinueView()

    request = _continue_request(hass)
    request.json = AsyncMock(side_effect=ValueError("bad json"))
    response = await view.post(request)
    assert response.status == 400

    response = await view.post(_continue_request(hass, body=["not", "a", "dict"]))
    assert response.status == 400
    # Nothing was consumed
    assert "req123" in hass.data[DOMAIN]["pending_auth_requests"]


@pytest.mark.asyncio
async def test_oidc_continue_view_get_describes_request():
    """GET returns what the consent screen shows and has no side effects."""
    hass = _continue_hass(
        pending={"req123": _pending()},
        clients={"client123": {"client_name": "Test App", "consent_required": True}},
    )
    view = OIDCContinueView()

    response = await view.get(_continue_request(hass, query={"request_id": "req123"}))

    assert response.status == 200
    data = json.loads(response.body.decode("utf-8"))
    assert data == {
        "client_name": "Test App",
        "redirect_host": "example.com",
        "scopes": ["openid", "profile"],
        "consent_required": True,
        "client_host": None,
        "redirect_is_loopback": False,
    }
    assert "req123" in hass.data[DOMAIN]["pending_auth_requests"]
    assert hass.data[DOMAIN]["authorization_codes"] == {}


@pytest.mark.asyncio
async def test_oidc_continue_view_get_shows_hostname_not_netloc():
    """The displayed host is the parsed hostname and port, never raw netloc."""
    hass = _continue_hass(
        pending={"req123": _pending(redirect_uri="https://ha.example.com@attacker.example:8443/cb")}
    )
    view = OIDCContinueView()

    response = await view.get(_continue_request(hass, query={"request_id": "req123"}))

    data = json.loads(response.body.decode("utf-8"))
    assert data["redirect_host"] == "attacker.example:8443"


@pytest.mark.asyncio
async def test_oidc_continue_view_get_defaults_consent_to_required():
    """A client stored without the flag may have come from dynamic registration,
    so it prompts until an operator clears the flag."""
    hass = _continue_hass(pending={"req123": _pending()})
    view = OIDCContinueView()

    response = await view.get(_continue_request(hass, query={"request_id": "req123"}))

    data = json.loads(response.body.decode("utf-8"))
    assert data["consent_required"] is True


@pytest.mark.asyncio
async def test_oidc_continue_view_get_tolerates_bad_stored_port():
    """A stored redirect URI with an out-of-range port does not break the consent screen."""
    hass = _continue_hass(pending={"req123": _pending(redirect_uri="https://example.com:99999/cb")})
    view = OIDCContinueView()

    response = await view.get(_continue_request(hass, query={"request_id": "req123"}))

    assert response.status == 200
    data = json.loads(response.body.decode("utf-8"))
    assert data["redirect_host"] == "example.com"


@pytest.mark.asyncio
async def test_oidc_continue_view_url_encodes_state():
    """State is encoded on both the approve and deny redirects."""
    state = "a&b=c#d+e"
    view = OIDCContinueView()

    hass = _continue_hass(pending={"req123": _pending(state=state)})
    response = await view.post(
        _continue_request(hass, body={"request_id": "req123", "approve": True})
    )
    data = json.loads(response.body.decode("utf-8"))
    assert data["redirect_url"].endswith("&state=a%26b%3Dc%23d%2Be")
    assert data["redirect_url"].startswith("https://example.com/callback?code=")

    hass = _continue_hass(pending={"req123": _pending(state=state)})
    response = await view.post(
        _continue_request(hass, body={"request_id": "req123", "approve": False})
    )
    data = json.loads(response.body.decode("utf-8"))
    assert data["redirect_url"] == (
        "https://example.com/callback?error=access_denied&state=a%26b%3Dc%23d%2Be"
    )


@pytest.mark.asyncio
async def test_oidc_continue_view_prunes_expired_codes():
    """Issuing a code drops expired codes and expired redemption records."""
    hass = _continue_hass(pending={"req123": _pending()})
    live = {"expires_at": time.time() + 600}
    stale = {"expires_at": time.time() - 1}
    hass.data[DOMAIN]["authorization_codes"] = {"stale": stale, "live": live}
    hass.data[DOMAIN]["redeemed_codes"] = {"stale": stale, "live": live}
    view = OIDCContinueView()

    await view.post(_continue_request(hass, body={"request_id": "req123", "approve": True}))

    codes = hass.data[DOMAIN]["authorization_codes"]
    assert "stale" not in codes
    assert codes["live"] is live
    assert len(codes) == 2  # the live code and the one just issued
    assert hass.data[DOMAIN]["redeemed_codes"] == {"live": live}


@pytest.mark.asyncio
async def test_oidc_continue_view_success():
    """Approving mints an authorization code and consumes the request."""
    hass = _continue_hass(pending={"req123": _pending()})
    view = OIDCContinueView()

    response = await view.post(
        _continue_request(hass, body={"request_id": "req123", "approve": True})
    )

    assert response.status == 200
    data = json.loads(response.body.decode("utf-8"))

    # Verify redirect URL
    assert data["redirect_url"].startswith("https://example.com/callback?code=")
    assert "state=state123" in data["redirect_url"]

    # Verify authorization code was created for the authenticated user
    codes = hass.data[DOMAIN]["authorization_codes"]
    assert len(codes) == 1
    auth_data = next(iter(codes.values()))
    assert auth_data["user_id"] == "user123"
    assert auth_data["client_id"] == "client123"
    assert auth_data["code_challenge"] == "challenge123"

    # Verify pending request was cleaned up
    assert "req123" not in hass.data[DOMAIN]["pending_auth_requests"]


@pytest.mark.asyncio
async def test_oidc_continue_view_deny():
    """Denying consumes the request and sends access_denied to the client."""
    hass = _continue_hass(pending={"req123": _pending()})
    view = OIDCContinueView()

    response = await view.post(
        _continue_request(hass, body={"request_id": "req123", "approve": False})
    )

    assert response.status == 200
    data = json.loads(response.body.decode("utf-8"))
    assert data["redirect_url"] == "https://example.com/callback?error=access_denied&state=state123"
    assert hass.data[DOMAIN]["authorization_codes"] == {}
    assert "req123" not in hass.data[DOMAIN]["pending_auth_requests"]


@pytest.mark.asyncio
async def test_oidc_continue_view_requires_explicit_approval():
    """Anything other than approve=true is a denial, so a missing field cannot mint a code."""
    hass = _continue_hass(pending={"req123": _pending()})
    view = OIDCContinueView()

    response = await view.post(_continue_request(hass, body={"request_id": "req123"}))

    assert response.status == 200
    data = json.loads(response.body.decode("utf-8"))
    assert "error=access_denied" in data["redirect_url"]
    assert hass.data[DOMAIN]["authorization_codes"] == {}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "domain_data",
    [{CONF_ALLOW_DYNAMIC_REGISTRATION: False}, {}],
    ids=["turned-off", "not-configured"],
)
async def test_oidc_register_view_refuses_when_registration_is_off(domain_data):
    """With registration off the request is refused before its body is read."""
    hass = Mock()
    store = Mock()
    store.async_save = AsyncMock()
    hass.data = {DOMAIN: {"clients": {}, "store": store, **domain_data}}

    request = Mock()
    request.app = {"hass": hass}
    request.json = AsyncMock(
        return_value={
            "client_name": "Test Client",
            "redirect_uris": ["https://example.com/callback"],
        }
    )

    response = await OIDCRegisterView().post(request)

    assert response.status == 403
    assert json.loads(response.body.decode("utf-8")) == {
        "error": "access_denied",
        "error_description": "Dynamic client registration is disabled",
    }
    request.json.assert_not_awaited()
    store.async_save.assert_not_awaited()
    assert hass.data[DOMAIN]["clients"] == {}


@pytest.mark.asyncio
async def test_oidc_register_view_success():
    """Test successful dynamic client registration."""
    from unittest.mock import patch

    hass = Mock()
    hass.data = {DOMAIN: {"clients": {}, "store": Mock(), CONF_ALLOW_DYNAMIC_REGISTRATION: True}}
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
    # A dynamically registered client always goes through the consent screen
    assert mock_create.call_args.kwargs["consent_required"] is True
    assert data["client_id"] == "test_client_id"
    assert data["client_secret"] == "test_client_secret"
    assert data["client_name"] == "Test Client"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "client_name",
    [{"name": "dict"}, "", "x" * 101],
    ids=["not-a-string", "blank", "too-long"],
)
async def test_oidc_register_view_rejects_bad_client_name(client_name):
    """The name is shown on the consent screen, so it must be a bounded string."""
    hass = Mock()
    hass.data = {DOMAIN: {"clients": {}, "store": Mock(), CONF_ALLOW_DYNAMIC_REGISTRATION: True}}

    request = Mock()
    request.app = {"hass": hass}
    request.json = AsyncMock(
        return_value={
            "client_name": client_name,
            "redirect_uris": ["https://example.com/callback"],
        }
    )

    response = await OIDCRegisterView().post(request)

    assert response.status == 400
    data = json.loads(response.body.decode("utf-8"))
    assert data["error"] == "invalid_client_metadata"
    assert hass.data[DOMAIN]["clients"] == {}


@pytest.mark.asyncio
async def test_oidc_register_view_minimal():
    """Test client registration with minimal valid data."""
    hass = Mock()
    store = Mock()
    store.async_save = AsyncMock(return_value=None)
    hass.data = {DOMAIN: {"clients": {}, "store": store, CONF_ALLOW_DYNAMIC_REGISTRATION: True}}

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
    hass.data = {DOMAIN: {"clients": {}, "store": store, CONF_ALLOW_DYNAMIC_REGISTRATION: True}}

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
            "client_id": "",
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
async def test_oidc_token_view_binds_aud_to_resource():
    """Access token aud is bound to the requested resource (RFC 8707)."""
    import base64

    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa

    from custom_components.oidc_provider.security import hash_client_secret

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    mock_token_store = Mock()
    mock_token_store.async_save = AsyncMock()

    resource = "https://ha.example.com/api/mcp"
    hass = Mock()
    hass.data = {
        DOMAIN: {
            "clients": {"test_client": {"client_secret_hash": hash_client_secret("test_secret")}},
            "authorization_codes": {
                "valid_code": {
                    "client_id": "test_client",
                    "redirect_uri": "https://example.com/callback",
                    "user_id": "user123",
                    "scope": "openid",
                    "resource": resource,
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
    data = json.loads(response.body.decode("utf-8"))

    claims = jwt.decode(data["access_token"], options={"verify_signature": False})
    assert claims["aud"] == resource
    assert claims["azp"] == "test_client"

    # The resource is persisted on the refresh token so refreshed access tokens
    # keep the same audience binding.
    saved = mock_token_store.async_save.call_args[0][0]["refresh_tokens"]
    assert saved
    assert all(rt["resource"] == resource for rt in saved.values())


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
async def test_oidc_token_view_replayed_code_revokes_its_refresh_token():
    """A code that already issued tokens is refused and its session revoked."""
    from custom_components.oidc_provider.http import OIDCTokenView
    from custom_components.oidc_provider.security import hash_client_secret

    hass = Mock()
    hass.data = {
        DOMAIN: {
            "clients": {"test_client": {"client_secret_hash": hash_client_secret("test_secret")}},
            "authorization_codes": {},
            "redeemed_codes": {
                "used_code": {
                    "client_id": "test_client",
                    "family": "fam1",
                    "expires_at": time.time() + 600,
                }
            },
            "refresh_tokens": {
                "fam1.issued": {"client_id": "test_client", "family": "fam1"},
                "fam1.rotated": {"client_id": "test_client", "family": "fam1"},
                "fam2.other": {"client_id": "test_client", "family": "fam2"},
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
            "code": "used_code",
            "redirect_uri": "https://example.com/callback",
        }
    )

    response = await OIDCTokenView().post(request)

    assert response.status == 400
    assert json.loads(response.body.decode("utf-8"))["error"] == "invalid_grant"
    # Every refresh token descended from the code is revoked, others are kept
    assert list(hass.data[DOMAIN]["refresh_tokens"]) == ["fam2.other"]
    assert hass.data[DOMAIN]["redeemed_codes"] == {}


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
    # The failed attempt consumed the code
    assert "valid_code" not in hass.data[DOMAIN]["authorization_codes"]


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

    mock_user = Mock()
    mock_user.name = "Test User"
    mock_user.is_owner = False
    mock_user.groups = []
    hass.auth = Mock()
    hass.auth.async_get_user = AsyncMock(return_value=mock_user)

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
    assert "refresh_token" in data
    assert "id_token" in data
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

    mock_token_store = Mock()
    mock_token_store.async_save = AsyncMock()

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

    mock_user = Mock()
    mock_user.name = "Test User"
    mock_user.is_owner = False
    mock_user.groups = []
    hass.auth = Mock()
    hass.auth.async_get_user = AsyncMock(return_value=mock_user)

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

    mock_user = Mock()
    mock_user.name = "user@example.com"
    mock_user.is_owner = False
    mock_user.groups = []
    hass.auth = Mock()
    hass.auth.async_get_user = AsyncMock(return_value=mock_user)

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

    # The presented token is replaced by a new one that remembers it
    refresh_tokens = hass.data[DOMAIN]["refresh_tokens"]
    assert data["refresh_token"] != "valid_refresh_token"
    assert list(refresh_tokens) == [data["refresh_token"]]
    assert list(refresh_tokens[data["refresh_token"]]["retired"]) == ["valid_refresh_token"]
    mock_token_store.async_save.assert_called_once()


def _rotation_hass(refresh_tokens):
    """Return hass state for refresh token rotation tests, with its token store."""
    from cryptography.hazmat.primitives.asymmetric import rsa

    from custom_components.oidc_provider.security import hash_client_secret

    token_store = Mock()
    token_store.async_save = AsyncMock()
    hass = Mock()
    hass.data = {
        DOMAIN: {
            "clients": {
                "test_client": {"client_secret_hash": hash_client_secret("test_secret")},
                "other_client": {"client_secret_hash": hash_client_secret("other_secret")},
            },
            "refresh_tokens": refresh_tokens,
            "rate_limit_attempts": {},
            "jwt_private_key": rsa.generate_private_key(public_exponent=65537, key_size=2048),
            "jwt_kid": "test-kid-1",
            "token_store": token_store,
        }
    }
    hass.auth = Mock()
    hass.auth.async_get_user = AsyncMock(return_value=None)
    return hass, token_store


async def _post_refresh_grant(hass, refresh_token, client_id="test_client", secret="test_secret"):
    """Present a refresh token at the token endpoint. Returns (status, body)."""
    from custom_components.oidc_provider.http import OIDCTokenView

    request = MagicMock()
    request.app = {"hass": hass}
    request.remote = "127.0.0.1"
    request.headers = {}
    request.url = Mock()
    request.url.origin.return_value = "http://localhost"
    request.post = AsyncMock(
        return_value={
            "grant_type": "refresh_token",
            "client_id": client_id,
            "client_secret": secret,
            "refresh_token": refresh_token,
        }
    )
    response = await OIDCTokenView().post(request)
    return response.status, json.loads(response.body.decode("utf-8"))


def _stored_token(family="fam1", **overrides):
    data = {
        "client_id": "test_client",
        "user_id": "user123",
        "scope": "openid",
        "family": family,
        "expires_at": time.time() + 3600,
    }
    data.update(overrides)
    return data


@pytest.mark.asyncio
async def test_refresh_rotation_keeps_family_and_expiry():
    """A rotated token stays in its family and keeps the session's original expiry."""
    expires_at = time.time() + 1234
    hass, _ = _rotation_hass({"fam1.a": _stored_token(expires_at=expires_at)})

    status, body = await _post_refresh_grant(hass, "fam1.a")

    assert status == 200
    assert body["refresh_token"].startswith("fam1.")
    stored = hass.data[DOMAIN]["refresh_tokens"][body["refresh_token"]]
    assert stored["family"] == "fam1"
    assert stored["expires_at"] == expires_at


@pytest.mark.asyncio
async def test_refresh_rotation_starts_a_family_for_older_tokens():
    """A token stored without a family is rotated into a new family."""
    legacy = _stored_token()
    del legacy["family"]
    hass, _ = _rotation_hass({"legacy_token": legacy})

    status, body = await _post_refresh_grant(hass, "legacy_token")

    assert status == 200
    family = hass.data[DOMAIN]["refresh_tokens"][body["refresh_token"]]["family"]
    assert body["refresh_token"].startswith(f"{family}.")


@pytest.mark.asyncio
async def test_replaced_refresh_token_within_grace_gets_the_current_token():
    """Presenting the replaced token right after rotation returns its replacement."""
    hass, _ = _rotation_hass({"fam1.a": _stored_token()})
    _, first = await _post_refresh_grant(hass, "fam1.a")

    status, second = await _post_refresh_grant(hass, "fam1.a")

    assert status == 200
    assert second["refresh_token"] == first["refresh_token"]
    assert second["access_token"]
    assert list(hass.data[DOMAIN]["refresh_tokens"]) == [first["refresh_token"]]


@pytest.mark.asyncio
async def test_late_duplicate_of_an_older_token_gets_the_current_one():
    """A is replaced by B and B by C; a delayed request with A within the minute gets C."""
    hass, _ = _rotation_hass({"fam1.a": _stored_token()})
    _, first = await _post_refresh_grant(hass, "fam1.a")
    _, second = await _post_refresh_grant(hass, first["refresh_token"])

    status, late = await _post_refresh_grant(hass, "fam1.a")

    assert status == 200
    assert late["refresh_token"] == second["refresh_token"]
    assert list(hass.data[DOMAIN]["refresh_tokens"]) == [second["refresh_token"]]


@pytest.mark.asyncio
async def test_token_responses_are_not_cached():
    """Token responses carry Cache-Control: no-store, errors included (RFC 6749 §5.1)."""
    from custom_components.oidc_provider.http import OIDCTokenView

    hass, _ = _rotation_hass({"fam1.a": _stored_token()})
    for token in ("fam1.a", "unknown"):
        request = MagicMock()
        request.app = {"hass": hass}
        request.remote = "127.0.0.1"
        request.headers = {}
        request.url = Mock()
        request.url.origin.return_value = "http://localhost"
        request.post = AsyncMock(
            return_value={
                "grant_type": "refresh_token",
                "client_id": "test_client",
                "client_secret": "test_secret",
                "refresh_token": token,
            }
        )
        response = await OIDCTokenView().post(request)
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["Pragma"] == "no-cache"


@pytest.mark.asyncio
async def test_replaced_refresh_token_after_grace_revokes_the_family():
    """A replaced token presented after the grace period revokes the whole session."""
    hass, token_store = _rotation_hass(
        {
            "fam1.b": _stored_token(retired={"fam1.a": time.time() - 61}),
            "fam2.x": _stored_token(family="fam2"),
        }
    )

    status, body = await _post_refresh_grant(hass, "fam1.a")

    assert (status, body["error"]) == (400, "invalid_grant")
    assert list(hass.data[DOMAIN]["refresh_tokens"]) == ["fam2.x"]
    token_store.async_save.assert_called_once()


@pytest.mark.asyncio
async def test_token_retired_before_the_grace_period_revokes_the_family():
    """A token retired too long ago is not remembered, so its family prefix revokes the session."""
    hass, _ = _rotation_hass({"fam1.c": _stored_token(retired={"fam1.b": time.time()})})

    status, _ = await _post_refresh_grant(hass, "fam1.a")

    assert status == 400
    assert hass.data[DOMAIN]["refresh_tokens"] == {}


@pytest.mark.asyncio
async def test_replaced_refresh_token_from_another_client_revokes_the_family():
    """Another client presenting a replaced token, even within the grace period, revokes it."""
    hass, _ = _rotation_hass({"fam1.b": _stored_token(retired={"fam1.a": time.time()})})

    status, _ = await _post_refresh_grant(hass, "fam1.a", "other_client", "other_secret")

    assert status == 400
    assert hass.data[DOMAIN]["refresh_tokens"] == {}


@pytest.mark.asyncio
async def test_unknown_refresh_token_revokes_nothing():
    """A token whose prefix matches no stored family is refused and changes nothing."""
    hass, token_store = _rotation_hass({"fam1.a": _stored_token()})

    status, _ = await _post_refresh_grant(hass, "fam9.zzz")

    assert status == 400
    assert list(hass.data[DOMAIN]["refresh_tokens"]) == ["fam1.a"]
    token_store.async_save.assert_not_called()


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
async def test_oidc_token_view_rejects_code_issued_to_other_client():
    """An authorization code is bound to the client it was issued to."""
    from custom_components.oidc_provider.security import hash_client_secret

    hass = Mock()
    hass.data = {
        DOMAIN: {
            "clients": {
                "victim_client": {
                    "client_secret_hash": hash_client_secret("victim_secret"),
                },
                "evil_client": {
                    "client_secret_hash": hash_client_secret("evil_secret"),
                },
            },
            "authorization_codes": {
                "victim_code": {
                    "client_id": "victim_client",
                    "redirect_uri": "https://example.com/callback",
                    "user_id": "user123",
                    "scope": "openid",
                    "expires_at": time.time() + 600,
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
            "grant_type": "authorization_code",
            "client_id": "evil_client",
            "client_secret": "evil_secret",
            "code": "victim_code",
            "redirect_uri": "https://example.com/callback",
        }
    )

    from custom_components.oidc_provider.http import OIDCTokenView

    view = OIDCTokenView()
    response = await view.post(request)

    assert response.status == 400
    data = json.loads(response.body.decode("utf-8"))
    assert data["error"] == "invalid_grant"
    # A cross-client redemption attempt consumes the code
    assert "victim_code" not in hass.data[DOMAIN]["authorization_codes"]
    assert hass.data[DOMAIN]["refresh_tokens"] == {}


@pytest.mark.asyncio
async def test_oidc_token_view_rejects_refresh_token_issued_to_other_client():
    """A refresh token presented by another client is rejected and revoked."""
    from custom_components.oidc_provider.security import hash_client_secret

    mock_token_store = Mock()
    mock_token_store.async_save = AsyncMock()

    hass = Mock()
    hass.data = {
        DOMAIN: {
            "clients": {
                "victim_client": {
                    "client_secret_hash": hash_client_secret("victim_secret"),
                },
                "evil_client": {
                    "client_secret_hash": hash_client_secret("evil_secret"),
                },
            },
            "refresh_tokens": {
                "victim_refresh_token": {
                    "client_id": "victim_client",
                    "user_id": "user123",
                    "scope": "openid",
                    "expires_at": time.time() + 3600,
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
            "client_id": "evil_client",
            "client_secret": "evil_secret",
            "refresh_token": "victim_refresh_token",
        }
    )

    from custom_components.oidc_provider.http import OIDCTokenView

    view = OIDCTokenView()
    response = await view.post(request)

    assert response.status == 400
    data = json.loads(response.body.decode("utf-8"))
    assert data["error"] == "invalid_grant"
    # Presentation by the wrong client revokes the token and persists the change
    assert "victim_refresh_token" not in hass.data[DOMAIN]["refresh_tokens"]
    mock_token_store.async_save.assert_called_once()


@pytest.mark.asyncio
async def test_refresh_token_from_another_client_revokes_its_family():
    """Presentation by another client revokes every token of that session."""
    hass, _ = _rotation_hass(
        {"fam1.a": _stored_token(), "fam1.b": _stored_token(), "fam2.x": _stored_token("fam2")}
    )

    status, _ = await _post_refresh_grant(hass, "fam1.a", "other_client", "other_secret")

    assert status == 400
    assert list(hass.data[DOMAIN]["refresh_tokens"]) == ["fam2.x"]


@pytest.mark.asyncio
async def test_oidc_token_view_rejects_basic_auth_body_client_id_mismatch():
    """Basic auth credentials and a body client_id naming another client are rejected."""
    import base64

    from custom_components.oidc_provider.security import hash_client_secret

    hass = Mock()
    hass.data = {
        DOMAIN: {
            "clients": {
                "victim_client": {
                    "client_secret_hash": hash_client_secret("victim_secret"),
                },
                "evil_client": {
                    "client_secret_hash": hash_client_secret("evil_secret"),
                },
            },
            "refresh_tokens": {
                "victim_refresh_token": {
                    "client_id": "victim_client",
                    "user_id": "user123",
                    "scope": "openid",
                    "expires_at": time.time() + 3600,
                }
            },
            "rate_limit_attempts": {},
        }
    }

    credentials = base64.b64encode(b"evil_client:evil_secret").decode("utf-8")

    request = MagicMock()
    request.app = {"hass": hass}
    request.remote = "127.0.0.1"
    request.headers = {"Authorization": f"Basic {credentials}"}
    request.post = AsyncMock(
        return_value={
            "grant_type": "refresh_token",
            "client_id": "victim_client",
            "refresh_token": "victim_refresh_token",
        }
    )

    from custom_components.oidc_provider.http import OIDCTokenView

    view = OIDCTokenView()
    response = await view.post(request)

    assert response.status == 401
    data = json.loads(response.body.decode("utf-8"))
    assert data["error"] == "invalid_client"


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
        "iss": "http://localhost/oidc",
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
async def test_oidc_userinfo_accepts_resource_bound_token():
    """UserInfo accepts a token whose aud is a resource URI (RFC 8707), not a
    registered client_id."""
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
        "iss": "http://localhost/oidc",
        "aud": "http://localhost/api/mcp",  # resource, not a client_id
        "azp": "test_client",
        "scope": "openid profile",
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
    mock_auth = Mock()
    mock_auth.async_get_user = AsyncMock(return_value=mock_user)

    hass = Mock()
    hass.auth = mock_auth
    hass.data = {
        DOMAIN: {
            "jwt_public_key": public_key,
            "jwt_kid": "test-kid-1",
            "clients": {},  # resource aud is intentionally not a registered client
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
    assert data["name"] == "Test User"


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
        "iss": "http://localhost/oidc",
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
        "iss": "http://localhost/oidc",
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
        "iss": "http://localhost/oidc",
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
        "iss": "http://localhost/oidc",
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
        "iss": "http://localhost/oidc",
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
        "iss": "http://localhost/oidc",
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
async def test_oidc_authorize_ignores_unsupported_scope():
    """Scopes outside the supported list are dropped (OIDC Core §3.1.2.1), so they
    never reach the consent screen or the token."""
    hass = Mock()
    hass.data = {
        DOMAIN: {
            "clients": {"test_client": {"redirect_uris": ["https://example.com/callback"]}},
            "pending_auth_requests": {},
        }
    }

    request = MagicMock()
    request.app = {"hass": hass}
    request.query = {
        "response_type": "code",
        "client_id": "test_client",
        "redirect_uri": "https://example.com/callback",
        "scope": "openid constructor offline_access profile",
        "code_challenge": "abc",
        "code_challenge_method": "S256",
    }

    from custom_components.oidc_provider.http import OIDCAuthorizationView

    response = await OIDCAuthorizationView().get(request)

    assert response.status == 200
    [pending] = hass.data[DOMAIN]["pending_auth_requests"].values()
    assert pending["scope"] == "openid profile"


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


CIMD_CLIENT_ID = "https://claude.ai/oauth/claude-code-client-metadata"


@pytest.mark.parametrize(
    ("requested", "registered", "allowed"),
    [
        ("https://app.example.com/cb", ["https://app.example.com/cb"], True),
        ("https://app.example.com:8443/cb", ["https://app.example.com/cb"], False),
        ("http://localhost:53682/callback", ["http://localhost/callback"], True),
        ("http://127.0.0.1:53682/callback", ["http://127.0.0.1/callback"], True),
        ("http://[::1]:53682/callback", ["http://[::1]:1234/callback"], True),
        ("http://localhost:53682/other", ["http://localhost/callback"], False),
        ("http://localhost:53682/callback?x=1", ["http://localhost/callback"], False),
        ("http://127.0.0.1:53682/callback", ["http://localhost/callback"], False),
        ("https://localhost:53682/callback", ["https://localhost/callback"], False),
        ("http://evil@localhost:53682/callback", ["http://localhost/callback"], False),
        ("http://localhost:99999/callback", ["http://localhost/callback"], False),
    ],
)
def test_redirect_uri_matching(requested, registered, allowed):
    """Redirect URIs match exactly, except loopback ones on any port (RFC 8252 §7.3)."""
    from custom_components.oidc_provider.http import _redirect_uri_allowed

    assert _redirect_uri_allowed(requested, registered) is allowed


@pytest.mark.parametrize(
    ("dcr", "cimd", "methods", "flag"),
    [
        (False, False, ["client_secret_post", "client_secret_basic"], None),
        (True, False, ["client_secret_post", "client_secret_basic", "none"], None),
        (False, True, ["client_secret_post", "client_secret_basic", "none"], True),
    ],
)
def test_client_authentication_metadata(dcr, cimd, methods, flag):
    """Public clients and metadata documents are advertised only while possible."""
    from custom_components.oidc_provider.const import CONF_ALLOW_CLIENT_METADATA_DOCUMENTS
    from custom_components.oidc_provider.http import _client_authentication_metadata

    hass = Mock()
    hass.data = {
        DOMAIN: {
            CONF_ALLOW_DYNAMIC_REGISTRATION: dcr,
            CONF_ALLOW_CLIENT_METADATA_DOCUMENTS: cimd,
        }
    }

    metadata = _client_authentication_metadata(hass)

    assert metadata["token_endpoint_auth_methods_supported"] == methods
    assert metadata.get("client_id_metadata_document_supported") is flag


@pytest.mark.asyncio
async def test_metadata_document_client_refreshes_without_a_secret():
    """A metadata document client is public and authenticates with its client_id alone."""
    hass, _ = _rotation_hass({"fam1.a": _stored_token(client_id=CIMD_CLIENT_ID)})

    status, body = await _post_refresh_grant(hass, "fam1.a", CIMD_CLIENT_ID, "")

    assert status == 200
    assert body["refresh_token"].startswith("fam1.")


@pytest.mark.asyncio
async def test_public_client_presenting_a_secret_is_refused():
    """A public client has no secret, so presenting one is refused."""
    hass, _ = _rotation_hass({"fam1.a": _stored_token(client_id=CIMD_CLIENT_ID)})

    status, body = await _post_refresh_grant(hass, "fam1.a", CIMD_CLIENT_ID, "guess")

    assert (status, body["error"]) == (401, "invalid_client")


@pytest.mark.asyncio
async def test_metadata_document_client_is_refused_when_turned_off():
    """Turning metadata documents off ends those clients' sessions at the next refresh."""
    from custom_components.oidc_provider.const import CONF_ALLOW_CLIENT_METADATA_DOCUMENTS

    hass, _ = _rotation_hass({"fam1.a": _stored_token(client_id=CIMD_CLIENT_ID)})
    hass.data[DOMAIN][CONF_ALLOW_CLIENT_METADATA_DOCUMENTS] = False

    status, body = await _post_refresh_grant(hass, "fam1.a", CIMD_CLIENT_ID, "")

    assert (status, body["error"]) == (401, "invalid_client")


@pytest.mark.asyncio
async def test_registered_public_client_refreshes_without_a_secret():
    """A client registered with auth method none authenticates without a secret."""
    hass, _ = _rotation_hass({"fam1.a": _stored_token(client_id="public_client")})
    hass.data[DOMAIN]["clients"]["public_client"] = {"token_endpoint_auth_method": "none"}

    status, _ = await _post_refresh_grant(hass, "fam1.a", "public_client", "")

    assert status == 200


@pytest.mark.asyncio
async def test_client_with_a_secret_stays_confidential_whatever_its_method():
    """A stored client holding a secret must present it, even if it asked for none."""
    from custom_components.oidc_provider.security import hash_client_secret

    hass, _ = _rotation_hass({"fam1.a": _stored_token(client_id="dcr_client")})
    hass.data[DOMAIN]["clients"]["dcr_client"] = {
        "token_endpoint_auth_method": "none",
        "client_secret_hash": hash_client_secret("dcr_secret"),
    }

    status, _ = await _post_refresh_grant(hass, "fam1.a", "dcr_client", "")
    assert status == 401
    status, _ = await _post_refresh_grant(hass, "fam1.a", "dcr_client", "dcr_secret")
    assert status == 200


def _register_hass():
    store = Mock()
    store.async_save = AsyncMock()
    hass = Mock()
    hass.data = {DOMAIN: {"clients": {}, "store": store, CONF_ALLOW_DYNAMIC_REGISTRATION: True}}
    return hass


async def _register(hass, body):
    request = Mock()
    request.app = {"hass": hass}
    request.remote = "127.0.0.1"
    request.json = AsyncMock(return_value=body)
    response = await OIDCRegisterView().post(request)
    return response.status, json.loads(response.body.decode("utf-8"))


@pytest.mark.asyncio
async def test_register_public_client_gets_no_secret():
    """Registering with auth method none creates a public client without a secret."""
    hass = _register_hass()

    status, body = await _register(
        hass,
        {
            "client_name": "Public",
            "redirect_uris": ["http://localhost/callback"],
            "token_endpoint_auth_method": "none",
        },
    )

    assert status == 201
    assert "client_secret" not in body
    assert body["token_endpoint_auth_method"] == "none"
    stored = hass.data[DOMAIN]["clients"][body["client_id"]]
    assert "client_secret_hash" not in stored


@pytest.mark.asyncio
async def test_register_unsupported_auth_method_falls_back_to_basic():
    """An auth method this server lacks is replaced, and the response says which applies."""
    hass = _register_hass()

    status, body = await _register(
        hass,
        {
            "client_name": "JWT",
            "redirect_uris": ["https://app.example.com/cb"],
            "token_endpoint_auth_method": "private_key_jwt",
        },
    )

    assert status == 201
    assert body["token_endpoint_auth_method"] == "client_secret_basic"
    assert body["client_secret"]


@pytest.mark.parametrize(
    ("host", "shown"),
    [
        ("claude.ai", "claude.ai"),
        ("сlaude.ai", "xn--laude-0ye.ai"),
        ("bücher.example", "xn--bcher-kva.example"),
    ],
)
def test_consent_screen_shows_hosts_in_ascii(host, shown):
    """A Unicode look-alike is shown in punycode, so it cannot pass for the real domain."""
    from custom_components.oidc_provider.http import _ascii_host

    assert _ascii_host(host) == shown
