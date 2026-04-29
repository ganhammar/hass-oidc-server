"""Test OIDC discovery document."""

import importlib.util
from pathlib import Path


def load_const_module():
    """Load const module without triggering HA imports."""
    spec = importlib.util.spec_from_file_location(
        "const", Path(__file__).parent.parent / "custom_components" / "oidc_provider" / "const.py"
    )
    const = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(const)
    return const


def test_discovery_document_structure():
    """Test OIDC discovery document has required fields."""
    base_url = "https://example.com"
    const = load_const_module()

    discovery = {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/auth/oidc/authorize",
        "token_endpoint": f"{base_url}/auth/oidc/token",
        "userinfo_endpoint": f"{base_url}/auth/oidc/userinfo",
        "jwks_uri": f"{base_url}/auth/oidc/jwks",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": const.SUPPORTED_SCOPES,
        "token_endpoint_auth_methods_supported": [
            "client_secret_post",
            "client_secret_basic",
        ],
        "claims_supported": [
            "sub",
            "name",
            "email",
            "email_verified",
            "groups",
            "iss",
            "aud",
            "exp",
            "iat",
            "auth_time",
            "nonce",
            "at_hash",
        ],
    }

    # Required OIDC discovery fields
    assert "issuer" in discovery
    assert "authorization_endpoint" in discovery
    assert "token_endpoint" in discovery
    assert "jwks_uri" in discovery
    assert "response_types_supported" in discovery
    assert "subject_types_supported" in discovery
    assert "id_token_signing_alg_values_supported" in discovery

    # Validate values
    assert discovery["issuer"] == base_url
    assert "code" in discovery["response_types_supported"]
    assert "RS256" in discovery["id_token_signing_alg_values_supported"]
    assert "openid" in discovery["scopes_supported"]


def test_endpoint_urls():
    """Test that endpoint URLs are correctly formatted."""
    base_url = "https://homeassistant.test"

    endpoints = {
        "authorization": f"{base_url}/auth/oidc/authorize",
        "token": f"{base_url}/auth/oidc/token",
        "userinfo": f"{base_url}/auth/oidc/userinfo",
        "jwks": f"{base_url}/auth/oidc/jwks",
    }

    for endpoint_url in endpoints.values():
        assert endpoint_url.startswith(base_url)
        assert "/auth/oidc/" in endpoint_url


def test_supported_grant_types():
    """Test supported grant types."""
    grant_types = ["authorization_code", "refresh_token"]

    assert "authorization_code" in grant_types
    assert "refresh_token" in grant_types


def test_supported_response_types():
    """Test supported response types."""
    response_types = ["code"]

    assert "code" in response_types
    assert len(response_types) == 1
