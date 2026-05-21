"""Tests for token validator."""

import logging
import time

import jwt
import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from custom_components.oidc_provider.const import DOMAIN
from custom_components.oidc_provider.token_validator import (
    _describe_token,
    validate_access_token,
)


@pytest.fixture
def mock_hass_with_keys(hass):
    """Create a Home Assistant instance with JWT keys."""
    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()

    # Initialize OIDC provider data
    hass.data[DOMAIN] = {
        "jwt_private_key": private_key,
        "jwt_public_key": public_key,
    }

    return hass, private_key


def test_validate_access_token_valid(mock_hass_with_keys):
    """Test validating a valid access token."""
    hass, private_key = mock_hass_with_keys

    # Add clients to hass.data
    hass.data[DOMAIN]["clients"] = {"test_client": {}}

    # Create a valid token
    payload = {
        "sub": "test_user",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "iss": "http://localhost/oidc",
        "aud": "test_client",  # Required audience
    }

    # Convert private key to PEM for JWT library
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    token = jwt.encode(payload, private_key_pem, algorithm="RS256")

    # Validate the token
    result = validate_access_token(hass, token, "http://localhost")

    assert result is not None
    assert result["sub"] == "test_user"
    assert result["iss"] == "http://localhost/oidc"


def test_validate_access_token_expired(mock_hass_with_keys):
    """Test validating an expired token."""
    hass, private_key = mock_hass_with_keys

    # Create an expired token
    payload = {
        "sub": "test_user",
        "iat": int(time.time()) - 7200,
        "exp": int(time.time()) - 3600,  # Expired 1 hour ago
        "iss": "http://localhost/oidc",
    }

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    token = jwt.encode(payload, private_key_pem, algorithm="RS256")

    # Validate the token
    result = validate_access_token(hass, token, "http://localhost")

    assert result is None


def test_validate_access_token_invalid_signature(mock_hass_with_keys):
    """Test validating a token with invalid signature."""
    hass, _ = mock_hass_with_keys

    # Create a token with a different key
    different_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    payload = {
        "sub": "test_user",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "iss": "http://localhost/oidc",
    }

    different_key_pem = different_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    token = jwt.encode(payload, different_key_pem, algorithm="RS256")

    # Validate the token
    result = validate_access_token(hass, token, "http://localhost")

    assert result is None


def test_validate_access_token_malformed(mock_hass_with_keys):
    """Test validating a malformed token."""
    hass, _ = mock_hass_with_keys

    # Validate a malformed token
    result = validate_access_token(hass, "not.a.valid.jwt.token", "http://localhost")

    assert result is None


def test_validate_access_token_no_oidc_provider(hass):
    """Test validating when OIDC provider is not loaded."""
    # Don't initialize OIDC provider data
    result = validate_access_token(hass, "any.token.here", "http://localhost")

    assert result is None


def test_validate_access_token_no_public_key(hass):
    """Test validating when public key is missing."""
    hass.data[DOMAIN] = {}  # OIDC provider loaded but no keys

    result = validate_access_token(hass, "any.token.here", "http://localhost")

    assert result is None


def test_validate_access_token_with_custom_claims(mock_hass_with_keys):
    """Test validating a token with custom claims."""
    hass, private_key = mock_hass_with_keys

    # Add clients to hass.data
    hass.data[DOMAIN]["clients"] = {"test_client": {}}

    # Create a token with custom claims
    payload = {
        "sub": "test_user",
        "name": "Test User",
        "email": "test@example.com",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "iss": "http://localhost/oidc",
        "aud": "test_client",  # Required audience
        "custom_claim": "custom_value",
    }

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    token = jwt.encode(payload, private_key_pem, algorithm="RS256")

    # Validate the token
    result = validate_access_token(hass, token, "http://localhost")

    assert result is not None
    assert result["sub"] == "test_user"
    assert result["name"] == "Test User"
    assert result["email"] == "test@example.com"
    assert result["custom_claim"] == "custom_value"


async def test_validate_access_token_rejects_missing_audience(mock_hass_with_keys):
    """Test that tokens without audience claim are rejected."""
    hass, private_key = mock_hass_with_keys

    # Add clients to hass.data
    hass.data[DOMAIN]["clients"] = {"test_client": {}}

    # Create token without audience
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    payload = {
        "sub": "user123",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        # Missing "aud" claim
    }
    token = jwt.encode(payload, private_pem, algorithm="RS256")

    result = validate_access_token(hass, token, "http://localhost")
    assert result is None


async def test_validate_access_token_rejects_invalid_audience(mock_hass_with_keys):
    """Test that tokens with unregistered audience are rejected."""
    hass, private_key = mock_hass_with_keys

    # Add clients to hass.data
    hass.data[DOMAIN]["clients"] = {"test_client": {}}

    # Create token with invalid audience
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    payload = {
        "sub": "user123",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "aud": "nonexistent_client",  # Not registered
    }
    token = jwt.encode(payload, private_pem, algorithm="RS256")

    result = validate_access_token(hass, token, "http://localhost")
    assert result is None


async def test_validate_access_token_accepts_valid_audience(mock_hass_with_keys):
    """Test that tokens with valid registered audience are accepted."""
    hass, private_key = mock_hass_with_keys

    # Add clients to hass.data
    hass.data[DOMAIN]["clients"] = {"test_client": {}}

    # Create token with valid audience
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    payload = {
        "sub": "user123",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "iss": "http://localhost/oidc",
        "aud": "test_client",  # Registered client
    }
    token = jwt.encode(payload, private_pem, algorithm="RS256")

    result = validate_access_token(hass, token, "http://localhost")
    assert result is not None
    assert result["sub"] == "user123"
    assert result["aud"] == "test_client"


async def test_validate_access_token_rejects_missing_issuer(mock_hass_with_keys):
    """Test that tokens without issuer claim are rejected."""
    hass, private_key = mock_hass_with_keys

    # Add clients to hass.data
    hass.data[DOMAIN]["clients"] = {"test_client": {}}

    # Create token without issuer
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    payload = {
        "sub": "user123",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "aud": "test_client",
        # Missing "iss" claim
    }
    token = jwt.encode(payload, private_pem, algorithm="RS256")

    result = validate_access_token(hass, token, "http://localhost")
    assert result is None


async def test_validate_access_token_rejects_invalid_issuer(mock_hass_with_keys):
    """Test that tokens with wrong issuer are rejected."""
    hass, private_key = mock_hass_with_keys

    # Add clients to hass.data
    hass.data[DOMAIN]["clients"] = {"test_client": {}}

    # Create token with wrong issuer
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    payload = {
        "sub": "user123",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "iss": "http://evil.com",  # Wrong issuer
        "aud": "test_client",
    }
    token = jwt.encode(payload, private_pem, algorithm="RS256")

    result = validate_access_token(hass, token, "http://localhost")
    assert result is None


async def test_validate_access_token_accepts_issuer_without_oidc_suffix(mock_hass_with_keys):
    """Callers may pass the base URL with or without the /oidc suffix.

    Tokens carry iss=base_url/oidc (RFC 8414). Sibling integrations like
    hass-mcp-server pass the unsuffixed base URL; validate_access_token
    normalizes it before checking.
    """
    hass, private_key = mock_hass_with_keys
    hass.data[DOMAIN]["clients"] = {"test_client": {}}

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    payload = {
        "sub": "user123",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "iss": "https://ha.example.com/oidc",
        "aud": "test_client",
    }
    token = jwt.encode(payload, private_pem, algorithm="RS256")

    # Caller passes the base URL (no /oidc suffix). Validation still succeeds.
    result = validate_access_token(hass, token, "https://ha.example.com")
    assert result is not None
    assert result["sub"] == "user123"

    # And the canonical /oidc-suffixed form works identically.
    result = validate_access_token(hass, token, "https://ha.example.com/oidc")
    assert result is not None
    assert result["sub"] == "user123"


async def test_validate_access_token_rejects_unsuffixed_iss(mock_hass_with_keys):
    """Tokens whose iss lacks the /oidc suffix are rejected."""
    hass, private_key = mock_hass_with_keys
    hass.data[DOMAIN]["clients"] = {"test_client": {}}

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    payload = {
        "sub": "user123",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "iss": "https://ha.example.com",  # missing /oidc suffix
        "aud": "test_client",
    }
    token = jwt.encode(payload, private_pem, algorithm="RS256")

    assert validate_access_token(hass, token, "https://ha.example.com") is None
    assert validate_access_token(hass, token, "https://ha.example.com/oidc") is None


def test_describe_token_extracts_header_fields():
    """JWT-shaped tokens surface alg/kid/typ for diagnostics."""
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    token = jwt.encode(
        {"sub": "u"}, private_pem, algorithm="RS256", headers={"kid": "abc", "typ": "JWT"}
    )

    info = _describe_token(token)

    assert "alg='RS256'" in info
    assert "kid='abc'" in info
    assert "typ='JWT'" in info
    assert "segments=3" in info
    assert "length=" in info
    assert token not in info


def test_describe_token_marks_unparseable_input():
    """Non-JWT bearer tokens are logged as <unparseable> without leaking content."""
    info = _describe_token("not-a-jwt")

    assert "header=<unparseable>" in info
    assert "length=9" in info
    assert "segments=1" in info
    assert "not-a-jwt" not in info


def test_describe_token_handles_empty():
    """Empty tokens don't blow up the diagnostic helper."""
    assert _describe_token("") == "token=<empty>"


def test_invalid_alg_failure_logs_actual_alg(mock_hass_with_keys, caplog):
    """An HS256 token presented for RS256 validation logs its alg header."""
    hass, _ = mock_hass_with_keys
    hass.data[DOMAIN]["clients"] = {"test_client": {}}

    # Sign with HS256 so PyJWT raises InvalidAlgorithmError before signature checks.
    token = jwt.encode(
        {
            "sub": "u",
            "iss": "http://localhost/oidc",
            "aud": "test_client",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
        },
        "shared-secret",
        algorithm="HS256",
    )

    with caplog.at_level(logging.WARNING, logger="custom_components.oidc_provider.token_validator"):
        result = validate_access_token(hass, token, "http://localhost")

    assert result is None
    assert any(
        "alg='HS256'" in record.getMessage() and "Invalid token" in record.getMessage()
        for record in caplog.records
    )


def test_malformed_token_failure_logs_unparseable(mock_hass_with_keys, caplog):
    """A non-JWT bearer surfaces as unparseable in the warning."""
    hass, _ = mock_hass_with_keys
    hass.data[DOMAIN]["clients"] = {"test_client": {}}

    with caplog.at_level(logging.WARNING, logger="custom_components.oidc_provider.token_validator"):
        result = validate_access_token(hass, "definitely-not-a-jwt", "http://localhost")

    assert result is None
    assert any("header=<unparseable>" in record.getMessage() for record in caplog.records)
