"""Tests for ID Token issuance (OIDC Core 1.0 §2)."""

import base64
import hashlib
import json
import time
from unittest.mock import AsyncMock, MagicMock, Mock

import jwt
import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from custom_components.oidc_provider.const import DOMAIN
from custom_components.oidc_provider.http import (
    OIDCAuthorizationView,
    OIDCContinueView,
    OIDCTokenView,
    OIDCUserInfoView,
)
from custom_components.oidc_provider.security import hash_client_secret


def _make_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, public_pem


def _make_user(name: str = "Test User", is_owner: bool = False):
    user = Mock()
    user.id = "user123"
    user.name = name
    user.is_owner = is_owner
    user.groups = []
    return user


def _pkce_pair():
    verifier = "valid_verifier_1234567890_abcdefghijklmnop"
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


def _build_token_hass(
    private_key,
    *,
    auth_code_data: dict,
    refresh_token_data: dict | None = None,
    user=None,
):
    """Build a Mock hass instance suitable for OIDCTokenView."""
    mock_token_store = Mock()
    mock_token_store.async_save = AsyncMock()
    hass = Mock()
    hass.data = {
        DOMAIN: {
            "clients": {
                "test_client": {
                    "client_secret_hash": hash_client_secret("test_secret"),
                    "redirect_uris": ["https://example.com/callback"],
                }
            },
            "authorization_codes": {"valid_code": auth_code_data} if auth_code_data else {},
            "refresh_tokens": refresh_token_data or {},
            "rate_limit_attempts": {},
            "jwt_private_key": private_key,
            "jwt_kid": "test-kid-1",
            "token_store": mock_token_store,
        }
    }
    hass.auth = Mock()
    hass.auth.async_get_user = AsyncMock(return_value=user or _make_user())
    return hass


_FIXED_HEADERS = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "ha.example.com"}
_FIXED_ISSUER = "https://ha.example.com"


def _post_authorization_code(hass, *, code_verifier=None):
    request = MagicMock()
    request.app = {"hass": hass}
    request.remote = "127.0.0.1"
    request.headers = dict(_FIXED_HEADERS)
    body = {
        "grant_type": "authorization_code",
        "client_id": "test_client",
        "client_secret": "test_secret",
        "code": "valid_code",
        "redirect_uri": "https://example.com/callback",
    }
    if code_verifier:
        body["code_verifier"] = code_verifier
    request.post = AsyncMock(return_value=body)
    return request


def _post_refresh(hass, refresh_token: str = "rt_value"):
    request = MagicMock()
    request.app = {"hass": hass}
    request.remote = "127.0.0.1"
    request.headers = dict(_FIXED_HEADERS)
    request.post = AsyncMock(
        return_value={
            "grant_type": "refresh_token",
            "client_id": "test_client",
            "client_secret": "test_secret",
            "refresh_token": refresh_token,
        }
    )
    return request


def _decode_id_token(token: str, public_pem: bytes, *, audience="test_client") -> dict:
    return jwt.decode(token, public_pem, algorithms=["RS256"], audience=audience)


# ---------------------------------------------------------------------------
# Authorization endpoint captures the nonce
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_authorize_captures_nonce():
    hass = Mock()
    hass.data = {
        DOMAIN: {
            "clients": {"test_client": {"redirect_uris": ["https://example.com/callback"]}},
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
        "nonce": "n-0S6_WzA2Mj",
        "code_challenge": "x",
        "code_challenge_method": "S256",
    }

    response = await OIDCAuthorizationView().get(request)
    assert response.status == 200

    pending = hass.data[DOMAIN]["pending_auth_requests"]
    [stored] = pending.values()
    assert stored["nonce"] == "n-0S6_WzA2Mj"


@pytest.mark.asyncio
async def test_authorize_missing_nonce_stores_none():
    hass = Mock()
    hass.data = {
        DOMAIN: {
            "clients": {"test_client": {"redirect_uris": ["https://example.com/callback"]}},
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
        "code_challenge": "x",
        "code_challenge_method": "S256",
    }

    response = await OIDCAuthorizationView().get(request)
    assert response.status == 200

    [stored] = hass.data[DOMAIN]["pending_auth_requests"].values()
    assert stored["nonce"] is None


# ---------------------------------------------------------------------------
# Continue endpoint propagates nonce + stamps auth_time
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_continue_propagates_nonce_and_stamps_auth_time():
    hass = Mock()
    hass.data = {
        DOMAIN: {
            "pending_auth_requests": {
                "req123": {
                    "client_id": "test_client",
                    "redirect_uri": "https://example.com/callback",
                    "scope": "openid",
                    "state": "",
                    "nonce": "abc-nonce",
                    "code_challenge": "c",
                    "code_challenge_method": "S256",
                    "expires_at": time.time() + 600,
                }
            },
            "authorization_codes": {},
        }
    }
    before = int(time.time())

    request = MagicMock()
    request.query = {"request_id": "req123"}
    request.app = {"hass": hass}
    request.__getitem__.return_value = Mock(id="user123")

    response = await OIDCContinueView().get(request)
    assert response.status == 200

    [code_data] = hass.data[DOMAIN]["authorization_codes"].values()
    assert code_data["nonce"] == "abc-nonce"
    assert code_data["auth_time"] >= before
    assert code_data["auth_time"] <= int(time.time())


# ---------------------------------------------------------------------------
# Token endpoint issues a spec-compliant id_token
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_id_token_issued_with_required_claims():
    private_key, public_pem = _make_keys()
    verifier, challenge = _pkce_pair()
    auth_time = int(time.time()) - 5

    hass = _build_token_hass(
        private_key,
        auth_code_data={
            "client_id": "test_client",
            "redirect_uri": "https://example.com/callback",
            "user_id": "user123",
            "scope": "openid",
            "nonce": "round-trip-nonce",
            "auth_time": auth_time,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "expires_at": time.time() + 600,
        },
    )

    response = await OIDCTokenView().post(_post_authorization_code(hass, code_verifier=verifier))
    assert response.status == 200
    body = json.loads(response.body.decode("utf-8"))
    assert "id_token" in body

    claims = _decode_id_token(body["id_token"], public_pem)

    # Required claims (OIDC Core §2)
    assert claims["sub"] == "user123"
    assert claims["aud"] == "test_client"
    assert claims["iss"]
    assert claims["iat"] <= int(time.time())
    assert claims["exp"] > claims["iat"]

    # Echoed nonce
    assert claims["nonce"] == "round-trip-nonce"

    # auth_time is what we stored at /oidc/continue time
    assert claims["auth_time"] == auth_time

    # token_use marks this as an id token
    assert claims["token_use"] == "id"

    # at_hash binds to the access token
    digest = hashlib.sha256(body["access_token"].encode("ascii")).digest()
    expected_at_hash = (
        base64.urlsafe_b64encode(digest[: len(digest) // 2]).decode("ascii").rstrip("=")
    )
    assert claims["at_hash"] == expected_at_hash


@pytest.mark.asyncio
async def test_id_token_omits_nonce_when_not_requested():
    private_key, public_pem = _make_keys()
    verifier, challenge = _pkce_pair()

    hass = _build_token_hass(
        private_key,
        auth_code_data={
            "client_id": "test_client",
            "redirect_uri": "https://example.com/callback",
            "user_id": "user123",
            "scope": "openid",
            "nonce": None,
            "auth_time": int(time.time()),
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "expires_at": time.time() + 600,
        },
    )

    response = await OIDCTokenView().post(_post_authorization_code(hass, code_verifier=verifier))
    body = json.loads(response.body.decode("utf-8"))
    claims = _decode_id_token(body["id_token"], public_pem)
    assert "nonce" not in claims


@pytest.mark.asyncio
async def test_id_token_includes_scope_gated_claims():
    private_key, public_pem = _make_keys()
    verifier, challenge = _pkce_pair()
    user = _make_user(name="user@example.com", is_owner=True)

    hass = _build_token_hass(
        private_key,
        user=user,
        auth_code_data={
            "client_id": "test_client",
            "redirect_uri": "https://example.com/callback",
            "user_id": "user123",
            "scope": "openid profile email groups",
            "nonce": None,
            "auth_time": int(time.time()),
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "expires_at": time.time() + 600,
        },
    )

    response = await OIDCTokenView().post(_post_authorization_code(hass, code_verifier=verifier))
    body = json.loads(response.body.decode("utf-8"))
    claims = _decode_id_token(body["id_token"], public_pem)

    assert claims["name"] == "user@example.com"
    assert claims["email"] == "user@example.com"
    assert claims["email_verified"] is False
    assert claims["groups"] == ["owner"]


@pytest.mark.asyncio
async def test_id_token_excludes_claims_when_scopes_absent():
    private_key, public_pem = _make_keys()
    verifier, challenge = _pkce_pair()

    hass = _build_token_hass(
        private_key,
        auth_code_data={
            "client_id": "test_client",
            "redirect_uri": "https://example.com/callback",
            "user_id": "user123",
            "scope": "openid",
            "nonce": None,
            "auth_time": int(time.time()),
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "expires_at": time.time() + 600,
        },
    )

    response = await OIDCTokenView().post(_post_authorization_code(hass, code_verifier=verifier))
    body = json.loads(response.body.decode("utf-8"))
    claims = _decode_id_token(body["id_token"], public_pem)

    for absent in ("name", "email", "email_verified", "groups"):
        assert absent not in claims


# ---------------------------------------------------------------------------
# Refresh-token grant re-issues an id_token
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_refresh_reissues_id_token_with_original_nonce_and_auth_time():
    private_key, public_pem = _make_keys()
    auth_time = int(time.time()) - 600

    hass = _build_token_hass(
        private_key,
        auth_code_data={},
        refresh_token_data={
            "rt_value": {
                "client_id": "test_client",
                "user_id": "user123",
                "scope": "openid",
                "nonce": "original-nonce",
                "auth_time": auth_time,
                "expires_at": time.time() + 3600,
            }
        },
    )

    response = await OIDCTokenView().post(_post_refresh(hass))
    assert response.status == 200
    body = json.loads(response.body.decode("utf-8"))
    assert "id_token" in body

    claims = _decode_id_token(body["id_token"], public_pem)
    assert claims["nonce"] == "original-nonce"
    assert claims["auth_time"] == auth_time
    assert claims["sub"] == "user123"

    # at_hash must match the *new* access token
    digest = hashlib.sha256(body["access_token"].encode("ascii")).digest()
    assert claims["at_hash"] == (
        base64.urlsafe_b64encode(digest[: len(digest) // 2]).decode("ascii").rstrip("=")
    )


@pytest.mark.asyncio
async def test_refresh_legacy_record_without_nonce_or_auth_time():
    """Refresh tokens persisted before this change have no nonce/auth_time keys."""
    private_key, public_pem = _make_keys()

    hass = _build_token_hass(
        private_key,
        auth_code_data={},
        refresh_token_data={
            "rt_value": {
                "client_id": "test_client",
                "user_id": "user123",
                "scope": "openid",
                "expires_at": time.time() + 3600,
            }
        },
    )

    response = await OIDCTokenView().post(_post_refresh(hass))
    assert response.status == 200
    body = json.loads(response.body.decode("utf-8"))
    assert "id_token" in body

    claims = _decode_id_token(body["id_token"], public_pem)
    # Original auth had no nonce → MUST NOT include
    assert "nonce" not in claims
    # auth_time was never recorded → omitted
    assert "auth_time" not in claims


@pytest.mark.asyncio
async def test_authorization_code_without_openid_scope_omits_id_token():
    """Defense-in-depth: even if an auth code somehow lacks openid scope, the
    code-grant response must not include an id_token."""
    private_key, _ = _make_keys()
    verifier, challenge = _pkce_pair()

    hass = _build_token_hass(
        private_key,
        auth_code_data={
            "client_id": "test_client",
            "redirect_uri": "https://example.com/callback",
            "user_id": "user123",
            "scope": "profile",  # no openid, bypassing the authorize-side check
            "nonce": None,
            "auth_time": int(time.time()),
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "expires_at": time.time() + 600,
        },
    )

    response = await OIDCTokenView().post(_post_authorization_code(hass, code_verifier=verifier))
    assert response.status == 200
    body = json.loads(response.body.decode("utf-8"))
    assert "access_token" in body
    assert "id_token" not in body


@pytest.mark.asyncio
async def test_refresh_without_openid_scope_omits_id_token():
    private_key, _ = _make_keys()

    hass = _build_token_hass(
        private_key,
        auth_code_data={},
        refresh_token_data={
            "rt_value": {
                "client_id": "test_client",
                "user_id": "user123",
                "scope": "profile",
                "expires_at": time.time() + 3600,
            }
        },
    )

    response = await OIDCTokenView().post(_post_refresh(hass))
    assert response.status == 200
    body = json.loads(response.body.decode("utf-8"))
    assert "id_token" not in body


# ---------------------------------------------------------------------------
# Persistence: refresh_tokens dict must include nonce/auth_time
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_authorization_code_persists_nonce_and_auth_time_on_refresh_record():
    private_key, _ = _make_keys()
    verifier, challenge = _pkce_pair()
    auth_time = int(time.time()) - 1

    hass = _build_token_hass(
        private_key,
        auth_code_data={
            "client_id": "test_client",
            "redirect_uri": "https://example.com/callback",
            "user_id": "user123",
            "scope": "openid",
            "nonce": "persist-me",
            "auth_time": auth_time,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "expires_at": time.time() + 600,
        },
    )

    response = await OIDCTokenView().post(_post_authorization_code(hass, code_verifier=verifier))
    assert response.status == 200

    [stored] = hass.data[DOMAIN]["refresh_tokens"].values()
    assert stored["nonce"] == "persist-me"
    assert stored["auth_time"] == auth_time

    # And it was flushed to the persistent store so it survives restart.
    hass.data[DOMAIN]["token_store"].async_save.assert_called_once()
    saved = hass.data[DOMAIN]["token_store"].async_save.call_args[0][0]
    [persisted] = saved["refresh_tokens"].values()
    assert persisted["nonce"] == "persist-me"
    assert persisted["auth_time"] == auth_time


# ---------------------------------------------------------------------------
# Userinfo rejects id_tokens
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_userinfo_rejects_id_token():
    private_key, _ = _make_keys()
    verifier, challenge = _pkce_pair()

    hass = _build_token_hass(
        private_key,
        auth_code_data={
            "client_id": "test_client",
            "redirect_uri": "https://example.com/callback",
            "user_id": "user123",
            "scope": "openid",
            "nonce": None,
            "auth_time": int(time.time()),
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "expires_at": time.time() + 600,
        },
    )

    response = await OIDCTokenView().post(_post_authorization_code(hass, code_verifier=verifier))
    body = json.loads(response.body.decode("utf-8"))
    id_token = body["id_token"]

    # Now attempt to use the id_token at /oidc/userinfo
    hass.data[DOMAIN]["jwt_public_key"] = private_key.public_key()

    userinfo_request = Mock()
    userinfo_request.app = {"hass": hass}
    userinfo_request.headers = {**_FIXED_HEADERS, "Authorization": f"Bearer {id_token}"}

    userinfo_response = await OIDCUserInfoView().get(userinfo_request)
    assert userinfo_response.status == 401
    payload = json.loads(userinfo_response.body.decode("utf-8"))
    assert payload["error"] == "invalid_token"


@pytest.mark.asyncio
async def test_userinfo_accepts_access_token():
    private_key, _ = _make_keys()
    verifier, challenge = _pkce_pair()

    hass = _build_token_hass(
        private_key,
        auth_code_data={
            "client_id": "test_client",
            "redirect_uri": "https://example.com/callback",
            "user_id": "user123",
            "scope": "openid",
            "nonce": None,
            "auth_time": int(time.time()),
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "expires_at": time.time() + 600,
        },
    )

    response = await OIDCTokenView().post(_post_authorization_code(hass, code_verifier=verifier))
    body = json.loads(response.body.decode("utf-8"))
    access_token = body["access_token"]

    hass.data[DOMAIN]["jwt_public_key"] = private_key.public_key()

    userinfo_request = Mock()
    userinfo_request.app = {"hass": hass}
    userinfo_request.headers = {**_FIXED_HEADERS, "Authorization": f"Bearer {access_token}"}

    userinfo_response = await OIDCUserInfoView().get(userinfo_request)
    assert userinfo_response.status == 200
    payload = json.loads(userinfo_response.body.decode("utf-8"))
    assert payload["sub"] == "user123"
