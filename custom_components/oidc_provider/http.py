"""HTTP endpoints for OIDC Provider."""

import base64
import hashlib
import html
import logging
import secrets
import time
import uuid
from typing import Any
from urllib.parse import urlparse

import jwt
from aiohttp import web
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from homeassistant.components.http import HomeAssistantView
from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store

from .client_manager import create_client
from .const import (
    ACCESS_TOKEN_EXPIRY,
    AUTHORIZATION_CODE_EXPIRY,
    CODE_CHALLENGE_METHOD_S256,
    CONF_REQUIRE_PKCE,
    DEFAULT_REQUIRE_PKCE,
    DOMAIN,
    GRANT_TYPE_AUTHORIZATION_CODE,
    GRANT_TYPE_REFRESH_TOKEN,
    GROUP_OWNER,
    HA_GROUP_TO_OIDC_GROUP,
    ID_TOKEN_EXPIRY,
    MAX_TOKEN_ATTEMPTS,
    PANEL_URL_PATH,
    RATE_LIMIT_PENALTY,
    RATE_LIMIT_WINDOW,
    REFRESH_TOKEN_EXPIRY,
    RESPONSE_TYPE_CODE,
    SCOPE_EMAIL,
    SCOPE_GROUPS,
    SCOPE_OPENID,
    SCOPE_PROFILE,
    STORAGE_KEY_KEYS,
    STORAGE_VERSION,
    SUPPORTED_CODE_CHALLENGE_METHODS,
    SUPPORTED_SCOPES,
    TOKEN_USE_ACCESS,
    TOKEN_USE_ID,
)
from .security import verify_client_secret
from .token_validator import get_issuer_from_request

_LOGGER = logging.getLogger(__name__)


def _normalize_resource(resource: str | None) -> str | None:
    """Validate an RFC 8707 resource indicator and return it, or None.

    The resource must be an absolute URI without a fragment (RFC 8707 §2).
    Malformed values are dropped so they can never end up as a token audience.
    """
    if not resource:
        return None
    parsed = urlparse(resource)
    if not parsed.scheme or not parsed.netloc or parsed.fragment:
        _LOGGER.warning("Ignoring malformed resource indicator: %s", resource)
        return None
    return resource


async def _save_refresh_tokens(hass: HomeAssistant) -> None:
    """Persist the current in-memory refresh tokens to the token store."""
    token_store = hass.data[DOMAIN].get("token_store")
    if token_store:
        await token_store.async_save({"refresh_tokens": hass.data[DOMAIN]["refresh_tokens"]})


async def _load_or_generate_keys(hass: HomeAssistant) -> tuple[Any, str]:
    """Load existing RSA keys from storage or generate new ones.

    Returns:
        Tuple of (private_key, kid)
    """
    store = Store(hass, STORAGE_VERSION, STORAGE_KEY_KEYS)
    stored_keys = await store.async_load()

    if stored_keys and "private_key_pem" in stored_keys:
        # Load existing key
        _LOGGER.info("Loading existing RSA key from storage")
        private_key = serialization.load_pem_private_key(
            stored_keys["private_key_pem"].encode(),
            password=None,
            backend=default_backend(),
        )
        kid = stored_keys.get("kid", "1")  # Fallback to "1" for old keys
    else:
        # Generate new key
        _LOGGER.info("Generating new RSA key pair for JWT signing")
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

        # Generate unique key ID
        kid = str(uuid.uuid4())

        # Save to storage
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        await store.async_save(
            {
                "private_key_pem": private_pem.decode(),
                "kid": kid,
                "created_at": time.time(),
            }
        )

        _LOGGER.info("RSA key pair generated and saved to storage with kid: %s", kid)

    return private_key, kid


def _resolve_user_groups(user: Any) -> list[str]:
    """Resolve OIDC groups from a Home Assistant user."""
    groups = []

    if getattr(user, "is_owner", False):
        groups.append(GROUP_OWNER)

    for group in getattr(user, "groups", []):
        oidc_group = HA_GROUP_TO_OIDC_GROUP.get(group.id)
        if oidc_group:
            groups.append(oidc_group)

    return groups


def _looks_like_email(value: str) -> bool:
    """Check if a string looks like an email address."""
    if not value or "@" not in value:
        return False
    local, _, domain = value.rpartition("@")
    return bool(local) and "." in domain


async def setup_http_endpoints(hass: HomeAssistant) -> None:
    """Set up the OIDC HTTP endpoints."""
    # Load or generate RSA key pair for JWT signing
    if "jwt_private_key" not in hass.data[DOMAIN]:
        private_key, kid = await _load_or_generate_keys(hass)
        hass.data[DOMAIN]["jwt_private_key"] = private_key
        hass.data[DOMAIN]["jwt_public_key"] = private_key.public_key()
        hass.data[DOMAIN]["jwt_kid"] = kid

    # Initialize rate limiting storage
    if "rate_limit_attempts" not in hass.data[DOMAIN]:
        hass.data[DOMAIN]["rate_limit_attempts"] = {}

    # Register views
    hass.http.register_view(OIDCDiscoveryView())
    hass.http.register_view(OAuth2AuthorizationServerMetadataView())
    hass.http.register_view(OAuth2AuthorizationServerMetadataAlternateView())
    hass.http.register_view(OIDCAuthorizationView())
    hass.http.register_view(OIDCContinueView())
    hass.http.register_view(OIDCTokenView())
    hass.http.register_view(OIDCUserInfoView())
    hass.http.register_view(OIDCJWKSView())
    hass.http.register_view(OIDCRegisterView())


class OIDCContinueView(HomeAssistantView):
    """OIDC Continue view - requires auth, retrieves stored request, generates code."""

    url = "/oidc/continue"
    name = "api:oidc:continue"
    requires_auth = True

    async def get(self, request: web.Request) -> web.Response:
        """Handle continuation after authentication."""
        hass = request.app["hass"]
        user = request["hass_user"]

        # Get request ID from query or session storage will pass it
        request_id = request.query.get("request_id")
        if not request_id:
            return web.Response(text="Missing request_id", status=400)

        pending_requests = hass.data[DOMAIN].get("pending_auth_requests", {})
        if request_id not in pending_requests:
            return web.Response(text="Invalid or expired request", status=400)

        stored_request = pending_requests[request_id]
        if stored_request["expires_at"] < time.time():
            del pending_requests[request_id]
            return web.Response(text="Request expired", status=400)

        # Extract parameters
        client_id = stored_request["client_id"]
        redirect_uri = stored_request["redirect_uri"]
        scope = stored_request["scope"]
        state = stored_request["state"]
        nonce = stored_request.get("nonce")
        code_challenge = stored_request.get("code_challenge")
        code_challenge_method = stored_request.get("code_challenge_method")
        resource = stored_request.get("resource")

        # Clean up
        del pending_requests[request_id]

        # Generate authorization code
        auth_code = secrets.token_urlsafe(32)
        hass.data[DOMAIN]["authorization_codes"][auth_code] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "user_id": user.id,
            "nonce": nonce,
            # OIDC §2 defines auth_time as when End-User authentication occurred.
            # /oidc/continue is auth-gated, so we know the user *is* authenticated
            # here, but the underlying HA session may be older. We stamp the time
            # the user transited the consent step as the closest approximation
            # available without reaching into HA's session internals. max_age
            # is not honored at the authorize endpoint, so this approximation
            # cannot mask a missed re-authentication today.
            "auth_time": int(time.time()),
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "resource": resource,
            "expires_at": time.time() + AUTHORIZATION_CODE_EXPIRY,
        }

        # Build redirect URL
        separator = "&" if "?" in redirect_uri else "?"
        redirect_url = f"{redirect_uri}{separator}code={auth_code}"
        if state:
            redirect_url += f"&state={state}"

        # Return JSON with redirect URL (since fetch can't follow external redirects)
        return web.json_response({"redirect_url": redirect_url})


class OIDCDiscoveryView(HomeAssistantView):
    """OIDC Discovery endpoint."""

    url = "/oidc/.well-known/openid-configuration"
    name = "api:oidc:discovery"
    requires_auth = False

    async def get(self, request: web.Request) -> web.Response:
        """Handle discovery request."""
        base_url = get_issuer_from_request(request)

        discovery = {
            "issuer": f"{base_url}/oidc",
            "authorization_endpoint": f"{base_url}/oidc/authorize",
            "token_endpoint": f"{base_url}/oidc/token",
            "userinfo_endpoint": f"{base_url}/oidc/userinfo",
            "jwks_uri": f"{base_url}/oidc/jwks",
            "registration_endpoint": f"{base_url}/oidc/register",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": SUPPORTED_SCOPES,
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
            "code_challenge_methods_supported": SUPPORTED_CODE_CHALLENGE_METHODS,
        }

        return web.json_response(discovery)


class OAuth2AuthorizationServerMetadataView(HomeAssistantView):
    """OAuth 2.0 Authorization Server Metadata endpoint (RFC 8414)."""

    url = "/.well-known/oauth-authorization-server/oidc"
    name = "api:oauth:as-metadata"
    requires_auth = False

    async def get(self, request: web.Request) -> web.Response:
        """Handle OAuth 2.0 Authorization Server Metadata request."""
        base_url = get_issuer_from_request(request)

        metadata = {
            "issuer": f"{base_url}/oidc",
            "authorization_endpoint": f"{base_url}/oidc/authorize",
            "token_endpoint": f"{base_url}/oidc/token",
            "registration_endpoint": f"{base_url}/oidc/register",
            "jwks_uri": f"{base_url}/oidc/jwks",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_post",
                "client_secret_basic",
            ],
            "code_challenge_methods_supported": SUPPORTED_CODE_CHALLENGE_METHODS,
            "scopes_supported": SUPPORTED_SCOPES,
        }

        return web.json_response(metadata)


class OAuth2AuthorizationServerMetadataAlternateView(HomeAssistantView):
    """OAuth 2.0 Authorization Server Metadata at alternate path.

    Some clients append /.well-known/oauth-authorization-server to the
    authorization server URL rather than inserting it after the authority
    as RFC 8414 specifies. This view serves the same metadata at that
    alternate location for compatibility.
    """

    url = "/oidc/.well-known/oauth-authorization-server"
    name = "api:oauth:as-metadata-alt"
    requires_auth = False

    async def get(self, request: web.Request) -> web.Response:
        """Handle OAuth 2.0 Authorization Server Metadata request."""
        base_url = get_issuer_from_request(request)

        metadata = {
            "issuer": f"{base_url}/oidc",
            "authorization_endpoint": f"{base_url}/oidc/authorize",
            "token_endpoint": f"{base_url}/oidc/token",
            "registration_endpoint": f"{base_url}/oidc/register",
            "jwks_uri": f"{base_url}/oidc/jwks",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_post",
                "client_secret_basic",
            ],
            "code_challenge_methods_supported": SUPPORTED_CODE_CHALLENGE_METHODS,
            "scopes_supported": SUPPORTED_SCOPES,
        }

        return web.json_response(metadata)


class OIDCAuthorizationView(HomeAssistantView):
    """OIDC Authorization endpoint."""

    url = "/oidc/authorize"
    name = "api:oidc:authorize"
    requires_auth = False

    async def get(self, request: web.Request) -> web.Response:
        """Handle authorization request."""
        hass = request.app["hass"]

        # Extract parameters from query string
        client_id = request.query.get("client_id")
        redirect_uri = request.query.get("redirect_uri")
        response_type = request.query.get("response_type")
        scope = request.query.get("scope", "")
        state = request.query.get("state", "")
        nonce = request.query.get("nonce")
        code_challenge = request.query.get("code_challenge")
        code_challenge_method = request.query.get(
            "code_challenge_method", CODE_CHALLENGE_METHOD_S256
        )
        # RFC 8707 resource indicator. Identifies the protected resource (e.g. the
        # MCP server) the access token will be used at; bound into the token aud.
        resource = _normalize_resource(request.query.get("resource"))

        # Validate parameters
        if not client_id or not redirect_uri or response_type != RESPONSE_TYPE_CODE:
            return web.Response(text="Invalid request", status=400)

        # Validate that openid scope is present (required by OIDC Core Section 3.1.2.1)
        requested_scopes = scope.split() if scope else []
        if SCOPE_OPENID not in requested_scopes:
            return web.Response(
                text="The openid scope is required for OIDC requests.",
                status=400,
            )

        # NOTE: max_age (OIDC Core §3.1.2.1) is intentionally not honored here.
        # The auth_time claim emitted in the id_token is stamped at the
        # /oidc/continue step, which approximates "authentication occurred"
        # because HA may have authenticated the user via a long-lived session.
        # If max_age support is added, auth_time MUST move to a primitive
        # representing actual login time (e.g. the HA refresh token's
        # created_at), otherwise max_age would silently no-op.

        # Check if PKCE is required
        require_pkce = hass.data[DOMAIN].get(CONF_REQUIRE_PKCE, DEFAULT_REQUIRE_PKCE)

        if require_pkce and not code_challenge:
            return web.Response(
                text="PKCE is required. Please provide code_challenge parameter.",
                status=400,
            )

        # Validate PKCE parameters
        if code_challenge:
            if code_challenge_method not in SUPPORTED_CODE_CHALLENGE_METHODS:
                supported = ", ".join(SUPPORTED_CODE_CHALLENGE_METHODS)
                return web.Response(
                    text=f"Unsupported code_challenge_method. Supported: {supported}",
                    status=400,
                )

        clients = hass.data[DOMAIN].get("clients", {})

        if client_id not in clients:
            return web.Response(text="Invalid client_id", status=400)

        client = clients[client_id]
        if redirect_uri not in client["redirect_uris"]:
            return web.Response(text="Invalid redirect_uri", status=400)

        # Store request and redirect to frontend panel (which requires auth)
        auth_request_id = secrets.token_urlsafe(16)

        # Store the authorization request parameters
        if "pending_auth_requests" not in hass.data[DOMAIN]:
            hass.data[DOMAIN]["pending_auth_requests"] = {}

        # Clean up expired pending requests
        current_time = time.time()
        expired_ids = [
            req_id
            for req_id, req_data in hass.data[DOMAIN]["pending_auth_requests"].items()
            if req_data["expires_at"] < current_time
        ]
        for req_id in expired_ids:
            del hass.data[DOMAIN]["pending_auth_requests"][req_id]

        hass.data[DOMAIN]["pending_auth_requests"][auth_request_id] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": response_type,
            "scope": scope,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "resource": resource,
            "expires_at": time.time() + 600,  # 10 minutes
        }

        # Return HTML that stores request ID in sessionStorage and redirects to panel
        # Note: auth_request_id is a cryptographically secure token, but we still escape it
        escaped_request_id = html.escape(auth_request_id)
        redirect_script = f"""
        <html>
        <head><title>OIDC Authorization</title></head>
        <body>
            <p>Redirecting to login...</p>
            <script>
                sessionStorage.setItem('oidc_request_id', '{escaped_request_id}');
                window.location.href = '/{PANEL_URL_PATH}';
            </script>
        </body>
        </html>
        """
        return web.Response(
            text=redirect_script,
            content_type="text/html",
        )


class OIDCTokenView(HomeAssistantView):
    """OIDC Token endpoint."""

    url = "/oidc/token"
    name = "api:oidc:token"
    requires_auth = False

    async def post(self, request: web.Request) -> web.Response:
        """Handle token request."""
        hass = request.app["hass"]
        data = await request.post()

        grant_type = data.get("grant_type")

        # Extract client credentials from either POST data or Authorization header
        client_id = data.get("client_id")
        client_secret = data.get("client_secret")

        # Check for HTTP Basic authentication
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Basic "):
            try:
                # Decode Basic auth credentials
                credentials = base64.b64decode(auth_header[6:]).decode("utf-8")
                client_id, client_secret = credentials.split(":", 1)
            except Exception as e:
                _LOGGER.warning("Invalid Basic auth header: %s", e)
                return web.json_response({"error": "invalid_client"}, status=401)

        # Check rate limiting
        rate_limit_key = f"{client_id}:{request.remote}"
        rate_limits = hass.data[DOMAIN]["rate_limit_attempts"]
        current_time = time.time()

        # Clean up old rate limit entries
        expired_keys = [
            key
            for key, data in rate_limits.items()
            if data["window_start"] < current_time - RATE_LIMIT_WINDOW
        ]
        for key in expired_keys:
            del rate_limits[key]

        # Check if client is rate limited
        if rate_limit_key in rate_limits:
            limit_data = rate_limits[rate_limit_key]
            if limit_data.get("locked_until", 0) > current_time:
                _LOGGER.warning(
                    "Rate limit active for client %s from %s", client_id, request.remote
                )
                return web.json_response(
                    {
                        "error": "invalid_client",
                        "error_description": "Too many failed attempts. Please try again later.",
                    },
                    status=429,
                )

        # Validate client
        clients = hass.data[DOMAIN].get("clients", {})
        if client_id not in clients:
            self._record_failed_attempt(hass, rate_limit_key, current_time)
            return web.json_response({"error": "invalid_client"}, status=401)

        client = clients[client_id]
        # Verify client secret using constant-time comparison
        # Support both old (plain) and new (hashed) client secrets for backward compatibility
        if "client_secret_hash" in client:
            # New hashed format
            if not verify_client_secret(client_secret, client["client_secret_hash"]):
                _LOGGER.warning("Invalid client secret for client %s", client_id)
                self._record_failed_attempt(hass, rate_limit_key, current_time)
                return web.json_response({"error": "invalid_client"}, status=401)
        elif "client_secret" in client:
            # Old plain text format (backward compatibility)
            if client["client_secret"] != client_secret:
                _LOGGER.warning("Invalid client secret for client %s (legacy)", client_id)
                self._record_failed_attempt(hass, rate_limit_key, current_time)
                return web.json_response({"error": "invalid_client"}, status=401)
        else:
            _LOGGER.error("Client %s has no secret configured", client_id)
            self._record_failed_attempt(hass, rate_limit_key, current_time)
            return web.json_response({"error": "invalid_client"}, status=401)

        # Successful authentication - clear rate limit
        if rate_limit_key in rate_limits:
            del rate_limits[rate_limit_key]

        if grant_type == GRANT_TYPE_AUTHORIZATION_CODE:
            return await self._handle_authorization_code(request, hass, data)
        elif grant_type == GRANT_TYPE_REFRESH_TOKEN:
            return await self._handle_refresh_token(request, hass, data)
        else:
            return web.json_response({"error": "unsupported_grant_type"}, status=400)

    def _record_failed_attempt(
        self, hass: HomeAssistant, rate_limit_key: str, current_time: float
    ) -> None:
        """Record a failed authentication attempt for rate limiting."""
        rate_limits = hass.data[DOMAIN]["rate_limit_attempts"]

        if rate_limit_key not in rate_limits:
            rate_limits[rate_limit_key] = {
                "attempts": 1,
                "window_start": current_time,
            }
        else:
            rate_limits[rate_limit_key]["attempts"] += 1

        # Check if we've exceeded max attempts
        if rate_limits[rate_limit_key]["attempts"] >= MAX_TOKEN_ATTEMPTS:
            rate_limits[rate_limit_key]["locked_until"] = current_time + RATE_LIMIT_PENALTY
            _LOGGER.warning(
                "Rate limit triggered for %s - locked for %d seconds",
                rate_limit_key,
                RATE_LIMIT_PENALTY,
            )

    async def _handle_authorization_code(
        self, _request: web.Request, hass: HomeAssistant, data: Any
    ) -> web.Response:
        """Handle authorization code grant."""
        code = data.get("code")
        redirect_uri = data.get("redirect_uri")
        code_verifier = data.get("code_verifier")

        auth_codes = hass.data[DOMAIN]["authorization_codes"]
        if code not in auth_codes:
            return web.json_response({"error": "invalid_grant"}, status=400)

        auth_data = auth_codes[code]

        # Validate authorization code
        if auth_data["expires_at"] < time.time():
            del auth_codes[code]
            return web.json_response({"error": "invalid_grant"}, status=400)

        if auth_data["redirect_uri"] != redirect_uri:
            return web.json_response({"error": "invalid_grant"}, status=400)

        # Validate PKCE code_verifier if code_challenge was provided
        code_challenge = auth_data.get("code_challenge")
        if code_challenge:
            if not code_verifier:
                del auth_codes[code]
                return web.json_response(
                    {"error": "invalid_grant", "error_description": "code_verifier required"},
                    status=400,
                )

            try:
                # Verify code_verifier matches code_challenge (only S256 supported)
                code_challenge_method = auth_data.get(
                    "code_challenge_method", CODE_CHALLENGE_METHOD_S256
                )
                if code_challenge_method != CODE_CHALLENGE_METHOD_S256:
                    # Only S256 method is supported (RFC 7636 + OAuth 2.1)
                    del auth_codes[code]
                    return web.json_response(
                        {
                            "error": "invalid_grant",
                            "error_description": (
                                f"Unsupported code_challenge_method: {code_challenge_method}. "
                                "Only S256 is supported."
                            ),
                        },
                        status=400,
                    )

                # Compute SHA256 hash of code_verifier
                verifier_hash = hashlib.sha256(code_verifier.encode("ascii")).digest()
                computed_challenge = (
                    base64.urlsafe_b64encode(verifier_hash).decode("ascii").rstrip("=")
                )

                if computed_challenge != code_challenge:
                    del auth_codes[code]
                    _LOGGER.warning(
                        "PKCE verification failed for client %s - expected %s, got %s",
                        auth_data["client_id"],
                        code_challenge,
                        computed_challenge,
                    )
                    return web.json_response(
                        {"error": "invalid_grant", "error_description": "Invalid code_verifier"},
                        status=400,
                    )
            except Exception as e:
                del auth_codes[code]
                _LOGGER.error("Error verifying PKCE: %s", str(e), exc_info=True)
                return web.json_response(
                    {"error": "invalid_grant", "error_description": "PKCE verification error"},
                    status=400,
                )

        # Generate tokens
        user_id = auth_data["user_id"]
        client_id = auth_data["client_id"]
        scope = auth_data["scope"]

        nonce = auth_data.get("nonce")
        auth_time = auth_data.get("auth_time")

        # The token audience is bound to the resource requested at the authorize
        # step (RFC 8707). A token request MAY also carry a resource indicator;
        # honor it only when the authorize step didn't specify one.
        resource = auth_data.get("resource") or _normalize_resource(data.get("resource"))

        access_token = await self._generate_access_token(
            _request, hass, user_id, scope, client_id, audience=resource
        )
        refresh_token = secrets.token_urlsafe(32)

        # Store refresh token (nonce + auth_time persisted so future refreshes
        # produce spec-correct id_tokens after Home Assistant restarts; resource
        # persisted so refreshed access tokens keep the same audience binding).
        hass.data[DOMAIN]["refresh_tokens"][refresh_token] = {
            "user_id": user_id,
            "client_id": client_id,
            "scope": scope,
            "nonce": nonce,
            "auth_time": auth_time,
            "resource": resource,
            "expires_at": time.time() + REFRESH_TOKEN_EXPIRY,
        }

        # Persist refresh tokens to storage
        await _save_refresh_tokens(hass)

        # Delete used authorization code
        del auth_codes[code]

        response_body: dict[str, Any] = {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_EXPIRY,
            "refresh_token": refresh_token,
            "scope": scope,
        }

        # Issue an id_token only when openid scope was granted (OIDC Core §3.1.3.3).
        # The authorize endpoint already enforces openid, so this branch is
        # effectively always taken today; the explicit check is defense-in-depth
        # against future changes loosening the authorize-side check.
        if SCOPE_OPENID in (scope or "").split():
            response_body["id_token"] = await self._generate_id_token(
                _request,
                hass,
                user_id,
                scope,
                client_id,
                nonce=nonce,
                auth_time=auth_time,
                access_token=access_token,
            )

        return web.json_response(response_body)

    async def _handle_refresh_token(
        self, _request: web.Request, hass: HomeAssistant, data: Any
    ) -> web.Response:
        """Handle refresh token grant."""
        refresh_token = data.get("refresh_token")

        refresh_tokens = hass.data[DOMAIN]["refresh_tokens"]
        if refresh_token not in refresh_tokens:
            return web.json_response({"error": "invalid_grant"}, status=400)

        token_data = refresh_tokens[refresh_token]

        # Validate refresh token
        if token_data["expires_at"] < time.time():
            del refresh_tokens[refresh_token]
            await _save_refresh_tokens(hass)
            return web.json_response({"error": "invalid_grant"}, status=400)

        if token_data["client_id"] != data.get("client_id"):
            return web.json_response({"error": "invalid_grant"}, status=400)

        # Generate new access token, preserving the original resource binding
        # (RFC 8707) so refreshed tokens stay valid at the same resource.
        access_token = await self._generate_access_token(
            _request,
            hass,
            token_data["user_id"],
            token_data["scope"],
            token_data["client_id"],
            audience=token_data.get("resource"),
        )

        # Re-issue an id_token when openid scope is granted (OIDC Core §12.2).
        # Original nonce and auth_time are carried forward; iat/exp/at_hash are
        # fresh. Old refresh tokens persisted before this change have neither
        # field, handled by .get() returning None.
        response_body: dict[str, Any] = {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_EXPIRY,
            "scope": token_data["scope"],
        }

        scope_value = token_data["scope"] or ""
        if SCOPE_OPENID in scope_value.split():
            response_body["id_token"] = await self._generate_id_token(
                _request,
                hass,
                token_data["user_id"],
                token_data["scope"],
                token_data["client_id"],
                nonce=token_data.get("nonce"),
                auth_time=token_data.get("auth_time"),
                access_token=access_token,
            )

        return web.json_response(response_body)

    async def _generate_access_token(
        self,
        request: web.Request,
        hass: HomeAssistant,
        user_id: str,
        scope: str,
        client_id: str,
        audience: str | None = None,
    ) -> str:
        """Generate JWT access token."""
        now = int(time.time())

        # Use dynamic issuer based on the actual base URL. The /oidc suffix is
        # required by RFC 8414: the issuer URL concatenated with
        # /.well-known/oauth-authorization-server must return the auth-server
        # metadata, and that metadata lives under /oidc.
        base_url = get_issuer_from_request(request)
        issuer = f"{base_url}/oidc"

        # When a resource indicator was supplied (RFC 8707), bind aud to that
        # resource and record the client in azp. Otherwise fall back to the
        # client_id as the audience for backward compatibility.
        payload = {
            "sub": user_id,
            "iat": now,
            "exp": now + ACCESS_TOKEN_EXPIRY,
            "iss": issuer,
            "aud": audience or client_id,
            "scope": scope,
            "token_use": TOKEN_USE_ACCESS,
        }
        if audience:
            payload["azp"] = client_id

        # Include groups claim when the groups scope is requested
        requested_scopes = scope.split() if scope else []
        if SCOPE_GROUPS in requested_scopes:
            user = await hass.auth.async_get_user(user_id)
            if user:
                payload["groups"] = _resolve_user_groups(user)

        private_key = hass.data[DOMAIN]["jwt_private_key"]
        kid = hass.data[DOMAIN]["jwt_kid"]
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        return jwt.encode(payload, private_pem, algorithm="RS256", headers={"kid": kid})

    async def _generate_id_token(
        self,
        request: web.Request,
        hass: HomeAssistant,
        user_id: str,
        scope: str,
        client_id: str,
        *,
        nonce: str | None,
        auth_time: int | None,
        access_token: str,
    ) -> str:
        """Generate an OIDC ID Token (OIDC Core 1.0 §2)."""
        now = int(time.time())
        base_url = get_issuer_from_request(request)
        issuer = f"{base_url}/oidc"

        payload: dict[str, Any] = {
            "iss": issuer,
            "sub": user_id,
            "aud": client_id,
            "iat": now,
            "exp": now + ID_TOKEN_EXPIRY,
            "token_use": TOKEN_USE_ID,
        }

        if auth_time is not None:
            payload["auth_time"] = int(auth_time)

        # Nonce: MUST be echoed when present in the auth request,
        # MUST NOT be included otherwise (OIDC Core §3.1.3.7).
        if nonce is not None:
            payload["nonce"] = nonce

        # at_hash: base64url-encoded left-most half of the SHA-256 hash of the
        # access token (OIDC Core §3.1.3.6). Defense-in-depth binding so a
        # stolen access token cannot be paired with a different id_token.
        digest = hashlib.sha256(access_token.encode("ascii")).digest()
        payload["at_hash"] = (
            base64.urlsafe_b64encode(digest[: len(digest) // 2]).decode("ascii").rstrip("=")
        )

        # Scope-gated identity claims. OIDC Core §5.4 permits returning these
        # in the id_token; many real-world clients (oauth2-proxy, mod_auth_openidc)
        # only read identity from the id_token, so include them when granted.
        requested_scopes = scope.split() if scope else []
        user = None
        if (
            SCOPE_PROFILE in requested_scopes
            or SCOPE_EMAIL in requested_scopes
            or SCOPE_GROUPS in requested_scopes
        ):
            user = await hass.auth.async_get_user(user_id)

        if user and SCOPE_PROFILE in requested_scopes:
            payload["name"] = user.name

        if user and SCOPE_EMAIL in requested_scopes:
            username = user.name or ""
            if _looks_like_email(username):
                payload["email"] = username
                payload["email_verified"] = False

        if user and SCOPE_GROUPS in requested_scopes:
            payload["groups"] = _resolve_user_groups(user)

        private_key = hass.data[DOMAIN]["jwt_private_key"]
        kid = hass.data[DOMAIN]["jwt_kid"]
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        return jwt.encode(payload, private_pem, algorithm="RS256", headers={"kid": kid})


class OIDCUserInfoView(HomeAssistantView):
    """OIDC UserInfo endpoint."""

    url = "/oidc/userinfo"
    name = "api:oidc:userinfo"
    requires_auth = False  # We'll validate the JWT ourselves

    async def get(self, request: web.Request) -> web.Response:
        """Handle userinfo request."""
        hass = request.app["hass"]

        # Get the access token from Authorization header
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return web.json_response({"error": "unauthorized"}, status=401)

        access_token = auth_header[7:]  # Remove "Bearer " prefix

        try:
            # Verify and decode the JWT
            public_key = hass.data[DOMAIN]["jwt_public_key"]
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            # Decode and verify the JWT with issuer verification. The /oidc
            # suffix matches what the token endpoint signs into the iss claim
            # (RFC 8414).
            expected_issuer = f"{get_issuer_from_request(request)}/oidc"

            payload = jwt.decode(
                access_token,
                public_pem,
                algorithms=["RS256"],
                issuer=expected_issuer,
                options={
                    "verify_aud": False,  # We verify manually below
                    "verify_signature": True,
                    "verify_exp": True,
                },
            )

            # Reject id_tokens at the userinfo endpoint. Only access tokens
            # are accepted here. Tokens issued before the token_use claim
            # existed have no token_use; treat absent as access for backward
            # compatibility, but explicitly reject token_use="id".
            if payload.get("token_use") == TOKEN_USE_ID:
                _LOGGER.warning("ID token presented at userinfo endpoint")
                return web.json_response({"error": "invalid_token"}, status=401)

            # Verify the audience claim exists. Access tokens are audience-bound
            # either to a registered client_id (legacy) or to a protected
            # resource URI (RFC 8707). Both are minted and signed by this
            # provider, which the decode above already verified, so either form
            # is accepted for returning the user's own profile.
            aud = payload.get("aud")
            if not aud:
                return web.json_response({"error": "invalid_token"}, status=401)

            # Extract user info from JWT
            user_id = payload.get("sub")
            if not user_id:
                return web.json_response({"error": "invalid_token"}, status=401)

            # Get user from Home Assistant
            user = await hass.auth.async_get_user(user_id)
            if not user:
                return web.json_response({"error": "user_not_found"}, status=404)

            userinfo = {
                "sub": user.id,
            }

            # Include claims based on requested scopes
            token_scope = payload.get("scope", "")
            requested_scopes = token_scope.split() if token_scope else []

            if SCOPE_PROFILE in requested_scopes:
                userinfo["name"] = user.name

            if SCOPE_EMAIL in requested_scopes:
                username = user.name or ""
                if _looks_like_email(username):
                    userinfo["email"] = username
                    userinfo["email_verified"] = False

            if SCOPE_GROUPS in requested_scopes:
                userinfo["groups"] = _resolve_user_groups(user)

            return web.json_response(userinfo)
        except jwt.ExpiredSignatureError:
            _LOGGER.error("Token expired")
            return web.json_response({"error": "token_expired"}, status=401)
        except jwt.InvalidTokenError as e:
            _LOGGER.error("Invalid token: %s", str(e))
            return web.json_response({"error": "invalid_token", "detail": str(e)}, status=401)
        except Exception as e:
            _LOGGER.error("Unexpected error validating token: %s", str(e), exc_info=True)
            return web.json_response({"error": "internal_error"}, status=500)


class OIDCJWKSView(HomeAssistantView):
    """OIDC JWKS (JSON Web Key Set) endpoint."""

    url = "/oidc/jwks"
    name = "api:oidc:jwks"
    requires_auth = False

    async def get(self, request: web.Request) -> web.Response:
        """Handle JWKS request."""
        hass = request.app["hass"]
        public_key = hass.data[DOMAIN]["jwt_public_key"]
        kid = hass.data[DOMAIN]["jwt_kid"]

        # Get the public key numbers
        public_numbers = public_key.public_numbers()

        # Convert modulus (n) and exponent (e) to base64url format
        def int_to_base64url(value: int) -> str:
            """Convert integer to base64url-encoded string."""
            # Convert to bytes (big-endian)
            value_bytes = value.to_bytes((value.bit_length() + 7) // 8, byteorder="big")
            # Base64url encode (no padding)
            return base64.urlsafe_b64encode(value_bytes).decode("utf-8").rstrip("=")

        jwks = {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "kid": kid,
                    "alg": "RS256",
                    "n": int_to_base64url(public_numbers.n),  # Modulus
                    "e": int_to_base64url(public_numbers.e),  # Exponent
                }
            ]
        }

        return web.json_response(jwks)


class OIDCRegisterView(HomeAssistantView):
    """OAuth 2.0 Dynamic Client Registration endpoint (RFC 7591)."""

    url = "/oidc/register"
    name = "api:oidc:register"
    requires_auth = False

    async def post(self, request: web.Request) -> web.Response:
        """Handle client registration request."""
        hass = request.app["hass"]

        try:
            data = await request.json()
        except Exception:
            return web.json_response(
                {"error": "invalid_request", "error_description": "Invalid JSON"},
                status=400,
            )

        # Validate required fields
        redirect_uris = data.get("redirect_uris")
        if not redirect_uris or not isinstance(redirect_uris, list):
            return web.json_response(
                {
                    "error": "invalid_redirect_uri",
                    "error_description": "redirect_uris is required and must be an array",
                },
                status=400,
            )

        # Extract client metadata
        client_name = data.get("client_name", "Dynamically Registered Client")
        grant_types = data.get("grant_types", ["authorization_code", "refresh_token"])
        response_types = data.get("response_types", ["code"])
        token_endpoint_auth_method = data.get("token_endpoint_auth_method", "client_secret_basic")

        # Validate grant types
        supported_grant_types = ["authorization_code", "refresh_token"]
        if not all(gt in supported_grant_types for gt in grant_types):
            supported = ", ".join(supported_grant_types)
            return web.json_response(
                {
                    "error": "invalid_client_metadata",
                    "error_description": f"Unsupported grant types. Supported: {supported}",
                },
                status=400,
            )

        # Validate response types
        if not all(rt in ["code"] for rt in response_types):
            return web.json_response(
                {
                    "error": "invalid_client_metadata",
                    "error_description": "Only 'code' response type is supported",
                },
                status=400,
            )

        # Create client using shared client_manager
        try:
            client_info = await create_client(
                hass,
                client_name=client_name,
                redirect_uris=redirect_uris,
                grant_types=grant_types,
                response_types=response_types,
                token_endpoint_auth_method=token_endpoint_auth_method,
            )
        except ValueError as e:
            return web.json_response(
                {
                    "error": "invalid_redirect_uri",
                    "error_description": str(e),
                },
                status=400,
            )

        return web.json_response(client_info, status=201)
