"""HTTP endpoints for OIDC Provider."""

import base64
import hashlib
import html
import logging
import secrets
import time
import uuid
from typing import Any
from urllib.parse import urlencode, urlparse, urlsplit

import jwt
from aiohttp import web
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from homeassistant.components.http import HomeAssistantView
from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store

from .cimd import ClientMetadataError, async_resolve_client, client_id_host, is_client_id_url
from .client_manager import create_client, validate_client_name
from .const import (
    ACCESS_TOKEN_EXPIRY,
    AUTHORIZATION_CODE_EXPIRY,
    CODE_CHALLENGE_METHOD_S256,
    CONF_ALLOW_CLIENT_METADATA_DOCUMENTS,
    CONF_ALLOW_DYNAMIC_REGISTRATION,
    CONF_REQUIRE_PKCE,
    DEFAULT_ALLOW_CLIENT_METADATA_DOCUMENTS,
    DEFAULT_ALLOW_DYNAMIC_REGISTRATION,
    DEFAULT_REQUIRE_PKCE,
    DOMAIN,
    GRANT_TYPE_AUTHORIZATION_CODE,
    GRANT_TYPE_REFRESH_TOKEN,
    GROUP_OWNER,
    HA_GROUP_TO_OIDC_GROUP,
    ID_TOKEN_EXPIRY,
    MAX_PENDING_AUTH_REQUESTS,
    MAX_PENDING_AUTH_REQUESTS_PER_ADDRESS,
    MAX_TOKEN_ATTEMPTS,
    PANEL_URL_PATH,
    RATE_LIMIT_PENALTY,
    RATE_LIMIT_WINDOW,
    REFRESH_TOKEN_EXPIRY,
    REFRESH_TOKEN_REUSE_GRACE,
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


def _dynamic_registration_enabled(hass: HomeAssistant) -> bool:
    """Return whether clients may register themselves at /oidc/register.

    The discovery documents advertise registration_endpoint only while this is
    true, so clients that discover endpoints are never sent to one that refuses
    them.
    """
    return bool(
        hass.data[DOMAIN].get(CONF_ALLOW_DYNAMIC_REGISTRATION, DEFAULT_ALLOW_DYNAMIC_REGISTRATION)
    )


def _client_metadata_documents_enabled(hass: HomeAssistant) -> bool:
    """Return whether an HTTPS URL client_id is resolved through its metadata document."""
    return bool(
        hass.data[DOMAIN].get(
            CONF_ALLOW_CLIENT_METADATA_DOCUMENTS, DEFAULT_ALLOW_CLIENT_METADATA_DOCUMENTS
        )
    )


def _client_authentication_metadata(hass: HomeAssistant) -> dict[str, Any]:
    """Return the discovery entries that describe how clients authenticate.

    Public clients (token_endpoint_auth_method none) come from dynamic
    registration and from metadata documents, so none is listed only while one
    of them is on. Claude uses a metadata document only when the server lists
    both none and client_id_metadata_document_supported.
    """
    methods = ["client_secret_post", "client_secret_basic"]
    if _dynamic_registration_enabled(hass) or _client_metadata_documents_enabled(hass):
        methods.append("none")
    metadata: dict[str, Any] = {"token_endpoint_auth_methods_supported": methods}
    if _client_metadata_documents_enabled(hass):
        metadata["client_id_metadata_document_supported"] = True
    return metadata


def _revocation_metadata(hass: HomeAssistant, base_url: str) -> dict[str, Any]:
    """Return the discovery entries for the revocation endpoint (RFC 7009, RFC 8414)."""
    return {
        "revocation_endpoint": f"{base_url}/oidc/revoke",
        "revocation_endpoint_auth_methods_supported": _client_authentication_metadata(hass)[
            "token_endpoint_auth_methods_supported"
        ],
    }


def _is_public_client(client: dict[str, Any]) -> bool:
    """Return whether a client authenticates without a secret.

    A client is public when it uses token_endpoint_auth_method none and holds
    no secret. A client stored with a secret stays confidential whatever method
    it asked for.
    """
    return (
        client.get("token_endpoint_auth_method") == "none"
        and "client_secret_hash" not in client
        and "client_secret" not in client
    )


def _token_endpoint_client(hass: HomeAssistant, client_id: str | None) -> dict[str, Any] | None:
    """Return the client a token request names, or None when there is none.

    A metadata document client is not fetched here. Its grants are bound to its
    client_id and to the PKCE verifier of the authorization that created them.
    """
    client = hass.data[DOMAIN].get("clients", {}).get(client_id)
    if client is None and is_client_id_url(client_id) and _client_metadata_documents_enabled(hass):
        return {"token_endpoint_auth_method": "none", "metadata_document": True}
    return client


_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _ascii_host(host: str) -> str:
    """Return a host as the consent screen shows it.

    International names are shown in punycode, so a Unicode look-alike cannot
    pass for the domain it imitates. Clients stored before redirect URIs had to
    be ASCII can still carry one.
    """
    if host.isascii():
        return host
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host.encode("ascii", "backslashreplace").decode("ascii")


def _redirect_uri_allowed(redirect_uri: str, registered: list[str]) -> bool:
    """Return whether a requested redirect URI matches a registered one.

    Matching is exact, except that a loopback redirect URI matches on any port
    (RFC 8252 §7.3). Native clients such as Claude Code listen on a port picked
    for each sign-in and register the URI without it.
    """
    if redirect_uri in registered:
        return True
    try:
        requested = urlsplit(redirect_uri)
        requested.port
    except ValueError:
        return False
    if (
        requested.scheme != "http"
        or requested.hostname not in _LOOPBACK_HOSTS
        or requested.username is not None
        or requested.fragment
    ):
        return False
    for uri in registered:
        try:
            candidate = urlsplit(uri)
            candidate.port
        except ValueError:
            continue
        if candidate.username is None and (
            candidate.scheme,
            candidate.hostname,
            candidate.path,
            candidate.query,
        ) == (requested.scheme, requested.hostname, requested.path, requested.query):
            return True
    return False


async def _save_refresh_tokens(hass: HomeAssistant) -> None:
    """Persist the current in-memory refresh tokens to the token store."""
    token_store = hass.data[DOMAIN].get("token_store")
    if token_store:
        await token_store.async_save({"refresh_tokens": hass.data[DOMAIN]["refresh_tokens"]})


def _new_refresh_token(family: str) -> str:
    """Return a refresh token in the given family.

    Every refresh token issued for one authorization carries the same family
    id as a prefix. A superseded token is no longer stored, so the prefix is
    what ties it back to the session it belonged to when it is presented again.
    """
    return f"{family}.{secrets.token_urlsafe(32)}"


def _refresh_token_family(token: str) -> str | None:
    """Return the family id a refresh token carries, if any."""
    family, separator, _ = token.partition(".")
    return family if separator and family else None


def _revoke_family(hass: HomeAssistant, family: str) -> bool:
    """Drop every stored refresh token of a family. Returns whether any was."""
    refresh_tokens = hass.data[DOMAIN]["refresh_tokens"]
    doomed = [token for token, data in refresh_tokens.items() if data.get("family") == family]
    for token in doomed:
        del refresh_tokens[token]
    return bool(doomed)


async def _revoke_code_grant(hass: HomeAssistant, grant: dict[str, Any]) -> None:
    """Revoke the refresh tokens descended from a redeemed authorization code."""
    if _revoke_family(hass, grant["family"]):
        await _save_refresh_tokens(hass)


def _session_key(token: str, data: dict[str, Any]) -> str:
    """Return what ties the refresh tokens of one sign-in together.

    That is the token family. A token stored before families existed is a
    session of its own until its first refresh puts it in one.
    """
    return data.get("family") or token


def _session_id(key: str) -> str:
    """Return the identifier a session is listed and revoked by.

    It is derived from the session key so the family id, which prefixes every
    refresh token of the session, is never shown.
    """
    return hashlib.sha256(key.encode()).hexdigest()[:24]


def _live_sessions(hass: HomeAssistant) -> dict[str, list[tuple[str, dict[str, Any]]]]:
    """Group the unexpired refresh tokens by session key."""
    now = time.time()
    sessions: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for token, data in hass.data[DOMAIN]["refresh_tokens"].items():
        if data["expires_at"] >= now:
            sessions.setdefault(_session_key(token, data), []).append((token, data))
    return sessions


def _revoke_session(hass: HomeAssistant, key: str) -> bool:
    """Drop every refresh token of a session. Returns whether any was stored."""
    refresh_tokens = hass.data[DOMAIN]["refresh_tokens"]
    doomed = [token for token, data in refresh_tokens.items() if _session_key(token, data) == key]
    for token in doomed:
        del refresh_tokens[token]
    return bool(doomed)


def _find_session(hass: HomeAssistant, token: str) -> tuple[str, str] | None:
    """Return the session key and client_id a refresh token belongs to.

    The token may be the current one of its session or one it replaced, which
    is traced through its family prefix.
    """
    refresh_tokens = hass.data[DOMAIN]["refresh_tokens"]
    data = refresh_tokens.get(token)
    if data is not None:
        return _session_key(token, data), data["client_id"]
    family = _refresh_token_family(token)
    for stored_token, data in refresh_tokens.items():
        if data.get("previous") == token or (family and data.get("family") == family):
            return _session_key(stored_token, data), data["client_id"]
    return None


def _client_display(hass: HomeAssistant, client_id: str, data: dict[str, Any]) -> dict[str, Any]:
    """Return how a session's client is named in lists of sessions."""
    client = hass.data[DOMAIN].get("clients", {}).get(client_id)
    if client is not None:
        name = client.get("client_name") or client_id
    else:
        name = data.get("client_name") or client_id
    return {
        "client_id": client_id,
        "client_name": name,
        "client_host": client_id_host(client_id) if is_client_id_url(client_id) else None,
    }


def user_sessions(hass: HomeAssistant, user_id: str) -> list[dict[str, Any]]:
    """Return a user's live sessions, most recently used first."""
    sessions = []
    for key, tokens in _live_sessions(hass).items():
        _, data = tokens[0]
        if data.get("user_id") != user_id:
            continue
        last_used = max((d.get("issued_at") or 0 for _, d in tokens), default=0)
        sessions.append(
            {
                "session_id": _session_id(key),
                **_client_display(hass, data["client_id"], data),
                "scopes": (data.get("scope") or "").split(),
                "signed_in_at": data.get("auth_time"),
                "last_used_at": last_used or None,
                "expires_at": int(data["expires_at"]),
            }
        )
    sessions.sort(key=lambda session: session["last_used_at"] or 0, reverse=True)
    return sessions


def client_sessions(hass: HomeAssistant) -> dict[str, dict[str, Any]]:
    """Return each client with live sessions: its display details and session count."""
    clients: dict[str, dict[str, Any]] = {}
    for tokens in _live_sessions(hass).values():
        _, data = tokens[0]
        entry = clients.setdefault(
            data["client_id"],
            {**_client_display(hass, data["client_id"], data), "active_sessions": 0},
        )
        entry["active_sessions"] += 1
    return clients


async def revoke_client_sessions(hass: HomeAssistant, client_id: str) -> int:
    """End every session of a client. Returns how many there were."""
    keys = {
        _session_key(token, data)
        for token, data in hass.data[DOMAIN]["refresh_tokens"].items()
        if data["client_id"] == client_id
    }
    for key in keys:
        _revoke_session(hass, key)
    if keys:
        await _save_refresh_tokens(hass)
    return len(keys)


def _prune_expired(entries: dict[str, dict[str, Any]]) -> None:
    """Drop the entries whose expires_at has passed."""
    now = time.time()
    for key in [key for key, value in entries.items() if value["expires_at"] < now]:
        del entries[key]


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
    hass.http.register_view(OIDCRevocationView())
    hass.http.register_view(OIDCSessionsView())
    hass.http.register_view(OIDCSessionView())


class OIDCContinueView(HomeAssistantView):
    """Consent step of the authorization flow.

    GET describes a pending authorization request so the login panel can show
    a consent screen. POST records the user's decision: an approval mints an
    authorization code, a denial sends the client an access_denied error.
    Both require an authenticated Home Assistant user.
    """

    url = "/oidc/continue"
    name = "api:oidc:continue"
    requires_auth = True

    @staticmethod
    def _get_pending_request(
        hass: HomeAssistant, request_id: str | None
    ) -> tuple[dict[str, Any], dict[str, Any]] | web.Response:
        """Return the pending request and its client, or the error response."""
        if not request_id:
            return web.Response(text="Missing request_id", status=400)

        pending_requests = hass.data[DOMAIN].get("pending_auth_requests", {})
        if request_id not in pending_requests:
            return web.Response(text="Invalid or expired request", status=400)

        stored_request = pending_requests[request_id]
        if stored_request["expires_at"] < time.time():
            del pending_requests[request_id]
            return web.Response(text="Request expired", status=400)

        client = hass.data[DOMAIN].get("clients", {}).get(
            stored_request["client_id"]
        ) or stored_request.get("metadata_client")
        if client is None:
            del pending_requests[request_id]
            return web.Response(text="Client no longer registered", status=400)

        return stored_request, client

    async def get(self, request: web.Request) -> web.Response:
        """Describe the pending request for the consent screen."""
        hass = request.app["hass"]

        result = self._get_pending_request(hass, request.query.get("request_id"))
        if isinstance(result, web.Response):
            return result
        stored_request, client = result

        # hostname rather than netloc so userinfo can never dress up the host
        parsed = urlparse(stored_request["redirect_uri"])
        redirect_host = _ascii_host(parsed.hostname or "")
        try:
            port = parsed.port
        except ValueError:
            port = None
        if port:
            redirect_host = f"{redirect_host}:{port}"

        return web.json_response(
            {
                "client_name": client.get("client_name", stored_request["client_id"]),
                "redirect_host": redirect_host,
                "scopes": stored_request["scope"].split(),
                # A client with no recorded setting predates the flag and may
                # have come from dynamic registration, so it prompts until an
                # operator clears the flag.
                "consent_required": bool(client.get("consent_required", True)),
                # A metadata document client is identified by the host serving
                # its document, which the draft says to show (§8.5).
                "client_host": (
                    client_id_host(stored_request["client_id"])
                    if client.get("metadata_document")
                    else None
                ),
                "redirect_is_loopback": parsed.hostname in _LOOPBACK_HOSTS,
            }
        )

    async def post(self, request: web.Request) -> web.Response:
        """Record the user's decision on the pending request."""
        hass = request.app["hass"]
        user = request["hass_user"]

        try:
            body = await request.json()
        except Exception:
            return web.Response(text="Invalid JSON body", status=400)
        if not isinstance(body, dict):
            return web.Response(text="Invalid JSON body", status=400)

        result = self._get_pending_request(hass, body.get("request_id"))
        if isinstance(result, web.Response):
            return result
        stored_request, client = result
        request_id = body["request_id"]

        # Extract parameters
        client_id = stored_request["client_id"]
        redirect_uri = stored_request["redirect_uri"]
        scope = stored_request["scope"]
        state = stored_request["state"]
        nonce = stored_request.get("nonce")
        code_challenge = stored_request.get("code_challenge")
        code_challenge_method = stored_request.get("code_challenge_method")
        resource = stored_request.get("resource")

        # A decision either way consumes the pending request
        del hass.data[DOMAIN]["pending_auth_requests"][request_id]

        separator = "&" if "?" in redirect_uri else "?"

        def build_redirect(**params: str) -> str:
            if state:
                params["state"] = state
            return f"{redirect_uri}{separator}{urlencode(params)}"

        if body.get("approve") is not True:
            _LOGGER.info("User %s denied authorization for client %s", user.id, client_id)
            return web.json_response({"redirect_url": build_redirect(error="access_denied")})

        # Codes that were never redeemed, and the records of redeemed ones, are
        # dropped once they expire so neither grows without bound.
        _prune_expired(hass.data[DOMAIN]["authorization_codes"])
        _prune_expired(hass.data[DOMAIN].setdefault("redeemed_codes", {}))

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
            # Kept with the session, so a client that is not stored, such as a
            # metadata document client, can still be named in session lists.
            "client_name": client.get("client_name"),
            "expires_at": time.time() + AUTHORIZATION_CODE_EXPIRY,
        }

        # Return JSON with redirect URL (since fetch can't follow external redirects)
        return web.json_response({"redirect_url": build_redirect(code=auth_code)})


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
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": SUPPORTED_SCOPES,
            **_client_authentication_metadata(request.app["hass"]),
            **_revocation_metadata(request.app["hass"], base_url),
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
        if _dynamic_registration_enabled(request.app["hass"]):
            discovery["registration_endpoint"] = f"{base_url}/oidc/register"

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
            "jwks_uri": f"{base_url}/oidc/jwks",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            **_client_authentication_metadata(request.app["hass"]),
            **_revocation_metadata(request.app["hass"], base_url),
            "code_challenge_methods_supported": SUPPORTED_CODE_CHALLENGE_METHODS,
            "scopes_supported": SUPPORTED_SCOPES,
        }
        if _dynamic_registration_enabled(request.app["hass"]):
            metadata["registration_endpoint"] = f"{base_url}/oidc/register"

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
            "jwks_uri": f"{base_url}/oidc/jwks",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            **_client_authentication_metadata(request.app["hass"]),
            **_revocation_metadata(request.app["hass"], base_url),
            "code_challenge_methods_supported": SUPPORTED_CODE_CHALLENGE_METHODS,
            "scopes_supported": SUPPORTED_SCOPES,
        }
        if _dynamic_registration_enabled(request.app["hass"]):
            metadata["registration_endpoint"] = f"{base_url}/oidc/register"

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

        # Unrecognised scope values are ignored (OIDC Core §3.1.2.1). Only the
        # granted scopes are stored, shown on the consent screen, and returned
        # with the token.
        granted_scopes = [sc for sc in requested_scopes if sc in SUPPORTED_SCOPES]
        if len(granted_scopes) != len(requested_scopes):
            _LOGGER.debug(
                "Ignoring unsupported scopes for client %s: %s",
                client_id,
                " ".join(sc for sc in requested_scopes if sc not in SUPPORTED_SCOPES),
            )
        scope = " ".join(granted_scopes)

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

        client = hass.data[DOMAIN].get("clients", {}).get(client_id)
        metadata_client = None
        if (
            client is None
            and is_client_id_url(client_id)
            and _client_metadata_documents_enabled(hass)
        ):
            try:
                client = metadata_client = await async_resolve_client(
                    hass, client_id, request.remote
                )
            except ClientMetadataError as err:
                _LOGGER.debug("Refused client metadata document %s: %s", client_id, err)
                return web.Response(text=f"Invalid client_id: {err}", status=400)

        if client is None:
            return web.Response(text="Invalid client_id", status=400)

        if not _redirect_uri_allowed(redirect_uri, client["redirect_uris"]):
            return web.Response(text="Invalid redirect_uri", status=400)

        # A public client has no secret, so PKCE is what binds the code to the
        # client that asked for it (OAuth 2.1 §7.5.1), whatever the PKCE option.
        if _is_public_client(client) and not code_challenge:
            return web.Response(
                text="PKCE is required for public clients. Please provide code_challenge.",
                status=400,
            )

        # Store request and redirect to frontend panel (which requires auth)
        auth_request_id = secrets.token_urlsafe(16)

        # Store the authorization request parameters
        if "pending_auth_requests" not in hass.data[DOMAIN]:
            hass.data[DOMAIN]["pending_auth_requests"] = {}

        # Clean up expired pending requests. Anyone can start one, so new ones
        # are refused past the caps; sign-ins already under way are kept.
        pending = hass.data[DOMAIN]["pending_auth_requests"]
        _prune_expired(pending)
        from_address = sum(1 for req in pending.values() if req.get("remote") == request.remote)
        if (
            len(pending) >= MAX_PENDING_AUTH_REQUESTS
            or from_address >= MAX_PENDING_AUTH_REQUESTS_PER_ADDRESS
        ):
            _LOGGER.debug("Refused authorization request from %s: too many pending", request.remote)
            return web.Response(
                text="Too many sign-ins in progress. Try again in a few minutes.",
                status=429,
                headers={"Retry-After": "60"},
            )

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
            # A metadata document client is not stored, so the consent step
            # reads the client the document described from here.
            "metadata_client": metadata_client,
            "remote": request.remote,
            "expires_at": time.time() + 600,  # 10 minutes
        }

        # Return HTML that stores request ID in sessionStorage and redirects to panel.
        # Styled like Home Assistant's own login page shell so the bounce does not
        # flash an unstyled page, and reads well if JavaScript is unavailable.
        # Note: auth_request_id is a cryptographically secure token, but we still escape it
        escaped_request_id = html.escape(auth_request_id)
        redirect_script = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Home Assistant</title>
<link rel="icon" href="/static/icons/favicon.ico">
<style>
  html {{
    background-color: #fafafa;
    color: #212121;
    font-family: Roboto, Noto, sans-serif;
    -webkit-font-smoothing: antialiased;
  }}
  body {{ margin: 0; padding: 32px 0; display: flex; flex-wrap: wrap; align-items: center; }}
  .content {{ width: 100%; max-width: 400px; margin: 0 auto; padding: 0 16px; }}
  .header {{ display: flex; align-items: center; justify-content: center; margin-bottom: 32px; }}
  .header img {{ height: 56px; width: 56px; }}
  .card {{
    background: #ffffff;
    border: 1px solid #e0e0e0;
    border-radius: 12px;
    padding: 16px;
    box-sizing: border-box;
  }}
  h1 {{ font-size: 28px; font-weight: 400; margin: 16px 0; }}
  p {{ font-size: 14px; line-height: 20px; }}
  @media (prefers-color-scheme: dark) {{
    html {{ background-color: #111111; color: #e1e1e1; }}
    .card {{ background: #1c1c1c; border-color: #333333; }}
  }}
</style>
</head>
<body>
<div class="content">
  <div class="header">
    <img src="/static/icons/favicon-192x192.png" alt="Home Assistant">
  </div>
  <div class="card">
    <h1>Redirecting to login</h1>
    <p>Taking you to Home Assistant to sign in and approve this request.</p>
    <noscript><p>JavaScript is required to continue.</p></noscript>
  </div>
</div>
<script>
  sessionStorage.setItem('oidc_request_id', '{escaped_request_id}');
  window.location.replace('/{PANEL_URL_PATH}');
</script>
</body>
</html>
"""
        return web.Response(
            text=redirect_script,
            content_type="text/html",
        )


def _record_failed_attempt(hass: HomeAssistant, rate_limit_key: str, current_time: float) -> None:
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


def _authenticate_client(
    request: web.Request, hass: HomeAssistant, data: Any
) -> tuple[str, dict[str, Any]] | web.Response:
    """Authenticate the client of a token or revocation request (RFC 6749 §2.3).

    Credentials come from HTTP Basic or the form body. Failed attempts are rate
    limited per client and address. Returns the client_id and its client, or
    the error response to send.
    """
    # Extract client credentials from either POST data or Authorization header
    body_client_id = data.get("client_id")
    client_id = body_client_id
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

        # A body client_id that disagrees with the Basic credentials is an
        # attempt to authenticate as one client while acting for another.
        if body_client_id and body_client_id != client_id:
            _LOGGER.warning(
                "client_id mismatch between Basic auth (%s) and request body (%s)",
                client_id,
                body_client_id,
            )
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
            _LOGGER.warning("Rate limit active for client %s from %s", client_id, request.remote)
            return web.json_response(
                {
                    "error": "invalid_client",
                    "error_description": "Too many failed attempts. Please try again later.",
                },
                status=429,
            )

    # Validate client
    client = _token_endpoint_client(hass, client_id)
    if client is None:
        _record_failed_attempt(hass, rate_limit_key, current_time)
        return web.json_response({"error": "invalid_client"}, status=401)

    # Verify client secret using constant-time comparison
    # Support both old (plain) and new (hashed) client secrets for backward compatibility
    if _is_public_client(client):
        # A public client has no secret to present; its grants are bound to
        # it by PKCE instead.
        if client_secret:
            _LOGGER.warning("Public client %s presented a client secret", client_id)
            _record_failed_attempt(hass, rate_limit_key, current_time)
            return web.json_response({"error": "invalid_client"}, status=401)
    elif "client_secret_hash" in client:
        # New hashed format
        if not verify_client_secret(client_secret, client["client_secret_hash"]):
            _LOGGER.warning("Invalid client secret for client %s", client_id)
            _record_failed_attempt(hass, rate_limit_key, current_time)
            return web.json_response({"error": "invalid_client"}, status=401)
    elif "client_secret" in client:
        # Old plain text format (backward compatibility)
        if client["client_secret"] != client_secret:
            _LOGGER.warning("Invalid client secret for client %s (legacy)", client_id)
            _record_failed_attempt(hass, rate_limit_key, current_time)
            return web.json_response({"error": "invalid_client"}, status=401)
    else:
        _LOGGER.error("Client %s has no secret configured", client_id)
        _record_failed_attempt(hass, rate_limit_key, current_time)
        return web.json_response({"error": "invalid_client"}, status=401)

    # Successful authentication - clear rate limit
    if rate_limit_key in rate_limits:
        del rate_limits[rate_limit_key]

    return client_id, client


class OIDCTokenView(HomeAssistantView):
    """OIDC Token endpoint."""

    url = "/oidc/token"
    name = "api:oidc:token"
    requires_auth = False

    async def post(self, request: web.Request) -> web.Response:
        """Handle token request.

        Responses carry tokens or say why none were issued, so no cache may keep
        them (RFC 6749 §5.1).
        """
        response = await self._token_response(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        return response

    async def _token_response(self, request: web.Request) -> web.Response:
        """Answer a token request."""
        hass = request.app["hass"]
        data = await request.post()

        grant_type = data.get("grant_type")

        authenticated = _authenticate_client(request, hass, data)
        if isinstance(authenticated, web.Response):
            return authenticated
        client_id, _client = authenticated

        # Grants are bound to the client that authenticated above, never to a
        # client_id taken from the request body.
        if grant_type == GRANT_TYPE_AUTHORIZATION_CODE:
            return await self._handle_authorization_code(request, hass, data, client_id)
        elif grant_type == GRANT_TYPE_REFRESH_TOKEN:
            return await self._handle_refresh_token(request, hass, data, client_id)
        else:
            return web.json_response({"error": "unsupported_grant_type"}, status=400)

    async def _handle_authorization_code(
        self, _request: web.Request, hass: HomeAssistant, data: Any, client_id: str
    ) -> web.Response:
        """Handle authorization code grant for the authenticated client."""
        code = data.get("code")
        redirect_uri = data.get("redirect_uri")
        code_verifier = data.get("code_verifier")

        # A code is good for one redemption attempt (RFC 6749 §4.1.2). Taking it
        # out of the store before anything awaits means a request racing this
        # one cannot find it, and a failed attempt cannot be retried.
        auth_data = hass.data[DOMAIN]["authorization_codes"].pop(code, None)
        redeemed_codes = hass.data[DOMAIN].setdefault("redeemed_codes", {})
        if auth_data is None:
            # A code that already issued tokens and is presented again may have
            # leaked, so the refresh token it issued is revoked (RFC 6749 §4.1.2).
            grant = redeemed_codes.pop(code, None)
            if grant is not None:
                _LOGGER.warning(
                    "Authorization code issued to client %s was presented again; "
                    "revoking the refresh token it issued",
                    grant["client_id"],
                )
                await _revoke_code_grant(hass, grant)
            return web.json_response({"error": "invalid_grant"}, status=400)

        # Validate authorization code
        if auth_data["expires_at"] < time.time():
            return web.json_response({"error": "invalid_grant"}, status=400)

        # The code may only be redeemed by the client it was issued to
        # (RFC 6749 §4.1.3).
        if auth_data["client_id"] != client_id:
            _LOGGER.warning(
                "Authorization code issued to client %s redeemed by client %s",
                auth_data["client_id"],
                client_id,
            )
            return web.json_response({"error": "invalid_grant"}, status=400)

        if auth_data["redirect_uri"] != redirect_uri:
            return web.json_response({"error": "invalid_grant"}, status=400)

        if not auth_data.get("code_challenge") and _is_public_client(
            _token_endpoint_client(hass, client_id) or {}
        ):
            return web.json_response(
                {"error": "invalid_grant", "error_description": "code_verifier required"},
                status=400,
            )

        # Validate PKCE code_verifier if code_challenge was provided
        code_challenge = auth_data.get("code_challenge")
        if code_challenge:
            if not code_verifier:
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
                _LOGGER.error("Error verifying PKCE: %s", str(e), exc_info=True)
                return web.json_response(
                    {"error": "invalid_grant", "error_description": "PKCE verification error"},
                    status=400,
                )

        # Generate tokens
        user_id = auth_data["user_id"]
        scope = auth_data["scope"]

        nonce = auth_data.get("nonce")
        auth_time = auth_data.get("auth_time")

        # The token audience is bound to the resource requested at the authorize
        # step (RFC 8707). A token request MAY also carry a resource indicator;
        # honor it only when the authorize step didn't specify one.
        resource = auth_data.get("resource") or _normalize_resource(data.get("resource"))

        # Kept until the code would have expired, so a later presentation of the
        # same code can revoke what this redemption issues.
        family = secrets.token_urlsafe(16)
        refresh_token = _new_refresh_token(family)
        grant = {
            "client_id": client_id,
            "family": family,
            "expires_at": auth_data["expires_at"],
        }
        redeemed_codes[code] = grant

        access_token = await self._generate_access_token(
            _request, hass, user_id, scope, client_id, audience=resource
        )

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
            "client_name": auth_data.get("client_name"),
            "family": family,
            "issued_at": time.time(),
            "expires_at": time.time() + REFRESH_TOKEN_EXPIRY,
        }

        # Persist refresh tokens to storage
        await _save_refresh_tokens(hass)

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

        # The code was presented again while these tokens were being issued.
        # That request took the record, so nothing issued here is handed out.
        if redeemed_codes.get(code) is not grant:
            await _revoke_code_grant(hass, grant)
            return web.json_response({"error": "invalid_grant"}, status=400)

        return web.json_response(response_body)

    async def _handle_refresh_token(
        self, _request: web.Request, hass: HomeAssistant, data: Any, client_id: str
    ) -> web.Response:
        """Handle refresh token grant for the authenticated client.

        Every successful refresh replaces the presented refresh token with a new
        one in the same family (RFC 9700 §4.14.2). Every token the session
        retired in the last REFRESH_TOKEN_REUSE_GRACE seconds is still answered
        with the current one, so a delayed duplicate from a client refreshing in
        several places does not end the session. Presented after that, or by
        another client, a retired token means the session's tokens have leaked,
        and the whole family is revoked.
        """
        refresh_token = data.get("refresh_token") or ""
        refresh_tokens = hass.data[DOMAIN]["refresh_tokens"]
        now = time.time()

        token_data = refresh_tokens.get(refresh_token)
        if token_data is None:
            return await self._handle_superseded_refresh_token(
                _request, hass, refresh_token, client_id
            )

        if token_data["expires_at"] < now:
            del refresh_tokens[refresh_token]
            await _save_refresh_tokens(hass)
            return web.json_response({"error": "invalid_grant"}, status=400)

        # The refresh token is bound to the client it was issued to
        # (RFC 6749 §6); the body client_id is caller-controlled and not used.
        # Presentation by another client indicates the token has leaked, so its
        # family is revoked (RFC 9700 §4.14).
        if token_data["client_id"] != client_id:
            del refresh_tokens[refresh_token]
            if token_data.get("family"):
                _revoke_family(hass, token_data["family"])
            await _save_refresh_tokens(hass)
            _LOGGER.warning(
                "Refresh token issued to client %s used by client %s; session revoked",
                token_data["client_id"],
                client_id,
            )
            return web.json_response({"error": "invalid_grant"}, status=400)

        # Tokens stored before rotation existed have no family; they start one.
        # The replacement keeps the original expiry, so a session lasts
        # REFRESH_TOKEN_EXPIRY from sign-in however often it is refreshed.
        family = token_data.get("family") or secrets.token_urlsafe(16)
        new_refresh_token = _new_refresh_token(family)
        # The tokens the session retired within the grace period, with when
        retired = {
            token: retired_at
            for token, retired_at in token_data.get("retired", {}).items()
            if now - retired_at <= REFRESH_TOKEN_REUSE_GRACE
        }
        retired[refresh_token] = now
        new_token_data = {**token_data, "family": family, "issued_at": now, "retired": retired}
        del refresh_tokens[refresh_token]
        refresh_tokens[new_refresh_token] = new_token_data
        await _save_refresh_tokens(hass)

        return await self._refresh_response(_request, hass, new_refresh_token, new_token_data)

    async def _handle_superseded_refresh_token(
        self, _request: web.Request, hass: HomeAssistant, refresh_token: str, client_id: str
    ) -> web.Response:
        """Answer a refresh token that is not stored: replaced, revoked or unknown."""
        refresh_tokens = hass.data[DOMAIN]["refresh_tokens"]
        successor = next(
            (
                (token, data)
                for token, data in refresh_tokens.items()
                if refresh_token and refresh_token in data.get("retired", {})
            ),
            None,
        )

        if successor is not None:
            successor_token, successor_data = successor
            retired_at = successor_data["retired"][refresh_token]
            if (
                successor_data["client_id"] == client_id
                and time.time() - retired_at <= REFRESH_TOKEN_REUSE_GRACE
                and successor_data["expires_at"] >= time.time()
            ):
                return await self._refresh_response(_request, hass, successor_token, successor_data)
            family = successor_data["family"]
        else:
            family = _refresh_token_family(refresh_token)

        if family and _revoke_family(hass, family):
            await _save_refresh_tokens(hass)
            _LOGGER.warning(
                "A replaced refresh token was presented by client %s; session revoked",
                client_id,
            )
        return web.json_response({"error": "invalid_grant"}, status=400)

    async def _refresh_response(
        self,
        _request: web.Request,
        hass: HomeAssistant,
        refresh_token: str,
        token_data: dict[str, Any],
    ) -> web.Response:
        """Issue fresh access and ID tokens for a stored refresh token."""
        # The access token keeps the original resource binding (RFC 8707), so
        # refreshed tokens stay valid at the same resource.
        access_token = await self._generate_access_token(
            _request,
            hass,
            token_data["user_id"],
            token_data["scope"],
            token_data["client_id"],
            audience=token_data.get("resource"),
        )

        response_body: dict[str, Any] = {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_EXPIRY,
            "refresh_token": refresh_token,
            "scope": token_data["scope"],
        }

        # Re-issue an id_token when openid scope is granted (OIDC Core §12.2).
        # Original nonce and auth_time are carried forward; iat/exp/at_hash are
        # fresh. Refresh tokens stored without either field get None from .get().
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

        # The session may have been revoked while these tokens were being
        # issued, by reuse detection, a sign-out or the revocation endpoint.
        if hass.data[DOMAIN]["refresh_tokens"].get(refresh_token) is not token_data:
            return web.json_response({"error": "invalid_grant"}, status=400)

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

        if not _dynamic_registration_enabled(hass):
            _LOGGER.debug(
                "Refused dynamic client registration from %s: it is turned off in the "
                "OIDC Provider options",
                request.remote,
            )
            return web.json_response(
                {
                    "error": "access_denied",
                    "error_description": "Dynamic client registration is disabled",
                },
                status=403,
            )

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
        try:
            client_name = validate_client_name(
                data.get("client_name", "Dynamically Registered Client")
            )
        except ValueError as e:
            return web.json_response(
                {"error": "invalid_client_metadata", "error_description": str(e)},
                status=400,
            )
        grant_types = data.get("grant_types", ["authorization_code", "refresh_token"])
        response_types = data.get("response_types", ["code"])
        # A client asking for none registers as a public client without a
        # secret. Any other method this server does not support is replaced by
        # client_secret_basic, and the response says so (RFC 7591 §3.2.1).
        token_endpoint_auth_method = data.get("token_endpoint_auth_method", "client_secret_basic")
        if token_endpoint_auth_method not in ("none", "client_secret_post", "client_secret_basic"):
            token_endpoint_auth_method = "client_secret_basic"

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
                # Anyone can reach this endpoint, so the registrant is not
                # vouched for by the operator and the user decides per login.
                consent_required=True,
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


class OIDCRevocationView(HomeAssistantView):
    """OAuth 2.0 Token Revocation endpoint (RFC 7009)."""

    url = "/oidc/revoke"
    name = "api:oidc:revoke"
    requires_auth = False

    async def post(self, request: web.Request) -> web.Response:
        """Revoke the session a refresh token belongs to.

        Access tokens are self-contained JWTs that expire within the hour and
        cannot be revoked one by one; like unknown tokens they are answered
        with 200 (RFC 7009 §2.2).
        """
        hass = request.app["hass"]
        data = await request.post()

        authenticated = _authenticate_client(request, hass, data)
        if isinstance(authenticated, web.Response):
            return authenticated
        client_id, _client = authenticated

        token = data.get("token")
        if not token:
            return web.json_response({"error": "invalid_request"}, status=400)

        session = _find_session(hass, token)
        if session is None:
            return web.Response(status=200)
        key, owner = session

        _revoke_session(hass, key)
        await _save_refresh_tokens(hass)

        # Only the client a token was issued to may revoke it (RFC 7009 §2.1).
        # Another client holding it means it leaked, so it is revoked anyway.
        if owner != client_id:
            _LOGGER.warning(
                "Refresh token issued to client %s presented for revocation by client %s; "
                "session revoked",
                owner,
                client_id,
            )
            return web.json_response({"error": "unauthorized_client"}, status=400)

        _LOGGER.info("Client %s revoked one of its sessions", client_id)
        return web.Response(status=200)


class OIDCSessionsView(HomeAssistantView):
    """The signed-in user's sessions with OIDC clients, listed in the login panel."""

    url = "/oidc/sessions"
    name = "api:oidc:sessions"
    requires_auth = True

    async def get(self, request: web.Request) -> web.Response:
        """List the user's live sessions."""
        hass = request.app["hass"]
        user = request["hass_user"]
        return web.json_response({"sessions": user_sessions(hass, user.id)})


class OIDCSessionView(HomeAssistantView):
    """One of the signed-in user's sessions."""

    url = "/oidc/sessions/{session_id}"
    name = "api:oidc:session"
    requires_auth = True

    async def delete(self, request: web.Request, session_id: str) -> web.Response:
        """End one of the user's sessions. Sessions of other users are not found."""
        hass = request.app["hass"]
        user = request["hass_user"]
        for key, tokens in _live_sessions(hass).items():
            _, data = tokens[0]
            if _session_id(key) == session_id and data.get("user_id") == user.id:
                _revoke_session(hass, key)
                await _save_refresh_tokens(hass)
                _LOGGER.info("User %s ended a session of client %s", user.id, data["client_id"])
                return web.json_response({"revoked": True})
        return web.json_response({"error": "not_found"}, status=404)
