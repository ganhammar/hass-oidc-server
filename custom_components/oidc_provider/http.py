"""HTTP endpoints for OIDC Provider."""

import asyncio
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
from homeassistant.generated.languages import LANGUAGES
from homeassistant.helpers.storage import Store
from homeassistant.helpers.translation import async_get_translations

from .cimd import ClientMetadataError, async_resolve_client, client_id_host, is_client_id_url
from .client_manager import (
    client_name_in_use,
    count_unused_dynamic_clients,
    create_client,
    prune_dynamic_clients,
    update_client,
    validate_client_name,
    validate_redirect_uris,
)
from .const import (
    ACCESS_TOKEN_EXPIRY,
    ACCESS_TOKEN_TYPE,
    AUTHORIZATION_CODE_EXPIRY,
    CLIENT_KIND_DYNAMIC,
    CLIENT_KIND_METADATA_DOCUMENT,
    CLIENT_KIND_REGISTERED,
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
    MAX_UNUSED_DYNAMIC_CLIENTS,
    PANEL_URL_PATH,
    RATE_LIMIT_PENALTY,
    RATE_LIMIT_WINDOW,
    REFRESH_TOKEN_EXPIRY,
    REFRESH_TOKEN_REUSE_GRACE,
    REGISTRATION_DYNAMIC,
    REGISTRATION_RATE_LIMIT_MAX,
    REGISTRATION_RATE_LIMIT_PER_ADDRESS,
    REGISTRATION_RATE_LIMIT_WINDOW,
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
from .resource_description import InvalidChoice, granted_scopes, validate_choice
from .resources import (
    async_access_rules,
    async_consent_access,
    async_display_model,
    async_remember_choice,
    find_resource,
    resource_scopes,
)
from .security import verify_client_secret
from .token_validator import decode_access_token, get_issuer_from_request

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


def _issuer_for(request: web.Request) -> str:
    """Return the issuer identifier for a request.

    It is the base URL with an /oidc suffix, as RFC 8414 requires: the issuer
    URL concatenated with /.well-known/oauth-authorization-server must return
    the auth-server metadata, and that metadata lives under /oidc.
    """
    return f"{get_issuer_from_request(request)}/oidc"


def _panel_language(hass: HomeAssistant, requested: str | None) -> str:
    """Return the language the login panel is shown in.

    That is the one the panel asks for, which is the user's own, when Home
    Assistant knows it, and otherwise the server's.
    """
    return requested if requested in LANGUAGES else hass.config.language


# The translation category holding the login panel's text. Home Assistant
# accepts nested text under it for an integration's own panels.
PANEL_STRINGS_CATEGORY = "config_panel"


async def async_panel_strings(hass: HomeAssistant, language: str) -> dict[str, str]:
    """Return the login panel's text in a language, keyed as in the translations.

    Keys missing from that language's translations come in English.
    """
    prefix = f"component.{DOMAIN}.{PANEL_STRINGS_CATEGORY}."
    translations = await async_get_translations(hass, language, PANEL_STRINGS_CATEGORY, [DOMAIN])
    return {
        key.removeprefix(prefix): value
        for key, value in translations.items()
        if key.startswith(prefix)
    }


def _scopes_supported(hass: HomeAssistant) -> list[str]:
    """Return the scopes the discovery documents advertise.

    Those are the OpenID Connect scopes and every scope a resource describes.
    A resource's scopes are granted as the user chooses on the consent screen,
    whether or not the client asked for them, and each resource server lists
    its own in its protected resource metadata (RFC 9728).
    """
    return [*SUPPORTED_SCOPES, *resource_scopes(hass)]


def _with_access_scopes(scope: str, access: dict[str, Any] | None) -> str:
    """Return a grant's scope with the scopes of the access chosen at its resource."""
    scopes = scope.split()
    if access:
        scopes.extend(granted for granted in access["scopes"] if granted not in scopes)
    return " ".join(scopes)


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

    The token may be the current one of its session, one the session retired
    in the grace period, or an older one traced through its family prefix.
    """
    refresh_tokens = hass.data[DOMAIN]["refresh_tokens"]
    data = refresh_tokens.get(token)
    if data is not None:
        return _session_key(token, data), data["client_id"]
    family = _refresh_token_family(token)
    for stored_token, data in refresh_tokens.items():
        if token in data.get("retired", {}) or (family and data.get("family") == family):
            return _session_key(stored_token, data), data["client_id"]
    return None


def _is_issued_jwt(hass: HomeAssistant, token: str) -> bool:
    """Return whether a token is a JWT this provider signed, expired or not.

    It is checked with the published key its kid names, so a token signed with
    a key kept from a rotation counts too.
    """
    try:
        kid = jwt.get_unverified_header(token).get("kid")
        if kid is None:
            key = hass.data[DOMAIN]["jwt_public_key"]
        else:
            key = hass.data[DOMAIN].get("jwt_verification_keys", {}).get(kid)
        if key is None:
            return False
        jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            options={"verify_exp": False, "verify_aud": False, "verify_iss": False},
        )
    except (jwt.InvalidTokenError, KeyError):
        return False
    return True


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
        access = data.get("access")
        sessions.append(
            {
                "session_id": _session_id(key),
                **_client_display(hass, data["client_id"], data),
                "scopes": (data.get("scope") or "").split(),
                # The access the user chose at the session's resource, as the
                # option chosen in each group of the resource's description
                "access": (
                    {"resource": access["resource"], "options": access["options"]}
                    if access
                    else None
                ),
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


async def remove_client(hass: HomeAssistant, client_id: str) -> tuple[bool, int]:
    """Remove a client and end every session it holds.

    A client identified by a metadata document URL is not stored, so only its
    sessions end; it can sign in again unless metadata documents are off.

    Returns:
        Whether a stored client was removed, and how many sessions ended
    """
    ended = await revoke_client_sessions(hass, client_id)
    clients = hass.data[DOMAIN]["clients"]
    if client_id not in clients:
        return False, ended
    del clients[client_id]
    await hass.data[DOMAIN]["store"].async_save({"clients": clients})
    return True, ended


def _managed_client(client_id: str, client: dict[str, Any], active_sessions: int) -> dict[str, Any]:
    """Return a stored client as the client management page lists it."""
    dynamic = client.get("registration") == REGISTRATION_DYNAMIC
    return {
        "client_id": client_id,
        "client_name": client.get("client_name") or client_id,
        "client_host": None,
        "registration": CLIENT_KIND_DYNAMIC if dynamic else CLIENT_KIND_REGISTERED,
        "redirect_uris": client.get("redirect_uris", []),
        "consent_required": bool(client.get("consent_required", True)),
        "created_at": client.get("created_at"),
        "active_sessions": active_sessions,
    }


def managed_clients(hass: HomeAssistant) -> list[dict[str, Any]]:
    """Return every client an administrator can manage, in name order.

    Stored clients come first by name. Clients that are not stored, which are
    those signed in through a metadata document, are known only through their
    sessions and have no settings to edit.
    """
    clients = hass.data[DOMAIN].get("clients", {})
    sessions = client_sessions(hass)
    listing = [
        _managed_client(client_id, client, sessions.get(client_id, {}).get("active_sessions", 0))
        for client_id, client in clients.items()
    ]
    listing += [
        {
            "client_id": client_id,
            "client_name": info["client_name"],
            "client_host": info["client_host"],
            "registration": CLIENT_KIND_METADATA_DOCUMENT,
            "active_sessions": info["active_sessions"],
        }
        for client_id, info in sessions.items()
        if client_id not in clients
    ]
    listing.sort(
        key=lambda c: (
            c["registration"] == CLIENT_KIND_METADATA_DOCUMENT,
            c["client_name"].casefold(),
        )
    )
    return listing


def _prune_expired(entries: dict[str, dict[str, Any]]) -> None:
    """Drop the entries whose expires_at has passed."""
    now = time.time()
    for key in [key for key, value in entries.items() if value["expires_at"] < now]:
        del entries[key]


def _generate_signing_key() -> dict[str, Any]:
    """Generate an RSA signing key in its stored form: private_key_pem, kid and created_at."""
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return {
        "private_key_pem": private_pem.decode(),
        "kid": str(uuid.uuid4()),
        "created_at": time.time(),
    }


async def _load_or_generate_keys(store: Store) -> dict[str, Any]:
    """Load the stored signing keys, generating and storing a signing key if there is none.

    The stored dict holds the current signing key at its top level
    (private_key_pem, kid, created_at). After a rotation that kept the key it
    replaced, previous_key holds that key's kid and public_key_pem. A dict
    without previous_key is a single current key, and releases that predate
    rotation read the same top-level fields.
    """
    stored_keys = await store.async_load()

    if stored_keys and "private_key_pem" in stored_keys:
        _LOGGER.info("Loading existing RSA key from storage")
        return stored_keys

    _LOGGER.info("Generating new RSA key pair for JWT signing")
    stored_keys = _generate_signing_key()
    await store.async_save(stored_keys)
    _LOGGER.info("RSA key pair generated and saved to storage with kid: %s", stored_keys["kid"])
    return stored_keys


def _use_signing_keys(hass: HomeAssistant, stored_keys: dict[str, Any]) -> None:
    """Make the stored keys the ones tokens are signed and verified with.

    jwt_private_key, jwt_public_key and jwt_kid are the current key, which signs
    every token. jwt_verification_keys maps the kid of every published key, the
    current one first, to its public key.
    """
    private_key = serialization.load_pem_private_key(
        stored_keys["private_key_pem"].encode(),
        password=None,
        backend=default_backend(),
    )
    kid = stored_keys.get("kid", "1")  # Fallback to "1" for old keys
    verification_keys = {kid: private_key.public_key()}

    previous_key = stored_keys.get("previous_key")
    if previous_key:
        verification_keys[previous_key["kid"]] = serialization.load_pem_public_key(
            previous_key["public_key_pem"].encode(), backend=default_backend()
        )

    domain_data = hass.data[DOMAIN]
    domain_data["jwt_private_key"] = private_key
    domain_data["jwt_public_key"] = verification_keys[kid]
    domain_data["jwt_kid"] = kid
    domain_data["jwt_verification_keys"] = verification_keys


async def async_rotate_signing_key(hass: HomeAssistant, keep_previous_key: bool) -> None:
    """Replace the signing key with a new one and persist the result.

    With keep_previous_key the replaced key stays published and keeps verifying
    the tokens it signed until the next rotation, so they work until they
    expire. Without it the replaced key is dropped at once and every token it
    signed is refused, which is the response to a leaked key.

    Rotations run one at a time. Two at once could each keep the key that was
    current when they started, so the key replaced by the first would come
    back as the previous key of the second.
    """
    domain_data = hass.data[DOMAIN]
    async with domain_data.setdefault("key_rotation_lock", asyncio.Lock()):
        stored_keys = await hass.async_add_executor_job(_generate_signing_key)
        replaced_kid = domain_data["jwt_kid"]

        if keep_previous_key:
            public_pem = domain_data["jwt_public_key"].public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            stored_keys["previous_key"] = {
                "kid": replaced_kid,
                "public_key_pem": public_pem.decode(),
            }

        await domain_data["key_store"].async_save(stored_keys)
        _use_signing_keys(hass, stored_keys)

    _LOGGER.info(
        "Rotated the JWT signing key to kid %s; the previous key %s was %s",
        stored_keys["kid"],
        replaced_kid,
        "kept for verification" if keep_previous_key else "dropped",
    )


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
    # Load or generate the RSA keys tokens are signed and verified with
    if "jwt_private_key" not in hass.data[DOMAIN]:
        key_store = Store(hass, STORAGE_VERSION, STORAGE_KEY_KEYS)
        hass.data[DOMAIN]["key_store"] = key_store
        _use_signing_keys(hass, await _load_or_generate_keys(key_store))

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
    hass.http.register_view(OIDCStringsView())
    hass.http.register_view(OIDCClientsView())


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

        details: dict[str, Any] = {
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

        described = find_resource(
            hass, stored_request.get("resource"), get_issuer_from_request(request)
        )
        if described is not None:
            access = await async_consent_access(
                hass,
                described,
                request["hass_user"],
                stored_request["client_id"],
                _panel_language(hass, request.query.get("language")),
            )
            if access is not None:
                details["access"] = access
                # What the client may do at the resource is the user's choice,
                # so the sign-in stops on the consent screen even for a client
                # registered without consent.
                details["consent_required"] = True

        return web.json_response(details)

    @staticmethod
    async def _chosen_access(
        hass: HomeAssistant,
        request: web.Request,
        stored_request: dict[str, Any],
        choice: Any,
    ) -> dict[str, Any] | None | web.Response:
        """Check the access chosen on the consent screen and return what it grants.

        For a resource that describes the access it offers, an approval must
        carry a choice that fits the description and the user's ceiling, which
        are asked again here rather than trusted from the screen. The result
        names the resource's integration, the option chosen in every group and
        the scopes that grants. None means the resource offers no choice, and
        an approval that carries one anyway is refused, since the screen showed
        something that no longer holds.
        """
        described = find_resource(
            hass, stored_request.get("resource"), get_issuer_from_request(request)
        )
        rules = (
            await async_access_rules(hass, described, request["hass_user"]) if described else None
        )
        if rules is None:
            if choice is None:
                return None
            return web.Response(
                text="The access you chose can no longer be checked. "
                "Start the sign-in again from the application.",
                status=400,
            )

        description, ceiling = rules
        if choice is None:
            return web.Response(text="Choose what the application may do", status=400)
        try:
            options = validate_choice(description, ceiling, choice)
        except InvalidChoice as err:
            return web.Response(text=f"Invalid access choice: {err}", status=400)
        return {
            "resource": described.domain,
            "options": options,
            "scopes": granted_scopes(description, options),
        }

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
        approve = body.get("approve") is True

        access = None
        if approve:
            access = await self._chosen_access(hass, request, stored_request, body.get("access"))
            if isinstance(access, web.Response):
                return access

        # A decision either way consumes the pending request. Another decision
        # on it may have been made while the resource was asked above.
        if hass.data[DOMAIN]["pending_auth_requests"].pop(request_id, None) is not stored_request:
            return web.Response(text="Invalid or expired request", status=400)

        # Extract parameters
        client_id = stored_request["client_id"]
        redirect_uri = stored_request["redirect_uri"]
        scope = stored_request["scope"]
        state = stored_request["state"]
        nonce = stored_request.get("nonce")
        code_challenge = stored_request.get("code_challenge")
        code_challenge_method = stored_request.get("code_challenge_method")
        resource = stored_request.get("resource")

        separator = "&" if "?" in redirect_uri else "?"

        def build_redirect(**params: str) -> str:
            if state:
                params["state"] = state
            # Every response names the issuer so the client can detect a mix-up
            # with another authorization server (RFC 9207).
            params["iss"] = _issuer_for(request)
            return f"{redirect_uri}{separator}{urlencode(params)}"

        if not approve:
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
            # What the user chose the client may do at the resource, when the
            # resource describes the access it offers
            "access": access,
            # Kept with the session, so a client that is not stored, such as a
            # metadata document client, can still be named in session lists.
            "client_name": client.get("client_name"),
            "expires_at": time.time() + AUTHORIZATION_CODE_EXPIRY,
        }
        if access is not None:
            await async_remember_choice(
                hass, user.id, client_id, access["resource"], access["options"]
            )

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
            "scopes_supported": _scopes_supported(request.app["hass"]),
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
            "authorization_response_iss_parameter_supported": True,
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
            "scopes_supported": _scopes_supported(request.app["hass"]),
            "authorization_response_iss_parameter_supported": True,
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
            "scopes_supported": _scopes_supported(request.app["hass"]),
            "authorization_response_iss_parameter_supported": True,
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

        # Only OpenID Connect scopes are granted from the request. Unrecognised
        # scope values are ignored (OIDC Core §3.1.2.1), and the scopes of a
        # resource that describes the access it offers are what the user
        # chooses on the consent screen, whatever the client asked for. The
        # token response's scope says what was granted (RFC 6749 §3.3).
        oidc_scopes = [sc for sc in requested_scopes if sc in SUPPORTED_SCOPES]
        if len(oidc_scopes) != len(requested_scopes):
            _LOGGER.debug(
                "Not granting requested scopes for client %s: %s",
                client_id,
                " ".join(sc for sc in requested_scopes if sc not in SUPPORTED_SCOPES),
            )
        scope = " ".join(oidc_scopes)

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

        # Generate tokens. The scope is what the user approved: the OpenID
        # Connect scopes, and the scopes of the access chosen at the resource.
        user_id = auth_data["user_id"]
        access = auth_data.get("access")
        scope = _with_access_scopes(auth_data["scope"], access)

        nonce = auth_data.get("nonce")
        auth_time = auth_data.get("auth_time")

        # The token audience is bound to the resource requested at the authorize
        # step (RFC 8707). A token request MAY also carry a resource indicator;
        # honor it only when the authorize step didn't specify one, and not for
        # a resource that asks the user what the client may do there, since the
        # user was not asked.
        resource = auth_data.get("resource")
        if resource is None:
            resource = _normalize_resource(data.get("resource"))
            if find_resource(hass, resource, get_issuer_from_request(_request)):
                return web.json_response(
                    {
                        "error": "invalid_target",
                        "error_description": "This resource asks the user what the "
                        "application may do there; name it in the authorization request",
                    },
                    status=400,
                )

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
            # The access the user chose at the resource, kept so the session
            # can show it and its refreshed tokens carry its scopes
            "access": access,
            "client_name": auth_data.get("client_name"),
            "family": family,
            "issued_at": time.time(),
            "expires_at": time.time() + REFRESH_TOKEN_EXPIRY,
        }

        # Persist refresh tokens to storage
        await _save_refresh_tokens(hass)

        # A dynamically registered client that has had a token issued was
        # approved by a user and is never pruned, even after its sessions end.
        stored_client = hass.data[DOMAIN].get("clients", {}).get(client_id)
        if (
            stored_client is not None
            and stored_client.get("registration") == REGISTRATION_DYNAMIC
            and "used_at" not in stored_client
        ):
            stored_client["used_at"] = time.time()
            await hass.data[DOMAIN]["store"].async_save({"clients": hass.data[DOMAIN]["clients"]})

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
        # The tokens the session retired within the grace period, each with the
        # time it was retired
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
        """Issue fresh access and ID tokens for a stored refresh token.

        A session whose resource describes the access it offers, but which was
        granted without a choice of that access, because it began before the
        resource described itself, is ended instead. The client then signs in
        again and the user chooses, so every token for such a resource carries
        a choice, and one without the resource's scopes means no access there.
        """
        if not token_data.get("access") and find_resource(
            hass, token_data.get("resource"), get_issuer_from_request(_request)
        ):
            _revoke_family(hass, token_data["family"])
            await _save_refresh_tokens(hass)
            _LOGGER.info(
                "Ended a session of client %s granted before its resource described the "
                "access it offers; the client has to sign in again",
                token_data["client_id"],
            )
            return web.json_response(
                {
                    "error": "invalid_grant",
                    "error_description": "The resource now asks what this application may "
                    "do there; sign in again",
                },
                status=400,
            )

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
        """Generate a JWT access token (RFC 9068)."""
        now = int(time.time())
        issuer = _issuer_for(request)

        # When a resource indicator was supplied (RFC 8707), bind aud to that
        # resource and record the client in azp. Otherwise fall back to the
        # client_id as the audience for backward compatibility. token_use marks
        # the token as an access token for validators that do not check typ.
        payload = {
            "sub": user_id,
            "iat": now,
            "exp": now + ACCESS_TOKEN_EXPIRY,
            "iss": issuer,
            "aud": audience or client_id,
            "client_id": client_id,
            "jti": str(uuid.uuid4()),
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

        return jwt.encode(
            payload, private_pem, algorithm="RS256", headers={"kid": kid, "typ": ACCESS_TOKEN_TYPE}
        )

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
        issuer = _issuer_for(request)

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
            # Verify the signature, expiry and issuer, and refuse ID tokens
            payload = decode_access_token(hass.data[DOMAIN], access_token, _issuer_for(request))

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

        # Convert modulus (n) and exponent (e) to base64url format
        def int_to_base64url(value: int) -> str:
            """Convert integer to base64url-encoded string."""
            # Convert to bytes (big-endian)
            value_bytes = value.to_bytes((value.bit_length() + 7) // 8, byteorder="big")
            # Base64url encode (no padding)
            return base64.urlsafe_b64encode(value_bytes).decode("utf-8").rstrip("=")

        # Every key that verifies tokens is published, the signing key first
        keys = []
        for kid, public_key in hass.data[DOMAIN]["jwt_verification_keys"].items():
            public_numbers = public_key.public_numbers()
            keys.append(
                {
                    "kty": "RSA",
                    "use": "sig",
                    "kid": kid,
                    "alg": "RS256",
                    "n": int_to_base64url(public_numbers.n),  # Modulus
                    "e": int_to_base64url(public_numbers.e),  # Exponent
                }
            )

        return web.json_response({"keys": keys})


def _registration_refusal(hass: HomeAssistant, remote: str | None) -> web.Response | None:
    """Count a registration against the limits, or return the refusal to send.

    Registrations are limited per hour overall and per remote address, so one
    caller cannot use up the hourly allowance. Dynamically registered clients
    that have not had a token yet are capped as well. Clients that have had one
    were approved by a user and do not count.
    """
    now = time.time()
    window_start = now - REGISTRATION_RATE_LIMIT_WINDOW
    recent = hass.data[DOMAIN].setdefault("registration_times", [])
    recent[:] = [t for t in recent if t > window_start]
    by_address = hass.data[DOMAIN].setdefault("registration_times_by_address", {})
    for address in list(by_address):
        by_address[address] = [t for t in by_address[address] if t > window_start]
        if not by_address[address]:
            del by_address[address]
    address_recent = by_address.setdefault(remote or "", [])

    limited = None
    if len(address_recent) >= REGISTRATION_RATE_LIMIT_PER_ADDRESS:
        limited = address_recent
    elif len(recent) >= REGISTRATION_RATE_LIMIT_MAX:
        limited = recent
    if limited is not None:
        retry_after = max(1, int(limited[0] + REGISTRATION_RATE_LIMIT_WINDOW - now) + 1)
        _LOGGER.debug("Refused dynamic client registration from %s: rate limited", remote)
        return web.json_response(
            {
                "error": "temporarily_unavailable",
                "error_description": "Too many client registrations, try again later",
            },
            status=429,
            headers={"Retry-After": str(retry_after)},
        )

    if count_unused_dynamic_clients(hass) >= MAX_UNUSED_DYNAMIC_CLIENTS:
        _LOGGER.debug("Refused dynamic client registration from %s: client limit reached", remote)
        return web.json_response(
            {
                "error": "temporarily_unavailable",
                "error_description": "Too many registered clients, try again later",
            },
            status=429,
        )

    recent.append(now)
    address_recent.append(now)
    return None


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

        try:
            validate_redirect_uris(redirect_uris)
        except ValueError as e:
            return web.json_response(
                {"error": "invalid_redirect_uri", "error_description": str(e)},
                status=400,
            )

        # The limits are checked only now, once the request is known to be
        # valid, so a caller sending its body slowly holds no slot. From the
        # checks to create_client storing the client nothing awaits, so
        # concurrent requests cannot together pass them.
        await prune_dynamic_clients(hass)
        refusal = _registration_refusal(hass, request.remote)
        if refusal is not None:
            return refusal

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
            dynamic=True,
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
        cannot be revoked one by one, so presenting one is answered with
        unsupported_token_type (RFC 7009 §2.2.1). Unknown tokens are answered
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
            if _is_issued_jwt(hass, token):
                return web.json_response(
                    {
                        "error": "unsupported_token_type",
                        "error_description": "Access tokens expire within an hour and "
                        "cannot be revoked; revoke the refresh token to end the session",
                    },
                    status=400,
                )
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

    # The panel reads the list again after ending a session. Home Assistant's
    # service worker answers a GET from its cache outside /api, which would
    # show the session that was just ended, so the panel uses the /api path.
    url = "/api/oidc_provider/sessions"
    extra_urls = ["/oidc/sessions"]
    name = "api:oidc:sessions"
    requires_auth = True

    async def get(self, request: web.Request) -> web.Response:
        """List the user's live sessions.

        With them comes the description of every resource a session chose
        access at, in the language the panel asks for, so the panel can name
        what was granted. A session whose resource cannot be described now is
        listed without its access.
        """
        hass = request.app["hass"]
        user = request["hass_user"]
        sessions = user_sessions(hass, user.id)
        language = _panel_language(hass, request.query.get("language"))
        resources: dict[str, dict[str, Any] | None] = {}
        for session in sessions:
            if session["access"] is None:
                continue
            domain = session["access"]["resource"]
            if domain not in resources:
                resources[domain] = await async_display_model(hass, domain, language)
            if resources[domain] is None:
                session["access"] = None
        return web.json_response(
            {
                "sessions": sessions,
                "resources": {domain: model for domain, model in resources.items() if model},
            }
        )


class OIDCSessionView(HomeAssistantView):
    """One of the signed-in user's sessions."""

    url = "/api/oidc_provider/sessions/{session_id}"
    extra_urls = ["/oidc/sessions/{session_id}"]
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


class OIDCStringsView(HomeAssistantView):
    """The login panel's text, in the signed-in user's language."""

    url = "/oidc/strings"
    name = "api:oidc:strings"
    requires_auth = True

    async def get(self, request: web.Request) -> web.Response:
        """Return the panel's text in the language the panel asks for."""
        hass = request.app["hass"]
        language = _panel_language(hass, request.query.get("language"))
        return web.json_response(
            {"language": language, "strings": await async_panel_strings(hass, language)}
        )


def _client_error(error: str, message: str, status: int = 400) -> web.Response:
    """Return a client management error the page can show."""
    return _client_response({"error": error, "message": message}, status)


def _client_response(body: dict[str, Any], status: int = 200) -> web.Response:
    """Return a client management response that is never cached.

    The list changes with every action on the page, and the response to a
    registration carries the client secret.
    """
    return web.json_response(body, status=status, headers={"Cache-Control": "no-store"})


def _redirect_uris_from(body: dict[str, Any]) -> list[str]:
    """Return the redirect URIs of a client management request.

    Raises:
        ValueError: If they are not a non-empty list of strings
    """
    redirect_uris = body.get("redirect_uris")
    if not isinstance(redirect_uris, list) or not all(isinstance(u, str) for u in redirect_uris):
        raise ValueError("redirect_uris must be a list of strings")
    redirect_uris = [uri.strip() for uri in redirect_uris if uri.strip()]
    if not redirect_uris:
        raise ValueError("At least one redirect URI is required")
    return redirect_uris


def _optional_bool(body: dict[str, Any], key: str) -> bool | None:
    """Return a boolean field of a request body, or None when it is absent.

    Raises:
        ValueError: If the field holds anything but a boolean
    """
    value = body.get(key)
    if value is not None and not isinstance(value, bool):
        raise ValueError(f"{key} must be true or false")
    return value


class OIDCClientsView(HomeAssistantView):
    """Client management for administrators, used by the login panel.

    It does what the client actions do: list, register, update and revoke.
    The client is named in the query string and not in the path, because the
    ID of a metadata document client is a URL, and proxies treat encoded
    slashes in a path differently. It is served under /api because Home
    Assistant's service worker answers a GET from its cache anywhere else,
    and the page reads the list again after every change.
    """

    url = "/api/oidc_provider/clients"
    name = "api:oidc:clients"
    requires_auth = True

    @staticmethod
    def _refusal(request: web.Request) -> web.Response | None:
        """Return the response for a user who is not an administrator.

        Callers compare the result with None: a response without headers of
        its own is an empty mapping, and so false, on older aiohttp releases.
        """
        if request["hass_user"].is_admin:
            return None
        return _client_error("forbidden", "Only administrators can manage clients", 403)

    @staticmethod
    async def _body(request: web.Request) -> dict[str, Any]:
        """Return the JSON object a request carries.

        Raises:
            ValueError: If the body is not a JSON object
        """
        try:
            body = await request.json()
        except ValueError as e:
            raise ValueError("The request body must be JSON") from e
        if not isinstance(body, dict):
            raise ValueError("The request body must be a JSON object")
        return body

    async def get(self, request: web.Request) -> web.Response:
        """List every client with its settings and session count."""
        if (refusal := self._refusal(request)) is not None:
            return refusal
        return _client_response({"clients": managed_clients(request.app["hass"])})

    async def post(self, request: web.Request) -> web.Response:
        """Register a client. The response is the only place its secret appears."""
        if (refusal := self._refusal(request)) is not None:
            return refusal
        hass = request.app["hass"]
        try:
            body = await self._body(request)
            client_name = validate_client_name(body.get("client_name"))
            redirect_uris = _redirect_uris_from(body)
            consent_required = _optional_bool(body, "consent_required") or False
            if client_name_in_use(hass, client_name):
                return _client_error(
                    "name_in_use", f"A client named '{client_name}' already exists", 409
                )
            client = await create_client(
                hass,
                client_name=client_name,
                redirect_uris=redirect_uris,
                consent_required=consent_required,
            )
        except ValueError as e:
            return _client_error("invalid_request", str(e))

        _LOGGER.info(
            "Administrator %s registered client %s", request["hass_user"].id, client["client_id"]
        )
        return _client_response(
            {
                "client_id": client["client_id"],
                "client_secret": client["client_secret"],
                "client_name": client["client_name"],
                "redirect_uris": client["redirect_uris"],
                "consent_required": client["consent_required"],
            },
            201,
        )

    async def patch(self, request: web.Request) -> web.Response:
        """Change a stored client's redirect URIs and consent setting."""
        if (refusal := self._refusal(request)) is not None:
            return refusal
        hass = request.app["hass"]
        client_id = request.query.get("client_id", "")
        try:
            body = await self._body(request)
            client = await update_client(
                hass,
                client_id,
                _redirect_uris_from(body),
                _optional_bool(body, "consent_required"),
            )
        except KeyError:
            return _client_error("not_found", "No such client is registered", 404)
        except ValueError as e:
            return _client_error("invalid_request", str(e))

        _LOGGER.info("Administrator %s updated client %s", request["hass_user"].id, client_id)
        active = client_sessions(hass).get(client_id, {}).get("active_sessions", 0)
        return _client_response(_managed_client(client_id, client, active))

    async def delete(self, request: web.Request) -> web.Response:
        """Revoke a client: remove it if it is stored and end its sessions."""
        if (refusal := self._refusal(request)) is not None:
            return refusal
        client_id = request.query.get("client_id", "")
        removed, ended = await remove_client(request.app["hass"], client_id)
        if not removed and not ended:
            return _client_error("not_found", "No such client is registered", 404)

        _LOGGER.info(
            "Administrator %s revoked client %s and ended %d sessions",
            request["hass_user"].id,
            client_id,
            ended,
        )
        return _client_response({"removed": removed, "ended_sessions": ended})
