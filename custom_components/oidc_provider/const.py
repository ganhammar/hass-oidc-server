"""Constants for the OIDC Provider integration."""

DOMAIN = "oidc_provider"

# Storage
STORAGE_VERSION = 1
STORAGE_KEY_KEYS = f"{DOMAIN}.keys"
STORAGE_KEY_TOKENS = f"{DOMAIN}.tokens"

# Token expiry times (in seconds)
ACCESS_TOKEN_EXPIRY = 3600  # 1 hour
ID_TOKEN_EXPIRY = 3600  # 1 hour
REFRESH_TOKEN_EXPIRY = 2592000  # 30 days
AUTHORIZATION_CODE_EXPIRY = 600  # 10 minutes

# A refresh token is replaced on every use. The one it replaced is still
# answered for this long, so a client that sent two refreshes at once or lost
# a response keeps its session; after that, presenting it revokes the session.
REFRESH_TOKEN_REUSE_GRACE = 60  # seconds

# Token type discriminator (custom claim used to distinguish access vs id tokens)
TOKEN_USE_ACCESS = "access"
TOKEN_USE_ID = "id"

# JOSE typ header of JWT access tokens (RFC 9068)
ACCESS_TOKEN_TYPE = "at+jwt"

# OIDC scopes
SCOPE_OPENID = "openid"
SCOPE_PROFILE = "profile"
SCOPE_EMAIL = "email"
SCOPE_GROUPS = "groups"

SUPPORTED_SCOPES = [SCOPE_OPENID, SCOPE_PROFILE, SCOPE_EMAIL, SCOPE_GROUPS]

# Home Assistant group IDs
HA_GROUP_ID_ADMIN = "system-admin"
HA_GROUP_ID_USER = "system-users"
HA_GROUP_ID_READ_ONLY = "system-read-only"

# OIDC group names
GROUP_OWNER = "owner"
GROUP_ADMIN = "admin"
GROUP_USER = "user"
GROUP_READ_ONLY = "read-only"

# Mapping from HA group IDs to OIDC group names
HA_GROUP_TO_OIDC_GROUP = {
    HA_GROUP_ID_ADMIN: GROUP_ADMIN,
    HA_GROUP_ID_USER: GROUP_USER,
    HA_GROUP_ID_READ_ONLY: GROUP_READ_ONLY,
}

# Grant types
GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code"
GRANT_TYPE_REFRESH_TOKEN = "refresh_token"

# Response types
RESPONSE_TYPE_CODE = "code"

# PKCE code challenge methods
CODE_CHALLENGE_METHOD_S256 = "S256"
CODE_CHALLENGE_METHOD_PLAIN = "plain"
SUPPORTED_CODE_CHALLENGE_METHODS = [CODE_CHALLENGE_METHOD_S256]

# Rate limiting
MAX_TOKEN_ATTEMPTS = 5  # Maximum failed attempts before rate limiting
RATE_LIMIT_WINDOW = 300  # 5 minutes in seconds
RATE_LIMIT_PENALTY = 60  # Lockout period in seconds after max attempts

# PKCE enforcement
DEFAULT_REQUIRE_PKCE = True  # Default to required for security (OAuth 2.1 compliance)
CONF_REQUIRE_PKCE = "require_pkce"

# Dynamic client registration (RFC 7591). Off for new installs because anyone
# who can reach /oidc/register can create a client while it is on.
DEFAULT_ALLOW_DYNAMIC_REGISTRATION = False
CONF_ALLOW_DYNAMIC_REGISTRATION = "allow_dynamic_registration"

# Client ID Metadata Documents: a client_id that is an HTTPS URL is resolved by
# fetching the client's metadata from it. On by default, since it lets clients
# such as Claude sign in without dynamic registration and every sign-in through
# such a client stops on the consent screen.
DEFAULT_ALLOW_CLIENT_METADATA_DOCUMENTS = True
CONF_ALLOW_CLIENT_METADATA_DOCUMENTS = "allow_client_metadata_documents"
CIMD_MAX_DOCUMENT_BYTES = 5 * 1024  # The draft's recommended limit
CIMD_FETCH_TIMEOUT = 5  # seconds
CIMD_FETCHES_PER_MINUTE = 30  # Fetches that miss the cache, across all callers
CIMD_FETCHES_PER_MINUTE_PER_ADDRESS = 5  # The same, for one remote address
CIMD_CACHE_MIN_TTL = 60  # seconds
CIMD_CACHE_DEFAULT_TTL = 3600  # seconds, when the response sets no max-age
CIMD_CACHE_MAX_TTL = 86400  # seconds
CIMD_CACHE_MAX_ENTRIES = 100

# Authorization requests waiting for the user to sign in and decide. Anyone can
# start one, so new ones are refused beyond these many, overall and from one
# remote address, rather than cancelling sign-ins already under way.
MAX_PENDING_AUTH_REQUESTS = 1000
MAX_PENDING_AUTH_REQUESTS_PER_ADDRESS = 20


# Dynamically registered clients that never had a token issued are pruned
# after the retention period; a client that had one was approved by a user and
# is kept. Registration is limited overall and per address, since the endpoint
# needs no login, and the unused clients it creates are capped.
REGISTRATION_DYNAMIC = "dynamic"
DYNAMIC_CLIENT_RETENTION = 86400  # 1 day in seconds
REGISTRATION_RATE_LIMIT_MAX = 20  # Successful registrations per window
REGISTRATION_RATE_LIMIT_PER_ADDRESS = 5  # The same, for one remote address
REGISTRATION_RATE_LIMIT_WINDOW = 3600  # 1 hour in seconds
MAX_UNUSED_DYNAMIC_CLIENTS = 200

# Frontend panel serving the login flow (hidden from the sidebar)
PANEL_URL_PATH = "oidc_login"
