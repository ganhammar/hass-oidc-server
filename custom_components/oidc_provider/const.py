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

# Token type discriminator (custom claim used to distinguish access vs id tokens)
TOKEN_USE_ACCESS = "access"
TOKEN_USE_ID = "id"

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

# Frontend panel serving the login flow (hidden from the sidebar)
PANEL_URL_PATH = "oidc_login"
