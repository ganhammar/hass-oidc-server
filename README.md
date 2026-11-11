# Home Assistant OIDC Server

A Home Assistant custom component that turns your Home Assistant instance into a fully functional OpenID Connect (OIDC) server, allowing external applications like Claude Connectors to authenticate against your Home Assistant users.

## Features

- **Standards-compliant OIDC server** with discovery endpoint
- **Integrates with Home Assistant's native authentication** including TOTP/2FA
- **JWT access tokens** (RFC 9068) with RSA signing and key rotation
- **Support for authorization code flow** with refresh tokens
- **Claude and other MCP clients connect without registration** through Client ID Metadata Documents
- **Easy client registration** via Home Assistant services
- **Consent screen** for clients you did not register yourself, styled like the Home Assistant login
- **Choose what an application may do**: an integration that accepts these tokens can describe the access it offers, and the consent screen lets each person choose it, as a level or area by area; the choice goes into the access token as scopes
- **No external dependencies** - runs entirely within Home Assistant

This integration acts as an OIDC abstraction layer on top of Home Assistant's built-in authentication system. It does not create new user accounts or add additional login methods—users authenticate with their existing Home Assistant credentials through the standard login interface.

## Installation

### HACS (Recommended)

1. Open HACS in Home Assistant
1. Search for "OIDC Provider"
1. Click "Download"
1. Restart Home Assistant
1. Configure the integration (see Configuration section below)

### Manual

1. Copy the `custom_components/oidc_provider` folder to your Home Assistant `config/custom_components/` directory
1. Restart Home Assistant
1. Configure the integration (see Configuration section below)

## Configuration

1. Go to **Settings** → **Devices & Services**
1. Click **Add Integration**
1. Search for "OIDC Provider"
1. Choose whether to **Allow client metadata documents** and **Allow dynamic client registration** (see below), then click **Submit**

### Options

Change these later under **Settings** → **Devices & Services** → **OIDC Provider** → **Configure**. Changes apply immediately, without a restart.

- **Require PKCE** (default: on): authorization requests must carry an S256 PKCE code challenge, as OAuth 2.1 requires. Public clients, which have no secret, always need it.
- **Allow client metadata documents** (default: on for new installs): accepts clients whose client ID is an HTTPS URL serving their metadata, as described in [Client ID Metadata Documents](#client-id-metadata-documents). This is how Claude connects. Turning it off ends those clients' sessions at their next token refresh.
- **Allow dynamic client registration** (default: off for new installs): lets clients register themselves at `/oidc/register` (RFC 7591). Only needed for clients that support neither client metadata documents nor a client you register for them. Every sign-in through a dynamically registered client stops on the [consent screen](#consent-screen).

Clients that use dynamic registration, such as Claude when client metadata documents are off, register a new client on every fresh connection, so abandoned registrations are cleaned up automatically. A dynamically registered client that has not had a token issued within a day of registering is removed. Once a user has approved one, it is kept even after its sessions end, since many clients reuse their client ID for the next sign-in. The cleanup runs when the integration starts and before each new registration. Clients you registered with `register_client`, and clients registered by earlier releases, are never removed automatically.

While dynamic client registration is off, `/oidc/register` answers `403` with `access_denied`, and the discovery documents leave out `registration_endpoint` so clients do not try to use it. Register clients yourself with the `register_client` action instead. Clients that registered while it was on keep working until you revoke them.

Installs set up before version 1.7.0 keep dynamic client registration on, since it was always on before, so clients that register themselves keep connecting after the upgrade. Turn it off in the options if you do not need it.

Installs set up before version 1.8.0 start with client metadata documents matching their dynamic client registration setting, so an install that admitted only clients you registered keeps doing so. Turn it on in the options to let Claude connect without registration.

If you switch from a fork of this integration that stores the same setting, a value you saved there is kept. An entry where it was never saved looks the same as an install from before 1.7.0, so registration is turned on; check the setting after switching.

## Usage

### Registering a Client

To register a new OIDC client (e.g., for Claude Connectors):

1. Go to **Developer Tools** → **Actions**
2. In the action dropdown, select **"Register OIDC Client"** (or type `oidc_provider.register_client`)
3. Fill in the fields:
   - **Client Name**: A friendly name (e.g., "Claude Connector")
   - **Redirect URIs**: Comma-separated list of allowed redirect URIs
   - **Require consent** (optional): Ask the user to approve each authorization. Off by default, since a client you register yourself is trusted
4. Click **"Perform Action"**
5. Copy the generated **Client ID** and **Client Secret** from the action's response

Example action call:

```yaml
action: oidc_provider.register_client
data:
  client_name: "Claude Connector"
  redirect_uris: "https://claude.ai/callback,https://app.claude.com/callback,https://claude.ai/api/mcp/auth_callback"
```

The response holds the credentials:

```yaml
client_id: client_xxxxxxxxxxxxx
client_secret: yyyyyyyyyyyyyyyyyyyyyyyy
client_name: Claude Connector
redirect_uris:
  - https://claude.ai/callback
  - https://app.claude.com/callback
  - https://claude.ai/api/mcp/auth_callback
consent_required: false
```

Called from an automation or script without a response variable, the action posts the credentials in a notification instead. Every Home Assistant user can read notifications, so dismiss it once you have saved the secret.

**Important**: Save these credentials securely. The client secret cannot be retrieved later.

### Client ID Metadata Documents

A client can identify itself with an HTTPS URL as its client ID instead of registering ([draft-ietf-oauth-client-id-metadata-document](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/), used by the MCP authorization specification). When a sign-in starts, Home Assistant fetches the client's name and allowed redirect URIs from that URL. Claude, Claude Code and other MCP clients prefer this over dynamic client registration, so with this option on you can leave dynamic client registration off and register nothing.

These clients are public: they have no secret and prove their sign-ins with PKCE. Every sign-in through one stops on the [consent screen](#consent-screen), which shows the host that serves the document, such as `claude.ai`, next to the client's name.

The fetch is limited to keep the endpoint from being used against your network:

- Only `https` URLs in normalized form with a host name and a path, without a query or fragment, are accepted. IP addresses in any notation are refused, and international host names must be given in punycode, so a look-alike cannot pass for another domain on the consent screen
- Host names that resolve only to private, loopback or other special-use addresses are refused, checked when the connection is made. IPv6 addresses that embed an IPv4 address, such as NAT64, count as that IPv4 address
- Redirects are not followed, documents larger than 5 KB are refused, and the request times out after 5 seconds. A failed fetch is answered with the same message whatever the cause, so it reveals nothing about your network
- Documents are cached for their `Cache-Control` lifetime, between 1 minute and 1 day, and not at all when marked `no-store` or `no-cache`. At most 30 uncached fetches run per minute, and at most 5 for any one address
- A document must not contain a client secret, must use `none` as its token endpoint authentication method, and must list its redirect URIs

### Consent Screen

Clients that registered themselves through `/oidc/register` (when [enabled](#options)) and clients identified by a [metadata document](#client-id-metadata-documents) are not vetted by you, so every authorization for them stops on a consent screen inside Home Assistant. It names the client, the host serving its metadata document if it has one, the site the user will be sent to, and the information the client will receive, with Approve and Deny buttons. When that site is on the user's own computer, as with Claude Code, the screen says so. Denying sends the client an `access_denied` error.

Clients you register with the `register_client` action skip the screen unless you set **Require consent**. Clients registered before version 1.6.0 have no consent setting and prompt until you turn it off, because there is no way to tell which of them came from dynamic registration. Use the `update_client` action with `consent_required: false` for the ones you registered yourself.

#### Choosing what an application may do

An integration that accepts this provider's tokens, such as an MCP server, can describe the access it offers. When an application signs in for such an integration (the `resource` it names is one of that integration's addresses), the consent screen asks what the application may do there:

- It opens on the integration's levels, such as "Look only" or "Control devices", each with one sentence on what it allows. A note appears under the selected level when there is something its name does not say.
- **Choose in detail** shows one setting per area, such as None, Read or Full, with what the current setting means and notes where an area reaches past another. A choice that matches no level is called Custom, with how it differs from the closest level.
- The first time, the integration's default level is selected; after that, the person's last choice for that application. It is marked "Your choice last time".
- An area that is unavailable right now, for example because it is turned off in that integration's options, can still be chosen and says why. Settings above what an administrator allows for the person are locked, with the reason, as is a level that would add nothing they may allow.
- The screen says the application can be signed out later under [Connected applications](#connected-applications).

The choice goes into the access token as scopes (see [Tokens](#tokens)), and the integration decides what each scope allows. This provider enforces none of it. A sign-in for such an integration stops on the screen even for a client registered without **Require consent**, since the choice is each person's to make; the last choice is preselected, so approving is one tap. Sign-ins for anything else work as described above, and an integration that has not described itself gets the approve or deny screen as before.

Integration authors: see [Describing a resource to the OIDC Provider](docs/resource-descriptions.md).

### Updating a Client

To update redirect URIs for an existing client:

1. Use **"List OIDC Clients"** to find the client ID
2. Go to **Developer Tools** → **Actions**
3. Select **"Update OIDC Client"**
4. Enter the client ID and new redirect URIs, and optionally whether consent is required

```yaml
action: oidc_provider.update_client
data:
  client_id: "client_xxxxxxxxxxxxx"
  redirect_uris: "https://new-app.example.com/callback,http://localhost:8080/auth"
  consent_required: false
```

### Revoking a Client

To revoke an existing client:

1. Use **"List OIDC Clients"** to find the client ID
2. Go to **Developer Tools** → **Actions**
3. Select **"Revoke OIDC Client"**
4. Enter the client ID

```yaml
action: oidc_provider.revoke_client
data:
  client_id: "client_xxxxxxxxxxxxx"
```

Revoking a client also ends every session it holds, so its refresh tokens stop working at once; access tokens it already has expire within the hour. A client that signed in with a [metadata document](#client-id-metadata-documents) is not stored, so revoking its URL client ID ends its sessions, and it can ask the user again on its next sign-in unless you turn metadata documents off.

**"List OIDC Clients"** shows the number of active sessions for each client, including clients that signed in with a metadata document, and returns the same list as a response when called from a script or **Developer Tools**.

### Connected Applications

Each user can see the applications signed in with their Home Assistant account at `https://your-ha-instance/oidc_login`, with when each signed in and was last used, and sign any of them out. For an application that was given a choice of access, the list shows what was chosen: the level's name, or Custom with how it differs from the closest level. Signing out ends that session, so the application gets no new access tokens and has to ask again; an access token it already holds keeps working until it expires, within the hour.

### Rotating the Signing Key

Access and ID tokens are signed with an RSA key that is generated on first start and kept in Home Assistant's storage. To replace it, an administrator runs **"Rotate Signing Key"** (`oidc_provider.rotate_signing_key`):

```yaml
action: oidc_provider.rotate_signing_key
data:
  keep_previous_key: true
```

- **`keep_previous_key: true`** (default): the old key stays published and keeps verifying the tokens it signed until the next rotation, so clients keep working until those tokens expire (within an hour). Use this for routine rotation.
- **`keep_previous_key: false`**: the old key is dropped at once and every outstanding access and ID token stops working. Use this if the key may have leaked.

Refresh tokens are not signed with this key, so clients holding one get new tokens without signing in again.

### OIDC Endpoints

Once installed, your Home Assistant instance exposes the following OIDC endpoints:

- **Discovery**: `https://your-ha-instance/oidc/.well-known/openid-configuration`
- **OAuth Authorization Server Metadata**: `https://your-ha-instance/.well-known/oauth-authorization-server/oidc`
- **Authorization**: `https://your-ha-instance/oidc/authorize`
- **Token**: `https://your-ha-instance/oidc/token`
- **UserInfo**: `https://your-ha-instance/oidc/userinfo`
- **JWKS**: `https://your-ha-instance/oidc/jwks` (the current signing key, and the previous one after a rotation that kept it)
- **Token Revocation**: `https://your-ha-instance/oidc/revoke` (RFC 7009). Revoking a refresh token ends its whole session; only the client it was issued to may revoke it. Access tokens cannot be revoked and are answered with `unsupported_token_type`; they expire within the hour
- **Dynamic Client Registration**: `https://your-ha-instance/oidc/register` (only while [dynamic client registration](#options) is on)

Both redirects back to the client, with `code` on approval or `error=access_denied` on denial, carry an `iss` parameter with the issuer (RFC 9207), and the discovery documents advertise `authorization_response_iss_parameter_supported`.

### Tokens

Access tokens are JWTs in the RFC 9068 profile. The header has `typ: at+jwt` and the `kid` of the signing key, and the claims include `iss`, `sub`, `aud`, `client_id`, `scope`, `jti`, `iat`, `exp` and `token_use: access`. `/oidc/userinfo` and the validator hass-mcp-server uses accept only access tokens, so an ID token is refused there.

`scope` holds the OpenID Connect scopes granted and, for a token bound to an integration that describes its access, the scopes of the access the person chose, whatever the application asked for. The token response's `scope` says the same, so the application learns what it was granted. Refreshed tokens keep the same scopes and the same `aud`.

A token bound to such an integration with none of its scopes grants nothing there, whether the person chose nothing or the token was issued before the integration described its access; the integration cannot tell the two apart. An integration that enforces its scopes refuses such a token at once and asks the application to authorize again, where the person chooses. A session that began before the integration described its access also ends at its next refresh. An application must name such an integration when it authorizes. Naming it only when redeeming the code is refused with `invalid_target` where the provider recognizes the address, which is best effort; a token issued that way carries none of the integration's scopes.

### Using with Claude Connectors

With [client metadata documents](#client-id-metadata-documents) on (the default), there is nothing to register:

1. In Claude, add a custom connector with your MCP server's URL and leave the client ID and secret empty
2. When prompted, log in with your Home Assistant credentials (TOTP/2FA supported)
3. Approve Claude on the consent screen

Claude Code works the same way, returning to a port on your computer that the consent screen points out.

To use a client you registered yourself instead, register one as described above and enter its client ID and secret in the connector settings.

## Security Considerations

- **HTTPS Required**: Your Home Assistant instance must be accessible via HTTPS with a valid certificate for OIDC to work with external services
- **Client Secrets**: Store client secrets securely and never commit them to version control
- **Refresh Tokens**: Persisted across restarts and valid for 30 days from sign-in. Every refresh replaces the refresh token with a new one. A replaced token keeps working for one minute after it was replaced, so a retried request, or one sent from another worker of the same client, does not end the session; presented after that, it revokes every token of that session, since only a leaked token is used that way (RFC 9700). Token responses are never cached (`Cache-Control: no-store`)
- **Access Tokens**: Valid for 1 hour by default
- **Client Actions**: Registering, updating, revoking and listing clients, and rotating the signing key, require a Home Assistant administrator. Automations, which run without a user, can still call them. A script runs as the user who started it, so it can call them only when an administrator starts it
- **Signing Key**: Kept until you [rotate it](#rotating-the-signing-key). Rotate with `keep_previous_key: false` if it may have leaked
- **Issuer Identification**: Authorization responses name the issuer (`iss`, RFC 9207) so clients that talk to several authorization servers can detect a mix-up
- **Authorization Codes**: Valid for 10 minutes and good for one redemption attempt. A code presented again after it issued tokens revokes every refresh token of that session
- **Dynamic Registration**: Off for new installs. While it is on, anyone who can reach your instance can register a client. Those clients always go through the consent screen, so a user has to approve them explicitly
- **Client Metadata Documents**: Anyone who can reach your instance can start a sign-in that makes Home Assistant fetch a URL. The fetch only reaches public addresses over HTTPS and is size, time and rate limited, as [described above](#client-id-metadata-documents). Sign-ins through these clients always go through the consent screen
- **Public Clients**: Clients without a secret, from metadata documents or registered with `token_endpoint_auth_method: none`, must use PKCE whatever the PKCE option says. Loopback redirect URIs (`http://localhost`, `http://127.0.0.1`, `http://[::1]`) match on any port, as RFC 8252 requires for native apps
- **Registration limits**: `/oidc/register` accepts at most 20 registrations per hour in total, at most 5 of them from one address, and at most 200 dynamically registered clients that have not had a token issued yet. Beyond that it answers `429` with `temporarily_unavailable` (and a `Retry-After` header for the hourly limits) and creates nothing. Clients a user has approved do not count toward the 200.
- **Limits Behind a Reverse Proxy**: The per-address limits on registrations, pending sign-ins and metadata document fetches count by the client address Home Assistant sees. Behind a reverse proxy, turn on [`use_x_forwarded_for`](https://www.home-assistant.io/integrations/http/#use_x_forwarded_for) and list the proxy in `trusted_proxies` so Home Assistant sees each client's own address. Otherwise every request appears to come from the proxy, and those limits apply to all clients together
- **Access Chosen at a Resource**: The scopes in a token are what the person chose on the consent screen, checked against what the integration describes and the person's ceiling when they approve. Scopes the application asks for never widen that. The integration that receives the token enforces the scopes; this provider only records and passes them on
- **Resource Binding**: A resource server that validates tokens with an expected audience (for example hass-mcp-server) only accepts tokens whose `aud` is that resource. Clients must send the `resource` parameter (RFC 8707) when authorizing; a token minted for a client without it is rejected there

## Supported Scopes

- `openid` - Required for OIDC
- `profile` - User profile information
- `email` - User email (uses HA user ID as fallback)
- `groups` - The user's Home Assistant groups

The discovery documents also list every scope an integration describes (see [Choosing what an application may do](#choosing-what-an-application-may-do)). Those are granted as the person chooses on the consent screen, not from the authorization request.

## Troubleshooting

### Client registration not appearing in logs

Check that you have the log level set appropriately in your `configuration.yaml`:

```yaml
logger:
  default: info
  logs:
    custom_components.oidc_provider: debug
```

### Authentication not working

1. Verify your Home Assistant instance is accessible via HTTPS
2. Check that the redirect URI matches exactly what the client is sending
3. Ensure the user has valid permissions in Home Assistant

### Tokens not being issued

Check the Home Assistant logs for detailed error messages. Common issues:
- Invalid client credentials
- Expired authorization codes (10 minute timeout)
- Mismatched redirect URIs

## Development

### Setup

```bash
poetry install
```

### Running Tests

```bash
poetry run pytest tests/ -v
```

### Running Tests with Coverage

```bash
poetry run pytest tests/ --cov=custom_components/oidc_provider --cov-report=term-missing
```

### Code Formatting

```bash
poetry run black custom_components/ tests/
```

### Linting

```bash
poetry run ruff check custom_components/ tests/
```

To auto-fix issues:

```bash
poetry run ruff check custom_components/ tests/ --fix
```

## License

MIT

## Contributing

Contributions are welcome! Please open an issue or pull request on GitHub.
