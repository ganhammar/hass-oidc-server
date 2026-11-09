# Home Assistant OIDC Server

A Home Assistant custom component that turns your Home Assistant instance into a fully functional OpenID Connect (OIDC) server, allowing external applications like Claude Connectors to authenticate against your Home Assistant users.

## Features

- **Standards-compliant OIDC server** with discovery endpoint
- **Integrates with Home Assistant's native authentication** including TOTP/2FA
- **JWT-based access tokens** with RSA signing
- **Support for authorization code flow** with refresh tokens
- **Easy client registration** via Home Assistant services
- **Consent screen** for dynamically registered clients, styled like the Home Assistant login
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
1. Choose whether to **Allow dynamic client registration** (see below), then click **Submit**

### Options

Change these later under **Settings** → **Devices & Services** → **OIDC Provider** → **Configure**. Changes apply immediately, without a restart.

- **Require PKCE** (default: on): authorization requests must carry an S256 PKCE code challenge, as OAuth 2.1 requires.
- **Allow dynamic client registration** (default: off for new installs): lets clients register themselves at `/oidc/register` (RFC 7591). MCP clients such as Claude use this to connect without a client you created for them. Every sign-in through a dynamically registered client stops on the [consent screen](#consent-screen).

While dynamic client registration is off, `/oidc/register` answers `403` with `access_denied`, and the discovery documents leave out `registration_endpoint` so clients do not try to use it. Register clients yourself with the `register_client` action instead. Clients that registered while it was on keep working until you revoke them.

Installs set up before version 1.7.0 keep dynamic client registration on, since it was always on before, so clients that register themselves keep connecting after the upgrade. Turn it off in the options if you do not need it.

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
5. Check the Home Assistant logs for the generated **Client ID** and **Client Secret**

Example action call:

```yaml
action: oidc_provider.register_client
data:
  client_name: "Claude Connector"
  redirect_uris: "https://claude.ai/callback,https://app.claude.com/callback,https://claude.ai/api/mcp/auth_callback"
```

The logs will display:

```
Registered OIDC client: Claude Connector
Client ID: client_xxxxxxxxxxxxx
Client Secret: yyyyyyyyyyyyyyyyyyyyyyyy
Redirect URIs: ['https://claude.ai/callback', 'https://app.claude.com/callback']
```

**Important**: Save these credentials securely. The client secret cannot be retrieved later.

### Consent Screen

Clients registered through the dynamic registration endpoint (`/oidc/register`, when [enabled](#options)) are not vetted by you, so every authorization for them stops on a consent screen inside Home Assistant. It names the client, the site the user will be sent to, and the information the client will receive, with Approve and Deny buttons. Denying sends the client an `access_denied` error.

Clients you register with the `register_client` action skip the screen unless you set **Require consent**. Clients registered before version 1.6.0 have no consent setting and prompt until you turn it off, because there is no way to tell which of them came from dynamic registration. Use the `update_client` action with `consent_required: false` for the ones you registered yourself.

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

### OIDC Endpoints

Once installed, your Home Assistant instance exposes the following OIDC endpoints:

- **Discovery**: `https://your-ha-instance/oidc/.well-known/openid-configuration`
- **OAuth Authorization Server Metadata**: `https://your-ha-instance/.well-known/oauth-authorization-server/oidc`
- **Authorization**: `https://your-ha-instance/oidc/authorize`
- **Token**: `https://your-ha-instance/oidc/token`
- **UserInfo**: `https://your-ha-instance/oidc/userinfo`
- **JWKS**: `https://your-ha-instance/oidc/jwks`
- **Dynamic Client Registration**: `https://your-ha-instance/oidc/register` (only while [dynamic client registration](#options) is on)

### Using with Claude Connectors

1. Register a client as described above
2. In Claude, configure a custom connector with:
   - **OIDC Discovery URL**: `https://your-ha-instance/oidc/.well-known/openid-configuration`
   - **Client ID**: The generated client ID
   - **Client Secret**: The generated client secret
3. When prompted, log in with your Home Assistant credentials (TOTP/2FA supported)

With [dynamic client registration](#options) on, Claude can register itself instead, so you can skip step 1 and leave the client ID and secret empty. You then approve it on the consent screen when you sign in.

## Security Considerations

- **HTTPS Required**: Your Home Assistant instance must be accessible via HTTPS with a valid certificate for OIDC to work with external services
- **Client Secrets**: Store client secrets securely and never commit them to version control
- **Refresh Tokens**: Persisted across restarts, valid for 30 days by default
- **Access Tokens**: Valid for 1 hour by default
- **Authorization Codes**: Valid for 10 minutes and good for one redemption attempt. A code presented again after it issued tokens revokes the refresh token it issued
- **Dynamic Registration**: Off for new installs. While it is on, anyone who can reach your instance can register a client. Those clients always go through the consent screen, so a user has to approve them explicitly
- **Resource Binding**: A resource server that validates tokens with an expected audience (for example hass-mcp-server) only accepts tokens whose `aud` is that resource. Clients must send the `resource` parameter (RFC 8707) when authorizing; a token minted for a client without it is rejected there

## Supported Scopes

- `openid` - Required for OIDC
- `profile` - User profile information
- `email` - User email (uses HA user ID as fallback)

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
