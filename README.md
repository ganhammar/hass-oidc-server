# OIDC Provider for Home Assistant

Let other applications sign people in with their Home Assistant account. This custom integration makes Home Assistant an OAuth 2.1 and OpenID Connect provider, the kind of service behind a "Sign in with Google" button: an application sends you to Home Assistant's own login page, and gets back who you are and, when it needs one, a token to act for you. It is how Claude signs in to an MCP server running in Home Assistant, and it works for self-hosted applications such as Grafana too.

What you can do with it:

- Connect Claude, Claude Code or another MCP client to an MCP server in Home Assistant, such as [hass-mcp-server](https://github.com/ganhammar/hass-mcp-server), without registering anything.
- Sign in to Grafana, or another application that supports OpenID Connect, with your Home Assistant account.
- Choose what an application may do in Home Assistant when it asks, such as look only, if the integration it connects to describes its access.
- See every application signed in with your account, change what it may do, and sign it out.

## Why this one

- **The accounts you already have, and nothing else to run.** People sign in on Home Assistant's own login page, two-factor authentication included. A separate identity provider such as Authentik or Keycloak is another service to run, with accounts of its own. Other OpenID Connect integrations for Home Assistant, such as hass-oidc-auth, work the other way round: they let you sign in to Home Assistant with an outside provider.
- **Standard OpenID Connect.** Home Assistant's built-in sign-in for applications is OAuth without OpenID Connect: no ID tokens, no user info, no published signing keys, and tokens that only Home Assistant can check, carrying every right of the user. This provider adds all of that, so ordinary applications can use it and other integrations can verify its tokens. See [how the two differ](https://github.com/ganhammar/hass-oidc-server/blob/main/docs/faq.md#how-is-this-different-from-home-assistants-built-in-sign-in).
- **Each person decides.** A consent screen names the application, where it sends you and what it will see. For an integration that describes its access, each person chooses what the application may do there, and can change it later.
- **Made for MCP clients.** Client ID Metadata Documents, PKCE, tokens bound to the server they are for, and rotating refresh tokens, as the MCP authorization specification asks.

## Quick start

**You need:** Home Assistant with HACS, an administrator account, and an HTTPS address for Home Assistant that the application can reach. For Claude, that address has to work from the internet.

1. **Install.** In HACS, search for "OIDC Provider", download it, and restart Home Assistant. Without HACS, see [Configuration](https://github.com/ganhammar/hass-oidc-server/blob/main/docs/configuration.md).
2. **Add the integration.** Under Settings > Devices & services > Add integration, choose **OIDC Provider** and submit the form as it is.
3. **Connect an application.**
   - **Claude:** set up an MCP server that signs in through this provider, such as [hass-mcp-server](https://github.com/ganhammar/hass-mcp-server), and add its address, such as `https://your-home-assistant/api/mcp_http`, as a custom connector in Claude. Claude sends you to Home Assistant to sign in and approve.
   - **An OpenID Connect application:** open `https://your-home-assistant/oidc_login?tab=clients`, register a client with the application's redirect URI, and give the application the client ID, the client secret and the issuer `https://your-home-assistant/oidc`.

[Connecting an application](https://github.com/ganhammar/hass-oidc-server/blob/main/docs/connecting.md) walks through both, with a worked example for Grafana.

## What it can do

| Area | What it offers |
|---|---|
| Sign-in | The authorization code flow with PKCE, on Home Assistant's own login page |
| Clients | Clients you register with a secret, MCP clients identified by a metadata document, and, if you allow it, clients that register themselves |
| Tokens | Signed access tokens bound to the server they are for, ID tokens, rotating refresh tokens, revocation |
| OpenID Connect | Discovery, user info, published signing keys, and the `profile`, `email` and `groups` scopes |
| Consent | A consent screen for clients you did not register, and a choice of access for integrations that describe theirs |
| Management | A Clients page and actions for administrators, and Connected applications for everyone |

## Staying in control

- **A consent screen** stops every sign-in through a client you did not register yourself, and you can require it for the ones you did.
- **Access per application.** An integration that describes its access, such as an MCP server, has each person choose what an application may do there.
- **Connected applications** shows each person the applications signed in with their account, to change what they may do or sign them out.
- **Clients that register themselves** are off for new installs, and limited and cleaned up when on.
- **Revoke a client** to end all its sessions at once, and **rotate the signing key** if it may have leaked.

See [The consent screen and Connected applications](https://github.com/ganhammar/hass-oidc-server/blob/main/docs/consent.md) and [Security](https://github.com/ganhammar/hass-oidc-server/blob/main/docs/security.md).

## Documentation

- [Connecting an application](https://github.com/ganhammar/hass-oidc-server/blob/main/docs/connecting.md): Claude and other MCP clients, a client you register, an OpenID Connect application such as Grafana
- [Managing clients](https://github.com/ganhammar/hass-oidc-server/blob/main/docs/clients.md): the Clients page and the actions
- [The consent screen and Connected applications](https://github.com/ganhammar/hass-oidc-server/blob/main/docs/consent.md): approving, choosing what an application may do, changing it, signing out
- [Configuration](https://github.com/ganhammar/hass-oidc-server/blob/main/docs/configuration.md): every option, and upgrading from older releases
- [Security](https://github.com/ganhammar/hass-oidc-server/blob/main/docs/security.md): what the provider protects against, what it leaves to you, rotating the signing key
- [Reference](https://github.com/ganhammar/hass-oidc-server/blob/main/docs/reference.md): endpoints, discovery, tokens and lifetimes, scopes and claims, limits, what is stored where
- [FAQ](https://github.com/ganhammar/hass-oidc-server/blob/main/docs/faq.md) and [Troubleshooting](https://github.com/ganhammar/hass-oidc-server/blob/main/docs/troubleshooting.md)
- [Describing a resource to the OIDC Provider](https://github.com/ganhammar/hass-oidc-server/blob/main/docs/resource-descriptions.md): for authors of integrations that accept this provider's tokens
- [Working on this integration](https://github.com/ganhammar/hass-oidc-server/blob/main/docs/development.md): tests, formatting and linting

**Updating and removing.** HACS shows updates as they are released. To remove the integration, delete it under Settings > Devices & services, remove it in HACS and restart. Its clients, sessions and signing key stay in Home Assistant's `.storage` folder as the `oidc_provider.*` files until you delete them.

**Help.** Questions and bugs go to the [issue tracker](https://github.com/ganhammar/hass-oidc-server/issues).

## License

[MIT](https://github.com/ganhammar/hass-oidc-server/blob/main/LICENSE)
