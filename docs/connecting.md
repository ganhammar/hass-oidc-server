# Connecting an application

[Back to the README](../README.md)

Every application signs in the same way. It sends the person to Home Assistant, where they sign in on Home Assistant's own login page, two-factor authentication included, and approve on a consent screen if one is shown. Home Assistant then sends them back to the application with a one-time code, which the application exchanges for tokens. This provider does not create accounts or add login methods: people sign in with the Home Assistant accounts they already have.

What differs between applications is how Home Assistant knows them. Each one is a *client*, and there are three kinds:

| The client is | For | What you do |
|---|---|---|
| Identified by a metadata document | Claude, Claude Code and other MCP clients that support it | Nothing, as long as **Allow client metadata documents** is on |
| Registered by you | Any application that takes a client ID and a client secret, such as Grafana | Register it on the [Clients page](clients.md) |
| Registered by itself | MCP clients that support neither of the above | Turn on **Allow dynamic client registration** |

## Before you start

- **An address that both the application and your browser reach.** The browser goes there to sign in, and the application to fetch its tokens. Claude connects from Anthropic's servers, so for Claude it has to be an HTTPS address that works from the internet.
- **One address everywhere.** Tokens name the address they were issued at, the *issuer*. An application or integration that checks it refuses a token issued at another address, so give the application the same address you sign in at. See [Reverse proxies and the issuer](troubleshooting.md#reverse-proxies-and-the-issuer).
- **The addresses an application asks for.** The issuer is `https://your-home-assistant/oidc`, and an application that discovers the rest reads it from `https://your-home-assistant/oidc/.well-known/openid-configuration`. Every endpoint is listed in the [Reference](reference.md#endpoints).

## Claude and other MCP clients

This provider handles the sign-in. It gives Claude nothing to use by itself: you also need an MCP server in Home Assistant that names this provider as the place to sign in, such as [hass-mcp-server](https://github.com/ganhammar/hass-mcp-server). You give Claude the MCP server's address, never this provider's, and the MCP server points Claude here.

Claude identifies itself with a Client ID Metadata Document: its client ID is an `https` address where Anthropic publishes Claude's name and the addresses it may return to. Home Assistant fetches that document when a sign-in starts, so there is nothing to register.

### Claude on the web, Desktop and mobile

1. Set up the MCP server as its documentation describes.
2. In Claude, open Customize > Connectors, select Add, then Add custom connector. Enter a name and the MCP server's address, such as `https://your-home-assistant/api/mcp_http` for hass-mcp-server, and click Continue.
3. Under OAuth client, keep **Use Claude's published identity**. Click Add, then Connect.
4. Claude sends you to Home Assistant. Sign in, check the consent screen, and approve. If the MCP server describes its access, you first choose what Claude may do; see [Choosing what an application may do](consent.md#choosing-what-an-application-may-do).

The consent screen shows the host that publishes the document, such as `claude.ai`, next to Claude's name. If your OIDC Provider was set up before version 1.8.0, check that **Allow client metadata documents** is on in its options; see [Upgrading from an older release](configuration.md#upgrading-from-an-older-release).

### Claude Code

Add the MCP server's address, then sign in from Claude Code:

```bash
claude mcp add --transport http home-assistant https://your-home-assistant/api/mcp_http
```

Run `/mcp` in Claude Code and follow the steps in your browser. Claude Code uses its own metadata document and returns to a port on your computer, which the consent screen points out: "This sends you back to an application on your own computer. Only approve if you started this sign-in yourself."

### Other MCP clients

A client that supports Client ID Metadata Documents works like Claude. One that registers itself instead needs [Allow dynamic client registration](configuration.md#allow-dynamic-client-registration) turned on. Any client that takes a client ID and secret can also use a client you register, as below.

### Using a client you register with Claude

If you would rather not use Claude's published identity, register a client for Claude on the [Clients page](clients.md#registering-a-client) with the redirect URI `https://claude.ai/api/mcp/auth_callback`. When you add the connector, choose **Use your own OAuth client** and enter the client ID and the client secret. A client you register here always has a secret, so Claude needs both.

For Claude Code, register `http://localhost/callback`. A redirect URI on `localhost`, `127.0.0.1` or `[::1]` matches on any port, so Claude Code can pick its own. Then add the server with your client:

```bash
claude mcp add --transport http --client-id YOUR_CLIENT_ID --client-secret home-assistant https://your-home-assistant/api/mcp_http
```

Claude Code asks for the secret.

## An OpenID Connect application

Applications such as Grafana can let people sign in with Home Assistant through OpenID Connect, often under a name such as "Generic OAuth" or "OpenID Connect".

1. **Find the application's redirect URI.** Its documentation names it, often as the callback URL. It has to be `https`, or `http` on `localhost`, `127.0.0.1` or `[::1]`.
2. **Register a client.** Open the [Clients page](clients.md) at `https://your-home-assistant/oidc_login?tab=clients`, select **Register a client**, enter a name and the redirect URI, and select **Register**. Copy the client ID and the client secret. The secret is shown only this once.
3. **Fill in the application's settings.** Applications name the fields differently:

| The application asks for | Enter |
|---|---|
| Issuer, issuer URL or provider URL | `https://your-home-assistant/oidc` |
| Discovery URL or well-known configuration | `https://your-home-assistant/oidc/.well-known/openid-configuration` |
| Authorization URL | `https://your-home-assistant/oidc/authorize` |
| Token URL | `https://your-home-assistant/oidc/token` |
| User info URL | `https://your-home-assistant/oidc/userinfo` |
| Signing keys or JWKS URL | `https://your-home-assistant/oidc/jwks` |
| Client ID and client secret | The ones from step 2 |
| Scopes | `openid profile email groups`, or fewer. `openid` is required |
| PKCE | On, with the S256 method. It is required unless you turn off [Require PKCE](configuration.md#require-pkce) |
| Client authentication | Either: in the `Authorization` header (basic) or in the request body (post) |

The application learns who signed in from the ID token or from the user info endpoint: the person's Home Assistant user ID as `sub`, their name, their groups (`owner`, `admin`, `user` or `read-only`) and, only when their name in Home Assistant is an email address, that address. [Scopes and claims](reference.md#scopes-and-claims) has the details.

Every Home Assistant user can sign in to every client. To limit an application to some people, or give them different roles, use the `groups` claim in the application, as the Grafana example below does for roles.

### Worked example: Grafana

Grafana's Generic OAuth connects to this provider with its endpoints named one by one.

1. Register a client named Grafana with the redirect URI `https://grafana.example.com/login/generic_oauth`, using Grafana's own address.
2. Add this to Grafana's configuration, with your client ID and secret and your Home Assistant address:

```ini
[auth.generic_oauth]
enabled = true
name = Home Assistant
client_id = YOUR_CLIENT_ID
client_secret = YOUR_CLIENT_SECRET
scopes = openid profile email groups
auth_url = https://your-home-assistant/oidc/authorize
token_url = https://your-home-assistant/oidc/token
api_url = https://your-home-assistant/oidc/userinfo
use_pkce = true
role_attribute_path = contains(groups[*], 'admin') && 'Admin' || 'Viewer'
```

3. Restart Grafana. Its login page then offers to sign in with Home Assistant.

The same settings can be made in Grafana under Administration > Authentication > Generic OAuth. `role_attribute_path` gives Home Assistant administrators Grafana's Admin role and everyone else Viewer.

Grafana's documentation says it needs an email address to sign someone in, and this provider only sends one when the person's name in Home Assistant is an email address. So this example works for the people whose Home Assistant name is their email address.

## Clients that register themselves

Some MCP clients register a client of their own at `/oidc/register` (RFC 7591, Dynamic Client Registration) before they sign in. Turn on [Allow dynamic client registration](configuration.md#allow-dynamic-client-registration) for them. Anyone who can reach Home Assistant can then register a client, so every sign-in through such a client stops on the consent screen, and the endpoint is limited and cleaned up as the configuration page describes.

Claude registers itself only when Client ID Metadata Documents are off, and then registers a new client on every fresh connection. With metadata documents on, registration can stay off.
