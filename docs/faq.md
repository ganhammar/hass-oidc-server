# FAQ

[Back to the README](../README.md)

## Getting started

### What do OAuth and OpenID Connect mean here?

They are the standards behind "Sign in with ..." buttons. OAuth lets an application act for you without ever seeing your password: you sign in where your account lives, and the application gets a token. OpenID Connect adds a standard way for the application to learn who signed in. This integration lets your Home Assistant be the place where people sign in.

### Do I need this to use Claude with Home Assistant?

Only with an MCP server that signs people in through it, such as [hass-mcp-server](https://github.com/ganhammar/hass-mcp-server). Home Assistant's built-in Model Context Protocol Server uses Home Assistant's own sign-in instead. This integration has nothing for Claude to use by itself; see [Claude and other MCP clients](connecting.md#claude-and-other-mcp-clients).

### How is this different from Home Assistant's built-in sign-in?

Home Assistant has its own OAuth sign-in for applications, the one its apps and its built-in MCP server use. An application is known there by its web address and can only return to that site or the addresses it publishes. There is no OpenID Connect: no ID tokens, no user info and no published signing keys. Its tokens are signed with a secret only Home Assistant knows and act with every right of the person who signed in.

This provider adds what that sign-in does not have:

- OpenID Connect, so applications such as Grafana can use it, and tokens that other integrations can verify with the published keys;
- clients you register with a client secret and any redirect URI;
- a consent screen naming the application, and, for an integration that describes its access, a choice of what the application may do there;
- [Connected applications](consent.md#connected-applications), where each person changes what an application may do or signs it out.

The two work side by side. This integration does not change how Home Assistant's own sign-in works.

### Why not run Authentik or Keycloak instead?

A separate identity provider is another service to run and keep up to date, with accounts of its own, and Home Assistant would itself need a community integration to sign people in through it. If you already run one for many services, it is likely the better hub. This provider is for using the Home Assistant accounts you already have, with nothing else to run.

### Which applications can use it?

Any application that supports OAuth 2 or OpenID Connect with the authorization code flow: MCP clients such as Claude and Claude Code, and self-hosted applications with a "Generic OAuth" or "OpenID Connect" login, such as Grafana. Some applications need an email address for every person, which this provider only sends when the person's Home Assistant name is an email address; see [Does the application get my email address?](#does-the-application-get-my-email-address)

### Does it work with Home Assistant Cloud?

Yes. Any HTTPS address that reaches Home Assistant works, Home Assistant Cloud's remote address included, as long as the application uses the same address for everything; see [One address everywhere](connecting.md#before-you-start).

### Which Home Assistant versions are supported?

Each change is tested against Home Assistant releases from 2025.4 to 2026.10.

## Using it

### Who can sign in?

Every active Home Assistant user, administrators or not. The provider does not limit which people may use which application. To keep an application to some people, use the `groups` claim in the application. See [Security](security.md#what-it-leaves-to-you).

### Does it add accounts or a new way to log in to Home Assistant?

No. People sign in with their existing Home Assistant accounts on Home Assistant's own login page, two-factor authentication included. The provider only hands the result to the application.

### Will I be asked to approve every time?

That depends on the client. A client an administrator registered skips the consent screen unless they turned on **Require consent**. Clients identified by a metadata document, such as Claude, and clients that registered themselves show it on every sign-in. A sign-in for an integration that describes its access always shows it, with your last choice preselected. Once signed in, an application renews its tokens without asking.

### Why does an application ask me to sign in again after a month?

A sign-in lasts 30 days, however often the application renews its tokens. After that it has to send you through the login page again. It also has to when you sign it out, when an administrator revokes it, and in the other cases [Troubleshooting](troubleshooting.md#an-application-has-to-sign-in-again) lists.

### Can I limit what an application may do?

Yes, when the integration it connects to describes its access, as an MCP server can: the consent screen asks what the application may do there, and **Change access** on [Connected applications](consent.md#connected-applications) changes it later. An application signed in for anything else gets no such choice: what it may do is up to the integration or application that receives its tokens.

### Does the application get my email address?

Only when your name in Home Assistant is an email address, since Home Assistant keeps no email address for you otherwise. It is then marked as not verified. The application gets your Home Assistant user ID as `sub` in any case, and your name and groups when it asks for them. See [Scopes and claims](reference.md#scopes-and-claims).

### Can a mobile app with its own address scheme sign in?

Not with a scheme such as `myapp://callback`: redirect URIs must be `https`, or `http` on `localhost`, `127.0.0.1` or `[::1]`. An app that can return through an `https` address it owns can use that instead.

### What happens to Claude when I turn off client metadata documents?

Its next token refresh is refused, so it stops working within the hour, and it cannot sign in again until you turn the option back on, register a client for it, or turn on dynamic client registration. See [Allow client metadata documents](configuration.md#allow-client-metadata-documents).

### Where does my data go?

Nowhere: clients, sessions and keys stay in Home Assistant's storage. The only requests the provider makes are fetches of client metadata documents, to the address a client names as its client ID. What an application does with what it learns about you is up to the application.
