# Security

[Back to the README](../README.md)

What the provider protects against, what it leaves to you, and what to do if a key or secret may have leaked. The numbers behind the limits are in the [Reference](reference.md#limits).

## What the provider protects against

- **A code intercepted on its way back.** PKCE binds each code to the application that started the sign-in. It is required by default, and always for clients without a secret, and only the S256 method is accepted. A code is good for one redemption attempt within 10 minutes, only by the client it was issued to and with the same redirect URI. A code presented again within those 10 minutes, after it issued tokens, ends the session it started.
- **A stolen refresh token.** Every refresh replaces the refresh token. A replaced token presented more than a minute later, or one presented by another client, ends the whole session (RFC 9700). However often it is refreshed, a session ends 30 days after sign-in.
- **A token used at the wrong server.** An access token is bound to the server the client named with `resource` (RFC 8707), and a server that checks its audience, such as hass-mcp-server, refuses tokens meant for another.
- **A client mixing up providers.** Every redirect back to a client names the issuer (`iss`, RFC 9207), and the discovery documents say so.
- **Applications you did not vet.** Every sign-in through a client identified by a metadata document, or one that registered itself, stops on the consent screen. It shows the host that published the client's document, the site the person will be sent to, and a warning when that site is on their own computer. Client names and redirect URIs are checked so they cannot pass for something else: names are one line without control or formatting characters, and addresses are ASCII with international host names in punycode.
- **Metadata documents fetched against your network.** Home Assistant only fetches them over HTTPS from public addresses, never from private, loopback or other special-use ones, with size, time and rate limits. A failed fetch says nothing about why. See [Client ID Metadata Documents](reference.md#client-id-metadata-documents).
- **Self-registration abuse.** Dynamic client registration is off for new installs. When on, it is rate limited overall and per address, the number of unused clients it creates is capped, and abandoned ones are removed after a day.
- **Guessing a client secret.** Secrets are random, 64 characters long, and stored only as a salted PBKDF2-SHA256 hash. After 5 failed attempts for one client from one address, that client is refused from that address for a minute.
- **A flood of sign-ins.** The sign-ins waiting on the login page are capped overall and per address, and expire after 10 minutes.
- **Cached tokens.** Token responses, and the Clients page's answers, are sent with `Cache-Control: no-store`.
- **Management by anyone but administrators.** Only administrators see the Clients tab and can call the actions. Automations can call them too, since they run without a user.

## What it leaves to you

- **HTTPS.** The provider does not require HTTPS itself. Serve Home Assistant over HTTPS with a valid certificate wherever it is reached from outside your own network, since codes, tokens and client secrets travel in those requests.
- **Who may sign in.** Every active Home Assistant user can sign in to every client, administrators or not. The provider does not limit which people may use which application, so do that in the application, for example with the `groups` claim.
- **Removing a person.** Removing or deactivating a Home Assistant user does not end their sessions here. Their applications keep getting new tokens until the session ends, up to 30 days after sign-in; `/oidc/userinfo` refuses a removed person, but not a deactivated one. An integration that checks the person on every request, as hass-mcp-server does, refuses them anyway. To cut someone off at once, have them sign out on [Connected applications](consent.md#connected-applications) first, or [revoke](clients.md#revoking-a-client) the clients they used, which signs everyone out of those clients.
- **Client secrets.** Keep them out of version control and anywhere others can read. The secret is shown once; called from an automation without a response variable, `register_client` posts it in a notification that every Home Assistant user can read, so dismiss it once you have saved it.
- **Backups.** Home Assistant's `.storage` folder, which backups include, holds the private signing key and every refresh token as they are. Anyone with a backup can sign tokens and continue sessions. Keep backups private, and if one leaks, [rotate the signing key](#rotating-the-signing-key) without keeping the old one and revoke the clients.
- **What an application may do at an integration.** The scopes a person chooses on the consent screen are checked against what the integration describes and what the person may allow when they approve, and the application's request never widens them. The integration that receives the token decides what each scope allows and enforces it; this provider only records the choice and passes it on.
- **Tokens already handed out.** Access tokens cannot be revoked. After a sign-out, a revoked client or a change of access, the access tokens an application already holds keep working until they expire, within the hour.
- **Outbound requests.** With client metadata documents on, anyone who can reach Home Assistant can start a sign-in that makes it fetch an address on the internet, within the limits above. Turn the option off if Home Assistant should not make such requests.

## Behind a reverse proxy

- **The issuer.** The provider builds its addresses from the host the request names (see [The issuer and the addresses](reference.md#the-issuer-and-the-addresses)). Have the proxy pass the original `Host`, or set `X-Forwarded-Host`, and set `X-Forwarded-Proto` when it ends TLS. A proxy that rewrites `Host` to an internal IP address makes the provider fall back to the external URL under Settings > System > Network, so set that too.
- **The limits per address.** The limits on sign-ins, registrations and metadata document fetches, and the lockout after failed client authentication, count by the client address Home Assistant sees. Turn on [`use_x_forwarded_for`](https://www.home-assistant.io/integrations/http/#use_x_forwarded_for) and list the proxy in `trusted_proxies`, so Home Assistant sees each client's own address. Otherwise every request appears to come from the proxy, and those limits apply to all clients together.

## Rotating the signing key

Access and ID tokens are signed with an RSA key that is generated on first start and kept in Home Assistant's storage. It stays until you replace it. To replace it, an administrator runs **Rotate Signing Key** (`oidc_provider.rotate_signing_key`):

```yaml
action: oidc_provider.rotate_signing_key
data:
  keep_previous_key: true
```

- **`keep_previous_key: true`** (the default): the old key stays published and keeps verifying the tokens it signed until the next rotation, so clients keep working until those tokens expire, within an hour. Use this for routine rotation.
- **`keep_previous_key: false`**: the old key is dropped at once and every outstanding access and ID token stops working. Use this if the key may have leaked.

Refresh tokens are not signed with this key, so clients holding one get new tokens without signing in again. To end those sessions as well, revoke the clients.
