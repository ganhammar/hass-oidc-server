# Reference

[Back to the README](../README.md)

The technical details: every endpoint, the discovery documents, what tokens hold and how long they last, the scopes and claims, the limits, and what is stored where. For setting things up, start with [Connecting an application](connecting.md).

## The issuer and the addresses

The provider's issuer is your Home Assistant address followed by `/oidc`, such as `https://ha.example.com/oidc`. Every endpoint below hangs off the same address. It is taken from each request, so it follows the address a client used:

1. The host in `X-Forwarded-Host`, or else in `Host`, when it is a host name, with the scheme from `X-Forwarded-Proto` or else the request's own. A header that holds anything but a host, such as a path, is ignored.
2. When that host is an IP address, or no header names a host, the external URL set under Settings > System > Network, if there is one.
3. Otherwise the IP address from the header. When a header was sent but holds no host, Home Assistant's internal URL, and when no host header was sent at all, the address the request arrived at.

The issuer appears in the discovery documents, as `iss` in every token, and as the `iss` parameter on every redirect back to a client (RFC 9207), so a client that talks to several providers can tell them apart. An integration that takes the issuer it expects from `get_issuer_from_request`, as hass-mcp-server does, works it out the same way from the request it receives, so a token is accepted only at the address it was issued at.

## Endpoints

| Path | Methods | What it is |
|---|---|---|
| `/oidc/.well-known/openid-configuration` | GET | OpenID Connect discovery document |
| `/.well-known/oauth-authorization-server/oidc` | GET | OAuth authorization server metadata (RFC 8414) |
| `/oidc/.well-known/oauth-authorization-server` | GET | The same metadata, for clients that append the well-known path to the issuer |
| `/oidc/authorize` | GET | Starts a sign-in and sends the person to the login page |
| `/oidc/token` | POST | Exchanges a code, or a refresh token, for tokens |
| `/oidc/userinfo` | GET | The claims about the person an access token is for |
| `/oidc/jwks` | GET | The public keys tokens are signed with |
| `/oidc/revoke` | POST | Ends the session of a refresh token (RFC 7009) |
| `/oidc/register` | POST | Dynamic client registration (RFC 7591), while it is turned on |

The login page and the endpoints behind it need a Home Assistant sign-in, and are there for the page rather than for applications:

| Path | Methods | What it is |
|---|---|---|
| `/oidc_login` | GET | The login page: the consent screen, Connected applications and the Clients tab |
| `/oidc/continue` | GET, POST | Describes a sign-in waiting for consent, and records the decision |
| `/api/oidc_provider/sessions` | GET | The signed-in person's sessions |
| `/oidc/sessions` | GET | The same |
| `/api/oidc_provider/sessions/{session_id}` | DELETE | Signs one of them out |
| `/oidc/sessions/{session_id}` | DELETE | The same |
| `/api/oidc_provider/sessions/{session_id}/access` | GET, PUT | Describes and changes what one of them may do |
| `/api/oidc_provider/strings` | GET | The page's text in the person's language |
| `/api/oidc_provider/clients` | GET, POST, PATCH, DELETE | Lists, registers, edits and revokes clients, for administrators |

### Authorization

`/oidc/authorize` takes the usual parameters of the authorization code flow:

- `client_id`, `redirect_uri` and `response_type=code` are required.
- `scope` must include `openid`. Of the rest, only `profile`, `email` and `groups` are granted from the request; other values are ignored, and the scopes of an integration that describes its access come from the person's choice.
- `state` and `nonce` are passed back, `state` on the redirect and `nonce` in the ID token.
- `code_challenge` with `code_challenge_method=S256`, required while [Require PKCE](configuration.md#require-pkce) is on and always for public clients. The method defaults to S256.
- `resource` names the server the token is for (RFC 8707) and becomes the access token's `aud`. It must be an absolute URI without a fragment; anything else is ignored.

A request that fails these checks is answered with a plain-text `400` page in the browser, or `429` when too many sign-ins are in progress, not with a redirect to the client; [Troubleshooting](troubleshooting.md#the-browser-shows-a-short-error-instead-of-the-login-page) lists the messages. `prompt`, `max_age` and request objects are not supported.

After the person approves, the redirect carries `code`, `state` and `iss`. After they deny, it carries `error=access_denied`, `state` and `iss`.

### Token

`/oidc/token` takes a form-encoded body.

- **Client authentication.** A client with a secret sends it with HTTP Basic authentication or as `client_id` and `client_secret` in the body. A public client sends only `client_id`, and is refused if it sends a secret. When both are given, the body's `client_id` must match the one in the header.
- **`grant_type=authorization_code`** with `code`, the same `redirect_uri` as the sign-in, and `code_verifier` when the sign-in had a code challenge. `resource` is honoured here only when the sign-in named none, and never for an integration that describes its access, which is refused with `invalid_target`.
- **`grant_type=refresh_token`** with `refresh_token`.

The response holds `access_token`, `token_type` (`Bearer`), `expires_in` (3600), `refresh_token`, `scope` and `id_token`, and is sent with `Cache-Control: no-store`. Errors are `invalid_client` (`401`, or `429` while the client is locked out, see [Limits](#limits)), `invalid_grant`, `invalid_target` and `unsupported_grant_type`.

### User info

`/oidc/userinfo` takes an access token as `Authorization: Bearer ...` and answers with `sub` and the claims its scopes allow, as in [Scopes and claims](#scopes-and-claims). An ID token is refused. Errors are `401` with `unauthorized` (no bearer token), `invalid_token` or `token_expired`, and `404` with `user_not_found` when the person no longer exists.

### Revocation

`/oidc/revoke` authenticates the client as the token endpoint does and takes `token`. A refresh token ends its whole session. Only the client it was issued to may revoke it: when another client presents it, the session is ended anyway, since the token has leaked, and the answer is `unauthorized_client`. An access token cannot be revoked and is answered with `unsupported_token_type`; it expires within the hour. An unknown token is answered with `200`, as RFC 7009 asks.

### Registration

`/oidc/register` takes a JSON body with `redirect_uris` (required), and optionally `client_name` (default "Dynamically Registered Client"), `grant_types` (`authorization_code` and `refresh_token`), `response_types` (`code`) and `token_endpoint_auth_method` (`none`, `client_secret_post` or `client_secret_basic`). It answers `201` with the client's ID, its secret unless it asked for `none`, and its metadata. The redirect URIs follow the [same rules](clients.md#registering-a-client) as for a client you register. A request that breaks the rules is answered with `400` and `invalid_redirect_uri` or `invalid_client_metadata`, or `invalid_request` when its body is not JSON. See [Allow dynamic client registration](configuration.md#allow-dynamic-client-registration) for when it is open and how it is limited.

## Discovery documents

The OpenID Connect discovery document and the two copies of the authorization server metadata hold:

| Field | In | Value |
|---|---|---|
| `issuer` | All | The issuer, see [above](#the-issuer-and-the-addresses) |
| `authorization_endpoint` | All | `/oidc/authorize` |
| `token_endpoint` | All | `/oidc/token` |
| `userinfo_endpoint` | OpenID Connect discovery | `/oidc/userinfo` |
| `jwks_uri` | All | `/oidc/jwks` |
| `registration_endpoint` | All, while dynamic client registration is on | `/oidc/register` |
| `revocation_endpoint` | All | `/oidc/revoke` |
| `revocation_endpoint_auth_methods_supported` | All | The same as `token_endpoint_auth_methods_supported` |
| `response_types_supported` | All | `code` |
| `grant_types_supported` | Authorization server metadata | `authorization_code`, `refresh_token` |
| `subject_types_supported` | OpenID Connect discovery | `public` |
| `id_token_signing_alg_values_supported` | OpenID Connect discovery | `RS256` |
| `scopes_supported` | All | `openid`, `profile`, `email`, `groups`, and every scope an integration describes |
| `token_endpoint_auth_methods_supported` | All | `client_secret_post`, `client_secret_basic`, and `none` while client metadata documents or dynamic client registration are on |
| `client_id_metadata_document_supported` | All, while client metadata documents are on | `true` |
| `claims_supported` | OpenID Connect discovery | `sub`, `name`, `email`, `email_verified`, `groups`, `iss`, `aud`, `exp`, `iat`, `auth_time`, `nonce`, `at_hash` |
| `code_challenge_methods_supported` | All | `S256` |
| `authorization_response_iss_parameter_supported` | All | `true` |

Every address in them is a full URL on the issuer's address.

## Scopes and claims

| Scope | What it adds |
|---|---|
| `openid` | Required. The person's Home Assistant user ID as `sub`, and an ID token |
| `profile` | `name`: the person's name in Home Assistant |
| `email` | `email` and `email_verified: false`, only when the person's name in Home Assistant looks like an email address. Home Assistant has no email address of its own for a person |
| `groups` | `groups`: `owner` for the owner, and `admin`, `user` or `read-only` for the Home Assistant group they are in |

The discovery documents also list every scope an integration describes; see [Choosing what an application may do](consent.md#choosing-what-an-application-may-do). Those are granted as the person chooses on the consent screen, never from the authorization request.

## Tokens

Access tokens and ID tokens are JWTs signed with RS256 and the current [signing key](#signing-keys), named by `kid` in their header. Refresh tokens are random strings, not JWTs, and are not signed.

### Access tokens

Access tokens follow the JWT profile of RFC 9068: the header has `typ: at+jwt`. Their claims:

- `iss`, `sub`, `iat`, `exp` and `jti`;
- `aud`: the `resource` the sign-in named, or else the client ID;
- `azp`: the client ID, when `aud` is a resource;
- `client_id` and `scope`;
- `token_use: access`;
- `groups`, when the `groups` scope was granted.

`/oidc/userinfo` and the validator other integrations use (`custom_components.oidc_provider.token_validator.validate_access_token`) accept only access tokens, so an ID token is refused there. The validator checks the signature, the expiry and the issuer, and that `aud` is the audience the integration expects, or, when it names none, the ID of a registered client.

### ID tokens

ID tokens have `iss`, `sub`, `aud` (the client ID), `iat`, `exp`, `at_hash` and `token_use: id`, the `nonce` when the sign-in sent one, and `auth_time`. `auth_time` is when the person passed the consent step, which can be later than when they last typed their password. The scopes add `name`, `email`, `email_verified` and `groups` as above. A refresh issues a new ID token with the same `nonce` and `auth_time`.

### Lifetimes

| Token | Lifetime |
|---|---|
| Access token | 1 hour |
| ID token | 1 hour |
| Refresh token | 30 days from sign-in |
| Authorization code | 10 minutes |
| Replaced refresh token | 1 minute |

A sign-in waiting on the login page is kept for 10 minutes as well. The lifetimes are fixed.

### Refresh tokens and sessions

A *session* is one sign-in by one person through one client, and its refresh token is what keeps it going. Sessions are kept across restarts.

- Every refresh replaces the refresh token with a new one. The session still ends 30 days after sign-in, however often it is refreshed; the application then has to sign the person in again.
- A replaced refresh token keeps working for 1 minute, so a retried request, or one from another worker of the same client, does not end the session. Presented after that, or by another client, it ends the whole session, since only a leaked token is used that way (RFC 9700).
- An authorization code is good for one attempt. Presented again within its 10 minutes after it issued tokens, it ends the session it started.
- A session also ends when the person signs it out on [Connected applications](consent.md#connected-applications), when an administrator [revokes its client](clients.md#revoking-a-client), and when the client revokes its refresh token at `/oidc/revoke`.

When a session ends, its refresh token stops working at once. Access tokens it already handed out keep working until they expire, within the hour.

## Access at a resource

A client names the server a token is for with the `resource` parameter (RFC 8707), and the access token's `aud` is that resource. Refreshed tokens keep the same `aud`. A server that checks tokens with an expected audience, such as hass-mcp-server, accepts only tokens whose `aud` is that server, so a client that leaves out `resource` gets tokens it refuses.

When the resource belongs to an integration that [describes its access](consent.md#choosing-what-an-application-may-do), the token's `scope` holds the OpenID Connect scopes granted and the scopes of the access the person chose, whatever the application asked for. The token response's `scope` says the same, so the application learns what it was granted. Refreshed tokens keep the same scopes until the person changes the application's access on Connected applications; from then on they carry the new ones. The integration decides what each scope allows; this provider only records and passes them on.

A token bound to such an integration with none of its scopes grants nothing there, whether the person chose nothing or the token was issued before the integration described its access; the integration cannot tell the two apart. An integration that enforces its scopes refuses such a token at once, and depending on how it refuses, the application refreshes first or authorizes again straight away, where the person chooses.

An application must name such an integration when it authorizes. Naming it only when redeeming the code is refused with `invalid_target`, since the person was not asked.

### Sign-ins from before an integration described its access

A session that began before the integration described its access carries no choice. At its next refresh it gets the access the integration names for such sessions, held at what the person may allow, and keeps it from then on as if the person had chosen it, so Connected applications shows it too. It is not remembered as the person's choice for their next sign-in. Until that refresh, the access token the session already holds, valid for up to an hour, carries none of the integration's scopes.

When the integration names no access for such sessions, or the person may not have it, the session ends at that refresh instead, with `invalid_grant`, and the application signs in again, where the person chooses. When the integration cannot answer at that refresh, the session is refreshed without its scopes and the next refresh tries again. Before that refresh, the person can give the session the access they choose with **Change access** on [Connected applications](consent.md#changing-what-an-application-may-do).

## Client ID Metadata Documents

A client whose client ID is an `https` address is resolved through the document at that address (draft-ietf-oauth-client-id-metadata-document, used by the MCP authorization specification) while [Allow client metadata documents](configuration.md#allow-client-metadata-documents) is on. The fetch is limited to keep it from being used against your network:

- Only `https` addresses in normalized form with a host name and a path, without a query, fragment, user name or dot segments, are accepted. IP addresses in any notation are refused, and international host names must be given in punycode, so a look-alike cannot pass for another domain on the consent screen.
- Host names that resolve only to private, loopback or other special-use addresses are refused, checked when the connection is made. IPv6 addresses that embed an IPv4 address, such as NAT64, count as that IPv4 address.
- Redirects are not followed, documents larger than 5 KB are refused, and the request times out after 5 seconds. A failed fetch is answered with the same message whatever the cause, so it reveals nothing about your network.
- Documents are cached for their `Cache-Control` lifetime, kept between 1 minute and 1 day, or for 1 hour when they name none, and not at all when marked `no-store` or `no-cache`. At most 100 are kept. Fetches that miss the cache are limited to 30 a minute, and 5 a minute for any one address.

A document must hold a `client_id` equal to its address and a list of `redirect_uris` that follow the [usual rules](clients.md#registering-a-client). It must not hold a client secret, its `token_endpoint_auth_method` must be `none` if given, and its `grant_types` and `response_types`, if given, must include `authorization_code` and `code`. Its `client_name` is shown on the consent screen; without a usable one, the host stands in.

## Limits

| What | Limit | Beyond it |
|---|---|---|
| Failed client authentication at the token and revocation endpoints | 5 for one client from one address, counted over 5 minutes | That client is refused from that address for 1 minute: `429` with `invalid_client` |
| Sign-ins waiting on the login page | 1000 in all, 20 from one address | `429`, "Too many sign-ins in progress", with `Retry-After` |
| Dynamic client registrations | 20 an hour in all, 5 from one address | `429` with `temporarily_unavailable` and `Retry-After` |
| Self-registered clients that have not had a token issued | 200 | `429` with `temporarily_unavailable` |
| Metadata document fetches that miss the cache | 30 a minute in all, 5 from one address | The sign-in is refused |
| Metadata document size | 5 KB | The sign-in is refused |
| Metadata document fetch | 5 seconds | The sign-in is refused |
| Client name | 100 characters | The client is refused |

The limits per address count by the address Home Assistant sees, so behind a reverse proxy they need Home Assistant to know each client's own address; see [Behind a reverse proxy](security.md#behind-a-reverse-proxy).

## Signing keys

Tokens are signed with a 2048-bit RSA key that is generated on first start and kept in Home Assistant's storage. `/oidc/jwks` publishes its public key, and after a rotation that kept it, the previous key as well, each with its `kid`. A token signed with a key that is no longer published is refused. To replace the key, see [Rotating the signing key](security.md#rotating-the-signing-key).

## What is stored where

The provider keeps its data in Home Assistant's `.storage` folder, which Home Assistant's backups include:

| File | Holds |
|---|---|
| `oidc_provider.clients` | The clients you or they registered, with each secret only as a salted PBKDF2-SHA256 hash |
| `oidc_provider.tokens` | The sessions: each refresh token with its person, client, scopes, resource and chosen access |
| `oidc_provider.keys` | The private signing key, and the previous public key after a rotation that kept it |
| `oidc_provider.access_choices` | Each person's last choice of access for each client at each integration, for the next consent screen |

Authorization codes, sign-ins waiting on the login page, cached metadata documents and the counts behind the limits are kept in memory only, so a restart drops them, and a sign-in that was under way has to start again. Expired refresh tokens are dropped when the integration starts.
