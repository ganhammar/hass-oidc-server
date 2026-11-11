# Troubleshooting

[Back to the README](../README.md)

## Seeing what happened

Most refusals are logged. Home Assistant's default log level is `warning`, and some of the provider's messages are at `info` or `debug`, so raise its logger in `configuration.yaml` and restart:

```yaml
logger:
  default: warning
  logs:
    custom_components.oidc_provider: debug
```

The log then says, for example, why a metadata document was refused, that a client secret or PKCE verifier did not match, or that a session was ended because a replaced refresh token came back.

## A client lands on Home Assistant's own login page

The address bar shows `/auth/authorize` rather than `/oidc/authorize`: the client went to Home Assistant's built-in sign-in instead of this provider. With a client you registered here, that page says "Invalid client id", since Home Assistant's own sign-in does not know this provider's clients, and Home Assistant counts each attempt as a failed login, so "Login attempt failed" notifications often come with it. The client did not find this provider, usually because:

- **It was given the wrong address.** Claude needs the MCP server's address, such as `https://your-home-assistant/api/mcp_http`, not this provider's discovery address or Home Assistant's own.
- **The MCP server does not point to this provider.** Check that it is set up to sign in through the OIDC Provider; see its documentation.
- **The discovery documents name an address the client cannot reach**, such as an internal IP address. See the next section.

## Reverse proxies and the issuer

Open `https://your-home-assistant/oidc/.well-known/openid-configuration` from outside your network, for example on a phone on mobile data. Every address in it should start with the address you opened, followed by `/oidc`. If it names an internal IP address, `http` instead of `https`, or another host:

- **The proxy rewrites the host.** The provider takes the address from `X-Forwarded-Host`, or else `Host`, and the scheme from `X-Forwarded-Proto`. Have the proxy pass the original host and set `X-Forwarded-Proto`. A proxy that sends an internal IP address as the host makes the provider use the external URL under Settings > System > Network instead, so set that. [The issuer and the addresses](reference.md#the-issuer-and-the-addresses) has the exact order.
- **The application uses two addresses.** Tokens carry the address they were issued at, and an application or integration that checks it refuses a token from another. Give the application one address for everything, the one people sign in at.

If every request through the proxy gets `400 Bad Request`, Home Assistant is refusing a proxy it is not set up for: it logs "A request from a reverse proxy was received from ..., but your HTTP integration is not set-up for reverse proxies". Turn on [`use_x_forwarded_for`](https://www.home-assistant.io/integrations/http/#use_x_forwarded_for) and list the proxy in `trusted_proxies`. Doing so also lets the provider's limits count each client by its own address; see [Behind a reverse proxy](security.md#behind-a-reverse-proxy).

## The browser shows a short error instead of the login page

`/oidc/authorize` checks the request before it sends anyone to sign in, and answers a request it refuses with one line of text:

| The page says | Why | What to do |
|---|---|---|
| Invalid request | `client_id` or `redirect_uri` is missing, or `response_type` is not `code` | Check the application's settings |
| The openid scope is required for OIDC requests. | The application did not ask for `openid` | Add `openid` to its scopes |
| PKCE is required. Please provide code_challenge parameter. | [Require PKCE](configuration.md#require-pkce) is on and the application did not use PKCE | Turn PKCE on in the application, with S256, or turn the option off for an application with a client secret |
| Unsupported code_challenge_method. Supported: S256 | The application uses the `plain` method | Set it to S256 |
| Invalid client_id | No client has that ID | Check for a typo. The client may have been revoked, or removed because it registered itself and had no token issued within a day. A client ID that is an `https` address needs **Allow client metadata documents** on |
| Invalid client_id: metadata document could not be fetched | Home Assistant could not fetch the client's document | Home Assistant needs to reach the internet. The document must come straight back with `200` from a public address, within 5 seconds and 5 KB |
| Invalid client_id: too many metadata document fetches, try again later | The [fetch limit](reference.md#limits) was reached | Wait a minute |
| Invalid client_id: followed by another reason | The client's document breaks a [rule](reference.md#client-id-metadata-documents) | The reason names the rule. It is the client's to fix |
| Invalid redirect_uri | The redirect URI is not one of the client's | Add it to the client exactly as the application sends it, see [Redirect URIs](#redirect-uris) |
| PKCE is required for public clients. Please provide code_challenge. | A client without a secret did not use PKCE | Turn PKCE on in the application |
| Too many sign-ins in progress. Try again in a few minutes. | Too many sign-ins were started and not finished | Wait; they expire after 10 minutes |

## Redirect URIs

The redirect URI a sign-in names must be one of the client's exactly: the scheme, host, port, path and query, and a trailing `/` counts. Only `http://localhost`, `http://127.0.0.1` and `http://[::1]` match on any port. To see what the application sends, look at the `redirect_uri` parameter in the address bar on the error page, where it is URL-encoded, and add exactly that on the [Clients page](clients.md#editing-a-client).

Registering a redirect URI fails when it is not `https` (or `http` on `localhost`, `127.0.0.1` or `[::1]`), when it uses another scheme such as `myapp://`, holds a fragment or a user name, or has non-ASCII characters; write an international host name in punycode.

## The application gets an error from the token endpoint

- **`invalid_client`** (`401`): the client ID or secret is wrong, a client without a secret sent one anyway, the client ID in the body differs from the one in the `Authorization` header, or the client is identified by a metadata document while **Allow client metadata documents** is off. After 5 such failures from one address the client is refused from there for a minute, with `429`.
- **`invalid_grant`** (`400`): the code is more than 10 minutes old or was already used, it was issued to another client, the `redirect_uri` differs from the sign-in's, or the PKCE `code_verifier` does not match. For a refresh, the refresh token expired, was replaced more than a minute ago, or its session was ended; see the next section.
- **`invalid_target`** (`400`): the application named an integration that describes its access only when redeeming the code. It must send `resource` when it starts the sign-in.

## An application has to sign in again

A session ends, and the application has to send the person through the login page again, when:

- it is 30 days since the person signed in;
- the person signed it out on [Connected applications](consent.md#connected-applications), or an administrator revoked its client;
- a replaced refresh token came back more than a minute later, or from another client. The log says "A replaced refresh token was presented by client ... ; session revoked" or "Refresh token issued to client ... used by client ...". An application that keeps several copies of its refresh token, for example in several places at once, can cause this;
- it is identified by a metadata document and **Allow client metadata documents** was turned off;
- it signed in for an integration before that integration described its access, and the integration gives such sessions none. The refresh answers "The resource now asks what this application may do there; sign in again".

## Clients that register themselves

- **`403` with `access_denied`** from `/oidc/register`: dynamic client registration is off, as it is for new installs. Turn it on under [Allow dynamic client registration](configuration.md#allow-dynamic-client-registration), or use client metadata documents or a client you register instead.
- **`429` with `temporarily_unavailable`**: a [registration limit](reference.md#limits) was reached. Wait for the time in `Retry-After`. "Too many registered clients" means 200 self-registered clients have had no token yet; they are removed a day after they registered.
- **A client disappeared**: a self-registered client that has not had a token issued within a day of registering is removed. The client registers again.
- **Many entries on the Clients tab**: some clients, such as Claude when metadata documents are off, register a new client on every fresh connection. The unused ones are cleaned up; turning on client metadata documents avoids them.

## Failed logins and IP bans

The provider's own endpoints answer a bad client secret or token themselves, so Home Assistant does not count those as failed logins, and they do not lead to an IP ban. These do count when the [`http` integration](https://www.home-assistant.io/integrations/http/#ip_ban_enabled) has `ip_ban_enabled` on:

- a wrong password on Home Assistant's login page;
- a client that ends up at Home Assistant's own sign-in with a client ID it does not know, as [above](#a-client-lands-on-home-assistants-own-login-page);
- an integration that counts a token it refuses, such as an MCP server refusing an expired access token. See that integration's documentation.

Behind a reverse proxy that Home Assistant does not know about, every request comes from the proxy's address, so a ban locks everyone out. Set up `use_x_forwarded_for` and `trusted_proxies` as described above.

## List OIDC Clients shows nothing in the log

The list is posted as a notification, not in the log; the log only says how many clients were listed. Called from Developer tools > Actions, the action also shows the list as its response. The [Clients page](clients.md#the-clients-page) shows the same.
