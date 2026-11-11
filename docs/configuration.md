# Configuration

[Back to the README](../README.md)

Install the integration through HACS by searching for "OIDC Provider", or without HACS by copying the `custom_components/oidc_provider` folder of this repository into the `custom_components` folder of your Home Assistant configuration. Restart Home Assistant either way.

Then add the integration under Settings > Devices & services > Add integration > **OIDC Provider**. The form asks for two of the options below, **Allow client metadata documents** and **Allow dynamic client registration**; submit it as it is unless you know you need otherwise. Only one OIDC Provider can be added.

Change the options later under Settings > Devices & services > OIDC Provider > Configure. Changes apply at once, without a restart. The same dialog links to the [Clients page](clients.md) (**Manage clients**) and to your [Connected applications](consent.md#connected-applications).

## Options at a glance

| Option | Default | What it does |
|---|---|---|
| Require PKCE | On | Every sign-in must use PKCE, see [Require PKCE](#require-pkce) |
| Allow client metadata documents | On | Clients such as Claude sign in without registering, see [Allow client metadata documents](#allow-client-metadata-documents) |
| Allow dynamic client registration | Off | Clients may register themselves, see [Allow dynamic client registration](#allow-dynamic-client-registration) |

The defaults are those of a new install. An install set up before version 1.8.0 may have other values; see [Upgrading from an older release](#upgrading-from-an-older-release).

## Require PKCE

PKCE (Proof Key for Code Exchange) ties the code a sign-in produces to the application that started it, so a code intercepted on its way back is useless to anyone else. With this option on, every authorization request must carry an S256 code challenge, as OAuth 2.1 requires; one without is refused with "PKCE is required".

Turn it off only for an application that cannot do PKCE and has a client secret. Clients without a secret, those identified by a metadata document and those that registered themselves as public clients, always need PKCE, whatever this option says. The `plain` method is never accepted.

## Allow client metadata documents

Accepts clients whose client ID is an `https` address serving their metadata, as Client ID Metadata Documents describe. Claude, Claude Code and other MCP clients sign in this way without registering first, so with this on you can leave dynamic client registration off and register nothing.

When a sign-in starts with such a client ID, Home Assistant fetches the document from the internet and reads the client's name and the redirect URIs it may use. These clients are public: they have no secret and prove their sign-ins with PKCE. Every sign-in through one stops on the [consent screen](consent.md#the-consent-screen), which shows the host that serves the document next to the client's name. The fetch is limited so it cannot be turned against your network; [Client ID Metadata Documents](reference.md#client-id-metadata-documents) has the rules.

Turning it off refuses the next token refresh of every client signed in this way, so they stop working within the hour and cannot sign in again while it is off.

## Allow dynamic client registration

Lets clients register themselves at `/oidc/register` (RFC 7591). Only needed for clients that support neither client metadata documents nor a client you register for them. Anyone who can reach Home Assistant can then register a client, so every sign-in through one stops on the consent screen.

While it is off, `/oidc/register` answers `403` with `access_denied`, and the discovery documents leave out `registration_endpoint`, so clients do not try to use it. Clients that registered while it was on keep working until you revoke them.

While it is on:

- Registrations are limited: at most 20 an hour in all, 5 of them from one address, and at most 200 self-registered clients that have not had a token issued yet. Beyond that the endpoint answers `429` with `temporarily_unavailable` and creates nothing. [Limits](reference.md#limits) lists every limit.
- Abandoned registrations are cleaned up. Some clients, such as Claude when metadata documents are off, register a new client on every fresh connection. A self-registered client that has not had a token issued within a day of registering is removed. Once a person has approved one, it is kept even after its sessions end, since many clients reuse their client ID for the next sign-in. The cleanup runs when the integration starts and before each new registration.
- A client may register without a secret by asking for the `none` authentication method, and is then a public client that must use PKCE. Any other method it asks for that is not supported becomes `client_secret_basic`.

Clients you registered yourself, and clients that registered themselves before version 1.8.0, are never removed automatically.

## Upgrading from an older release

The options keep what an install did before, so an upgrade changes nothing you relied on:

- **From before 1.7.0:** dynamic client registration stays on, since it was always on before, so clients that register themselves keep connecting. Turn it off if you do not need it.
- **From before 1.8.0:** **Allow client metadata documents** starts with the same setting as dynamic client registration, so an install that admitted only clients you registered keeps doing so. Turn it on to let Claude connect without registering.
- **From a fork of this integration** that stores the same setting: a value you saved there is kept. An install where it was never saved looks the same as one from before 1.7.0, so registration is turned on; check the setting after switching.

The integration logs what it chose for both options when it brings an older install up to date.
