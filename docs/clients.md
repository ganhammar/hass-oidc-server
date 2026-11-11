# Managing clients

[Back to the README](../README.md)

Administrators register, edit and revoke clients on a page inside Home Assistant, or with the actions below from Developer tools, an automation or a script. A client is how Home Assistant knows an application; [Connecting an application](connecting.md) explains the kinds.

## The Clients page

Open Settings > Devices & services > OIDC Provider > Configure and follow the **Manage clients** link, or go to `https://your-home-assistant/oidc_login?tab=clients`. The page has no entry in the sidebar.

The **Clients** tab is shown to administrators only, next to their own [Connected applications](consent.md#connected-applications). Other users who open the address see only their Connected applications.

The tab lists every client:

- **Registered** clients, the ones you registered. A client that registered itself before version 1.8.0 is listed here too, since those releases did not record the difference.
- **Registered by itself (dynamic registration)**, the ones that came through `/oidc/register`.
- **Identified by a metadata document**, such as Claude. These are not stored, so one is listed only while it holds a session, with the host that serves its document.

Each shows its client ID and number of active sessions. A stored client also shows its redirect URIs and whether the consent screen is "Shown on every sign-in" or "Skipped".

### Registering a client

1. Select **Register a client**.
2. Enter a **Name**, which people see when the application asks for access. It can be up to 100 characters, on one line, and no other client may have it.
3. Enter the **Redirect URIs**, one per line: the addresses the application may send people back to.
4. Leave **Require consent** off to skip the consent screen for this client, or turn it on to have people approve each sign-in. A client you register is trusted, so it is off by default.
5. Select **Register**.

The page shows the **Client ID** and **Client secret**, each with a **Copy** button. Copy the secret now: only a hash of it is stored, so it cannot be shown again. A client ID is a random string of 43 letters, digits, `-` and `_`.

A redirect URI has to be:

- an absolute `https` address, or `http` on `localhost`, `127.0.0.1` or `[::1]`. Other schemes, such as `myapp://callback`, are refused;
- ASCII, with an international host name in its punycode form, so a look-alike cannot pass for another domain on the consent screen;
- without a fragment (`#...`) or a user name and password.

A sign-in must name one of the client's redirect URIs exactly. The one exception is a redirect URI on `http://localhost`, `http://127.0.0.1` or `http://[::1]`, which matches on any port as long as the rest is the same, since native applications such as Claude Code pick a port for each sign-in.

### Editing a client

**Edit** changes a stored client's redirect URIs and whether it requires consent. Its name and secret stay as they are; to get a new secret, register a new client and revoke the old one.

### Revoking a client

**Revoke** removes the client and ends every session it holds at once, so its refresh tokens stop working and it can no longer sign anyone in. Access tokens it already holds keep working until they expire, within the hour.

A client identified by a metadata document is not stored, so its button reads **End sessions**: its sessions end, and it can ask people to sign in again unless you turn off [Allow client metadata documents](configuration.md#allow-client-metadata-documents).

## Actions

The same operations are available as actions, under Developer tools > Actions, in automations and in scripts. Only administrators can call them. Automations, which run without a user, can call them too, and a script runs as the user who started it, so it can call them only when an administrator starts it.

| Action | Name | Fields | What it does |
|---|---|---|---|
| `oidc_provider.register_client` | Register OIDC Client | `client_name`, `redirect_uris`, `consent_required` | Registers a client and returns its client ID and secret |
| `oidc_provider.update_client` | Update OIDC Client | `client_id`, `redirect_uris`, `consent_required` | Replaces a client's redirect URIs and, when given, its consent setting |
| `oidc_provider.revoke_client` | Revoke OIDC Client | `client_id` | Removes a client and ends every session it holds |
| `oidc_provider.list_clients` | List OIDC Clients | none | Lists every client with its redirect URIs and active sessions |
| `oidc_provider.rotate_signing_key` | Rotate Signing Key | `keep_previous_key` | Replaces the key that signs tokens, see [Rotating the signing key](security.md#rotating-the-signing-key) |

`redirect_uris` in these actions is one text field with the addresses separated by commas.

### Register OIDC Client

In Developer tools > Actions, choose **Register OIDC Client**, fill in **Client Name** and **Redirect URIs**, and select **Perform action**. The response shows the client ID and secret. In YAML:

```yaml
action: oidc_provider.register_client
data:
  client_name: "Grafana"
  redirect_uris: "https://grafana.example.com/login/generic_oauth"
```

`consent_required` is optional and off by default. Called from Developer tools, or with a response variable, the action returns the credentials:

```yaml
client_id: q3Vb0yCq5xN8pR2tLmW7ZkA1sD4fG6hJ9uE0oI3yT5w
client_secret: (64 random characters, shown only this once)
client_name: Grafana
redirect_uris:
  - https://grafana.example.com/login/generic_oauth
consent_required: false
```

Called from an automation or script without a response variable, it posts the credentials in a notification instead. Every Home Assistant user can read notifications, so dismiss it once you have saved the secret. A name that is already taken, or a redirect URI that breaks the rules above, is refused with a notification and, when a response was asked for, an error.

### Update OIDC Client

Find the client ID on the Clients page or with **List OIDC Clients**.

```yaml
action: oidc_provider.update_client
data:
  client_id: "q3Vb0yCq5xN8pR2tLmW7ZkA1sD4fG6hJ9uE0oI3yT5w"
  redirect_uris: "https://grafana.example.com/login/generic_oauth,http://localhost:3000/login/generic_oauth"
  consent_required: false
```

The redirect URIs replace the client's list. Leave `consent_required` out to keep the current setting. The result, or why the update failed, is posted in a notification. Clients registered before version 1.6.0 have no consent setting and show the consent screen until you set it to false.

### Revoke OIDC Client

```yaml
action: oidc_provider.revoke_client
data:
  client_id: "q3Vb0yCq5xN8pR2tLmW7ZkA1sD4fG6hJ9uE0oI3yT5w"
```

Revoking works as on the Clients page. For a client that signed in with a metadata document, give its URL client ID, such as `https://claude.ai/...`, to end its sessions. A client ID that is neither stored nor signed in only logs a warning.

### List OIDC Clients

The list is posted in a notification, not in the log: every client with its client ID, redirect URIs, whether it requires consent and its active sessions, followed by the clients signed in through a metadata document. Client secrets cannot be shown. Called from Developer tools, or with a response variable, it also returns the list as `clients`.
