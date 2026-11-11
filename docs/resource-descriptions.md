# Describing a resource to the OIDC Provider

This page is for authors of integrations that accept this provider's access tokens, such as an MCP server running inside Home Assistant. It explains how such an integration, a *resource server*, describes the access it offers so that the person signing in can choose it on the consent screen.

The provider stays generic. It knows nothing about what your scopes mean:

| | The provider | Your integration |
|---|---|---|
| What the options mean | Does not know | Defines them |
| The consent screen | Renders what you describe | Supplies the wording, in the user's language |
| The token | Puts the chosen scopes in its `scope` claim | Reads them |
| Enforcement | None | Maps scopes to what a request may do |
| A user's ceiling | Asks you and shows it | Answers, and enforces it |

Neither project imports the other for this. Without the provider your module is never read; with a provider that predates this feature, the consent screen is the plain approve or deny screen and tokens carry none of your scopes.

## How the provider finds you

Ship a module named `oidc_provider.py` in your integration's folder:

```
custom_components/your_integration/
├── __init__.py
├── manifest.json
└── oidc_provider.py
```

The provider collects it through Home Assistant's [integration platforms](https://developers.home-assistant.io/docs/creating_integration_file_structure/#integration-platforms) (`async_process_integration_platforms(hass, "oidc_provider", ...)`), the mechanism `diagnostics` and `system_health` use. It works whichever of the two integrations loads first, and it only looks at integrations that are loaded. Each integration describes one resource.

Descriptions are collected once per Home Assistant run, the first time both integrations are loaded, and kept until Home Assistant restarts. Reloading your integration, or removing it, does not collect again or forget what was collected. Until the next restart:

- Your resource keeps matching sign-ins, so they keep asking your module (see below), and a module that fails then gives the plain screen.
- Your scopes stay in the provider's discovery documents.
- Sessions for your resource that began before your description keep being settled at their next refresh, as [Sessions from before your description](#sessions-from-before-your-description) describes.
- A change to your `resource` takes effect only after a restart, and so does a change to the scopes listed in the provider's discovery documents. The rest of the description is asked for again at every consent screen and approval.

## The module

| Function | Required | Called | Returns |
|---|---|---|---|
| `async_describe_resource(hass, language)` | Yes | Once when collected, with Home Assistant's language; at every consent screen and on Connected applications, with the user's language; and when the user approves or a [session from before your description](#sessions-from-before-your-description) is refreshed, with Home Assistant's language | The description, with its text in `language` |
| `async_get_availability(hass, language)` | No | At every consent screen, with the user's language, and when the user approves or a session from before your description is refreshed, with Home Assistant's language | Which groups are unavailable right now and why: `{group_id: reason}`, or `None` |
| `async_get_ceiling(hass, user, language)` | No | At every consent screen, with the user's language, and when the user approves or a session from before your description is refreshed, with Home Assistant's language | The most this user may grant, or `None` |

When the user approves, all three are asked again and their answers must still be valid. The choice is checked against that description and ceiling; availability does not change what may be approved.

They may be coroutines or plain functions. Each call has 10 seconds to answer; a coroutine that takes longer is cancelled and treated as a failure (see [Validation](#validation)). A plain function runs on Home Assistant's event loop and cannot be cancelled, so it must not block: do any I/O in a coroutine. `user` is Home Assistant's `User` signing in. `language` is a language code Home Assistant knows, such as `en`, `sv` or `pt-BR`.

Availability and the ceiling are functions rather than part of the description because they are the only things that change while Home Assistant runs: availability follows your integration's options, and the ceiling depends on who signs in. The description itself is plain data, so the same model could come from somewhere other than a Home Assistant module later. The two answers are plain data too, in the shapes below.

## The description

```python
{
    "resource": ["/api/mcp", "/api/mcp_http"],  # where you answer: paths or URLs
    "name": "MCP Server",                       # your resource's name
    "prompt": "Choose what {app} can do in Home Assistant.",  # optional
    "detail_intro": "For each area, choose None, Read or Full.",  # optional
    "scopes": {...},          # every scope you understand
    "presets": [...],         # the levels, lowest first
    "default_preset": "read", # optional: preselected the first time
    "existing_sessions_preset": "admin",  # optional: what sessions from before get
    "sections": [...],        # the areas, in groups with a heading
}
```

| Key | What it is |
|---|---|
| `resource` | The resource indicators (RFC 8707) your tokens are bound to, as one string or a list. A path starting with `/` names you at every address Home Assistant answers on: `/api/mcp` matches `https://ha.example.com/api/mcp` and `http://192.168.1.10:8123/api/mcp` alike. The host is left out of the match on purpose. The client decides which address its requests arrive at, so matching on it would let the client decide whether the user is asked. An absolute `http` or `https` URL matches as written, with its scheme and host in any case (RFC 3986). The path matches exactly either way, so `/api/MCP` and `/api/mcp/` are not `/api/mcp`. List every path you answer on. A client's `resource` that matches none of them fails safe: the consent screen offers no choice, and the token carries none of your scopes. A client must send the same value as `resource` when it authorizes; the provider binds the token's `aud` to it as before. |
| `name` | Your resource's name. The provider's log messages give it next to your integration's domain. The consent screen does not show it. |
| `prompt` | The line above the levels. Defaults to "Choose what {app} can do." |
| `detail_intro` | A paragraph under the heading of the detailed view. Use it to say what your settings mean. |
| `scopes` | Every scope a choice can grant: `{scope: {"title": ..., "description": ...}}`, a title and one sentence each. They are advertised in the provider's discovery documents. |
| `presets` | The levels, in order from least to most. See below. |
| `default_preset` | The level preselected the first time a user meets a client. Defaults to the first preset. Afterwards the user's last choice for that client is preselected. |
| `existing_sessions_preset` | The level a session that began before your integration described itself gets at its next refresh, so it keeps working without the user. Name the preset closest to what such a token could do at your resource before. Optional; without it such a session ends at that refresh. See [Sessions from before your description](#sessions-from-before-your-description). |
| `sections` | The groups of areas, in order, each with a heading. See below. |

### Sections, groups and options

A *section* has an `id`, a `title` (the heading, such as "Devices"), its `groups`, and optional `notes` shown under its last group.

A *group* (an area on the screen) has an `id`, a `title`, and two or more `options`, lowest first. The user chooses exactly one option in every group.

An *option* has:

| Key | What it is |
|---|---|
| `id` | Unique in its group, such as `none`, `read` or `full` |
| `label` | What the segmented control shows, such as "Read" |
| `description` | One sentence on what this option gives, shown under the row while it is chosen and read to screen readers for every option |
| `scopes` | The scopes it grants. Optional; leave it out for an option that grants nothing |
| `notes` | Optional notes shown under the row while this option is chosen and their conditions hold |

### Presets

A *preset* (a level) has an `id`, a `title`, a one-sentence `description`, and `options`: the option it chooses in every group. It may also have:

- `scopes`: what the token carries when the user's choice is exactly this preset. Use it for a shorthand scope such as `mcp:read`, which keeps the common case short. Without it, a preset grants the scopes of the options it chooses.
- `notes`: shown inside the level while it is selected, for something its title does not say.

Every preset must choose an option for every group, and no two presets may choose the same options.

When the choice matches no preset, the token carries the scopes of each chosen option. On the screen that choice is called Custom and summarised against the closest preset ("Like Control devices, except: Cameras: None").

### Notes and their conditions

A note is `{"text": ..., "when": [...]}`. It is shown when every condition in `when` holds; a note without `when` is shown whenever its place is shown. Notes look like Home Assistant's info alerts.

A condition is one of:

| Condition | Holds when |
|---|---|
| `{"group": "entities", "in": ["read", "full"]}` | That group's chosen option is one of these |
| `{"some_group": "below_highest", "except": [...]}` | At least one other group is not at its highest option |
| `{"some_group": "at_lowest", "except": [...]}` | At least one other group is at its lowest option |

"Other" leaves out the groups listed in `except` and, for a note on an option, that option's own group. These three cover notes that depend on the same row, on another row, and on the rest of the rows, such as "Actions reach further than devices, whatever the other areas say" on Entities at Full.

### Text and languages

Every text you return is shown as plain text. `{app}` anywhere in it is replaced with the application's name. Return the text in the `language` you are given; the provider asks again for every screen. One way is to keep your text in your own translations under `common`, which hassfest accepts as flat keys, and look it up:

```python
from homeassistant.helpers.translation import async_get_translations


async def async_describe_resource(hass, language):
    strings = await async_get_translations(hass, language, "common", [DOMAIN])

    def text(key):
        return strings[f"component.{DOMAIN}.common.{key}"]

    return build_description(text)
```

`async_get_translations` falls back to English for keys a language lacks. The structure (ids, options, presets) must not depend on the language: the provider checks a choice against the description it gets when the user approves, in Home Assistant's language.

## Availability

`async_get_availability` returns `{group_id: reason}` for every group that is unavailable right now, for example because its option is off in your integration or the integration it needs is not set up. The area keeps its row and can still be chosen: it shows "Not available" and your reason. The grant records the user's choice, and what the application can actually do is the grant limited by what is switched on, so nothing appears later that the user did not pick.

## The ceiling

`async_get_ceiling` returns the most this user may grant:

```python
{
    "groups": {
        "diagnostics": {
            "max": "read",
            "reason": "An administrator has limited this to Read for your account.",
        },
    },
    "reason": "Not available for your account. An administrator has limited what you can allow.",
}
```

Options above `max` are shown locked with the group's reason and cannot be chosen; the provider checks this again when the user approves. A preset that would add nothing the user may grant to the one before it is locked with the top-level `reason`, which is required once anything is limited. A preset only partly above the ceiling stays selectable and is held at the ceiling. Return `None`, or leave the function out, for no ceiling.

`locked_presets` locks presets by id, with the same `reason`, whatever the groups allow. Use it with group limits for a limit that applies to everyone, such as a read-only mode where every group is held at Read and every level above the lowest is locked:

```python
{
    "groups": {
        group: {"max": "read", "reason": "The MCP Server integration is in read-only mode."}
        for group in ("entities", "dashboards", "files")
    },
    "locked_presets": ["control", "configure", "admin"],
    "reason": "Not available: the MCP Server integration is in read-only mode.",
}
```

At least one preset must stay unlocked.

Locking a preset locks its exact choice and its scope. An approval whose options are exactly a locked preset's is refused, also when the user sets them one by one in the detailed view; the screen then says why next to Approve and does not let the user approve. So a token never carries a locked preset's own `scopes`. A choice that differs from a locked preset in any group is not affected and carries the scopes of its options, so to keep an option out of reach, limit its group with `max`. The screen never opens on a locked preset's choice: a locked `default_preset` gives way to the nearest unlocked preset below it, or else above it, and a last choice that is exactly a locked preset gives way to that default.

The ceiling on the consent screen is for the user's benefit. Enforce it yourself on every request too: a ceiling can be lowered after a token was issued.

## Validation

A description is checked when it is collected, and every answer is checked when it is asked for. The rules:

- `resource`, `name`, `scopes`, `presets` and `sections` are required; text is a non-empty string.
- Ids are lower case letters and digits joined by single `-` or `_`, up to 64 characters. Group ids are unique across sections; option ids are unique in their group; preset and section ids are unique.
- Scopes are OAuth scope tokens (printable ASCII without spaces, `"` or `\`) and may not be one of the provider's own (`openid`, `profile`, `email`, `groups`). Every scope an option or preset grants is declared under `scopes`.
- A group has at least two options; a preset chooses a known option for every group; no two presets choose the same; `default_preset` and `existing_sessions_preset` name presets.
- Conditions name groups and options that exist.
- Resource paths start with a single `/`, name more than `/` and have no query or fragment; URLs are `http` or `https`, without credentials or a fragment. Neither may hold whitespace, control characters, or `.` or `..` segments (also percent-encoded). No two integrations may describe the same resource, compared as above.
- Availability names known groups, each with a reason. A ceiling names known groups, each with a known `max` and a reason, and known presets in `locked_presets`, leaving at least one unlocked, plus a top-level reason.
- Keys the provider does not know are ignored, so a description written for a later release still works.

A module without `async_describe_resource`, a description that breaks a rule, or one whose function raises or does not answer within 10 seconds, is logged as a warning naming your integration and ignored, so sign-ins carry on as if you had not described yourself. If anything fails or does not validate when the consent screen loads, the warning says so and that sign-in gets the plain approve or deny screen without your scopes. If it happens when the user approves, the approval is refused, and the screen is shown again from your answers at that time, which is the plain screen while you still cannot answer. To check a description in your own tests while the provider is installed, call `custom_components.oidc_provider.resource_description.validate_description(description)`; it raises `InvalidDescription` with the reason.

## What arrives in the token

An access token for your resource has your resource in `aud` (as today) and the chosen scopes in `scope`, after the OpenID Connect scopes:

```json
{
  "aud": "https://ha.example.com/api/mcp",
  "client_id": "https://claude.ai/oauth/mcp-oauth-client-metadata",
  "scope": "openid profile email mcp:control",
  "sub": "8b9c..."
}
```

- The scopes come from the user's choice, whatever the client asked for. The client learns them from the token response's `scope` (RFC 6749 §3.3).
- A choice that is exactly a preset with its own `scopes` carries those; any other choice carries the scopes of each chosen option. Expect both forms.
- Refreshed tokens carry the same scopes and the same audience.
- A token for your resource with none of your scopes grants nothing there. That is a token for which the user chose options that grant no scopes, such as the lowest everywhere, and an access token of a session from before your description, until that session's next refresh gives it access. The provider gives you no way to tell the two apart, and you need none: a resource that enforces its scopes refuses such a token at once.
- Refuse a request whose token lacks the scopes it needs with `403` and a challenge that names them with `openid`, such as `WWW-Authenticate: Bearer error="insufficient_scope", scope="openid mcp:control"` (RFC 6750 §3.1). An MCP client then goes back through authorization, where the user chooses.
- A token with none of your scopes may be refused either way, and each answer leads somewhere else:
  - `401` with `WWW-Authenticate: Bearer error="invalid_token"` makes the client refresh. That refresh gives a session from before your description the access you name for it, so the client carries on without asking the user. If the refreshed token still carries none of your scopes, your next `401` makes the client start authorization again, where the user chooses.
  - `403` with `error="insufficient_scope"`, and `openid` in the challenge's `scope`, sends the client straight to authorization, where the user chooses. The client does not refresh first, so a session from before your description does not get the access you name for it.
- A session that began before your integration described itself carries no choice. At its next refresh it gets the access you name in `existing_sessions_preset`, or ends with `invalid_grant` and the client signs in again; see [Sessions from before your description](#sessions-from-before-your-description).
- The provider refuses to bind a token to your resource when the client names it only at the token endpoint, with `invalid_target`, since the user was not asked.

Read the claims with the provider's validator, as you do now, and require your own audience:

```python
from custom_components.oidc_provider.token_validator import (
    get_issuer_from_request,
    validate_access_token,
)

# The address the request reached, such as https://ha.example.com
base_url = get_issuer_from_request(request)
claims = validate_access_token(hass, token, base_url, expected_audience=f"{base_url}/api/mcp")
scopes = set((claims or {}).get("scope", "").split())
```

Then decide what the request may do from those scopes, limited by what your integration has switched on and by the user's ceiling. The provider enforces none of it.

## Sessions from before your description

A session that began before your integration described itself carries no choice of your access, and its tokens carry none of your scopes. So does a session approved on the plain screen while your module could not answer. The provider settles such a session's access at its next refresh:

- When the description it collected names `existing_sessions_preset`, it asks your module for the description and the user's ceiling, as when a user approves, and takes the preset that description names. Each group's option is held at the ceiling's `max` for that group where it is above it. If the result is a choice the user may make, the session keeps it as its access, as if the user had chosen it: the refreshed token and every later one carry its scopes, and Connected applications shows it. The scopes follow the rule for any choice, so the preset's own `scopes` when nothing was held at the ceiling, and otherwise those of each option, or those of another preset the result is exactly. It is not remembered as the user's choice, so the user's next consent screen for that client still opens on the user's own last choice or on `default_preset`.
- The session ends at that refresh with `invalid_grant`, and the client signs in again where the user chooses, when the description names no `existing_sessions_preset`, when the result is exactly the choice of a preset the ceiling locks (see [The ceiling](#the-ceiling)), or when the user no longer exists.
- When your module fails, does not answer within 10 seconds, or gives an answer that does not validate, the session is refreshed without your scopes and the provider logs a warning. The next refresh asks again.

The access token such a session already holds, valid for up to an hour, carries none of your scopes until the client refreshes. How you refuse it decides whether the client refreshes first; see [What arrives in the token](#what-arrives-in-the-token).

## Scopes in your metadata and challenges

The provider refuses an authorization request without the `openid` scope, with `400` before the consent screen. MCP clients take the scope they request from the `scope` of your `401` or `403` challenge, or else from `scopes_supported` in your protected resource metadata (RFC 9728). So:

- List `openid` in `scopes_supported`, with your own scopes.
- Put `openid` in the `scope` of every challenge you send, with the scopes the request needs: `WWW-Authenticate: Bearer resource_metadata="...", scope="openid mcp:read"`.

A client that asks for your scopes gets only what the user chooses: the provider grants them from the consent screen, whatever the client asked for, and adds them to its own discovery documents.

## Clients registered without consent

A client an administrator registered with consent not required skips the consent screen. When the sign-in is for a described resource it stops on the screen anyway: what the client may do there is the user's to choose, and each user may have their own ceiling, which one level fixed at registration could not respect. The user's last choice is preselected, so it is one tap. Sign-ins of such clients for anything else skip the screen as before.

## Complete example

A description for an MCP server with five areas, four levels and every kind of note. The text is English here; return it in the requested language as described above.

```python
"""Describe this integration's resource to the OIDC Provider integration."""

from typing import Any

from homeassistant.auth.models import User
from homeassistant.core import HomeAssistant


def _area(gid: str, title: str, texts: dict[str, str]) -> dict[str, Any]:
    labels = {"none": "None", "read": "Read", "full": "Full"}
    return {
        "id": gid,
        "title": title,
        "options": [
            {
                "id": level,
                "label": labels[level],
                "description": texts[level],
                **({"scopes": [f"mcp:{gid}:{level}"]} if level != "none" else {}),
            }
            for level in texts
        ],
    }


ENTITIES = _area(
    "entities",
    "Entities and their states",
    {
        "none": "{app} cannot see states or perform actions.",
        "read": "{app} can see states, history, the logbook and statistics.",
        "full": "{app} can also perform actions and fire events, such as turning lights on and off.",
    },
)
ENTITIES["options"][2]["notes"] = [
    {
        "text": "Actions reach further than devices. An action can also run a script, "
        "turn an automation off or restart Home Assistant, whatever the other areas say.",
        "when": [{"some_group": "below_highest"}],
    }
]

CAMERAS = _area(
    "cameras",
    "Cameras and images",
    {
        "none": "{app} cannot fetch camera images or image files.",
        "read": "{app} can see what your cameras show right now, and saved images such as snapshots.",
    },
)
CAMERAS["options"][0]["notes"] = [
    {
        "text": "Your cameras still show up as entities.",
        "when": [{"group": "entities", "in": ["read"]}],
    },
    {
        "text": "Your cameras still show up as entities, and an action can still take a snapshot.",
        "when": [{"group": "entities", "in": ["full"]}],
    },
]

DASHBOARDS = _area(
    "dashboards",
    "Dashboards",
    {
        "none": "{app} cannot see or change dashboards.",
        "read": "{app} can see how your dashboards are set up.",
        "full": "{app} can also create, change and delete dashboards.",
    },
)
for option in DASHBOARDS["options"][:2]:
    option["notes"] = [
        {
            "text": "Dashboards kept in YAML files can still be changed through Config files.",
            "when": [{"group": "files", "in": ["full"]}],
        }
    ]

TEMPLATES = _area(
    "templates",
    "Templates",
    {
        "none": "{app} cannot use templates.",
        "read": "{app} can work out values with templates. A template can read any state in your home.",
    },
)
TEMPLATES["options"][1]["notes"] = [
    {
        "text": "Templates can still read the states that Entities and their states hides.",
        "when": [{"group": "entities", "in": ["none"]}],
    }
]

FILES = _area(
    "files",
    "Config files",
    {
        "none": "{app} cannot read or change configuration files.",
        "read": "{app} can read your configuration files, such as configuration.yaml. Never secrets.yaml.",
        "full": "{app} can also change, delete and restore them. A backup is made before every change.",
    },
)

ACTIONS_NOTE = {
    "text": "Actions reach further than devices. An action can also run a script, "
    "turn an automation off or restart Home Assistant."
}

DESCRIPTION: dict[str, Any] = {
    "resource": ["/api/mcp", "/api/mcp_http"],
    "name": "MCP Server",
    "prompt": "Choose what {app} can do in Home Assistant.",
    "detail_intro": (
        "For each area, choose None, Read or Full. Read lets {app} look, and Full also lets "
        "it make changes. None hides the area's tools, but the things themselves can still "
        "show up elsewhere, for example as entities."
    ),
    "scopes": {
        "mcp:read": {"title": "Look only", "description": "Every area at Read, files at None."},
        "mcp:control": {"title": "Control devices", "description": "Look only, and actions."},
        "mcp:configure": {"title": "Edit the setup", "description": "Control, and changing the setup."},
        "mcp:admin": {"title": "Administer", "description": "Every area at its highest."},
        **{
            scope: {"title": scope, "description": f"Grants {scope}."}
            for group in (ENTITIES, CAMERAS, DASHBOARDS, TEMPLATES, FILES)
            for option in group["options"]
            for scope in option.get("scopes", [])
        },
    },
    "presets": [
        {
            "id": "read",
            "title": "Look only",
            "description": "See devices, history and settings, without changing anything.",
            "options": {"entities": "read", "cameras": "read", "dashboards": "read", "templates": "read", "files": "none"},
            "scopes": ["mcp:read"],
        },
        {
            "id": "control",
            "title": "Control devices",
            "description": "Also turn things on and off, perform actions and manage calendar events.",
            "options": {"entities": "full", "cameras": "read", "dashboards": "read", "templates": "read", "files": "none"},
            "scopes": ["mcp:control"],
            "notes": [ACTIONS_NOTE],
        },
        {
            "id": "configure",
            "title": "Edit the setup",
            "description": "Also change automations, scripts, scenes, dashboards and helpers, "
            "and organize or remove devices and entities.",
            "options": {"entities": "full", "cameras": "read", "dashboards": "full", "templates": "read", "files": "none"},
            "scopes": ["mcp:configure"],
            "notes": [ACTIONS_NOTE],
        },
        {
            "id": "admin",
            "title": "Administer",
            "description": "Also add and remove integrations, change configuration files and "
            "AppDaemon apps, and restart Home Assistant.",
            "options": {"entities": "full", "cameras": "read", "dashboards": "full", "templates": "read", "files": "full"},
            "scopes": ["mcp:admin"],
        },
    ],
    "default_preset": "read",
    # Tokens could do everything here before this description existed
    "existing_sessions_preset": "admin",
    "sections": [
        {"id": "devices", "title": "Devices", "groups": [ENTITIES, CAMERAS]},
        {"id": "setup", "title": "Setup", "groups": [DASHBOARDS, TEMPLATES]},
        {
            "id": "system",
            "title": "System",
            "groups": [FILES],
            "notes": [
                {
                    "text": "Config files reach past the other areas. {app} can change any YAML "
                    "file, such as configuration.yaml or a dashboard kept in YAML, whatever the "
                    "other areas say.",
                    "when": [
                        {"group": "files", "in": ["full"]},
                        {"some_group": "below_highest", "except": ["files"]},
                    ],
                },
                {
                    "text": "Config files reach past the other areas. {app} can read what is "
                    "written in your YAML files, such as a dashboard kept in YAML, whatever the "
                    "other areas say.",
                    "when": [
                        {"group": "files", "in": ["read"]},
                        {"some_group": "at_lowest", "except": ["files"]},
                    ],
                },
            ],
        },
    ],
}


async def async_describe_resource(hass: HomeAssistant, language: str) -> dict[str, Any]:
    """Describe the access this resource offers."""
    return DESCRIPTION


async def async_get_availability(hass: HomeAssistant, language: str) -> dict[str, str]:
    """Say which areas are turned off right now."""
    return {"files": "Turned off in the MCP Server integration's options."}


async def async_get_ceiling(hass: HomeAssistant, user: User, language: str) -> dict[str, Any] | None:
    """Say the most this user may grant."""
    if user.is_admin:
        return None
    return {
        "groups": {
            "files": {"max": "none", "reason": "An administrator has limited this for your account."},
        },
        "reason": "Not available for your account. An administrator has limited what you can allow.",
    }
```
