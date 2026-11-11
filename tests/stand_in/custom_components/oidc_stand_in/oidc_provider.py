"""The stand-in resource server's description, as the provider collects it.

Tests change DESCRIPTION, UNAVAILABLE and CEILINGS to drive the provider, and
read CALLS to see what it asked.
"""

import copy
from typing import Any

from homeassistant.auth.models import User
from homeassistant.core import HomeAssistant


def _area(gid: str, title: str, levels: list[str], descriptions: dict[str, str]) -> dict[str, Any]:
    labels = {"none": "None", "read": "Read", "full": "Full"}
    return {
        "id": gid,
        "title": title,
        "options": [
            {
                "id": level,
                "label": labels[level],
                "description": descriptions[level],
                **({"scopes": [f"stand_in:{gid}:{level}"]} if level != "none" else {}),
            }
            for level in levels
        ],
    }


def _option(group: dict[str, Any], oid: str) -> dict[str, Any]:
    return next(option for option in group["options"] if option["id"] == oid)


LIGHTS = _area(
    "lights",
    "Lights and switches",
    ["none", "read", "full"],
    {
        "none": "{app} cannot see lights or switches.",
        "read": "{app} can see which lights are on.",
        "full": "{app} can also turn lights on and off.",
    },
)
_option(LIGHTS, "full")["notes"] = [
    {
        "text": "Actions reach further than lights, whatever the other areas say.",
        "when": [{"some_group": "below_highest"}],
    }
]
CAMERAS = _area(
    "cameras",
    "Cameras",
    ["none", "read"],
    {
        "none": "{app} cannot see camera images.",
        "read": "{app} can see what your cameras show.",
    },
)
_option(CAMERAS, "none")["notes"] = [
    {"text": "Cameras still show up as devices.", "when": [{"group": "lights", "in": ["read"]}]},
    {
        "text": "Cameras still show up as devices, and an action can still take a snapshot.",
        "when": [{"group": "lights", "in": ["full"]}],
    },
]
AUTOMATIONS = _area(
    "automations",
    "Automations",
    ["none", "read", "full"],
    {
        "none": "{app} cannot see or change automations.",
        "read": "{app} can see how automations are set up.",
        "full": "{app} can also create, change and delete automations.",
    },
)
TEMPLATES = _area(
    "templates",
    "Templates",
    ["none", "read"],
    {
        "none": "{app} cannot use templates.",
        "read": "{app} can work out values with templates.",
    },
)
_option(TEMPLATES, "read")["notes"] = [
    {
        "text": "Templates can still read what Lights and switches hides.",
        "when": [{"group": "lights", "in": ["none"]}],
    }
]
FILES = _area(
    "files",
    "Config files",
    ["none", "read", "full"],
    {
        "none": "{app} cannot read or change configuration files.",
        "read": "{app} can read your configuration files.",
        "full": "{app} can also change them.",
    },
)


def _preset(pid: str, title: str, description: str, options: dict[str, str]) -> dict[str, Any]:
    return {
        "id": pid,
        "title": title,
        "description": description,
        "options": options,
        "scopes": [f"stand_in:{pid}"],
    }


DESCRIPTION: dict[str, Any] = {
    "resource": ["/api/stand_in", "/api/stand_in_http"],
    "name": "Stand-in",
    "prompt": "Choose what {app} can do in the stand-in.",
    "detail_intro": "For each area, choose None, Read or Full.",
    "scopes": {
        **{
            f"stand_in:{pid}": {"title": title, "description": f"{title} everything."}
            for pid, title in (
                ("read", "Look only"),
                ("control", "Control devices"),
                ("configure", "Edit the setup"),
                ("admin", "Administer"),
            )
        },
        **{
            scope: {"title": scope, "description": f"Grants {scope}."}
            for group in (LIGHTS, CAMERAS, AUTOMATIONS, TEMPLATES, FILES)
            for option in group["options"]
            for scope in option.get("scopes", [])
        },
    },
    "presets": [
        _preset(
            "read",
            "Look only",
            "See devices and settings, without changing anything.",
            {
                "lights": "read",
                "cameras": "read",
                "automations": "read",
                "templates": "read",
                "files": "none",
            },
        ),
        {
            **_preset(
                "control",
                "Control devices",
                "Also turn things on and off.",
                {
                    "lights": "full",
                    "cameras": "read",
                    "automations": "read",
                    "templates": "read",
                    "files": "none",
                },
            ),
            "notes": [{"text": "Actions reach further than lights."}],
        },
        _preset(
            "configure",
            "Edit the setup",
            "Also change automations.",
            {
                "lights": "full",
                "cameras": "read",
                "automations": "full",
                "templates": "read",
                "files": "none",
            },
        ),
        _preset(
            "admin",
            "Administer",
            "Also change configuration files.",
            {
                "lights": "full",
                "cameras": "read",
                "automations": "full",
                "templates": "read",
                "files": "full",
            },
        ),
    ],
    "default_preset": "read",
    "sections": [
        {"id": "devices", "title": "Devices", "groups": [LIGHTS, CAMERAS]},
        {"id": "setup", "title": "Setup", "groups": [AUTOMATIONS, TEMPLATES]},
        {
            "id": "system",
            "title": "System",
            "groups": [FILES],
            "notes": [
                {
                    "text": "Config files reach past the other areas.",
                    "when": [
                        {"group": "files", "in": ["full"]},
                        {"some_group": "below_highest", "except": ["files"]},
                    ],
                },
                {
                    "text": "Config files can be read whatever the other areas say.",
                    "when": [
                        {"group": "files", "in": ["read"]},
                        {"some_group": "at_lowest", "except": ["files"]},
                    ],
                },
            ],
        },
    ],
}

# Group id to the reason it is unavailable right now
UNAVAILABLE: dict[str, str] = {}
# User id to that user's ceiling
CEILINGS: dict[str, dict[str, Any]] = {}
# (function, language) for every call the provider made
CALLS: list[tuple[str, str]] = []


async def async_describe_resource(hass: HomeAssistant, language: str) -> dict[str, Any]:
    """Describe the stand-in, with its name in Swedish when asked for Swedish."""
    CALLS.append(("describe", language))
    description = copy.deepcopy(DESCRIPTION)
    if language == "sv" and isinstance(description, dict):
        description["name"] = "Ersättaren"
    return description


async def async_get_availability(hass: HomeAssistant, language: str) -> dict[str, str]:
    """Say which areas are unavailable right now."""
    CALLS.append(("availability", language))
    return dict(UNAVAILABLE)


async def async_get_ceiling(hass: HomeAssistant, user: User, language: str) -> Any:
    """Say the most this user may grant."""
    CALLS.append(("ceiling", language))
    return copy.deepcopy(CEILINGS.get(user.id))
