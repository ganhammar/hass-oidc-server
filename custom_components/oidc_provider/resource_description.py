"""The description a resource server gives of what it offers.

A resource server, such as another integration that accepts this provider's
access tokens, describes the access a person can grant it: its scopes, presets
of scopes (levels) and groups (areas) in which one option is chosen. The
consent screen renders the description, the person's choice goes into the
access token as scopes, and the resource server enforces them. Nothing here
knows what any scope means.

The description is plain data, so the same model works whoever supplies it.
Everything in this module is pure: it validates descriptions and the answers
a resource gives at consent time, and turns a choice into scopes.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any
from urllib.parse import urlsplit

import voluptuous as vol

from .const import SUPPORTED_SCOPES

# Lower case letters and digits, joined by single hyphens or underscores
_ID_PATTERN = re.compile(r"^[a-z0-9]+(?:[_-][a-z0-9]+)*$")
_ID_MAX_LENGTH = 64
# An OAuth scope token (RFC 6749 §3.3): printable ASCII except space, " and \
_SCOPE_PATTERN = re.compile(r"^[\x21\x23-\x5b\x5d-\x7e]+$")
_SCOPE_MAX_LENGTH = 128

CLAUSE_BELOW_HIGHEST = "below_highest"
CLAUSE_AT_LOWEST = "at_lowest"


class InvalidDescription(ValueError):
    """A description, or a resource's answer about one, breaks the contract."""


def _text(value: Any) -> str:
    """Validate text shown to the person: a string that is not blank."""
    if not isinstance(value, str) or not value.strip():
        raise vol.Invalid("expected text that is not empty")
    return value


def _identifier(value: Any) -> str:
    """Validate an id: lower case letters and digits joined by - or _."""
    if not isinstance(value, str) or len(value) > _ID_MAX_LENGTH or not _ID_PATTERN.match(value):
        raise vol.Invalid(
            "expected an id of lower case letters and digits, joined by single - or _"
        )
    return value


def _scope(value: Any) -> str:
    """Validate a scope token that is not one of the provider's own scopes."""
    if (
        not isinstance(value, str)
        or len(value) > _SCOPE_MAX_LENGTH
        or not _SCOPE_PATTERN.match(value)
    ):
        raise vol.Invalid("expected a scope without spaces, quotes or backslashes")
    if value in SUPPORTED_SCOPES:
        raise vol.Invalid(f"{value} is an OpenID Connect scope of the provider")
    return value


def _resource(value: Any) -> str:
    """Validate where a resource answers: a path on this Home Assistant or a URL.

    A path starts with a single slash and is matched against resource
    indicators on whichever address the authorization request reached Home
    Assistant at. A URL is matched as it is written.
    """
    if not isinstance(value, str):
        raise vol.Invalid("expected a path or URL")
    if value.startswith("/") and not value.startswith("//"):
        parts = urlsplit(value)
        if parts.query or parts.fragment or "?" in value or "#" in value:
            raise vol.Invalid("a resource path cannot have a query or fragment")
        return value
    parts = urlsplit(value)
    if (
        parts.scheme not in ("http", "https")
        or not parts.hostname
        or parts.username is not None
        or parts.fragment
        or "#" in value
    ):
        raise vol.Invalid(
            "expected a path starting with / or an absolute http(s) URL without a fragment"
        )
    return value


def _unique(values: list[str]) -> list[str]:
    """Validate that a list holds no duplicates."""
    duplicates = sorted({value for value in values if values.count(value) > 1})
    if duplicates:
        raise vol.Invalid(f"duplicate entries: {', '.join(duplicates)}")
    return values


_CLAUSE_SCHEMA = vol.Any(
    {
        vol.Required("group"): _identifier,
        vol.Required("in"): vol.All([_identifier], vol.Length(min=1)),
    },
    {
        vol.Required("some_group"): vol.In([CLAUSE_BELOW_HIGHEST, CLAUSE_AT_LOWEST]),
        vol.Optional("except", default=list): [_identifier],
    },
    msg=(
        "expected a condition such as {'group': id, 'in': [option ids]} or "
        "{'some_group': 'below_highest' or 'at_lowest', 'except': [group ids]}"
    ),
)

_NOTE_SCHEMA = {
    vol.Required("text"): _text,
    vol.Optional("when", default=list): [_CLAUSE_SCHEMA],
}

_OPTION_SCHEMA = {
    vol.Required("id"): _identifier,
    vol.Required("label"): _text,
    vol.Required("description"): _text,
    vol.Optional("scopes", default=list): vol.All([_scope], _unique),
    vol.Optional("notes", default=list): [_NOTE_SCHEMA],
}

_GROUP_SCHEMA = {
    vol.Required("id"): _identifier,
    vol.Required("title"): _text,
    vol.Required("options"): vol.All([_OPTION_SCHEMA], vol.Length(min=2)),
}

_SECTION_SCHEMA = {
    vol.Required("id"): _identifier,
    vol.Required("title"): _text,
    vol.Required("groups"): vol.All([_GROUP_SCHEMA], vol.Length(min=1)),
    vol.Optional("notes", default=list): [_NOTE_SCHEMA],
}

_PRESET_SCHEMA = {
    vol.Required("id"): _identifier,
    vol.Required("title"): _text,
    vol.Required("description"): _text,
    vol.Required("options"): vol.Schema({_identifier: _identifier}, extra=vol.PREVENT_EXTRA),
    vol.Optional("scopes"): vol.All([_scope], vol.Length(min=1), _unique),
    vol.Optional("notes", default=list): [_NOTE_SCHEMA],
}

# Keys this release does not know are dropped rather than refused, so a
# description written for a later release still works here.
DESCRIPTION_SCHEMA = vol.Schema(
    {
        vol.Required("resource"): vol.All(
            vol.Any(_resource, [_resource]),
            lambda value: value if isinstance(value, list) else [value],
            vol.Length(min=1),
            _unique,
        ),
        vol.Required("name"): _text,
        vol.Optional("prompt"): _text,
        vol.Optional("detail_intro"): _text,
        vol.Required("scopes"): vol.All(
            vol.Schema(
                {_scope: {vol.Required("title"): _text, vol.Required("description"): _text}},
                extra=vol.PREVENT_EXTRA,
            ),
            vol.Length(min=1),
        ),
        vol.Required("presets"): vol.All([_PRESET_SCHEMA], vol.Length(min=1)),
        vol.Optional("default_preset"): _identifier,
        vol.Required("sections"): vol.All([_SECTION_SCHEMA], vol.Length(min=1)),
    },
    extra=vol.REMOVE_EXTRA,
)


def _reason(err: vol.Invalid) -> str:
    """Return what is wrong and where, such as "expected text at sections[0].title"."""
    where = "".join(f"[{key}]" if isinstance(key, int) else f".{key}" for key in err.path)
    return f"{err.msg} at {where.lstrip('.')}" if where else err.msg


def iter_groups(description: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Yield every group of a validated description, in the order shown."""
    for section in description["sections"]:
        yield from section["groups"]


def _option_ids(group: dict[str, Any]) -> list[str]:
    """Return a group's option ids, from lowest to highest."""
    return [option["id"] for option in group["options"]]


def validate_description(data: Any) -> dict[str, Any]:
    """Return a description in its complete form, or raise InvalidDescription.

    The structure is checked first, then that every reference between its
    parts resolves: presets name an option for every group, notes name groups
    and options that exist, and every scope granted is declared.
    """
    if not isinstance(data, dict):
        raise InvalidDescription("a description must be a dict")
    try:
        description = DESCRIPTION_SCHEMA(data)
    except vol.Invalid as err:
        raise InvalidDescription(_reason(err)) from err

    declared = set(description["scopes"])
    groups: dict[str, dict[str, Any]] = {}
    section_ids: list[str] = []
    for section in description["sections"]:
        section_ids.append(section["id"])
        for group in section["groups"]:
            if group["id"] in groups:
                raise InvalidDescription(f"group '{group['id']}' appears more than once")
            groups[group["id"]] = group
            option_ids = _option_ids(group)
            if len(set(option_ids)) != len(option_ids):
                raise InvalidDescription(f"group '{group['id']}' repeats an option id")
    if len(set(section_ids)) != len(section_ids):
        raise InvalidDescription("a section id appears more than once")

    def check_scopes(scopes: list[str], where: str) -> None:
        unknown = [scope for scope in scopes if scope not in declared]
        if unknown:
            raise InvalidDescription(f"{where} grants undeclared scopes: {', '.join(unknown)}")

    def check_notes(notes: list[dict[str, Any]], where: str) -> None:
        for note in notes:
            for clause in note["when"]:
                if "group" in clause:
                    group = groups.get(clause["group"])
                    if group is None:
                        raise InvalidDescription(
                            f"a note of {where} names unknown group '{clause['group']}'"
                        )
                    unknown = [oid for oid in clause["in"] if oid not in _option_ids(group)]
                    if unknown:
                        raise InvalidDescription(
                            f"a note of {where} names unknown options of group "
                            f"'{clause['group']}': {', '.join(unknown)}"
                        )
                else:
                    unknown = [gid for gid in clause["except"] if gid not in groups]
                    if unknown:
                        raise InvalidDescription(
                            f"a note of {where} names unknown groups: {', '.join(unknown)}"
                        )

    for section in description["sections"]:
        check_notes(section["notes"], f"section '{section['id']}'")
        for group in section["groups"]:
            for option in group["options"]:
                where = f"option '{option['id']}' of group '{group['id']}'"
                check_scopes(option["scopes"], where)
                check_notes(option["notes"], where)

    preset_ids: list[str] = []
    seen_options: dict[tuple[tuple[str, str], ...], str] = {}
    for preset in description["presets"]:
        where = f"preset '{preset['id']}'"
        if preset["id"] in preset_ids:
            raise InvalidDescription(f"{where} appears more than once")
        preset_ids.append(preset["id"])
        missing = [gid for gid in groups if gid not in preset["options"]]
        if missing:
            raise InvalidDescription(f"{where} chooses no option for: {', '.join(missing)}")
        for gid, oid in preset["options"].items():
            if gid not in groups:
                raise InvalidDescription(f"{where} names unknown group '{gid}'")
            if oid not in _option_ids(groups[gid]):
                raise InvalidDescription(f"{where} names unknown option '{oid}' of group '{gid}'")
        # Kept in the order the groups are shown
        preset["options"] = {gid: preset["options"][gid] for gid in groups}
        key = tuple(preset["options"].items())
        if key in seen_options:
            raise InvalidDescription(
                f"{where} chooses the same options as preset '{seen_options[key]}'"
            )
        seen_options[key] = preset["id"]
        check_scopes(preset.get("scopes", []), where)
        check_notes(preset["notes"], where)

    description.setdefault("default_preset", preset_ids[0])
    if description["default_preset"] not in preset_ids:
        raise InvalidDescription(
            f"default_preset '{description['default_preset']}' is not one of the presets"
        )
    return description


def _group_map(description: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {group["id"]: group for group in iter_groups(description)}


def validate_availability(description: dict[str, Any], data: Any) -> dict[str, str]:
    """Return which groups are unavailable right now and why, or raise InvalidDescription.

    The answer maps group ids to the reason shown on the consent screen. A
    group left out is available. None means every group is.
    """
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise InvalidDescription("availability must map group ids to reasons")
    groups = _group_map(description)
    for gid, reason in data.items():
        if gid not in groups:
            raise InvalidDescription(f"availability names unknown group '{gid}'")
        if not isinstance(reason, str) or not reason.strip():
            raise InvalidDescription(f"availability of group '{gid}' needs a reason")
    return dict(data)


def validate_ceiling(description: dict[str, Any], data: Any) -> dict[str, Any] | None:
    """Return the most a user may grant, or raise InvalidDescription.

    groups maps a group id to the highest option the user may choose there
    (max) and why (reason). A group left out has no limit. locked_presets
    names presets the user may not pick, such as every level above the lowest
    while the resource is read-only; a preset that would add nothing the user
    may grant to the one before it is locked as well. reason says why a preset
    is locked and is needed once anything is limited. None, or nothing
    limited, means no ceiling.
    """
    if data is None:
        return None
    if (
        not isinstance(data, dict)
        or not isinstance(data.get("groups", {}), dict)
        or not isinstance(data.get("locked_presets", []), list)
    ):
        raise InvalidDescription(
            "a ceiling must be a dict with a groups dict and a locked_presets list"
        )
    groups = _group_map(description)
    limits = {}
    for gid, limit in data.get("groups", {}).items():
        if gid not in groups:
            raise InvalidDescription(f"the ceiling names unknown group '{gid}'")
        if (
            not isinstance(limit, dict)
            or limit.get("max") not in _option_ids(groups[gid])
            or not isinstance(limit.get("reason"), str)
            or not limit["reason"].strip()
        ):
            raise InvalidDescription(
                f"the ceiling of group '{gid}' needs max, one of its option ids, and a reason"
            )
        limits[gid] = {"max": limit["max"], "reason": limit["reason"]}
    preset_ids = [preset["id"] for preset in description["presets"]]
    locked = [pid for pid in preset_ids if pid in data.get("locked_presets", [])]
    unknown = [pid for pid in data.get("locked_presets", []) if pid not in preset_ids]
    if unknown:
        raise InvalidDescription(
            f"the ceiling locks unknown presets: {', '.join(map(str, unknown))}"
        )
    if len(locked) == len(preset_ids):
        raise InvalidDescription("a ceiling cannot lock every preset")
    if not limits and not locked:
        return None
    reason = data.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        raise InvalidDescription("a ceiling that limits anything needs a reason for locked presets")
    return {"groups": limits, "locked_presets": locked, "reason": reason}


class InvalidChoice(ValueError):
    """The access chosen on the consent screen does not fit the description."""


def validate_choice(
    description: dict[str, Any], ceiling: dict[str, Any] | None, choice: Any
) -> dict[str, str]:
    """Return the option chosen for every group, or raise InvalidChoice.

    The choice is {"options": {group id: option id}} with one option for every
    group, none of them above the ceiling.
    """
    if not isinstance(choice, dict) or not isinstance(choice.get("options"), dict):
        raise InvalidChoice("expected an options dict")
    chosen = choice["options"]
    groups = _group_map(description)
    if set(chosen) != set(groups):
        raise InvalidChoice("expected one option for every group")
    limits = (ceiling or {}).get("groups", {})
    options = {}
    for gid, group in groups.items():
        ids = _option_ids(group)
        if chosen[gid] not in ids:
            raise InvalidChoice(f"unknown option for group {gid}")
        limit = limits.get(gid)
        if limit is not None and ids.index(chosen[gid]) > ids.index(limit["max"]):
            raise InvalidChoice(f"the option for group {gid} is above the ceiling")
        options[gid] = chosen[gid]
    return options


def known_options(description: dict[str, Any], options: Any) -> dict[str, str]:
    """Return the entries of a stored choice that still name a group and option."""
    if not isinstance(options, dict):
        return {}
    groups = _group_map(description)
    return {
        gid: oid
        for gid, oid in options.items()
        if gid in groups and oid in _option_ids(groups[gid])
    }


def granted_scopes(description: dict[str, Any], options: dict[str, str]) -> list[str]:
    """Return the scopes a complete choice grants.

    A choice that is exactly a preset with its own scopes grants those, which
    keeps the common case short. Any other choice grants the scopes of each
    chosen option, in the order the groups are shown.
    """
    for preset in description["presets"]:
        if preset["options"] == options and "scopes" in preset:
            return list(preset["scopes"])
    scopes: list[str] = []
    for group in iter_groups(description):
        option = next(option for option in group["options"] if option["id"] == options[group["id"]])
        scopes.extend(scope for scope in option["scopes"] if scope not in scopes)
    return scopes


def matching_preset(description: dict[str, Any], options: dict[str, str]) -> str | None:
    """Return the id of the preset a choice is exactly, if any."""
    return next(
        (preset["id"] for preset in description["presets"] if preset["options"] == options),
        None,
    )


def resource_matches(resources: list[str], indicator: str | None, base_url: str) -> bool:
    """Return whether a resource indicator (RFC 8707) names a described resource.

    A path is matched on the address the authorization request reached Home
    Assistant at, which is where a resource server on this Home Assistant
    answers too; a URL is matched as written.
    """
    if not indicator:
        return False
    base = base_url.rstrip("/")
    return any(
        indicator == (f"{base}{resource}" if resource.startswith("/") else resource)
        for resource in resources
    )


def _without_scopes(entry: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in entry.items() if key != "scopes"}


def consent_model(description: dict[str, Any]) -> dict[str, Any]:
    """Return what the consent screen needs of a description.

    Scopes stay on the server: the screen shows what each choice means, in
    the resource's words, and the server turns the choice into scopes.
    """
    model = {
        key: description[key]
        for key in ("name", "prompt", "detail_intro", "default_preset")
        if key in description
    }
    model["presets"] = [_without_scopes(preset) for preset in description["presets"]]
    model["sections"] = [
        {
            **section,
            "groups": [
                {
                    **group,
                    "options": [_without_scopes(option) for option in group["options"]],
                }
                for group in section["groups"]
            ],
        }
        for section in description["sections"]
    ]
    return model
