"""Tests for the resource description contract and its validation."""

import copy

import pytest

from custom_components.oidc_provider.resource_description import (
    InvalidChoice,
    InvalidDescription,
    consent_model,
    granted_scopes,
    iter_groups,
    known_options,
    matching_preset,
    resource_matches,
    validate_availability,
    validate_ceiling,
    validate_choice,
    validate_description,
)


@pytest.fixture
def raw(stand_in):
    """The stand-in's description as it supplies it, safe to change."""
    return copy.deepcopy(stand_in.DESCRIPTION)


@pytest.fixture
def description(raw):
    return validate_description(raw)


ADMIN = {
    "lights": "full",
    "cameras": "read",
    "automations": "full",
    "templates": "read",
    "files": "full",
}


def test_stand_in_description_is_valid_and_complete(description):
    """Defaults are filled in so every part can be read without checking for it."""
    assert description["resource"] == ["/api/stand_in", "/api/stand_in_http"]
    assert description["default_preset"] == "read"
    assert [group["id"] for group in iter_groups(description)] == [
        "lights",
        "cameras",
        "automations",
        "templates",
        "files",
    ]
    lights = description["sections"][0]["groups"][0]
    assert lights["options"][0]["scopes"] == []
    assert lights["options"][0]["notes"] == []
    assert description["sections"][0]["notes"] == []
    assert description["presets"][0]["notes"] == []
    clause = description["sections"][2]["notes"][0]["when"][1]
    assert clause == {"some_group": "below_highest", "except": ["files"]}
    note = lights["options"][2]["notes"][0]
    assert note["when"] == [{"some_group": "below_highest", "except": []}]


def test_single_resource_default_preset_and_unknown_keys(raw):
    """A single resource becomes a list, the first preset is the default, and
    keys this release does not know are dropped rather than refused."""
    raw["resource"] = "https://notes.example.com/api"
    del raw["default_preset"]
    raw["time_limits"] = ["1h"]
    raw["sections"][0]["groups"][0]["icon"] = "mdi:lightbulb"

    description = validate_description(raw)

    assert description["resource"] == ["https://notes.example.com/api"]
    assert description["default_preset"] == "read"
    assert "time_limits" not in description
    assert "icon" not in description["sections"][0]["groups"][0]


@pytest.mark.parametrize(
    "resource",
    ["/api/stand_in/", "/api/v1.0/x", "/api/..x", "https://notes.example.com", "http://[::1]/api"],
)
def test_resources_that_only_look_unusual_are_accepted(raw, resource):
    raw["resource"] = resource

    assert validate_description(raw)["resource"] == [resource]


def _with(raw, *_changes):
    """Return raw once the changes passed as arguments have been made to it."""
    return raw


def _group(raw, index):
    return [group for section in raw["sections"] for group in section["groups"]][index]


MALFORMED = {
    "not a dict": (lambda raw: None, "a description must be a dict"),
    "missing name": (
        lambda raw: _with(raw, raw.pop("name")),
        "required key not provided at name",
    ),
    "blank title": (
        lambda raw: _with(raw, raw["sections"][0].update(title="  ")),
        "expected text that is not empty",
    ),
    "bad id": (
        lambda raw: _with(raw, _group(raw, 0).update(id="Lights")),
        "expected an id of lower case letters",
    ),
    "scope with a space": (
        lambda raw: _with(
            raw, raw["scopes"].update({"bad scope": {"title": "t", "description": "d"}})
        ),
        "expected a scope without spaces, quotes or backslashes at scopes.bad scope",
    ),
    "scope with a trailing newline": (
        lambda raw: _with(
            raw, raw["scopes"].update({"stand_in:evil\n": {"title": "t", "description": "d"}})
        ),
        "expected a scope without spaces, quotes or backslashes",
    ),
    "openid as a resource scope": (
        lambda raw: _with(raw, raw["presets"][0].update(scopes=["openid"])),
        "openid is an OpenID Connect scope",
    ),
    "id with a trailing newline": (
        lambda raw: _with(raw, raw["sections"][0].update(id="devices\n")),
        "expected an id of lower case letters",
    ),
    "relative resource": (lambda raw: _with(raw, raw.update(resource="api/x")), "expected a path"),
    "resource with a trailing newline": (
        lambda raw: _with(raw, raw.update(resource="/api/stand_in\n")),
        "a resource cannot contain whitespace or control characters",
    ),
    "resource with a space": (
        lambda raw: _with(raw, raw.update(resource="/api/stand in")),
        "a resource cannot contain whitespace or control characters",
    ),
    "resource with a control character": (
        lambda raw: _with(raw, raw.update(resource="https://notes.example.com/api\x00")),
        "a resource cannot contain whitespace or control characters",
    ),
    "root as a resource": (
        lambda raw: _with(raw, raw.update(resource="/")),
        "a resource path must name more than /",
    ),
    "resource path with a .. segment": (
        lambda raw: _with(raw, raw.update(resource="/api/../auth/token")),
        "a resource cannot have . or .. segments",
    ),
    "resource path with an encoded .. segment": (
        lambda raw: _with(raw, raw.update(resource="/api/%2E%2e/auth/token")),
        "a resource cannot have . or .. segments",
    ),
    "resource path with a . segment": (
        lambda raw: _with(raw, raw.update(resource="/api/./stand_in")),
        "a resource cannot have . or .. segments",
    ),
    "resource URL with a .. segment": (
        lambda raw: _with(raw, raw.update(resource="https://notes.example.com/api/../admin")),
        "a resource cannot have . or .. segments",
    ),
    "network path resource": (
        lambda raw: _with(raw, raw.update(resource="//host/x")),
        "expected a path",
    ),
    "resource path with a query": (
        lambda raw: _with(raw, raw.update(resource=["/api/x?debug"])),
        "a resource path cannot have a query or fragment at resource[0]",
    ),
    "ftp resource": (
        lambda raw: _with(raw, raw.update(resource="ftp://host/x")),
        "expected a path",
    ),
    "resource with userinfo": (
        lambda raw: _with(raw, raw.update(resource="https://user@host/x")),
        "expected a path",
    ),
    "resource with a fragment": (
        lambda raw: _with(raw, raw.update(resource="https://host/x#y")),
        "expected a path",
    ),
    "resource not a string": (lambda raw: _with(raw, raw.update(resource=5)), "expected a path"),
    "repeated resource": (
        lambda raw: _with(raw, raw.update(resource=["/api/x", "/api/x"])),
        "duplicate entries: /api/x",
    ),
    "no resource": (
        lambda raw: _with(raw, raw.update(resource=[])),
        "length of value must be at least 1",
    ),
    "group with one option": (
        lambda raw: _with(raw, _group(raw, 1).update(options=_group(raw, 1)["options"][:1])),
        "length of value must be at least 2",
    ),
    "repeated group": (
        lambda raw: _with(raw, raw["sections"][1]["groups"].append(copy.deepcopy(_group(raw, 0)))),
        "group 'lights' appears more than once",
    ),
    "repeated option": (
        lambda raw: _with(
            raw, _group(raw, 1)["options"].append(copy.deepcopy(_group(raw, 1)["options"][0]))
        ),
        "group 'cameras' repeats an option id",
    ),
    "repeated section": (
        lambda raw: _with(raw, raw["sections"][1].update(id="devices")),
        "a section id appears more than once",
    ),
    "undeclared option scope": (
        lambda raw: _with(raw, _group(raw, 0)["options"][1].update(scopes=["stand_in:other"])),
        "option 'read' of group 'lights' grants undeclared scopes: stand_in:other",
    ),
    "repeated option scope": (
        lambda raw: _with(
            raw,
            _group(raw, 0)["options"][1].update(
                scopes=["stand_in:lights:read", "stand_in:lights:read"]
            ),
        ),
        "duplicate entries",
    ),
    "undeclared preset scope": (
        lambda raw: _with(raw, raw["presets"][0].update(scopes=["stand_in:everything"])),
        "preset 'read' grants undeclared scopes: stand_in:everything",
    ),
    "preset missing a group": (
        lambda raw: _with(raw, raw["presets"][0]["options"].pop("files")),
        "preset 'read' chooses no option for: files",
    ),
    "preset with an unknown group": (
        lambda raw: _with(raw, raw["presets"][0]["options"].update(garden="read")),
        "preset 'read' names unknown group 'garden'",
    ),
    "preset with an unknown option": (
        lambda raw: _with(raw, raw["presets"][0]["options"].update(cameras="full")),
        "preset 'read' names unknown option 'full' of group 'cameras'",
    ),
    "repeated preset": (
        lambda raw: _with(raw, raw["presets"][1].update(id="read")),
        "preset 'read' appears more than once",
    ),
    "presets that are the same choice": (
        lambda raw: _with(
            raw, raw["presets"][1].update(options=dict(raw["presets"][0]["options"]))
        ),
        "preset 'control' chooses the same options as preset 'read'",
    ),
    "unknown default preset": (
        lambda raw: _with(raw, raw.update(default_preset="everything")),
        "default_preset 'everything' is not one of the presets",
    ),
    "note on an unknown group": (
        lambda raw: _with(raw, raw["sections"][2]["notes"][0]["when"][0].update(group="garden")),
        "a note of section 'system' names unknown group 'garden'",
    ),
    "note on an unknown option": (
        lambda raw: _with(
            raw, raw["presets"][1]["notes"][0].update(when=[{"group": "cameras", "in": ["full"]}])
        ),
        "a note of preset 'control' names unknown options of group 'cameras': full",
    ),
    "note excepting an unknown group": (
        lambda raw: _with(
            raw, _group(raw, 0)["options"][2]["notes"][0]["when"][0].update({"except": ["garden"]})
        ),
        "a note of option 'full' of group 'lights' names unknown groups: garden",
    ),
    "malformed condition": (
        lambda raw: _with(raw, raw["sections"][2]["notes"][0]["when"].append({"group": "files"})),
        "expected a condition such as",
    ),
    "unknown quantifier": (
        lambda raw: _with(
            raw, raw["sections"][2]["notes"][0]["when"].append({"some_group": "most"})
        ),
        "expected a condition such as",
    ),
}


@pytest.mark.parametrize("case", MALFORMED.values(), ids=MALFORMED.keys())
def test_malformed_descriptions_are_refused_with_the_reason(raw, case):
    change, message = case

    with pytest.raises(InvalidDescription) as err:
        validate_description(change(raw))

    assert message in str(err.value)


def test_availability(description):
    assert validate_availability(description, None) == {}
    assert validate_availability(description, {"files": "Turned off."}) == {"files": "Turned off."}
    for data, message in (
        (["files"], "availability must map group ids to reasons"),
        ({"garden": "Off."}, "unknown group 'garden'"),
        ({"files": " "}, "availability of group 'files' needs a reason"),
        ({"files": None}, "availability of group 'files' needs a reason"),
    ):
        with pytest.raises(InvalidDescription, match=message):
            validate_availability(description, data)


def test_ceiling(description):
    assert validate_ceiling(description, None) is None
    assert validate_ceiling(description, {"groups": {}}) is None
    assert validate_ceiling(description, {}) is None
    ceiling = {
        "groups": {"files": {"max": "read", "reason": "Limited.", "extra": 1}},
        "reason": "Not for you.",
    }
    assert validate_ceiling(description, ceiling) == {
        "groups": {"files": {"max": "read", "reason": "Limited."}},
        "locked_presets": [],
        "reason": "Not for you.",
    }
    # Presets can be locked by name, as for a resource in a read-only mode
    read_only = {"locked_presets": ["admin", "control"], "reason": "Read-only mode."}
    assert validate_ceiling(description, read_only) == {
        "groups": {},
        "locked_presets": ["control", "admin"],
        "reason": "Read-only mode.",
    }
    assert validate_ceiling(description, {"locked_presets": []}) is None
    for data, message in (
        ("files", "a ceiling must be a dict"),
        ({"groups": ["files"]}, "a ceiling must be a dict"),
        ({"locked_presets": "admin"}, "a ceiling must be a dict"),
        ({"locked_presets": ["everything"], "reason": "r"}, "locks unknown presets: everything"),
        (
            {"locked_presets": ["read", "control", "configure", "admin"], "reason": "r"},
            "cannot lock every preset",
        ),
        ({"locked_presets": ["admin"]}, "needs a reason for locked"),
        ({"groups": {"garden": {}}}, "unknown group 'garden'"),
        ({"groups": {"files": {"max": "most", "reason": "r"}}}, "needs max"),
        ({"groups": {"files": {"max": "read"}}}, "needs max"),
        ({"groups": {"files": "read"}}, "needs max"),
        ({"groups": {"files": {"max": "read", "reason": "r"}}}, "needs a reason for locked"),
    ):
        with pytest.raises(InvalidDescription, match=message):
            validate_ceiling(description, data)


def test_choice(description):
    ceiling = validate_ceiling(
        description,
        {"groups": {"files": {"max": "read", "reason": "Limited."}}, "reason": "No."},
    )
    choice = {"options": {**ADMIN, "files": "read"}}
    assert validate_choice(description, ceiling, choice) == {**ADMIN, "files": "read"}
    assert validate_choice(description, None, {"options": ADMIN}) == ADMIN

    for data, message in (
        (None, "expected an options dict"),
        ({"options": ["files"]}, "expected an options dict"),
        ({"options": {"files": "read"}}, "one option for every group"),
        ({"options": {**ADMIN, "garden": "read"}}, "one option for every group"),
        ({"options": {**ADMIN, "cameras": "full"}}, "unknown option for group cameras"),
        ({"options": ADMIN}, "the option for group files is above the ceiling"),
    ):
        with pytest.raises(InvalidChoice, match=message):
            validate_choice(description, ceiling, data)


def test_known_options_drop_what_the_description_no_longer_has(description):
    stored = {"lights": "full", "cameras": "full", "garden": "read", "files": "none"}
    assert known_options(description, stored) == {"lights": "full", "files": "none"}
    assert known_options(description, None) == {}


def test_granted_scopes(description):
    """A choice that is exactly a preset grants the preset's scopes; any
    other choice grants the scopes of its options."""
    assert granted_scopes(description, ADMIN) == ["stand_in:admin"]
    assert granted_scopes(description, {**ADMIN, "cameras": "none", "files": "read"}) == [
        "stand_in:lights:full",
        "stand_in:automations:full",
        "stand_in:templates:read",
        "stand_in:files:read",
    ]

    del description["presets"][3]["scopes"]
    assert granted_scopes(description, ADMIN) == [
        "stand_in:lights:full",
        "stand_in:cameras:read",
        "stand_in:automations:full",
        "stand_in:templates:read",
        "stand_in:files:full",
    ]


def test_options_sharing_a_scope_grant_it_once(raw):
    raw["sections"][0]["groups"][1]["options"][1]["scopes"] = ["stand_in:lights:read"]
    description = validate_description(raw)
    options = {**ADMIN, "lights": "read", "files": "none"}
    assert granted_scopes(description, options) == [
        "stand_in:lights:read",
        "stand_in:automations:full",
        "stand_in:templates:read",
    ]


def test_matching_preset(description):
    assert matching_preset(description, ADMIN) == "admin"
    assert matching_preset(description, {**ADMIN, "files": "read"}) is None


@pytest.mark.parametrize(
    ("indicator", "base", "matches"),
    [
        ("https://ha.example.com/api/stand_in", "https://ha.example.com", True),
        ("https://ha.example.com/api/stand_in_http", "https://ha.example.com/", True),
        ("https://other.example.com/api/stand_in", "https://ha.example.com", False),
        ("https://ha.example.com/api/stand_in/", "https://ha.example.com", False),
        ("https://notes.example.com/api", "https://ha.example.com", True),
        (None, "https://ha.example.com", False),
    ],
)
def test_resource_matches(indicator, base, matches):
    resources = ["/api/stand_in", "/api/stand_in_http", "https://notes.example.com/api"]
    assert resource_matches(resources, indicator, base) is matches


def test_consent_model_leaves_scopes_and_resources_on_the_server(description):
    model = consent_model(description)

    assert set(model) == {
        "name",
        "prompt",
        "detail_intro",
        "default_preset",
        "presets",
        "sections",
    }
    assert "scopes" not in model["presets"][0]
    assert model["presets"][0]["options"] == description["presets"][0]["options"]
    option = model["sections"][0]["groups"][0]["options"][1]
    assert option == {
        "id": "read",
        "label": "Read",
        "description": "{app} can see which lights are on.",
        "notes": [],
    }
    # The description itself is untouched
    assert description["presets"][0]["scopes"] == ["stand_in:read"]
