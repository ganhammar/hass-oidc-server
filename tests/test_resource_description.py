"""Tests for the resource description contract and its validation."""

import copy

import pytest

from custom_components.oidc_provider.resource_description import (
    InvalidChoice,
    InvalidDescription,
    consent_model,
    existing_sessions_options,
    granted_scopes,
    iter_groups,
    known_options,
    matching_preset,
    reasons_not_allowed,
    resource_matches,
    resources_overlap,
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
    assert description["existing_sessions_preset"] == "control"
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
    """A single resource becomes a list, the first preset is the default, sessions
    from before get no preset unless one is named, and keys this release does not
    know are dropped rather than refused."""
    raw["resource"] = "https://notes.example.com/api"
    del raw["default_preset"]
    del raw["existing_sessions_preset"]
    raw["time_limits"] = ["1h"]
    raw["sections"][0]["groups"][0]["icon"] = "mdi:lightbulb"

    description = validate_description(raw)

    assert description["resource"] == ["https://notes.example.com/api"]
    assert description["default_preset"] == "read"
    assert "existing_sessions_preset" not in description
    assert existing_sessions_options(description, None) is None
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
    "unknown preset for existing sessions": (
        lambda raw: _with(raw, raw.update(existing_sessions_preset="everything")),
        "existing_sessions_preset 'everything' is not one of the presets",
    ),
    "malformed preset for existing sessions": (
        lambda raw: _with(raw, raw.update(existing_sessions_preset=["control"])),
        "expected an id of lower case letters and digits, joined by single - or _ at "
        "existing_sessions_preset",
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


def test_a_choice_that_is_exactly_a_locked_preset_is_refused(description):
    """Locking a preset locks its exact choice, and with it the preset's own scopes."""
    ceiling = validate_ceiling(description, {"locked_presets": ["admin"], "reason": "Not for you."})

    with pytest.raises(InvalidChoice, match="those of preset admin, which is locked"):
        validate_choice(description, ceiling, {"options": ADMIN})

    # A choice a group away from it is checked as before
    near = {**ADMIN, "cameras": "none"}
    assert validate_choice(description, ceiling, {"options": near}) == near
    # So is the same choice without the lock
    assert validate_choice(description, None, {"options": ADMIN}) == ADMIN


CONTROL = {
    "lights": "full",
    "cameras": "read",
    "automations": "read",
    "templates": "read",
    "files": "none",
}


def test_existing_sessions_options_are_the_preset_held_at_the_ceiling(description):
    assert existing_sessions_options(description, None) == CONTROL

    ceiling = validate_ceiling(
        description,
        {
            "groups": {
                "lights": {"max": "read", "reason": "Limited."},
                "cameras": {"max": "none", "reason": "Limited."},
                # At or above the preset's option, so nothing changes there
                "automations": {"max": "read", "reason": "Limited."},
                "files": {"max": "read", "reason": "Limited."},
            },
            "reason": "No.",
        },
    )
    options = existing_sessions_options(description, ceiling)

    assert options == {**CONTROL, "lights": "read", "cameras": "none"}
    assert validate_choice(description, ceiling, {"options": options}) == options
    # The preset itself is left as it is
    assert description["presets"][1]["options"] == CONTROL


def test_existing_sessions_options_of_a_locked_preset_are_refused(description):
    """They are a choice like any other, so locking the preset refuses them."""
    ceiling = validate_ceiling(description, {"locked_presets": ["control"], "reason": "No."})
    options = existing_sessions_options(description, ceiling)

    assert options == CONTROL
    with pytest.raises(InvalidChoice, match="those of preset control, which is locked"):
        validate_choice(description, ceiling, {"options": options})


def test_reasons_a_choice_is_no_longer_allowed_come_from_the_ceiling(description):
    """It is held at the ceiling group by group, and is then a locked preset or not."""
    assert reasons_not_allowed(description, None, ADMIN) == []

    ceiling = validate_ceiling(
        description,
        {
            "groups": {
                "lights": {"max": "read", "reason": "Read only."},
                "automations": {"max": "read", "reason": "Read only."},
                "files": {"max": "read", "reason": "Files are read only."},
            },
            "locked_presets": ["control"],
            "reason": "Not for you.",
        },
    )
    # Each reason once, in the order the groups are shown
    assert reasons_not_allowed(description, ceiling, ADMIN) == [
        "Read only.",
        "Files are read only.",
    ]
    # Held at the ceiling, Control devices is Look only, which is not locked
    assert reasons_not_allowed(description, ceiling, CONTROL) == ["Read only."]
    # A choice the ceiling leaves as it is
    assert reasons_not_allowed(description, ceiling, {**CONTROL, "lights": "read"}) == []

    # Exactly a locked preset, or one once held at the ceiling
    ceiling = validate_ceiling(
        description,
        {
            "groups": {"lights": {"max": "read", "reason": "Read only."}},
            "locked_presets": ["read"],
            "reason": "Not for you.",
        },
    )
    look_only = {**CONTROL, "lights": "read"}
    assert reasons_not_allowed(description, ceiling, look_only) == ["Not for you."]
    assert reasons_not_allowed(description, ceiling, CONTROL) == ["Read only.", "Not for you."]
    # A choice missing a group the description gained is no preset
    partial = {gid: oid for gid, oid in look_only.items() if gid != "files"}
    assert reasons_not_allowed(description, ceiling, partial) == []


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
    ("indicator", "matches"),
    [
        ("https://ha.example.com/api/stand_in", True),
        ("https://ha.example.com/api/stand_in_http", True),
        ("https://ha.example.com/api/stand_in/", False),
        ("https://ha.example.com/api", False),
        ("https://notes.example.com/api", True),
        (None, False),
        # A path names the resource at any address, so which address a request
        # arrives at cannot decide whether the user is asked
        ("https://other.example.com/api/stand_in", True),
        ("http://192.168.1.10:8123/api/stand_in", True),
        ("https://ha.example.com/api/stand_in?x=1", True),
        # Scheme and host in any case, the path exactly (RFC 3986 §6.2.2.1)
        ("HTTPS://HA.Example.COM/api/stand_in", True),
        ("https://Notes.Example.com/api", True),
        ("https://ha.example.com/API/stand_in", False),
        ("https://notes.example.com/API", False),
        ("https://notes.example.com/api?x=1", False),
    ],
)
def test_resource_matches(indicator, matches):
    resources = ["/api/stand_in", "/api/stand_in_http", "https://notes.example.com/api"]
    assert resource_matches(resources, indicator) is matches


@pytest.mark.parametrize(
    ("first", "second", "shared"),
    [
        (["/api/a", "/api/b"], ["/api/b"], ["/api/b"]),
        (["/api/a"], ["https://x.example.com/api/a"], ["/api/a"]),
        (["https://x.example.com/api/a"], ["/api/a"], ["https://x.example.com/api/a"]),
        (
            ["https://x.example.com/api/a"],
            ["HTTPS://X.example.com/api/a"],
            ["https://x.example.com/api/a"],
        ),
        (["/api/a", "https://x.example.com/api"], ["/api/c", "https://y.example.com/api"], []),
    ],
)
def test_resources_overlap(first, second, shared):
    assert resources_overlap(first, second) == shared


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
