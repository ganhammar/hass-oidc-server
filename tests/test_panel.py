"""Tests for the login panel: its text, and its script run without a browser."""

import copy
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from homeassistant.core import HomeAssistant

from custom_components.oidc_provider.http import OIDCStringsView, async_panel_strings
from custom_components.oidc_provider.resource_description import (
    InvalidChoice,
    consent_model,
    known_options,
    validate_ceiling,
    validate_choice,
    validate_description,
)

COMPONENT = Path(__file__).parent.parent / "custom_components" / "oidc_provider"
PANEL = COMPONENT / "www" / "oidc-auth-panel.js"
HARNESS = Path(__file__).parent / "panel_harness.js"
NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="running the panel's script needs Node.js")

LOOK_ONLY = {
    "lights": "read",
    "cameras": "read",
    "automations": "read",
    "templates": "read",
    "files": "none",
}
CONTROL = {**LOOK_ONLY, "lights": "full"}
ADMIN = {**CONTROL, "automations": "full", "files": "full"}


async def test_panel_strings_come_from_the_translations(
    enable_custom_integrations: None, hass: HomeAssistant
):
    strings = await async_panel_strings(hass, "en")

    assert strings["consent.heading"] == "Approve access?"
    assert strings["consent.alert"] == (
        "You're about to give {client} access to your Home Assistant instance."
    )
    assert strings["access.choose_in_detail"] == "Choose in detail"
    assert all("." in key and not key.startswith("component.") for key in strings)


async def test_panel_strings_fall_back_to_english(
    enable_custom_integrations: None, hass: HomeAssistant
):
    """Only English ships, so every other language gets the English text."""
    assert await async_panel_strings(hass, "sv") == await async_panel_strings(hass, "en")


async def test_strings_view_answers_in_the_language_asked_for(
    enable_custom_integrations: None, hass: HomeAssistant
):
    request = MagicMock()
    request.app = {"hass": hass}
    request.query = {"language": "nl"}

    response = await OIDCStringsView().get(request)

    data = json.loads(response.body)
    assert data["language"] == "nl"
    assert data["strings"]["sessions.heading"] == "Connected applications"

    request.query = {"language": "klingon"}
    response = await OIDCStringsView().get(request)
    assert json.loads(response.body)["language"] == hass.config.language


def test_the_panel_bundles_the_english_of_the_translations():
    """The panel falls back to its own English when its text cannot be loaded, so
    it carries every string of translations/en.json, and the same words."""
    bundled = re.search(r"const FALLBACK_STRINGS = (\{.*?\n\});", PANEL.read_text(), re.S)
    english = json.loads((COMPONENT / "translations" / "en.json").read_text())["config_panel"]

    assert json.loads(bundled.group(1)) == {
        f"{section}.{key}": text
        for section, strings in english.items()
        for key, text in strings.items()
    }


def test_strings_view_needs_a_signed_in_user():
    assert OIDCStringsView.requires_auth is True
    assert OIDCStringsView.url == "/api/oidc_provider/strings"


# --- The panel's script -------------------------------------------------------


def _run_panel(test: str, **values: Any) -> Any:
    """Run a test against the panel's script and return what the test returns.

    The test is the body of an async function with the panel's top-level names
    in scope, and each value is given to it as a constant of the same name.
    """
    prelude = "".join(f"const {name} = {json.dumps(value)};\n" for name, value in values.items())
    result = subprocess.run(
        [NODE, str(HARNESS), str(PANEL)],
        input=prelude + test,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def _access_model(stand_in, ceiling=None, *, remembered=None, raw=None) -> dict[str, Any]:
    """Return what the consent endpoint gives the panel of the stand-in's resource."""
    description = validate_description(raw or copy.deepcopy(stand_in.DESCRIPTION))
    return {
        "resource": "oidc_stand_in",
        **consent_model(description),
        "unavailable": {},
        "ceiling": validate_ceiling(description, ceiling),
        "remembered": remembered,
    }


OPENING = """
const access = new AccessChoice(model);
return {
  selected: access.selected,
  rows: access.rows,
  locked: [...access.locked],
  lastChoice: access.lastChoice,
};
"""


@needs_node
def test_a_locked_presets_choice_cannot_be_approved_from_the_detailed_view(stand_in):
    model = _access_model(stand_in, {"locked_presets": ["admin"], "reason": "Not for you."})

    result = _run_panel(
        """
        const access = new AccessChoice(model);
        const panel = new OidcLoginPanel();
        panel._access = access;
        panel.querySelectorAll = () => [];
        const approvals = [];
        panel._decide = async (approve) => approvals.push(access.rows);
        for (const [group, option] of Object.entries(admin)) {
          access.chooseOption(group, option);
        }
        const selected = access.selected;
        const locked = access.lockedChoice(access.rows).id;
        await panel._onDecision(true);
        access.chooseOption('cameras', 'none');
        await panel._onDecision(true);
        return { selected, locked, approvals, stillLocked: access.lockedChoice(access.rows) };
        """,
        model=model,
        admin=ADMIN,
    )

    # The screen calls it Custom, and says why it cannot be approved
    assert result["selected"] == "_custom"
    assert result["locked"] == "admin"
    # Only the choice that differs from the locked level was approved
    assert result["approvals"] == [{**ADMIN, "cameras": "none"}]
    assert result["stillLocked"] is None


@needs_node
def test_the_screen_does_not_open_on_a_locked_default(stand_in):
    model = _access_model(stand_in, {"locked_presets": ["read"], "reason": "Not for you."})

    result = _run_panel(OPENING, model=model)

    # Nothing is below the lowest level, so the nearest one above it
    assert result["selected"] == "control"
    assert result["rows"] == CONTROL

    raw = copy.deepcopy(stand_in.DESCRIPTION)
    raw["default_preset"] = "configure"
    model = _access_model(stand_in, {"locked_presets": ["configure"], "reason": "No."}, raw=raw)

    result = _run_panel(OPENING, model=model)

    # The nearest open level below a locked default comes first
    assert result["selected"] == "control"


@needs_node
def test_a_last_choice_that_is_now_a_locked_level_is_not_preselected(stand_in):
    model = _access_model(stand_in, remembered=ADMIN)
    assert _run_panel(OPENING, model=model)["lastChoice"] == "admin"

    model = _access_model(
        stand_in, {"locked_presets": ["admin"], "reason": "Not for you."}, remembered=ADMIN
    )

    result = _run_panel(OPENING, model=model)

    assert result["selected"] == "read"
    assert result["rows"] == LOOK_ONLY
    assert result["lastChoice"] is None


@needs_node
def test_a_level_held_at_a_locked_levels_choice_is_locked_too(stand_in):
    """Held at the ceiling, a level could otherwise land on a choice the server refuses."""
    raw = copy.deepcopy(stand_in.DESCRIPTION)
    read, control, configure, admin = raw["presets"]
    raw["presets"] = [read, control, admin, configure]
    ceiling = {
        "groups": {"files": {"max": "none", "reason": "Limited."}},
        "locked_presets": ["configure"],
        "reason": "Not for you.",
    }

    result = _run_panel(OPENING, model=_access_model(stand_in, ceiling, raw=raw))

    assert set(result["locked"]) == {"admin", "configure"}
    description = validate_description(raw)
    with pytest.raises(InvalidChoice, match="which is locked"):
        validate_choice(
            description,
            validate_ceiling(description, ceiling),
            {"options": {**ADMIN, "files": "none"}},
        )


@needs_node
def test_the_bundled_english_stands_in_when_the_text_cannot_be_loaded():
    result = _run_panel("""
        const panel = new OidcLoginPanel();
        panel._fetchJson = async () => {
          throw Object.assign(new Error('500 Internal Server Error'), { status: 500 });
        };
        await panel._loadStrings();
        const failed = [panel._t('consent.heading'), panel._t('sessions.heading')];
        panel._fetchJson = async () => ({ strings: { 'consent.heading': 'Godkänn åtkomst?' } });
        await panel._loadStrings();
        return { failed, loaded: [panel._t('consent.heading'), panel._t('consent.deny')] };
        """)

    assert result["failed"] == ["Approve access?", "Connected applications"]
    # Loaded text wins, and English fills in what it lacks
    assert result["loaded"] == ["Godkänn åtkomst?", "Deny"]


@needs_node
def test_names_are_spliced_into_text_as_written():
    """A $ pattern in a client's name is not a replacement pattern."""
    result = _run_panel(
        """
        const panel = new OidcLoginPanel();
        panel._details = { client_name: name };
        return [
          panel._res('{app} can see {app}.'),
          panel._resText('Ask {app}'),
          panel._t('access.prompt', { app: name }),
          panel._t('access.prompt', { app: markup(panel._appName()) }),
        ];
        """,
        name="Bot $& $' $1 <b>",
    )

    escaped = "Bot $&amp; $&#39; $1 &lt;b&gt;"
    assert result == [
        f"<bdi>{escaped}</bdi> can see <bdi>{escaped}</bdi>.",
        f"Ask {escaped}",
        f"Choose what {escaped} can do.",
        f"Choose what <bdi>{escaped}</bdi> can do.",
    ]


RELOAD = """
const panel = new OidcLoginPanel();
panel._requestId = 'req';
panel._hass = { locale: { language: 'en' } };
const shown = [];
panel._renderAccess = () => {
  const access = panel._access;
  shown.push({ view: access.view, rows: access.rows, selected: access.selected });
};
panel._renderCard = () => shown.push('plain');
panel._wireDecision = () => {};
panel.querySelectorAll = () => [];
panel._renderError = (error) => shown.push(error.message);
const requests = [];
panel._fetchJson = async (url, init = {}) => {
  requests.push(`${init.method || 'GET'} ${url}`);
  if (init.method === 'POST') {
    throw Object.assign(new Error('400 Invalid access choice'), { status: 400 });
  }
  if (now === null) {
    throw Object.assign(new Error('400 Invalid or expired request'), { status: 400 });
  }
  return now;
};
panel._renderConsent(before);
panel._access.view = 'detailed';
for (const [group, option] of Object.entries(chosen)) {
  panel._access.chooseOption(group, option);
}
await panel._onDecision(true);
return {
  requests,
  shown: shown.slice(1),
  notice: panel._notice || null,
  deciding: panel._deciding,
};
"""


def _details(access):
    return {
        "client_name": "App",
        "redirect_host": "app.example.com",
        "scopes": ["openid", "profile"],
        "consent_required": True,
        "client_host": None,
        "redirect_is_loopback": False,
        **({"access": access} if access else {}),
    }


@needs_node
def test_a_refused_approval_shows_the_screen_again_from_the_current_access(stand_in):
    """The ceiling was lowered after the screen loaded: the choice is kept as far as it
    still fits, the view too, and a notice says what happened."""
    before = _details(_access_model(stand_in))
    now = _details(
        _access_model(
            stand_in,
            {
                "groups": {"lights": {"max": "read", "reason": "Limited."}},
                "reason": "Not for you.",
            },
        )
    )

    result = _run_panel(RELOAD, before=before, now=now, chosen={**CONTROL, "cameras": "none"})

    # The request is read again at an address of its own, since the service
    # worker would answer the address it was first read at from its cache
    refused, again = result["requests"]
    assert refused == "POST /oidc/continue"
    assert re.fullmatch(r"GET /oidc/continue\?request_id=req&language=en&again=\d+", again)
    assert result["shown"] == [
        {"view": "detailed", "rows": {**LOOK_ONLY, "cameras": "none"}, "selected": "_custom"}
    ]
    assert result["notice"] == (
        "The access you can allow changed after this page opened. "
        "Check your choice and approve again."
    )
    assert result["deciding"] is False

    # A resource that no longer offers a choice gets the plain screen
    result = _run_panel(RELOAD, before=before, now=_details(None), chosen=CONTROL)

    assert result["shown"] == ["plain"]
    assert result["notice"] is not None


@needs_node
def test_a_refused_approval_of_a_request_that_is_gone_shows_the_error(stand_in):
    before = _details(_access_model(stand_in))

    result = _run_panel(RELOAD, before=before, now=None, chosen=CONTROL)

    assert result["shown"] == ["400 Invalid access choice"]
    assert result["notice"] is None


# --- Changing a session's access ----------------------------------------------


def _change_model(stand_in, ceiling=None, *, current=None, remembered=None) -> dict[str, Any]:
    """Return what the session access endpoint gives the panel of the stand-in's resource."""
    return {**_access_model(stand_in, ceiling, remembered=remembered), "current": current}


CUSTOM = {**LOOK_ONLY, "cameras": "none", "files": "read"}


@needs_node
def test_changing_access_opens_on_the_sessions_current_choice(stand_in):
    opening = """
    const access = new AccessChoice(model, model.current);
    return { selected: access.selected, rows: access.rows, lastChoice: access.lastChoice };
    """

    result = _run_panel(opening, model=_change_model(stand_in, current=CUSTOM))
    assert result == {"selected": "_custom", "rows": CUSTOM, "lastChoice": None}

    # The ceiling as it is now holds the choice down
    ceiling = {"groups": {"files": {"max": "none", "reason": "Limited."}}, "reason": "No."}
    result = _run_panel(opening, model=_change_model(stand_in, ceiling, current=ADMIN))
    assert result["rows"] == {**ADMIN, "files": "none"}
    assert result["selected"] == "configure"

    # A choice that is now a locked level's gives way to the default
    locked = {"locked_presets": ["admin"], "reason": "Not for you."}
    result = _run_panel(opening, model=_change_model(stand_in, locked, current=ADMIN))
    assert (result["selected"], result["rows"]) == ("read", LOOK_ONLY)

    # Without current options, the choice opens as the consent screen would
    result = _run_panel(opening, model=_change_model(stand_in, remembered=CONTROL))
    assert (result["selected"], result["lastChoice"]) == ("control", "control")


CHANGE = """
const panel = new OidcLoginPanel();
panel._hass = { locale: { language: 'en' } };
panel._home = true;
panel._tab = 'sessions';
const shown = [];
panel._renderAccess = () => {
  const access = panel._access;
  shown.push({
    view: access.view,
    rows: access.rows,
    selected: access.selected,
    notice: panel._notice || null,
    heading: panel._choiceHeading(),
  });
};
panel._showTab = async (tab, notice = '') => {
  panel._changing = null;
  shown.push({ tab, notice });
};
panel.querySelectorAll = () => [];
panel._renderError = (error) => shown.push(error.message);
const requests = [];
panel._fetchJson = async (url, init = {}) => {
  requests.push([init.method || 'GET', url, init.body ? JSON.parse(init.body) : null]);
  const answer = answers.shift();
  if (answer.status) {
    throw Object.assign(new Error(`${answer.status} refused`), { status: answer.status });
  }
  return answer;
};
await panel._openChange(session);
"""

SESSION = {
    "session_id": "sid",
    "client_name": "App $&",
    "client_host": "app.example.com",
    "signed_in_at": None,
    "last_used_at": None,
    "access_offered_by": "oidc_stand_in",
}
ACCESS_URL = "/api/oidc_provider/sessions/sid/access"


def _change_details(access):
    return {"client_name": "App $&", "client_host": "app.example.com", "access": access}


@needs_node
def test_saving_a_change_of_access(stand_in):
    details = _change_details(_change_model(stand_in, current=CUSTOM))

    result = _run_panel(
        CHANGE + """
        panel._access.choosePreset('control');
        await panel._onSave();
        return { requests, shown };
        """,
        session=SESSION,
        answers=[details, {"access": {}}],
    )

    assert result["requests"] == [
        ["GET", f"{ACCESS_URL}?language=en", None],
        ["PUT", ACCESS_URL, {"options": CONTROL}],
    ]
    opened, listed = result["shown"]
    assert (opened["view"], opened["rows"], opened["selected"]) == ("simple", CUSTOM, "_custom")
    # The heading names the application being changed, as the list does
    assert "Change access for <bdi>App $&amp;</bdi> from <bdi>app.example.com</bdi>" in (
        opened["heading"]
    )
    # Back on the list, which says when the change takes effect
    assert listed == {
        "tab": "sessions",
        "notice": "Saved. The access you chose applies the next time <bdi>App $&amp;</bdi> "
        "gets new access; access it already has runs out within the hour.",
    }


@needs_node
def test_a_refused_change_shows_the_choice_again_from_the_current_access(stand_in):
    """As on the consent screen: the choice is kept as far as it still fits, the view
    too, and a notice says what happened."""
    before = _change_details(_change_model(stand_in, current=CUSTOM))
    ceiling = {"groups": {"lights": {"max": "read", "reason": "Limited."}}, "reason": "No."}
    now = _change_details(_change_model(stand_in, ceiling, current=CUSTOM))

    result = _run_panel(
        CHANGE + """
        panel._access.view = 'detailed';
        panel._access.chooseOption('lights', 'full');
        await panel._onSave();
        return { requests, shown, busy: panel._busy, changing: panel._changing.session_id };
        """,
        session=SESSION,
        answers=[before, {"status": 400}, now],
    )

    assert [request[0] for request in result["requests"]] == ["GET", "PUT", "GET"]
    again = result["shown"][-1]
    assert again["view"] == "detailed"
    assert again["rows"] == CUSTOM
    assert again["notice"] == (
        "The access you can allow changed after this page opened. "
        "Check your choice and save again."
    )
    assert (result["busy"], result["changing"]) == (False, "sid")


@needs_node
def test_a_session_that_is_gone_goes_back_to_the_list(stand_in):
    gone = "<bdi>App $&amp;</bdi> is no longer signed in, so its access cannot be changed."
    details = _change_details(_change_model(stand_in, current=CUSTOM))

    result = _run_panel(
        CHANGE + "await panel._onSave(); return shown;",
        session=SESSION,
        answers=[details, {"status": 404}],
    )
    assert result[-1] == {"tab": "sessions", "notice": gone}

    # Gone already when the choice is opened
    result = _run_panel(CHANGE + "return shown;", session=SESSION, answers=[{"status": 404}])
    assert result == [{"tab": "sessions", "notice": gone}]

    # Any other failure is an error
    result = _run_panel(CHANGE + "return shown;", session=SESSION, answers=[{"status": 503}])
    assert result == ["503 refused"]


@needs_node
def test_a_locked_choice_is_not_saved_and_cancel_saves_nothing(stand_in):
    locked = {"locked_presets": ["admin"], "reason": "Not for you."}
    details = _change_details(_change_model(stand_in, locked, current=CUSTOM))

    result = _run_panel(
        CHANGE + """
        for (const [group, option] of Object.entries(admin)) {
          panel._access.chooseOption(group, option);
        }
        await panel._onSave();
        await panel._leaveChange();
        return { requests, shown };
        """,
        session=SESSION,
        answers=[details],
        admin=ADMIN,
    )

    assert [request[0] for request in result["requests"]] == ["GET"]
    assert result["shown"][-1] == {"tab": "sessions", "notice": ""}


@needs_node
def test_connected_applications_offer_change_access_where_the_resource_offers_it():
    result = _run_panel(
        """
        const panel = new OidcLoginPanel();
        panel._hass = { locale: { language: 'en' } };
        panel._home = true;
        panel._tab = 'sessions';
        let card = '';
        panel._renderCard = (html) => { card = html; };
        panel.querySelectorAll = () => [];
        panel._fetchJson = async () => ({ sessions, resources: {} });
        await panel._renderSessions();
        return card;
        """,
        sessions=[
            {**SESSION, "access": None},
            {**SESSION, "session_id": "other", "access": None, "access_offered_by": None},
        ],
    )

    assert result.count('data-change="0"') == 1
    assert "data-change" not in result.split('data-session="sid"')[1]
    assert result.count(">Change access</ha-button>") == 1
    assert result.count(">Sign out</ha-button>") == 2


RENDER = """
globalThis.CSS = { escape: (value) => value };
const views = {};
// An attribute turned on or off, such as Save's disabled, and markup put into
// an element, such as the notice's #oidc-saving, are kept with their view as
// "selector attribute"
const element = (selector) => ({
  set innerHTML(html) {
    views[panel._access.view][`${selector} innerHTML`] = html;
  },
  addEventListener() {},
  toggleAttribute(name, on) {
    views[panel._access.view][`${selector} ${name}`] = on;
  },
  focus() {},
  querySelector: () => element(),
});
const panel = new OidcLoginPanel();
panel._hass = { locale: { language: 'en' } };
panel.querySelector = (selector) => element(selector);
panel.querySelectorAll = () => [];
panel._renderCard = (card, before = '') => {
  views[panel._access.view] = { card, before };
};
"""

# Both views of the choice, as rendered
SHOW_BOTH_VIEWS = """
panel._access.view = 'detailed';
panel._renderAccess();
return views;
"""


def _granted_model(stand_in, ceiling=None, *, granted, current=None) -> dict[str, Any]:
    """Return what the session access endpoint gives the panel of a session that has
    granted, the entries the description still has, or no choice when it is None."""
    return {**_change_model(stand_in, ceiling, current=current or granted), "granted": granted}


def _render_change(stand_in, ceiling=None, *, granted, current=None, name="App $&"):
    """Render both views of changing the access of a session that has granted under
    the ceiling."""
    model = _granted_model(stand_in, ceiling, granted=granted, current=current)
    return _run_panel(
        RENDER + "panel._renderChange(session, details);" + SHOW_BOTH_VIEWS,
        session={**SESSION, "client_name": name},
        details={**_change_details(model), "client_name": name},
    )


CURRENT_BADGE = '<span class="badge">What it has now</span>'
CANCEL_KEEPS = (
    '<p class="hint" id="oidc-cancel-keeps">Cancel keeps the access <bdi>App $&amp;</bdi> '
    "has now.</p>"
)
CANCEL_DESCRIBED = 'aria-describedby="oidc-cancel-keeps"'


def _notice(reason: str, changes: str) -> str:
    """Return the text of the notice that the choice opens on another than what the
    session has, with what saving it changes."""
    return (
        f"You can no longer allow the access App $&amp; has now. {reason} "
        f"Saving changes {changes}; Cancel leaves it as it is."
    )


def _text(html: str) -> str:
    """Return the text of markup, with its spaces as a browser shows them."""
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", html)).strip()


def _label(card: str, level: str) -> str:
    """Return the label of a level, or of Custom, in the simple view."""
    return re.search(rf'id="oidc-level-{level}-label">(.*?)</span>\s*<span', card, re.S).group(1)


def _marked(card: str) -> list[str]:
    """Return the options of the simple view marked as what the session has now."""
    return re.findall(rf'id="oidc-level-([\w-]+)-label">[^<]*{re.escape(CURRENT_BADGE)}', card)


def _checked(card: str) -> str:
    """Return the option of the simple view the choice is on."""
    return re.search(r'value="([^"]+)" checked', card).group(1)


def _current_line(card: str) -> str | None:
    """Return the text of the detailed view's line on what the session has now."""
    match = re.search(r'<div class="hint current-access">(.*?)</div>\s*<p>', card, re.S)
    return re.sub(r"<[^>]+>", "", match.group(1)) if match else None


@needs_node
def test_changing_access_marks_what_the_session_has_now(stand_in):
    views = _render_change(stand_in, granted=CONTROL)
    simple, detailed = views["simple"]["card"], views["detailed"]["card"]

    # The level it has, in the place of the consent screen's last choice
    assert _label(simple, "control") == f"Control devices{CURRENT_BADGE}"
    assert _marked(simple) == ["control"]
    assert "Your choice last time" not in simple
    assert _current_line(detailed) == "What App $&amp; has now: Control devices"
    # It can have it, so nothing more is said
    assert "<ha-alert" not in views["simple"]["before"] + views["detailed"]["before"]
    assert "Cancel keeps" not in simple + detailed
    assert CANCEL_DESCRIBED not in simple + detailed

    # A choice that is no level is on Custom, and named as on the list of applications
    views = _render_change(stand_in, granted=CUSTOM)
    assert _label(views["simple"]["card"], "custom") == f"Custom{CURRENT_BADGE}"
    assert _current_line(views["detailed"]["card"]) == (
        "What App $&amp; has now: CustomLike Look only, except:Cameras: NoneConfig files: Read"
    )

    # A session without a choice opens on what its next refresh gives it, unmarked
    views = _render_change(stand_in, granted=None, current=CONTROL)
    assert _checked(views["simple"]["card"]) == "control"
    assert "What it has now" not in views["simple"]["card"]
    assert _current_line(views["detailed"]["card"]) is None


@needs_node
def test_custom_is_marked_only_while_it_shows_what_the_session_has(stand_in):
    result = _run_panel(
        """
        const access = new AccessChoice(model, model.current);
        const before = access.isCurrent(CUSTOM);
        access.chooseOption('templates', 'none');
        const other = access.isCurrent(CUSTOM);
        access.chooseOption('templates', 'read');
        return { before, other, back: access.isCurrent(CUSTOM) };
        """,
        model=_granted_model(stand_in, granted=CUSTOM),
    )

    assert result == {"before": True, "other": False, "back": True}


FILES_READ = {
    "groups": {"files": {"max": "read", "reason": "Config files are limited to Read for you."}},
    "reason": "No.",
}


@needs_node
@pytest.mark.parametrize(
    ("ceiling", "reason", "opens_on", "changes", "marked"),
    [
        # Held at the ceiling, Administer is still a level of its own, which is not
        # what the session has, so it is not marked
        (
            FILES_READ,
            "Config files are limited to Read for you.",
            "admin",
            "Config files to Read",
            [],
        ),
        # Held at the ceiling, Administer is Edit the setup's choice
        (
            {"groups": {"files": {"max": "none", "reason": "Files are off."}}, "reason": "No."},
            "Files are off.",
            "configure",
            "Config files to None",
            [],
        ),
        # A locked level's choice gives way to the default level, and the locked level
        # is what the session has
        (
            {"locked_presets": ["admin"], "reason": "Read-only mode."},
            "Read-only mode.",
            "read",
            "Lights and switches to Read, Automations to Read, and Config files to None",
            ["admin"],
        ),
    ],
)
def test_changing_access_says_when_it_cannot_open_on_what_the_session_has(
    stand_in, ceiling, reason, opens_on, changes, marked
):
    views = _render_change(stand_in, ceiling, granted=ADMIN)

    for view in ("simple", "detailed"):
        before, card = views[view]["before"], views[view]["card"]
        assert '<ha-alert alert-type="warning">' in before
        assert _text(before) == _notice(reason, changes)
        # Said again right above Save, which stays on, and Cancel is described by it
        assert CANCEL_KEEPS in card
        assert (
            f'id="oidc-cancel-change" appearance="plain" variant="neutral" {CANCEL_DESCRIBED}'
            in card
        )
        assert views[view]["#oidc-save disabled"] is False
    simple = views["simple"]["card"]
    assert _checked(simple) == opens_on
    # Only a level that shows exactly what the session has is marked, here a locked one
    assert _marked(simple) == marked
    for level in marked:
        assert re.search(rf'value="{level}"\s+disabled', simple)
    # Choose in detail names it whatever the ceiling
    assert _current_line(views["detailed"]["card"]) == "What App $&amp; has now: Administer"


@needs_node
def test_a_lowered_custom_choice_is_named_but_not_marked_on_custom(stand_in):
    """Custom shows the lowered choice, which is not what the session has."""
    ceiling = {"groups": {"files": {"max": "none", "reason": "Files are off."}}, "reason": "No."}

    views = _render_change(stand_in, ceiling, granted=CUSTOM)

    simple = views["simple"]["card"]
    assert _text(views["simple"]["before"]) == _notice("Files are off.", "Config files to None")
    assert _checked(simple) == "_custom"
    assert _marked(simple) == []
    assert _current_line(views["detailed"]["card"]) == (
        "What App $&amp; has now: CustomLike Look only, except:Cameras: NoneConfig files: Read"
    )


@needs_node
def test_what_saving_changes_follows_the_choice_on_the_screen(stand_in):
    choose = """
    const access = panel._access;
    const saving = () => views[access.view]['#oidc-saving innerHTML'];
    const seen = [];
    for (const [group, option] of steps) {
      access.chooseOption(group, option);
      panel._updateApproval();
      seen.push([saving(), views[access.view]['#oidc-save disabled']]);
    }
    return seen;
    """
    model = _granted_model(stand_in, FILES_READ, granted=ADMIN)

    result = _run_panel(
        RENDER + "panel._renderChange(session, details);" + choose,
        session=SESSION,
        details=_change_details(model),
        steps=[["files", "none"], ["lights", "none"], ["cameras", "none"], ["templates", "none"]],
    )

    saving = "Saving changes {}; Cancel leaves it as it is."
    assert result == [
        [saving.format("Config files to None"), False],
        [saving.format("Lights and switches to None and Config files to None"), False],
        [
            saving.format("Lights and switches to None, Cameras to None, and Config files to None"),
            False,
        ],
        # Past three areas, the choice speaks for itself
        ["Saving changes it to the choice below; Cancel leaves it as it is.", False],
    ]

    # A choice that is what the session has is a locked level's, which cannot be saved
    model = _granted_model(stand_in, {"locked_presets": ["admin"], "reason": "No."}, granted=ADMIN)
    result = _run_panel(
        RENDER + "panel._renderChange(session, details);" + choose,
        session=SESSION,
        details=_change_details(model),
        steps=[[group, option] for group, option in ADMIN.items()],
    )
    assert result[-1] == ["", True]


WITHOUT_CAMERAS = {gid: oid for gid, oid in LOOK_ONLY.items() if gid != "cameras"}
WITHOUT_LIGHTS = {gid: oid for gid, oid in LOOK_ONLY.items() if gid != "lights"}


@needs_node
@pytest.mark.parametrize(
    ("granted", "ceiling", "reason", "opens_on", "changes", "marked"),
    [
        # Filled in, it is Look only, which is locked, so the choice opens on the
        # nearest open level
        (
            WITHOUT_CAMERAS,
            {"locked_presets": ["read"], "reason": "Look only is off."},
            "Look only is off.",
            "control",
            "Lights and switches to Full",
            ["read"],
        ),
        # Filled in, its Lights and switches are above what the user may allow
        (
            WITHOUT_LIGHTS,
            {"groups": {"lights": {"max": "none", "reason": "Lights are off."}}, "reason": "No."},
            "Lights are off.",
            "read",
            "Lights and switches to None",
            [],
        ),
    ],
)
def test_a_group_the_session_has_no_option_for_is_filled_in_as_the_list_does(
    stand_in, granted, ceiling, reason, opens_on, changes, marked
):
    """The description gained the group, or dropped the option the session has there,
    since the session chose. The server leaves the group out, and the panel takes it as
    in the default level, as the list of applications does, before it compares."""
    views = _render_change(stand_in, ceiling, granted=granted)

    simple = views["simple"]["card"]
    assert _checked(simple) == opens_on
    assert _marked(simple) == marked
    assert _text(views["simple"]["before"]) == _notice(reason, changes)
    assert CANCEL_KEEPS in simple
    assert _current_line(views["detailed"]["card"]) == "What App $&amp; has now: Look only"


NAMES = """
const panel = new OidcLoginPanel();
panel._hass = { locale: { language: 'en' } };
panel._details = details;
panel._access = new AccessChoice(details.access, details.access.current);
const text = (html) => html.replace(/<[^>]+>/g, ' ').replace(/\\s+/g, ' ').trim();
const session = {
  client_name: details.client_name,
  access: { resource: 'oidc_stand_in', options: stored },
};
return {
  list: text(panel._sessionAccess(session, { oidc_stand_in: display })),
  change: text(panel._currentHtml()),
};
"""


@needs_node
@pytest.mark.parametrize(
    ("stored", "ceiling", "words"),
    [
        # Held at the ceiling, this is the level Administer, but it is not Administer
        (
            {**ADMIN, "files": "read"},
            FILES_READ,
            "Custom Like Edit the setup, except: Config files: Read",
        ),
        # The closest level is found without the ceiling, which locks Look only
        (
            CUSTOM,
            {"locked_presets": ["read"], "reason": "No."},
            "Custom Like Look only, except: Cameras: None Config files: Read",
        ),
        # An option the description no longer has is left out by both
        ({**LOOK_ONLY, "cameras": "everything"}, None, "Look only"),
    ],
)
def test_the_change_screen_names_what_the_session_has_as_the_list_does(
    stand_in, stored, ceiling, words
):
    description = validate_description(copy.deepcopy(stand_in.DESCRIPTION))
    granted = known_options(description, stored)
    model = _granted_model(stand_in, ceiling, granted=granted)

    result = _run_panel(
        NAMES, details=_change_details(model), stored=stored, display=consent_model(description)
    )

    assert result["list"] == f"Access: {words}"
    assert result["change"] == f"What App $&amp; has now: {words}"


EVERY_CHOICE = """
const groups = model.sections.flatMap((section) => section.groups);
const product = (lists) =>
  lists.reduce((all, list) => all.flatMap((head) => list.map((item) => [...head, item])), [[]]);
const subsets = (items) =>
  items.reduce((all, item) => [...all, ...all.map((subset) => [...subset, item])], [[]]);

// Every ceiling: each group held at any option but its highest, or not held,
// with any levels locked but all of them
const presetIds = model.presets.map((preset) => preset.id);
const ceilings = [];
const highest = (group) => group.options.slice(0, -1).map((option) => option.id);
for (const maxes of product(groups.map((group) => [null, ...highest(group)]))) {
  const limits = Object.fromEntries(
    groups.flatMap((group, index) =>
      maxes[index] ? [[group.id, { max: maxes[index], reason: `${group.id} is held.` }]] : []
    )
  );
  for (const locked of subsets(presetIds).filter((subset) => subset.length < presetIds.length)) {
    const limited = Object.keys(limits).length > 0 || locked.length > 0;
    const ceiling = { groups: limits, locked_presets: locked, reason: 'Levels are locked.' };
    ceilings.push(limited ? ceiling : null);
  }
}
// Every choice a session can have as the server sends it, with an option for
// every group or for some of them
const entries = (ids) =>
  groups.flatMap((group, index) => (ids[index] ? [[group.id, ids[index]]] : []));
const choices = product(groups.map((group) => [null, ...group.options.map((option) => option.id)]))
  .map((ids) => Object.fromEntries(entries(ids)))
  .filter((choice) => Object.keys(choice).length > 0);
const complete = choices.filter((choice) => Object.keys(choice).length === groups.length);
const incomplete = choices.filter((choice) => Object.keys(choice).length < groups.length);
const few = ceilings.filter(
  (ceiling) =>
    !ceiling || (Object.keys(ceiling.groups).length <= 1 && ceiling.locked_presets.length <= 1)
);

const failures = [];
const counts = { cases: 0, moved: 0 };
const check = (ceiling, granted) => {
  const access = new AccessChoice({ ...model, ceiling, current: granted, granted }, granted);
  const shown = access.presets.map((preset) => preset.id);
  if (access.customRows) {
    shown.push(CUSTOM);
  }
  const marked = shown.filter((id) => access.isCurrent(id));
  const opensOnWhatItHas = access.same(access.rows, access.granted);
  const markedLocked = marked.length <= 1 && marked.every((id) => access.locked.has(id));
  const fine = opensOnWhatItHas
    ? access.adjusted.length === 0 && marked.length === 1 && marked[0] === access.selected
    : access.adjusted.length > 0 && markedLocked;
  if (!fine) {
    failures.push({ ceiling, granted, rows: access.rows, adjusted: access.adjusted, marked });
  }
  counts.cases += 1;
  counts.moved += opensOnWhatItHas ? 0 : 1;
};
for (const ceiling of ceilings) {
  complete.forEach((granted) => check(ceiling, granted));
}
for (const ceiling of few) {
  incomplete.forEach((granted) => check(ceiling, granted));
}
return { ...counts, failures: failures.slice(0, 3) };
"""


@needs_node
def test_the_notice_shows_exactly_when_the_choice_opens_on_another(stand_in):
    """Every choice a session can have at the stand-in, under every ceiling: the notice
    shows exactly when the choice opens on something other than what the session has,
    and otherwise what it has is marked on exactly the option the choice opens on. When
    it does show, a level the session has is marked only when it is locked.

    A choice missing groups is filled in without the ceiling, so it then behaves as the
    complete choice it becomes, which every ceiling is tried with. It is tried with the
    ceilings that hold at most one group and lock at most one level."""
    result = _run_panel(EVERY_CHOICE, model=_change_model(stand_in))

    assert result["failures"] == []
    assert result["cases"] == 108 * 1620 + 467 * 45
    assert 0 < result["moved"] < result["cases"]


@needs_node
def test_the_reasons_in_the_notice_are_text(stand_in):
    ceiling = {
        "groups": {"files": {"max": "read", "reason": "<img src=x onerror=alert(1)> {app} & co"}},
        "reason": "No.",
    }

    views = _render_change(stand_in, ceiling, granted=ADMIN, name="<b>$&</b>")

    before = views["simple"]["before"]
    assert "<img" not in before
    assert "<b>" not in before
    assert (
        "&lt;img src=x onerror=alert(1)&gt; <bdi>&lt;b&gt;$&amp;&lt;/b&gt;</bdi> &amp; co" in before
    )


@needs_node
def test_without_what_the_session_has_nothing_is_marked_or_said(stand_in):
    """As from a server that does not send granted."""
    model = _change_model(stand_in, {"locked_presets": ["admin"], "reason": "No."}, current=ADMIN)

    views = _run_panel(
        RENDER + "panel._renderChange(session, details);" + SHOW_BOTH_VIEWS,
        session=SESSION,
        details=_change_details(model),
    )

    simple = views["simple"]["card"]
    assert _checked(simple) == "read"
    assert "What it has now" not in simple
    assert "<ha-alert" not in views["simple"]["before"] + views["detailed"]["before"]
    assert "Cancel keeps" not in simple
    assert _current_line(views["detailed"]["card"]) is None


@needs_node
def test_a_refused_change_is_shown_again_with_the_notice(stand_in):
    details = _change_details(_granted_model(stand_in, FILES_READ, granted=ADMIN))

    result = _run_panel(
        RENDER + """
        panel._tab = 'sessions';
        panel._fetchJson = async () => {
          const answer = answers.shift();
          if (answer.status) {
            throw Object.assign(new Error('refused'), { status: answer.status });
          }
          return answer;
        };
        await panel._openChange(session);
        panel._access.choosePreset('configure');
        await panel._onSave();
        return { views, selected: panel._access.selected };
        """,
        session=SESSION,
        answers=[details, {"status": 400}, details],
    )

    simple = result["views"]["simple"]
    # The choice made, with what saving it changes, and why it is shown again
    assert result["selected"] == "configure"
    assert _text(simple["before"]) == (
        _notice("Config files are limited to Read for you.", "Config files to None")
        + " The access you can allow changed after this page opened. "
        "Check your choice and save again."
    )
    assert CANCEL_KEEPS in simple["card"]
    assert _marked(simple["card"]) == []


@needs_node
def test_the_consent_screen_marks_only_the_last_choice(stand_in):
    result = _run_panel(
        RENDER + "panel._renderConsent(details);" + SHOW_BOTH_VIEWS,
        details=_details(_access_model(stand_in, remembered=CONTROL)),
    )

    simple = result["simple"]["card"]
    assert (
        _label(simple, "control")
        == 'Control devices<span class="badge">Your choice last time</span>'
    )
    assert "What it has now" not in simple
    assert _current_line(result["detailed"]["card"]) is None
    for view in result.values():
        assert view["before"].count("<ha-alert") == 1
        assert "about to give <b><bdi>App</bdi></b> access" in view["before"]
        assert "Cancel keeps" not in view["card"]


@needs_node
def test_the_consent_screen_still_names_its_own_heading_and_buttons(stand_in):
    result = _run_panel(
        """
        const panel = new OidcLoginPanel();
        panel._details = details;
        return { heading: panel._choiceHeading(), footer: panel._accessFooter() };
        """,
        details=_details(_access_model(stand_in)),
    )

    assert result["heading"] == '<h1 tabindex="-1">Approve access?</h1>'
    assert 'id="oidc-approve"' in result["footer"]
    assert "You can change what <bdi>App</bdi> can do, or sign it out" in result["footer"]
