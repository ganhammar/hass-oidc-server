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
