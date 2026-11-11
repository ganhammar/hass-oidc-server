"""The documentation names what the integration really offers, and its links lead somewhere.

The references are written by hand, so these fail when an option, action,
endpoint, discovery field, scope, lifetime or limit changes without the page
that lists it following. The integration author page's complete example is
checked against the contract it documents.
"""

import inspect
import json
import re
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import yaml
from homeassistant.components.http import HomeAssistantView

from custom_components.oidc_provider import const, http
from custom_components.oidc_provider.client_manager import MAX_CLIENT_NAME_LENGTH
from custom_components.oidc_provider.resource_description import (
    existing_sessions_options,
    granted_scopes,
    validate_availability,
    validate_ceiling,
    validate_choice,
    validate_description,
)

ROOT = Path(__file__).parent.parent
DOCS = ROOT / "docs"
README = ROOT / "README.md"
PAGES = [README, *sorted(DOCS.rglob("*.md"))]
COMPONENT = ROOT / "custom_components" / "oidc_provider"
REPO_URL = "https://github.com/ganhammar/hass-oidc-server/blob/main/"
AUTHOR_PAGE = DOCS / "resource-descriptions.md"


def _prose(page: Path) -> str:
    """Return a page without its fenced code blocks."""
    return re.sub(r"(?ms)^```.*?^```", "", page.read_text())


def _section(text: str, heading: str) -> str:
    """Return the body of a section, up to the next heading of its level or above."""
    match = re.search(rf"(?m)^(#+) {re.escape(heading)}\n", text)
    assert match, f"no section '{heading}'"
    level = len(match[1])
    end = re.compile(rf"(?m)^#{{1,{level}}} ")
    following = end.search(text, match.end())
    return text[match.end() : following.start() if following else len(text)]


def _rows(section: str) -> list[list[str]]:
    """Return the cells of every table row in a section, without header rows."""
    rows = []
    table: list[str] = []
    for line in [*section.splitlines(), ""]:
        if line.startswith("|"):
            table.append(line)
            continue
        rows += [[cell.strip() for cell in row.strip("|").split("|")] for row in table[2:]]
        table = []
    return rows


def _code(cell: str) -> list[str]:
    """Return the code spans in a table cell."""
    return re.findall(r"`([^`]+)`", cell)


def _anchors(page: Path) -> set[str]:
    """Return the anchors GitHub gives a page's headings."""
    anchors: set[str] = set()
    for line in _prose(page).splitlines():
        if not line.startswith("#"):
            continue
        slug = re.sub(r"[^\w\- ]", "", line.lstrip("#").strip().lower()).replace(" ", "-")
        anchor, number = slug, 0
        while anchor in anchors:
            number += 1
            anchor = f"{slug}-{number}"
        anchors.add(anchor)
    return anchors


def _duration(seconds: int) -> str:
    """Return a duration as the pages write it, such as 10 minutes or 1 hour."""
    for unit, size in (("day", 86400), ("hour", 3600), ("minute", 60), ("second", 1)):
        if seconds % size == 0:
            count = seconds // size
            return f"{count} {unit}{'s' if count != 1 else ''}"
    raise AssertionError(seconds)


def _per(seconds: int) -> str:
    """Return a rate's window as the pages write it, such as an hour."""
    return {60: "a minute", 3600: "an hour"}[seconds]


@pytest.mark.parametrize("page", PAGES, ids=lambda page: str(page.relative_to(ROOT)))
def test_links_between_the_pages_lead_somewhere(page: Path):
    """The README links by full URL, since HACS shows it outside the repository.

    Pages under docs/ link to each other relatively, so they work on any branch.
    """
    for target in re.findall(r"\]\(([^)\s]+)\)", _prose(page)):
        if target.startswith(REPO_URL):
            assert page == README, f"{page.name} links to {target} by full URL, not relatively"
            path, _, anchor = target[len(REPO_URL) :].partition("#")
            linked = ROOT / path
        elif target.startswith(("http://", "https://", "mailto:")):
            continue
        else:
            path, _, anchor = target.partition("#")
            assert page != README or not path, f"README links to {target} relatively"
            linked = (page.parent / path).resolve() if path else page
        assert linked.is_file(), f"{page.name} links to missing {target}"
        if anchor and linked.suffix == ".md":
            assert anchor in _anchors(linked), f"{page.name} links to missing anchor {target}"


def test_the_readme_links_every_page():
    linked = set(re.findall(rf"\]\({re.escape(REPO_URL)}(docs/[\w-]+\.md)", README.read_text()))

    assert linked == {str(page.relative_to(ROOT)) for page in DOCS.glob("*.md")}


class TestOptions:
    """Configuration lists every option with the name and default the UI shows."""

    page = (DOCS / "configuration.md").read_text()
    translations = json.loads((COMPONENT / "translations" / "en.json").read_text())

    def _options(self) -> dict[str, str]:
        return self.translations["options"]["step"]["init"]["data"]

    def test_every_option_has_a_row_with_its_default(self):
        documented = {row[0]: row[1] for row in _rows(_section(self.page, "Options at a glance"))}

        assert documented == {
            label: "On" if getattr(const, f"DEFAULT_{key.upper()}") else "Off"
            for key, label in self._options().items()
        }

    def test_every_option_has_a_section(self):
        for label in self._options().values():
            assert _section(self.page, label).strip(), label

    def test_the_setup_form_asks_only_for_options(self):
        setup = self.translations["config"]["step"]["user"]["data"]

        assert setup.items() <= self._options().items()


class TestActions:
    """Managing clients lists every action with its name and fields."""

    services = yaml.safe_load((COMPONENT / "services.yaml").read_text())
    rows = _rows(_section((DOCS / "clients.md").read_text(), "Actions"))

    def test_every_action_in_services_yaml_is_registered(self):
        source = (COMPONENT / "__init__.py").read_text()
        registered = re.findall(
            r'async_register(?:_admin_service)?\(\s*(?:hass,\s*)?DOMAIN,\s*"(\w+)"', source
        )

        assert sorted(registered) == sorted(self.services)

    def test_every_action_has_a_row(self):
        documented = {_code(row[0])[0]: row[1] for row in self.rows}

        assert documented == {
            f"{const.DOMAIN}.{action}": schema["name"] for action, schema in self.services.items()
        }

    def test_every_row_names_the_actions_fields(self):
        documented = {_code(row[0])[0]: sorted(_code(row[2])) for row in self.rows}

        assert documented == {
            f"{const.DOMAIN}.{action}": sorted(schema.get("fields") or {})
            for action, schema in self.services.items()
        }


def _views() -> list[type[HomeAssistantView]]:
    """Return the views the integration registers."""
    registered = re.findall(
        r"register_view\((\w+)\(\)\)", inspect.getsource(http.setup_http_endpoints)
    )
    return [getattr(http, name) for name in registered]


def test_the_reference_lists_every_endpoint_with_its_methods():
    methods = ("get", "post", "put", "patch", "delete")
    expected = {f"/{const.PANEL_URL_PATH}": "GET"}
    for view in _views():
        allowed = ", ".join(method.upper() for method in methods if hasattr(view, method))
        for url in [view.url, *getattr(view, "extra_urls", [])]:
            expected[url] = allowed

    rows = _rows(_section((DOCS / "reference.md").read_text(), "Endpoints"))

    assert {_code(row[0])[0]: row[1] for row in rows} == expected


async def test_the_reference_lists_every_field_of_the_discovery_documents():
    """With every option on, so that the fields that depend on one are there too."""
    hass = Mock()
    hass.data = {
        const.DOMAIN: {
            const.CONF_ALLOW_DYNAMIC_REGISTRATION: True,
            const.CONF_ALLOW_CLIENT_METADATA_DOCUMENTS: True,
        }
    }
    request = Mock()
    request.headers = {}
    request.url.origin.return_value = "https://ha.example.com"
    request.app = {"hass": hass}

    async def fields(view: type[HomeAssistantView]) -> set[str]:
        return set(json.loads((await view().get(request)).body))

    openid = await fields(http.OIDCDiscoveryView)
    metadata = await fields(http.OAuth2AuthorizationServerMetadataView)
    assert metadata == await fields(http.OAuth2AuthorizationServerMetadataAlternateView)

    expected = {}
    for field in openid | metadata:
        if field in openid and field in metadata:
            expected[field] = "All"
        elif field in openid:
            expected[field] = "OpenID Connect discovery"
        else:
            expected[field] = "Authorization server metadata"

    rows = _rows(_section((DOCS / "reference.md").read_text(), "Discovery documents"))

    assert {_code(row[0])[0]: row[1].split(",")[0] for row in rows} == expected


class TestReference:
    """The reference's scopes, lifetimes and limits are the code's."""

    page = (DOCS / "reference.md").read_text()

    def test_every_scope_has_a_row(self):
        rows = _rows(_section(self.page, "Scopes and claims"))

        assert [_code(row[0])[0] for row in rows] == const.SUPPORTED_SCOPES

    def test_the_lifetimes_are_the_codes(self):
        documented = {row[0]: row[1] for row in _rows(_section(self.page, "Lifetimes"))}
        expected = {
            "Access token": const.ACCESS_TOKEN_EXPIRY,
            "ID token": const.ID_TOKEN_EXPIRY,
            "Refresh token": const.REFRESH_TOKEN_EXPIRY,
            "Authorization code": const.AUTHORIZATION_CODE_EXPIRY,
            "Replaced refresh token": const.REFRESH_TOKEN_REUSE_GRACE,
        }

        assert documented.keys() == expected.keys()
        for token, seconds in expected.items():
            assert documented[token].startswith(_duration(seconds)), token

    def test_the_limits_are_the_codes(self):
        documented = {row[0]: " ".join(row[1:]) for row in _rows(_section(self.page, "Limits"))}
        expected = {
            "Failed client authentication at the token and revocation endpoints": [
                f"{const.MAX_TOKEN_ATTEMPTS} for one client from one address",
                f"over {_duration(const.RATE_LIMIT_WINDOW)}",
                f"for {_duration(const.RATE_LIMIT_PENALTY)}",
            ],
            "Sign-ins waiting on the login page": [
                f"{const.MAX_PENDING_AUTH_REQUESTS} in all, "
                f"{const.MAX_PENDING_AUTH_REQUESTS_PER_ADDRESS} from one address"
            ],
            "Dynamic client registrations": [
                f"{const.REGISTRATION_RATE_LIMIT_MAX} {_per(const.REGISTRATION_RATE_LIMIT_WINDOW)}"
                f" in all, {const.REGISTRATION_RATE_LIMIT_PER_ADDRESS} from one address"
            ],
            "Self-registered clients that have not had a token issued": [
                str(const.MAX_UNUSED_DYNAMIC_CLIENTS)
            ],
            "Metadata document fetches that miss the cache": [
                f"{const.CIMD_FETCHES_PER_MINUTE} a minute in all, "
                f"{const.CIMD_FETCHES_PER_MINUTE_PER_ADDRESS} from one address"
            ],
            "Metadata document size": [f"{const.CIMD_MAX_DOCUMENT_BYTES // 1024} KB"],
            "Metadata document fetch": [_duration(const.CIMD_FETCH_TIMEOUT)],
            "Client name": [f"{MAX_CLIENT_NAME_LENGTH} characters"],
        }

        assert documented.keys() == expected.keys()
        for limit, phrases in expected.items():
            for phrase in phrases:
                assert phrase in documented[limit], f"{limit}: {phrase}"


def test_the_faq_names_the_home_assistant_releases_ci_tests():
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "main.yml").read_text())
    tested = sorted(
        tuple(int(part) for part in entry["ha-version"].split(".")[:2])
        for entry in workflow["jobs"]["integration-test"]["strategy"]["matrix"]["include"]
    )
    oldest, newest = (".".join(map(str, version)) for version in (tested[0], tested[-1]))

    assert f"from {oldest} to {newest}" in (DOCS / "faq.md").read_text()


def _complete_example() -> dict:
    text = AUTHOR_PAGE.read_text().split("## Complete example", 1)[1]
    code = re.search(r"```python\n(.*?)```", text, re.S).group(1)
    namespace: dict = {}
    exec(compile(code, str(AUTHOR_PAGE), "exec"), namespace)
    return namespace


async def test_the_complete_example_is_a_valid_description():
    example = _complete_example()

    description = validate_description(await example["async_describe_resource"](None, "en"))
    availability = validate_availability(
        description, await example["async_get_availability"](None, "en")
    )
    ceiling = validate_ceiling(
        description,
        await example["async_get_ceiling"](None, SimpleNamespace(is_admin=False), "en"),
    )

    assert description["resource"] == ["/api/mcp", "/api/mcp_http"]
    assert availability == {"files": "Turned off in the MCP Server integration's options."}
    assert ceiling["groups"]["files"]["max"] == "none"
    assert await example["async_get_ceiling"](None, SimpleNamespace(is_admin=True), "en") is None
    control = description["presets"][1]["options"]
    assert granted_scopes(description, control) == ["mcp:control"]
    assert granted_scopes(description, {**control, "cameras": "none"}) == [
        "mcp:entities:full",
        "mcp:dashboards:read",
        "mcp:templates:read",
    ]
    # A session from before gets Administer, which a user limited to no files gets held at
    # the choice of Edit the setup
    assert existing_sessions_options(description, None) == description["presets"][3]["options"]
    options = validate_choice(
        description, ceiling, {"options": existing_sessions_options(description, ceiling)}
    )
    assert granted_scopes(description, options) == ["mcp:configure"]
