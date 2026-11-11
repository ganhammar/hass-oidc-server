"""The documentation's complete example follows the contract it documents."""

import re
from pathlib import Path
from types import SimpleNamespace

from custom_components.oidc_provider.resource_description import (
    granted_scopes,
    validate_availability,
    validate_ceiling,
    validate_description,
)

DOCS = Path(__file__).parent.parent / "docs" / "resource-descriptions.md"


def _complete_example() -> dict:
    text = DOCS.read_text().split("## Complete example", 1)[1]
    code = re.search(r"```python\n(.*?)```", text, re.S).group(1)
    namespace: dict = {}
    exec(compile(code, str(DOCS), "exec"), namespace)
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
