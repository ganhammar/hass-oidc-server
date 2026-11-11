# Working on this integration

[Back to the README](../README.md)

Contributions are welcome: open an issue or a pull request on [GitHub](https://github.com/ganhammar/hass-oidc-server).

## Setup

```bash
poetry install
```

## Tests

The unit tests, as CI runs them, with coverage:

```bash
poetry run pytest tests --ignore=tests/test_e2e.py --cov=custom_components/oidc_provider --cov-report=term-missing
```

The end-to-end tests in `tests/test_e2e.py` set the integration up on a real Home Assistant and drive a whole sign-in over HTTP. Locally they run against the Home Assistant version Poetry installed:

```bash
poetry run pytest tests/test_e2e.py
```

CI runs them against several Home Assistant releases, the oldest and newest of which the [FAQ](faq.md#which-home-assistant-versions-are-supported) names.

`test_oidc_flow.py` in the repository root is not part of the suite. It signs in against a running Home Assistant by hand: it asks for the address, a client ID and secret, a callback port and a resource, opens the browser, and then shows the discovery document, the access token's claims and the user info. Register a client with the redirect URI `http://localhost/callback` for it. Run it with `poetry run python test_oidc_flow.py`.

## Formatting and linting

```bash
poetry run black custom_components/ tests/
poetry run ruff check custom_components/ tests/
```

`poetry run ruff check custom_components/ tests/ --fix` fixes what Ruff can.

## The documentation

The README is a landing page, and everything else is under `docs/`. HACS shows the README outside the repository, where relative links break, so the README links to the pages by full URL (`https://github.com/ganhammar/hass-oidc-server/blob/main/docs/...`). Pages under `docs/` link to each other relatively.

A new option, action or endpoint needs its row in the docs: the option in the table on [Configuration](configuration.md#options-at-a-glance), the action in the table on [Managing clients](clients.md#actions), and the endpoint, or a field of the discovery documents, in the tables on the [Reference](reference.md). `tests/test_docs.py` fails when one is missing, when a link or anchor between the README and the pages leads nowhere, and when the README links to a page other than by full URL.
