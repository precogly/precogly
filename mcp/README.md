# Precogly MCP

MCP server for Precogly threat modeling.

## Status

Code mode ([0012](docs/0012-code-mode-over-the-api-schema.md)): three tools over
Precogly's REST API instead of one tool per question.

- `whoami` — the user, their organizations and roles, and the token's scopes.
- `search` — runs model-written Python over the OpenAPI schema, reduced and with
  `$ref`s inlined (`spec.py`).
- `execute` — runs model-written Python with an async `request()` that calls the API
  in-process as the token's user ([0014](docs/0014-tools-call-the-api-in-process.md)).
  Writes need the `write` scope.

Model-written code runs in a `pydantic-monty` sandbox pool opened in the server's
lifespan. Results are capped at 24,000 characters and stay valid JSON (`truncate.py`).

The mounting application supplies the token verifier, `request()` and the schema, so
this package never imports Django: `backend/apps/core/mcp/` and
`backend/config/mcp_mount.py` are the other half.

## Connecting

The server runs only mounted inside Precogly; there is no stdio transport
([0013](docs/0013-the-server-is-mounted-only.md)). Precogly serves the endpoint from its own WSGI process at `/mcp`, and supplies a token
verifier — this package never imports Django. `backend/config/mcp_mount.py` is the
whole of the wiring. A client then needs no configuration beyond the URL:

```json
{
  "mcp": {
    "precogly": {
      "type": "remote",
      "url": "http://localhost:8000/mcp",
      "enabled": true
    }
  }
}
```

For [opencode](https://opencode.ai), that is an `opencode.json` — either in the project
root or in `~/.config/opencode/`, which makes the server reachable from any directory —
followed by:

```bash
opencode mcp auth precogly     # discovery, registration, browser consent
opencode mcp list              # ✓ connected
```

The client discovers where to authorize from the 401 this endpoint returns, registers
itself, and sends the user to Precogly's own login and consent screens
([0004](docs/0004-where-the-user-authorizes.md),
[0009](docs/0009-the-auth-pages-are-built-not-copied.md)). Nothing is pasted anywhere.
For Claude Code, see `docs/guides/mcp.md` at the repository root.

## Development

Run these from this directory. uv installs this member's dependencies only, so
Django and psycopg stay out of it even though they are in the same lock.

```bash
uv run pytest              # run tests
uv run ruff check .        # lint
uv run ruff format .       # format
uv run mypy src            # type-check (strict)
uv run pip-audit           # scan dependencies for CVEs
```

The git hooks are the repository's, installed once from the root with
`uv run pre-commit install`.

Tests need no running Precogly. `mcp.client.Client` drives the server over in-memory
streams, so `tools/list` and `tools/call` are exercised as a client sees them, and a
fake `request` in `tests/test_tools.py` stands in for Precogly. The sandbox is real.
The tools' examples run against the real schema and API in the backend's
`apps/core/tests/test_mcp_*_examples.py`.

The fake is also their blind spot: once, every test passed against a version of
`tools/call` that failed on the first real request, because the fake never enforced the
audience binding a live token carries. A change to how tools reach data, or to what
Precogly's serializers return, wants a run against a seeded stack before it is believed.

## Design

- [0001](docs/0001-service-token-model.md) — service token model (partially superseded by 0003)
- [0002](docs/0002-tool-implementation-order.md) — tool implementation order
- [0003](docs/0003-oauth-authorization-server.md) — Precogly is the authorization server (resource server superseded by 0008)
- [0004](docs/0004-where-the-user-authorizes.md) — where the user authorizes
- [0005](docs/0005-code-execution-over-tools.md) — code execution over tools
- [0006](docs/0006-catalog-search-filters-here.md) — catalog search filters here
- [0007](docs/0007-re-authenticating-at-consent.md) — re-authenticating at consent
- [0008](docs/0008-the-mcp-server-runs-inside-precogly.md) — the MCP server runs inside Precogly (submodule superseded by 0011)
- [0009](docs/0009-the-auth-pages-are-built-not-copied.md) — the authorization pages are built, not copied
- [0010](docs/0010-the-mcp-app-owns-its-resource-metadata.md) — the MCP app owns its resource metadata
- [0011](docs/0011-the-mcp-package-lives-in-this-repository.md) — the MCP package lives in this repository (supersedes 0008's submodule)
- [0012](docs/0012-code-mode-over-the-api-schema.md) — code mode over the API schema
- [0013](docs/0013-the-server-is-mounted-only.md) — the server is mounted only (supersedes stdio)
- [0014](docs/0014-tools-call-the-api-in-process.md) — tools call the API in-process
