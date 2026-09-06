# Precogly MCP

MCP server for Precogly threat modeling.

## Status

Early. Four tools, all read-only:

- `list_threat_models` — threat models in the caller's organizations, most recently
  updated first, with `total` beside them. Mounted, that is everything the caller can
  read; over stdio it is one page of twenty, so `total` is how you tell the difference.
- `search_threat_library`, `search_countermeasure_library`, `search_component_library` —
  the shared catalogs installed packs populate, with `matched` and `catalogSize` beside
  the rows.

Both transports work end to end. A tool reads Precogly through a protocol the mounting
application supplies rather than by forwarding the caller's token, which cannot work
mounted: a token issued for the MCP endpoint is audience-bound and invalid at Precogly's
REST API by construction ([0008](docs/0008-the-mcp-server-runs-inside-precogly.md)).

## Two transports

Which one you run decides where the credential comes from. The tools, their schemas
and their results are identical.

| | mounted in Precogly | stdio |
|---|---|---|
| credential | a user authorizes in a browser; the token is the caller's | `PRECOGLY_TOKEN` from the environment |
| lifetime | 10 hours, refreshed by the client without a prompt | 60 minutes, re-exported by hand |
| acts as | the user who authorized it | whoever the token belongs to |
| verified by | the mounting application, against its own tables | not verified; forwarded as-is |

The mounted transport is the product ([0008](docs/0008-the-mcp-server-runs-inside-precogly.md));
stdio is what predates it and what the MCP specification prescribes for a server that
speaks over a pipe.

### Mounted

Precogly serves the endpoint from its own WSGI process at `/mcp`, and supplies a token
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

### Stdio

Two environment variables, both read by the server process:

| | |
|---|---|
| `PRECOGLY_TOKEN` | Bearer token for the Precogly API. Required. |
| `PRECOGLY_URL` | Base URL of the deployment. Defaults to `http://localhost:8000`. |

Against a locally seeded instance, a token comes from the login endpoint:

```bash
export PRECOGLY_URL=http://localhost:8000
export PRECOGLY_TOKEN=$(curl -s -X POST "$PRECOGLY_URL/api/auth/login/" \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@precogly.dev","password":"admin123"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access'])")
```

Either entry point runs it:

```bash
uv run precogly-mcp                  # console script
uv run python -m precogly_mcp.server # equivalent
```

The MCP Inspector runs it too, for poking at schemas by hand. `--with-editable .` is required —
`mcp dev` runs the file in an ephemeral environment containing only `mcp`, so without it
nothing in this package imports:

```bash
uv run mcp dev src/precogly_mcp/server.py --with-editable .
```

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
streams, so `tools/list` and `tools/call` are exercised as a client sees them, and
`httpx2.MockTransport` stands in for the API.

That transport is also their blind spot: every test passed against a version of
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
