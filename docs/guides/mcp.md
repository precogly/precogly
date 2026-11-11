# MCP Server

Precogly includes an MCP server. It lets AI assistants such as Claude.ai, Claude Code, and other MCP clients read data from your Precogly instance. Today the server is read-only. It cannot create or change anything.

## Available tools

| Tool | What it does | Key parameters |
| --- | --- | --- |
| `list_threat_models` | Lists the threat models in your organizations, most recently updated first. | `organization_id` (optional) |
| `search_threat_library` | Searches the shared library of threat templates. | `query` |
| `search_countermeasure_library` | Searches the shared library of countermeasure templates. | `query`, `control_function`, `control_nature`, `cost` |
| `search_component_library` | Searches the shared library of component templates. | `query`, `category`, `kind` |

All parameters are optional. Leave them out to get everything.

### What comes back

**`list_threat_models`** returns a `models` list and a `total`. Each model has its name, description, criticality, owner (email), owning team, business unit, compliance frameworks, risk scoring method, methodologies, lifecycle phase, approval date, primary system name, serial number, version, blueprint count, and created and updated times. It does not return the contents of a model.

`frameworks` shows which frameworks at least one countermeasure maps to. It does not mean the model is compliant. Check `total` before saying how many models exist. Over the stdio transport, only the first 20 are returned.

**The three library searches** return `matches`, `matched` (how many matched), and `catalogSize` (how many the library holds). The libraries are shared by all organizations and filled by installed packs. They are templates, not the threats, countermeasures, or components in a particular model.

| Tool | Matching rules | Fields in each row |
| --- | --- | --- |
| `search_threat_library` | `query` matches name, description, and taxonomy titles. A taxonomy ID such as `CWE-20` must match in full. | Name, description, pack name, taxonomy entries (taxonomy, external ID, title) |
| `search_countermeasure_library` | `query` matches name and description. `control_function` is for example `preventive`, `detective`, or `corrective`. `control_nature` is `technical`, `administrative`, or `physical`. `cost` is `low`, `medium`, or `high`. | Name, description, control functions, control nature, cost, default status (`gap` or `platform`), pack name |
| `search_component_library` | `query` matches name, component type, provider, and qualified slug. `category` is `process`, `datastore`, `external_human_actor`, or `external_system_actor`. `kind` is a CycloneDX asset type such as `device`, `service`, or `data-store`. | Qualified slug, name, category, kind, effective kind, component type, provider, pack name |

All text matching ignores case.

## Connect an MCP client

The endpoint is `<your Precogly URL>/mcp`. On a local install it is `http://localhost:8000/mcp`.

You do not paste a token anywhere. The first time a client connects, it is sent to Precogly's own login and consent pages in your browser. You sign in and approve access. The client then gets a token that acts as you.

!!! note
    The token sees only the data in the organizations you belong to. It has the same access you have, no more.

The access token lasts 10 hours. The client refreshes it without asking you again, for up to 7 days. After that, you sign in again.

### Claude.ai

1. Go to **Settings > Connectors > Add custom connector**.
2. Enter the name `Precogly` and the URL `https://precogly.example.com/mcp`. Use your own domain.
3. Keep the detected defaults (Sign in now, Register automatically).
4. Sign in to Precogly when the browser opens, and approve access.

Claude.ai connects from the internet, so your Precogly must be reachable on a public HTTPS address. See [Self-hosting notes](#self-hosting-notes).

### Claude Code

Add the server from the command line:

```bash
claude mcp add --transport http precogly http://localhost:8000/mcp
```

Or add it to the `.mcp.json` file in your project:

```json
{
  "mcpServers": {
    "precogly": {
      "type": "http",
      "url": "http://localhost:8000/mcp"
    }
  }
}
```

Use your own URL for a deployed instance. Then run `/mcp` inside Claude Code and choose **Authenticate** to sign in through your browser.

### Other clients

Any client that supports the MCP remote transport can connect to the endpoint. The endpoint uses OAuth 2.0 with dynamic client registration, so the client registers itself.

For example, [opencode](https://opencode.ai) reads this from `opencode.json`:

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

Then run:

```bash
opencode mcp auth precogly     # discovery, registration, browser consent
opencode mcp list              # shows "connected"
```

## Self-hosting notes

The MCP endpoint runs inside the Precogly backend. You do not deploy a separate service.

For a public endpoint, set these in the backend environment:

| Variable | Meaning | Default |
| --- | --- | --- |
| `MCP_RESOURCE_URL` | The full public URL of the endpoint, for example `https://precogly.example.com/mcp`. | `http://localhost:8000/mcp` |
| `MCP_ISSUER_URL` | The public root URL of Precogly, for example `https://precogly.example.com`. | `http://localhost:8000` |

`MCP_RESOURCE_URL` must be the exact URL clients use to reach Precogly. Tokens are issued for that address and checked against it. If it is wrong, every token is rejected.

Your reverse proxy must send these paths to the backend:

- `/mcp`
- `/o/*` (sign-in and token endpoints)
- `/.well-known/*` (discovery documents)

Do not run gunicorn with `--preload`. The MCP endpoint starts its own background thread in each worker.

For a complete setup with Caddy and automatic TLS, see [Self-Hosting on AWS](self-hosting-aws.md).

## Stdio transport

Developers can also run the MCP server as a local process that talks over stdio. The tools are the same. The difference is the credential: there is no browser sign-in. You supply a token yourself, and the server passes it to the Precogly REST API without checking it.

| Variable | Meaning |
| --- | --- |
| `PRECOGLY_TOKEN` | Bearer token for the Precogly API. Required. |
| `PRECOGLY_URL` | Base URL of your Precogly. Default `http://localhost:8000`. |

Tokens last 60 minutes. When one expires, get a new one and export it again. Over stdio, `list_threat_models` returns one page of 20 models, so read `total`.

For a local dev instance, you can get a token from the login endpoint:

```bash
export PRECOGLY_URL=http://localhost:8000
export PRECOGLY_TOKEN=$(curl -s -X POST "$PRECOGLY_URL/api/auth/login/" \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@precogly.dev","password":"admin123"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access'])")
```

Then run the server from the `mcp/` directory of the repository:

```bash
uv run precogly-mcp
```

## Troubleshooting

**The client says it cannot discover or register.** The proxy may not be routing `/.well-known/*` and `/o/*` to the backend. The client finds the sign-in address from the 401 response of `/mcp`, so all three paths must work.

**Sign-in works but tool calls fail with an invalid token.** `MCP_RESOURCE_URL` does not match the URL the client connects to. Set it to the exact public URL, including `/mcp`, and restart the backend.

**502 from `/mcp`.** The backend container is not running. Check the container status and the backend logs.

**421 "Invalid Host header".** The MCP server only accepts requests addressed to `localhost`, `127.0.0.1` or `::1`. Behind a reverse proxy that forwards your public host name, it rejects every request. This is a known issue and is not yet fixed.

**Redirect loop on login.** The proxy headers are not trusted by Django. See the matching entry in the [AWS guide](self-hosting-aws.md).

**The list of threat models looks short.** Compare the number returned with `total`. Over stdio, only the first 20 are returned.

**Tools stopped working after a while.** Over stdio, the token expired after 60 minutes. Export a new `PRECOGLY_TOKEN`.
