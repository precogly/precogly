# MCP Server

Precogly includes an MCP server. It lets AI assistants such as Claude.ai, Claude Code, and other MCP clients work with your Precogly instance through its REST API, as you.

## Available tools

| Tool | What it does |
| --- | --- |
| `whoami` | Shows who the connection acts as: your user, your organizations and your role in each, and the connection's scopes. |
| `search` | Finds API endpoints. The assistant writes Python that searches the API's OpenAPI schema for the endpoints, parameters, and request bodies it needs. |
| `execute` | Calls the API. The assistant writes Python that makes the calls and works out the answer, for example counting threats across every page of a listing. |

The assistant's code runs in a sandbox with no network or file access. Its only way to reach Precogly is the API, as you, so it sees only your organizations and can do only what you can. Each `execute` run may make 100 API calls and take 30 seconds.

### Reading and changing data

A connection can read by default. Changing data, such as creating or editing a threat model, needs the `write` scope, which the client has to ask for and you have to approve when you sign in. Without it, any call that changes data is refused. Your MCP client may ask before running `execute`, because the tool can change data.

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

## Troubleshooting

**The client says it cannot discover or register.** The proxy may not be routing `/.well-known/*` and `/o/*` to the backend. The client finds the sign-in address from the 401 response of `/mcp`, so all three paths must work.

**Sign-in works but tool calls fail with an invalid token.** `MCP_RESOURCE_URL` does not match the URL the client connects to. Set it to the exact public URL, including `/mcp`, and restart the backend.

**502 from `/mcp`.** The backend container is not running. Check the container status and the backend logs.

**421 "Invalid Host header".** The MCP server only accepts requests addressed to `localhost`, `127.0.0.1` or `::1`. Behind a reverse proxy that forwards your public host name, it rejects every request. This is a known issue and is not yet fixed.

**Redirect loop on login.** The proxy headers are not trusted by Django. See the matching entry in the [AWS guide](self-hosting-aws.md).
