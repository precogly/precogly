# 0013: The server is mounted only

Status: proposed
Date: 2026-11-06
Relates to: [0008](0008-the-mcp-server-runs-inside-precogly.md),
[0011](0011-the-mcp-package-lives-in-this-repository.md), #661
Supersedes: the stdio transport

The MCP server runs only at `/mcp`, inside Precogly. Stdio, its `precogly-mcp` entry
point, `HTTPReader` and `client.py` are removed.

## Why

- **Stdio forwards a token it was not issued.** It sends `PRECOGLY_TOKEN`, a login JWT
  for `/api/`, unchecked. The MCP specification forbids this: "MCP servers **MUST NOT**
  accept any tokens that were not explicitly issued for the MCP server"
  ([Security Best Practices](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices),
  Token Passthrough).
- **Code mode would need a second dispatch path.** Its `request()` (#661) runs in
  Precogly's process. A stdio server is a separate process, so it would need HTTP and a
  token in the agent's environment.
- **No documented client needs it.** Claude Code and opencode connect over HTTP
  (`docs/guides/mcp.md`).

## Trade-offs

- Clients without a browser, such as `claude -p` in CI, cannot sign in. Nobody is known
  to depend on this; nobody has been asked. If one does, the fix is an OAuth grant made
  for it, such as the device authorization grant (RFC 8628), not stdio.
- `client.py`'s DRF error formatting is deleted with it. `request()` needs the same and
  can take it from history.
