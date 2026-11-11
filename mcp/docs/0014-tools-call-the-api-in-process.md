# 0014: Tools call the API in-process

Status: accepted
Date: 2026-11-07
Relates to: [0008](0008-the-mcp-server-runs-inside-precogly.md),
[0012](0012-code-mode-over-the-api-schema.md), #441, #487
Supersedes: the dispatch question in [0012](0012-code-mode-over-the-api-schema.md)'s
Open section, and `ORMReader` from [0008](0008-the-mcp-server-runs-inside-precogly.md)

Code-mode tools reach data through `request(access_token, method, path)` in
`backend/apps/core/mcp/api.py`. It runs the REST API's views in-process as the user
the `/mcp` token resolved to.

## Decision

- **Full middleware chain.** A `BaseHandler` with middleware loaded dispatches a
  `RequestFactory`-built request, so the call passes through what an external request
  does. Calling a view directly would skip middleware.
- **No credential crosses the call.** DRF ignores `request.user` and runs its own
  authentication classes, so `dispatch` sets `request._force_auth_user`, which makes
  DRF use `ForcedAuthentication` alone.
- **Addressed to the public origin.** The request carries the host and scheme of
  `MCP_RESOURCE_URL`. `RequestFactory`'s default, `testserver` over http, gets a 400
  from `ALLOWED_HOSTS` and a 301 from `SECURE_SSL_REDIRECT` in production. Tests hide
  both, so the dispatch tests override settings to look like production.
- **Unsafe methods require the `write` scope,** checked before dispatch.
- **Errors raise.** Status 400 or above raises `APIError` with DRF's reason, so a model
  that forgets to check a status cannot read an error body as data.
- **The hand-written tools and `ORMReader` are removed,** on the same branch as
  `execute`, so the server is never released without a way to read data.

## Rejected

- **Loopback HTTP**, as Cloudflare does. Their server is a separate service, so HTTP is
  its only route, and it holds a second Cloudflare token per user
  ([`src/auth/oauth-handler.ts` at `e8bc56f`](https://github.com/cloudflare/mcp/blob/e8bc56f8638bc8ee6b6a2ccc1541b7fab46187e2/src/auth/oauth-handler.ts)).
  Precogly would need one too, because `/api/` refuses the audience-bound `/mcp` token.
  It would also deadlock: each `/mcp` call holds one of gunicorn's eight slots
  (`--workers 4 --threads 2`) while its `/api/` calls wait for another.
- **Keeping the four tools on `ORMReader` until `execute` ships.** The branch is
  unmerged, so removing them early costs nothing as long as it merges with `execute`.

## Trade-offs

- `request()` inherits the API's leaks as well as its checks. MCP10 in #487 (catalog
  tables that serve tenant-authored rows to every organization) is in the viewsets too.
- Dispatch costs more than a direct query. Not measured.
- If the server moves to its own service, `request()` becomes HTTP and needs the second
  token.
