# 0015: Consent is a page of the application

Status: proposed
Date: 2026-11-08
Relates to: [0003](0003-oauth-authorization-server.md),
[0007](0007-re-authenticating-at-consent.md), [0012](0012-code-mode-over-the-api-schema.md)
Supersedes: the server-rendered login and consent in
[0004](0004-where-the-user-authorizes.md), and [0009](0009-the-auth-pages-are-built-not-copied.md)

The consent screen an MCP client opens is a route of the React application. The
authorization server keeps the validated request and hands the page a short-lived handle;
the page reads it and posts the user's decision with the application's own JWT.
django-oauth-toolkit still validates the request, issues the code and runs the token
endpoint.

## Context

[0004](0004-where-the-user-authorizes.md) put login and consent in Django templates styled
like the application, and [0009](0009-the-auth-pages-are-built-not-copied.md) built their
stylesheet from the application's design tokens and class strings. The pages still drift,
because the markup is written twice. They also cost more than their looks:

- **Two more routes to proxy.** Login lives at `/accounts/login/` and its stylesheet under
  `/static/`. The proxy setups in `docs/guides/mcp.md` and the AWS guide route neither, so
  on those setups the authorize redirect lands on the SPA. Read from the configuration,
  not yet reproduced.
- **Committed build output.** `backend/static/css/auth.css` is generated from
  `frontend/src/auth.css`, and nothing checks that the committed copy is current.

The ecosystem has settled the shape. Of 20 remote MCP servers surveyed on 2026-11-08,
about 12 send the user to the product's own consent page. Supabase's is a React route
in its dashboard. Three (Cloudflare, Sentry, Neon) put an MCP-only page, rendered as an
HTML string, in front of the product's OAuth. Every authorization server that lets a
separate UI render consent keeps the request server-side and hands the UI a handle:
Ory Hydra's `consent_challenge`, Supabase's `authorization_id`, Spring Authorization
Server's `state`, Authlete's `ticket`. Supabase is the closest to Precogly. Its SPA reads
the handle and posts the decision with its own bearer JWT, and the handle belongs to the
first user who reads it.

## Decision

```text
 MCP client        Django (/o/authorize/)          SPA (/oauth/consent)         API
     │                     │                               │                     │
     │── GET authorize ───>│ validate (DOT)                │                     │
     │                     │ store request, id = handle    │                     │
     │<── 302 /oauth/consent?id=handle ─────────────────────>│                     │
     │                     │                               │ signed out: login   │
     │                     │                               │── GET handle (JWT) ─>│ bind to user
     │                     │                               │<── client, scopes ───│
     │                     │                               │ user confirms,      │
     │                     │                               │ re-enters password  │
     │                     │                               │── POST decision ────>│ check password,
     │                     │                               │   (JWT)             │ mark used, DOT
     │                     │                               │<── redirect_url ─────│ issues the code
     │<── navigate to redirect_url?code=… ───────────────────│                     │
```

- **A pending authorization** is a row: a random 32-byte id, the validated request, the
  user (empty until bound), an expiry 10 minutes out, and a used flag. The id is the
  only thing that leaves the server.
- **`/o/authorize/`** runs django-oauth-toolkit's `validate_authorization_request`,
  stores the row, and redirects to the SPA. It no longer requires a session. Errors
  before a valid `redirect_uri` is known render as today; later ones go back to the
  client, as django-oauth-toolkit sends them.
- **Reading the handle** (`GET`, JWT) binds the row to the caller on first read. Any other
  user, an expired row or a used row gets 404. It returns what the MCP security best
  practices require the page to show: the client's name, the scopes with their
  descriptions, and the registered `redirect_uri`. A loopback redirect is flagged so the
  page can warn about it.
- **The decision** (`POST`, JWT) carries allow or deny and the password. It locks the row,
  checks the password under a rate limit, marks the row used, and calls
  `create_authorization_response` with a request whose user is the JWT's. The response is
  the URL to send the browser to; the SPA navigates there.
- **The page** is `/oauth/consent`. A signed-out user goes through the application's own
  login and comes back. The SPA sends `frame-ancestors 'none'` and
  `X-Frame-Options: DENY` on every page, not only this one, since no Precogly page is
  meant to be framed and any of them could be overlaid to trick a click. They are set
  in `frontend/nginx.conf` and `frontend/vercel.json`; the AWS guide's Caddy proxies the
  same nginx image and passes them through.
- **Removed:** the allauth login route and `LOGIN_URL`, `authorize.html`,
  `precogly_auth_base.html`, `auth.css` and its build script. The connected-applications
  and revoke pages become a settings page in the SPA. The token, registration, discovery
  and `/mcp` endpoints are unchanged.

The second sign-in from [0007](0007-re-authenticating-at-consent.md) stays, as a password
field on the consent card instead of a second login page. Every Precogly account has a
password today; no social or SSO provider is configured. An account without one would
need another way to confirm, and none is designed here.

Step-up authorization for `write` (SESSION.md, not yet built) reuses this page: the
client's re-authorization opens it with `write` among the scopes.

## Verified

A spike on 2026-11-08 against django-oauth-toolkit 3.4.1 drove the flow above outside its
view. It validated a GET, kept the request as JSON, then called
`create_authorization_response` from a separate POST whose user was set by hand. The code
was issued, and the grant held the user, the PKCE challenge and the resource. Two things
the implementation has to carry:

- The view mixin's `create_authorization_response` takes the scopes as one
  space-separated string; `OAuthLibCore`'s takes a list. Passing the string to
  `OAuthLibCore` fails with `invalid_scope`, because it checks `set(scopes)`, the
  string's characters.
- `resource` is not in the validated credentials. It comes from the GET's query and must
  be stored as a list, as `form_valid` does; otherwise saving the grant fails with
  "Resource must be a list of URI strings".

## Rejected

- **allauth headless, so the SPA holds a Django session.** It works beside the JWT login:
  a spike showed DRF ignores the session cookie and `/o/authorize/` accepts it. But it is
  a second authentication system, the cookie rides on every same-origin `/api` request,
  and from allauth 65.20.0 a fresh login no longer counts as recent, so a signed-out user
  would type the password twice.
- **React components rendered on Django-served pages**, the shape of Auth0's custom
  Universal Login and Logto's bring-your-own UI. It ends the visual drift and leaves
  django-oauth-toolkit stock, but keeps two page shells and the `/accounts` and `/static`
  routes. The fallback if this record's flow proves too costly.
- **The status quo.** The drift is what started this.
- **A JSON authorize endpoint upstream.** django-oauth-toolkit's maintainer declined one
  (#1305), wanting spec or major-provider backing first.

## Trade-offs

- **We own security-critical glue.** django-oauth-toolkit's view re-validates a tampered
  form and calls its two methods in order; here, our code does. The handle's binding,
  expiry and single use, and the `resource` carried across, each need a test.
- **The password check needs a rate limit that does not exist yet.** Nothing in Precogly
  limits password attempts today, the JWT login included.
- **Consent needs JavaScript.** The template pages worked without it. Claude Code and
  opencode open the system browser, which runs it; a client that renders consent in a
  restricted webview is not known to exist, but none was checked.
- **The connected-applications page moves too**, which is more SPA work than consent
  alone.

## Sources

- MCP security best practices (consent page requirements):
  <https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices>
- RFC 9700 §4.16 (clickjacking at the authorization endpoint):
  <https://www.rfc-editor.org/rfc/rfc9700.txt>
- Supabase Auth v2.197.0, `internal/api/oauthserver/authorize.go`:
  <https://github.com/supabase/auth/blob/v2.197.0/internal/api/oauthserver/authorize.go>
- Ory Hydra v26.2.0, `consent/strategy_default.go`:
  <https://github.com/ory/hydra/blob/v26.2.0/consent/strategy_default.go>
- django-oauth-toolkit #1305: <https://github.com/django-oauth/django-oauth-toolkit/issues/1305>
- django-allauth 65.20.0 changelog, reauthentication:
  <https://github.com/pennersr/django-allauth/blob/3d4d78c988fbe8c89a2882b61da7536904da7af7/ChangeLog.rst>
- Cloudflare's approval page:
  <https://github.com/cloudflare/mcp-server-cloudflare/blob/a21972e219289337731a066befb5c66886b9ce7b/packages/mcp-common/src/workers-oauth-utils.ts>
