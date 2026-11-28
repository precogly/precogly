# 0004: Where the user authorizes

Status: partly superseded. The server-rendered login and consent, and the session that
authenticates them ("Two authentication mechanisms"), by
[0015](0015-consent-is-a-page-of-the-application.md); the drift trade-off earlier by
[0009](0009-the-auth-pages-are-built-not-copied.md). `ALLOW_LOCALHOST_LOOPBACK` stands.
Date: 2026-07-29
Relates to: [0003](0003-oauth-authorization-server.md)

Precogly routes a server-rendered login and a consent screen, both styled to match the
application, so that the browser window opened during authorization looks like Precogly.

[0003](0003-oauth-authorization-server.md) decides that Precogly issues the tokens and
what the MCP server does with them. This decides only what the user sees while that
happens, and what Precogly has to route for it to work at all. The grant, the token
model, and the choice of django-oauth-toolkit are settled there and not revisited here.

## Context

Precogly has no browser login page. `config/urls.py` routes `dj_rest_auth.urls` and
nothing else for authentication; the only browser-facing Django views in the project are
`/admin/` and the API documentation. allauth is installed with its account middleware
(`config/settings/base.py:51-53`, `:81`), but its URLs are never included and `LOGIN_URL`
is unset. What users think of as the login page is the React application on `:5173`,
which posts to `/api/auth/login/` and holds a JWT client-side. That is not a Django
session, and nothing server-rendered can consume it.

django-oauth-toolkit's `AuthorizationView` extends `LoginRequiredMixin` through
`BaseAuthorizationView` (`views/base.py:38`) and never overrides `login_url`, so an
unauthenticated request to the authorize endpoint is redirected to `LOGIN_URL`. Django's
default for that is `/accounts/login/`, and this project routes nothing under
`/accounts/` — `resolve("/accounts/login/")` raises `Resolver404`.

Install the authorization server and change nothing else, and the browser window opens on
a 404. Routing a login is therefore not polish on a flow that already works; it is what
makes the flow work at all. The screen nobody chose arrives one step later — from routing
allauth and stopping there, which does work and is the option rejected below.

## Decision

Route allauth's browser login, and override the two templates the flow renders.

- `path("accounts/", include("allauth.urls"))` in `config/urls.py`, with `LOGIN_URL` set
  to match. allauth is already installed and `APP_DIRS` is on, so this alone produces a
  working server-rendered login that establishes a real session.
- Override allauth's login template and django-oauth-toolkit's `authorize.html` so both
  carry the application's styling.

`ALLOW_LOCALHOST_LOOPBACK` has to be on for the return leg. django-oauth-toolkit applies
RFC 8252's loopback port exemption to `127.0.0.1` and `::1` only, and deliberately withholds
it from the hostname `localhost` because §8.3 marks that spelling NOT RECOMMENDED
(`models.py:1098-1114`). Clients spell it `localhost` anyway — the callback in Claude Code's
own connector is `http://localhost:<port>/callback` — so without the setting the redirect
URI matches on the first authorization and fails whenever the client next binds a different
ephemeral port. It presents as an intermittent `redirect_uri` mismatch with nothing in the
request to explain it.

The second half is the decision. The first half is what makes the flow function; without
the second, the user leaves a designed product, authorizes on two pages that look like
neither it nor each other, and comes back.

**Rejected: routing allauth and keeping the default templates.** It is two lines and it
works, which is exactly why it would ship and why the styled version would then never be
written. The cost of the templates is CSS, paid once, against a screen every user of this
integration sees.

**Rejected: rendering the authorize UI in the SPA.** The most control and the only option
where the redirect never leaves the design system, at the cost of implementing consent
against the authorization server's endpoints. Worth revisiting when the consent screen has
to carry product logic rather than styling — choosing an organization during consent is
the deferred item in 0003 that would force it.

## Two authentication mechanisms, deliberately

Sessions authenticate the authorize handshake. Bearer tokens authenticate the API. Both
exist from here on.

This is recorded because it reads as a mistake in context. `base.py:171` notes that
`SessionAuthentication` was removed from the DRF configuration after stale `sessionid`
cookies caused CSRF errors during login. The session introduced here is not that session
returning: it is not a DRF authentication class, it authenticates no API request, and it
lives only long enough to establish who is granting consent. Anyone who finds it later,
recognises the pattern that was removed, and removes it again will break authorization
without breaking a single test that exists today.

## Trade-offs

- **Two templates to keep in step with the frontend.** They live in the Django app and
  will drift from the React application, because nothing links them. Accepted: the
  alternative that avoids drift is implementing consent in the SPA, which costs more than
  the drift does.

  Withdrawn by [0009](0009-the-auth-pages-are-built-not-copied.md). The choice was not
  between drift and rendering consent in the SPA: the pages can be built from the
  application's own tokens, which links them. The drift was real in the meantime and
  shipped three defects.

- **The consent screen becomes a product surface.** Once it is styled it invites content —
  scope explanations, organization pickers, revocation links. That is a feature backlog
  attached to a screen whose current job is to say yes. Worth knowing before it starts.
