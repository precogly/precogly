# 0007: The second sign-in is the point

Status: accepted; the password is asked on the consent page rather than a second login
page since [0015](0015-consent-is-a-page-of-the-application.md)
Date: 2026-08-08
Relates to: [0003](0003-oauth-authorization-server.md), [0004](0004-where-the-user-authorizes.md),
[0015](0015-consent-is-a-page-of-the-application.md)

A user who is already signed into Precogly is asked for their password again when they
authorize an MCP client. That stays, and the login page says why.

## Context

[0004](0004-where-the-user-authorizes.md) decided that Precogly routes a server-rendered
login and a consent screen. It designed for a user who is not signed in. The common case
is the opposite: someone is working in Precogly, connects a client, and a browser window
opens asking for a password they entered an hour ago.

The mechanics are not an oversight in the backend. `dj_rest_auth`'s `SESSION_LOGIN`
defaults to `True` and Precogly does not override it, so `POST /api/auth/login/` already
sets a `sessionid` alongside the JWTs it returns — and that session satisfies
django-oauth-toolkit's authorize view on its own. The cookie is discarded on the way out:
`frontend/src/lib/api.ts` sends no `credentials: "include"` on any request, and `login()`
opens by clearing cookies, with a comment recording that stale `sessionid` cookies once
caused CSRF failures. So the session exists for exactly one response and is never seen
again.

That means the second sign-in is roughly one line away from not happening, which is what
makes it worth deciding rather than fixing on reflex.

## Decision

Keep it, and change the copy so it reads as a decision rather than as a bug.

The login template renders "Confirm it's you", and explains that an application is about
to act on the user's behalf, whenever `next` points at the authorize endpoint. Any other
arrival at the login page is an ordinary sign-in and says so. A test pins both, because
the copy *is* the mitigation — a tidy-up that restores a generic "Sign in" turns the
decision back into an accident with nothing failing.

Granting an agent standing access to a threat model is the most consequential thing a
user can do in Precogly without a confirmation dialog. Re-authenticating in front of it
is the same move GitHub makes for sensitive operations, and this is a security product.

## Rejected

- **Keep the session cookie in the SPA** — add `credentials: "include"` to the login
  request. Nearly free, since the server half already works. Rejected because it makes
  every request in the application carry a session cookie in order to smooth one rare
  action, and this project removed session handling from the DRF configuration
  deliberately. The scar tissue is real even if the specific failure is no longer
  reachable: `SessionAuthentication` is out of `DEFAULT_AUTHENTICATION_CLASSES`, so DRF
  no longer enforces CSRF off that cookie.

- **Bridge on demand** — an endpoint the SPA calls with its JWT immediately before
  redirecting to `/o/authorize/`, minting a session and forwarding. Keeps the cookie
  inside the authorization flow, where it belongs. Rejected for now as roughly thirty
  lines spent removing a prompt we have just decided we want. It is the fallback if the
  prompt turns out to be a real complaint rather than a supposed one.

- **Render consent in the SPA** — already rejected in
  [0004](0004-where-the-user-authorizes.md), and it dissolves this question entirely
  since the redirect never leaves the application. Still the right answer once consent
  has to carry product logic; consent-time organization selection, deferred in
  [0003](0003-oauth-authorization-server.md), is what would force it.

## Trade-offs

- **It is friction users have not been trained to expect.** Nobody re-authenticates you
  to connect Atlassian, Linear or Notion, so a password prompt reads as an obstacle
  rather than as care. This is the strongest argument against the decision and it is not
  answered, only accepted: the copy is a bet that a stated reason converts the friction
  into reassurance. If connection-abandonment is ever measurable, that bet is testable.

- **The reasoning lives in copy, which is the least durable place to put it.** A
  rewording loses it. The test is what stops that being silent, but a test can be
  updated to match a change nobody thought through.
